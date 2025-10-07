#!/usr/bin/env python3
import os
import json
import yaml
import paramiko
from datetime import datetime

# === File Paths ===
BASE_DIR = os.path.expanduser("~/network-auditor")
REPORTS_DIR = os.path.join(BASE_DIR, "reports")
DEVICE_INVENTORY = os.path.join(BASE_DIR, "device_inventory.yaml")
BASELINE_DIR = os.path.join(BASE_DIR, "baselines")
SSH_BASELINE = os.path.join(BASELINE_DIR, "ssh_baseline.yaml")
FIREWALL_BASELINE = os.path.join(BASELINE_DIR, "firewall_baseline.yaml")
USERS_BASELINE = os.path.join(BASELINE_DIR, "users_baseline.yaml")

os.makedirs(REPORTS_DIR, exist_ok=True)


# === Utility Functions ===
def load_yaml(path):
    with open(path, "r") as f:
        return yaml.safe_load(f)


def ssh_connect(ip, username, password):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=username, password=password)
    return client


def run_command(client, cmd, sudo=False):
    if sudo:
        cmd = f"sudo -S -p '' {cmd}"
    stdin, stdout, stderr = client.exec_command(cmd)
    if sudo:
        stdin.write("AuditPass123\n")
        stdin.flush()
    return stdout.read().decode().strip()


# === Extractors ===
def extract_ssh_config(client):
    output = run_command(client, "cat /etc/ssh/sshd_config")
    ssh_config = {}
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            key, value = parts
            ssh_config[key] = value.strip()
    return ssh_config


def extract_users(client):
    output = run_command(client, "cat /etc/passwd")
    users = [line.split(":")[0] for line in output.splitlines()]
    return users


def extract_firewall(client):
    rules = []
    defaults = {}

    try:
        stdout = run_command(client, "sudo ufw status numbered")
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Status"):
                continue
            if line.startswith("["):
                line = line.split("]", 1)[-1].strip()
            parts = line.split()
            if len(parts) < 2:
                continue

            port_proto = parts[0]
            action = parts[1].upper()
            if action == "ALLOW":
                action = "ACCEPT"
            elif action == "DENY":
                action = "DROP"

            if "/" in port_proto:
                port_str, proto = port_proto.split("/")
                try:
                    port = int(port_str)
                    rules.append({"port": port, "protocol": proto.lower(), "action": action})
                except ValueError:
                    continue
    except Exception as e:
        print(f"Error extracting firewall rules: {e}")

    try:
        stdout = run_command(client, "sudo ufw status verbose")
        for line in stdout.splitlines():
            if line.startswith("Default:"):
                parts = line.replace("Default:", "").split(",")
                for p in parts:
                    p = p.strip()
                    if "incoming" in p:
                        defaults["INPUT"] = "DROP" if "deny" in p.lower() else "ACCEPT"
                    elif "forward" in p:
                        defaults["FORWARD"] = "DROP" if "deny" in p.lower() else "ACCEPT"
                    elif "outgoing" in p:
                        defaults["OUTPUT"] = "DROP" if "deny" in p.lower() else "ACCEPT"
    except Exception as e:
        print(f"Error extracting firewall defaults: {e}")

    defaults.setdefault("INPUT", "DROP")
    defaults.setdefault("FORWARD", "DROP")
    defaults.setdefault("OUTPUT", "ACCEPT")

    return rules, defaults


# === Comparisons ===
MANDATORY_SSH_DEFAULTS = {
    "PermitRootLogin": "no",
    "PermitEmptyPasswords": "no",
}


def compare_ssh_config(actual, ssh_baseline):
    violations = []
    for rule in ssh_baseline["compliance_rules"]:
        param = rule["parameter"]
        expected = str(rule["expected"])
        severity = rule["severity"]

        actual_value = actual.get(param, MANDATORY_SSH_DEFAULTS.get(param))
        if actual_value is None:
            continue

        if str(actual_value).lower() != expected.lower():
            violations.append({
                "area": "ssh_config",
                "rule": rule["rule"],
                "parameter": param,
                "expected": expected,
                "actual": actual_value,
                "severity": severity,
                "remediation": f"Set {param} to {expected} in sshd_config"
            })
    return violations


def compare_users(actual_users, users_baseline):
    violations = []

    for req in users_baseline.get("required_users", []):
        if req["username"] not in actual_users:
            violations.append({
                "area": "users",
                "rule": req["description"],
                "expected": f"User {req['username']} exists",
                "actual": "Missing",
                "severity": req["severity"],
                "remediation": f"Create user {req['username']}"
            })

    for prob in users_baseline.get("prohibited_users", []):
        if prob["username"] in actual_users:
            violations.append({
                "area": "users",
                "rule": prob["description"],
                "expected": f"User {prob['username']} absent",
                "actual": "Present",
                "severity": prob["severity"],
                "remediation": f"Remove user {prob['username']}"
            })
    return violations


def compare_firewall(actual_rules, actual_defaults, fw_baseline):
    violations = []

    for req in fw_baseline.get("required_rules", []):
        found = any(
            r["port"] == req["port"] and
            r["protocol"] == req["protocol"] and
            r["action"].upper() == req["action"].upper()
            for r in actual_rules
        )
        if not found:
            violations.append({
                "area": "firewall",
                "severity": req["severity"],
                "rule": req["description"],
                "expected": f"{req['action']} {req['protocol']}/{req['port']}",
                "actual": "Not found",
                "remediation": f"Allow {req['protocol']}/{req['port']} in firewall"
            })

    for blk in fw_baseline.get("blocked_rules", []):
        found = any(
            r["port"] == blk["port"] and
            r["protocol"] == blk["protocol"] and
            r["action"].upper() != blk["action"].upper()
            for r in actual_rules
        )
        if found:
            violations.append({
                "area": "firewall",
                "severity": blk["severity"],
                "rule": blk["description"],
                "expected": f"{blk['action']} {blk['protocol']}/{blk['port']}",
                "actual": "Found",
                "remediation": f"Remove rule allowing {blk['protocol']}/{blk['port']}"
            })

    for chain, expected in fw_baseline.get("default_policy", {}).items():
        actual = actual_defaults.get(chain, "Unknown")
        if actual != expected:
            violations.append({
                "area": "firewall",
                "severity": "critical",
                "rule": f"Default policy for {chain}",
                "expected": expected,
                "actual": actual,
                "remediation": f"Set default policy {chain} to {expected}"
            })

    return violations


# === Score Calculation ===
def calculate_score(violations):
    score = 100
    for v in violations:
        if v["severity"] == "critical":
            score -= 15
        elif v["severity"] == "warning":
            score -= 5
    return max(score, 0)


# === Report Generation ===
def generate_report(hostname, violations, score):
    report = {
        "device": hostname,
        "timestamp": datetime.utcnow().isoformat(),
        "score": score,
        "violations": violations
    }
    report_path = os.path.join(REPORTS_DIR, f"{hostname}_report.json")
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2)
    return report


# === Main ===
def main():
    devices = load_yaml(DEVICE_INVENTORY)["devices"]
    ssh_baseline = load_yaml(SSH_BASELINE)
    fw_baseline = load_yaml(FIREWALL_BASELINE)
    users_baseline = load_yaml(USERS_BASELINE)

    for device in devices:
        print(f"Auditing {device['hostname']} ({device['ip']})...")
        try:
            client = ssh_connect(device["ip"], device["username"], device["password"])

            ssh_conf = extract_ssh_config(client)
            users = extract_users(client)
            fw_rules, fw_defaults = extract_firewall(client)

            violations = []
            violations.extend(compare_ssh_config(ssh_conf, ssh_baseline))
            violations.extend(compare_users(users, users_baseline))
            violations.extend(compare_firewall(fw_rules, fw_defaults, fw_baseline))

            score = calculate_score(violations)
            generate_report(device["hostname"], violations, score)

            print(f"  Score: {score}")
            if violations:
                for v in violations:
                    print(f"  - [{v['severity'].upper()}] {v['rule']} (Expected: {v['expected']} | Actual: {v['actual']})")
            else:
                print("  No violations found")

            client.close()
        except Exception as e:
            print(f"  Failed to audit {device['hostname']}: {e}")


if __name__ == "__main__":
    main()
