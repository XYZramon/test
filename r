#!/usr/bin/env python3
import os
import json
import yaml
import paramiko
from datetime import datetime

# === File Paths ===
BASE_DIR = os.path.expanduser("~/network-auditor") #The base folder just to ensure that incase of operating/running outside of folder
REPORTS_DIR = os.path.join(BASE_DIR, "reports") #Ensures that the reports folder is known to be a sub-folder of the network-auditor folder

# assigning the names of the files/folders to a variable for easier calling
DEVICE_INVENTORY = os.path.join(BASE_DIR, "device_inventory.yaml")
BASELINE_DIR = os.path.join(BASE_DIR, "baselines")
SSH_BASELINE = os.path.join(BASELINE_DIR, "ssh_baseline.yaml")
FIREWALL_BASELINE = os.path.join(BASELINE_DIR, "firewall_baseline.yaml")
USERS_BASELINE = os.path.join(BASELINE_DIR, "users_baseline.yaml")

os.makedirs(REPORTS_DIR, exist_ok=True)# Creates the folder incase it does not already exist


# === Utility Functions ===
def load_yaml(path):  #Open the baseline yaml files and read them/
    with open(path, "r") as f:
        return yaml.safe_load(f)


def ssh_connect(ip, username, password): # Uses Paramiko to connect to the network devices via ssh and inputs the username/password of the user/device its connecting to
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=username, password=password)
    return client


def run_command(client, cmd, sudo=False): # Shortcut for any commands that need to be run particularly if the commands require  sudo for higher priviledge
    if sudo:
        cmd = f"sudo -S -p '' {cmd}"
    stdin, stdout, stderr = client.exec_command(cmd)
    if sudo:
        stdin.write("AuditPass123\n")  # Adjust if sudo password differs
        stdin.flush()
    return stdout.read().decode().strip()


# === Extractors ===
def extract_ssh_config(client): #Extracting the devices ssh configurations of the device being connected to.
    output = run_command(client, "cat /etc/ssh/sshd_config")
    ssh_config = {}

    for line in output.splitlines(): # Split and strip all lines to get rid of any /n or extra spaces
        line = line.strip()
        if not line:
            continue
        # Remove inline comments
        line = line.split("#", 1)[0].strip()
        if not line:
            continue

        parts = line.split(None, 1)  # split only on first whitespace
        if len(parts) != 2:
            continue

        key, value = parts
        ssh_config[key] = value.strip() #Assigns the rule with the expected output as a dictionary input

    return ssh_config



def extract_users(client): #Extracts the rules/results of user/password relations within the password file from the network device the host is connected to.
    output = run_command(client, "cat /etc/passwd")
    users = [line.split(":")[0] for line in output.splitlines()]
    return users


def extract_firewall(client):#Extracting the device's firewall configurations of the device being connected to.
    rules = []
    defaults = {}

    # Get rules
    try:
        stdout = run_command(client, "sudo ufw status numbered") #Runs the command to view active firewall rules
        for line in stdout.splitlines():
            line = line.strip()
            if not line or line.startswith("Status") or line.startswith("["):
                # Remove numbering like "[ 1]" at start
                if line.startswith("["):
                    line = line.split("]", 1)[-1].strip()
                else:
                    continue

            # Split line into columns
            parts = line.split()
            if len(parts) < 2:
                continue

            port_proto = parts[0]  # e.g., 22/tcp
            action = parts[1].upper()  # e.g., ALLOW or DENY

            # Normalize action for comparison function
            if action == "ALLOW":
                action = "ACCEPT"
            elif action == "DENY":
                action = "DROP"

            # Split port/protocol
            if "/" in port_proto:
                port_str, proto = port_proto.split("/")
                try:
                    port = int(port_str)
                except ValueError:
                    continue
                rules.append({"port": port, "protocol": proto.lower(), "action": action})
    except Exception as e:
        print(f"    [!] Error extracting firewall rules: {e}")

    # Get defaults
    try:
        stdout = run_command(client, "sudo ufw status verbose")
        for line in stdout.splitlines():
            if line.startswith("Default:"):
                # Example: "Default: deny (incoming), deny (forward), allow (outgoing)"
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
        print(f"    [!] Error extracting firewall defaults: {e}")

    # Ensure all chains exist
    defaults.setdefault("INPUT", "DROP") #Defualts should there be no other rules declared or applicable 
    defaults.setdefault("FORWARD", "DROP")
    defaults.setdefault("OUTPUT", "ACCEPT")

    return rules, defaults



# === Comparisons ===
MANDATORY_SSH_PARAMS = ["PermitRootLogin", "PermitEmptyPasswords"] # Defualts to check


MANDATORY_SSH_DEFAULTS = { # Defualts corresponding rules incase the device doesn't have the rule or doesn't properly convey
    "PermitRootLogin": "no",
    "PermitEmptyPasswords": "no",
}

def compare_ssh_config(actual, ssh_baseline): # 
    violations = []
    for rule in ssh_baseline["compliance_rules"]:
        param = rule["parameter"]
        expected = str(rule["expected"])
        severity = rule["severity"]

        # use actual value if present, else default for mandatory parameters
        actual_value = actual.get(param, MANDATORY_SSH_DEFAULTS.get(param))

        # optional parameters not in defaults → auto pass
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




def compare_users(actual_users, users_baseline): #Compares the users of the device to the baseline rules users to check for violations
    violations = []
    # Required users
    for req in users_baseline["required_users"]: # Checks that a required user exists in the device and adds the violation to array if it is missing
        if req["username"] not in actual_users:
            violations.append({
                "area": "users",
                "rule": req["description"],
                "expected": f"User {req['username']} exists",
                "actual": "Missing",
                "severity": req["severity"],
                "remediation": f"Create user {req['username']}"
            })
    # Prohibited users
    for prob in users_baseline["prohibited_users"]: # Checks that a user  that is not supposed to exist is not in the device and adds the violation to array if the user exists
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


def compare_firewall(actual_rules, actual_defaults, fw_baseline): # Compares device's firewall rules to the baseline yaml rules to check for violations
    violations = []

    # Required rules
    for req in fw_baseline.get("required_rules", []): #Checks for the required rules existing in the device's firewall rules and adds the violation should it be missing
        found = any(
            r["port"] == req["port"]
            and r["protocol"] == req["protocol"]
            and r["action"].upper() == req["action"].upper()
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

    # Blocked rules
    for blk in fw_baseline.get("blocked_rules", []): # Checks for rules that are not supposed to exist or should be blocking access are as they are supposed to be and adds the violation should the comparison not match
        found = any(
            r["port"] == blk["port"]
            and r["protocol"] == blk["protocol"]
            and r["action"].upper() != blk["action"].upper()
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

    # Default policy checks
    for chain, expected in fw_baseline.get("default_policy", {}).items(): #Checks defaults to device's default firewall rules and adds any violations should the defaults not match
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
def calculate_score(violations): #Calculates the score by subtracting any and all violations depending on the serverity of the violation.
    score = 100
    for v in violations:
        if v["severity"] == "critical":
            score -= 15
        elif v["severity"] == "warning":
            score -= 5
    return max(score, 0)


# === Report Generation ===
def generate_report(hostname, violations, score): # Generates the violation report and inserts the report for each device into the reports sub-folder of network-auditor folder
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
    devices = load_yaml(DEVICE_INVENTORY)["devices"] #Loads the yaml into a from where it was opened
    ssh_baseline = load_yaml(SSH_BASELINE) 
    fw_baseline = load_yaml(FIREWALL_BASELINE)
    users_baseline = load_yaml(USERS_BASELINE)

    for device in devices:
        print(f"Auditing {device['hostname']} ({device['ip']}) ...")
        try:
            client = ssh_connect(device["ip"], device["username"], device["password"]) #SSH connection to the network device 

            ssh_conf = extract_ssh_config(client) #Extration of the baseline rules from the baseline yaml files.
            users = extract_users(client)
            fw_rules, fw_defaults = extract_firewall(client)

            violations = [] #Add in all violations that the device has by extending the array with the comparison results 
            violations.extend(compare_ssh_config(ssh_conf, ssh_baseline))
            violations.extend(compare_users(users, users_baseline))
            violations.extend(compare_firewall(fw_rules, fw_defaults, fw_baseline))
        

            score = calculate_score(violations) # Pulls the score after all violations have been docked for printing below
            report = generate_report(device["hostname"], violations, score) # Generates the report (score and violations ) and composes it into a file in the reports folder.

            print(f"  Score: {score}") # Print the Devices' score and any violations that were found
            if violations:
                for v in violations:
                    print(f"  - [{v['severity'].upper()}] {v['rule']} (Expected: {v['expected']} | Actual: {v['actual']})")
            else:
                print("  ✅ No violations found")

            client.close()
        except Exception as e: # Error message should the ssh fail and/or the device could not be audited
            print(f"  ❌ Failed to audit {device['hostname']}: {e}")


if __name__ == "__main__":
    main()
