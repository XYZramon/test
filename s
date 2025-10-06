#!/usr/bin/env python3

import paramiko
import yaml
import json
import os

# Paths
DEVICE_INVENTORY_FILE = os.path.expanduser('~/network-auditor/device_inventory.yaml')
BASELINE_DIR = os.path.expanduser('~/network-auditor/baselines')
REPORTS_DIR = os.path.expanduser('~/network-auditor/reports')

# Ensure reports directory exists
os.makedirs(REPORTS_DIR, exist_ok=True)


def load_yaml(file_path):
    with open(file_path, 'r') as f:
        return yaml.safe_load(f)


def ssh_connect(hostname, username, password):
    """Connect to a device via SSH and return a Paramiko client."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(hostname=hostname, username=username, password=password)
    return client


def extract_config(client):
    """Extract SSH config, user accounts, and firewall rules."""
    extracted = {}

    # Extract SSH configuration
    stdin, stdout, stderr = client.exec_command('cat /etc/ssh/sshd_config')
    extracted['sshd_config'] = stdout.read().decode()

    # Extract user accounts
    stdin, stdout, stderr = client.exec_command('cat /etc/passwd')
    extracted['users'] = stdout.read().decode()

    # Extract firewall rules (requires sudo)
    stdin, stdout, stderr = client.exec_command('sudo ufw status numbered')
    extracted['firewall'] = stdout.read().decode()

    return extracted


def compare_to_baseline(extracted, baseline):
    """Compare extracted config to baseline and identify violations."""
    violations = []

    # SSH config comparison
    for key, expected in baseline.get('sshd_config', {}).items():
        actual = None
        for line in extracted['sshd_config'].splitlines():
            if line.strip().startswith(key):
                actual = line.split()[-1]
        if actual != expected:
            severity = 'Critical' if key in baseline.get('critical', []) else 'Warning'
            violations.append({
                'type': 'sshd_config',
                'item': key,
                'expected': expected,
                'actual': actual,
                'severity': severity,
                'recommendation': f'Set {key} to {expected}'
            })

    # Users comparison
    baseline_users = set(baseline.get('users', []))
    actual_users = set([line.split(':')[0] for line in extracted['users'].splitlines()])
    for user in baseline_users - actual_users:
        violations.append({
            'type': 'users',
            'item': user,
            'expected': 'Present',
            'actual': 'Missing',
            'severity': 'Critical',
            'recommendation': f'Ensure user {user} exists on the system'
        })

    # Firewall rules comparison
    baseline_rules = set(baseline.get('firewall', []))
    actual_rules = set(extracted['firewall'].splitlines())
    for rule in baseline_rules - actual_rules:
        violations.append({
            'type': 'firewall',
            'item': rule,
            'expected': 'Present',
            'actual': 'Missing',
            'severity': 'Warning',
            'recommendation': f'Add firewall rule: {rule}'
        })

    return violations


def calculate_security_score(violations):
    score = 100
    for v in violations:
        if v['severity'] == 'Critical':
            score -= 15
        elif v['severity'] == 'Warning':
            score -= 5
    return max(score, 0)


def generate_report(hostname, violations, score):
    report = {
        'hostname': hostname,
        'score': score,
        'violations': violations
    }

    # Print grouped by severity
    grouped = {'Critical': [], 'Warning': []}
    for v in violations:
        grouped[v['severity']].append(v)
    print(f"\nReport for {hostname}:")
    print(f"Security Score: {score}/100")
    for severity, items in grouped.items():
        print(f"\n{severity} Violations:")
        for item in items:
            print(f"- {item['type']}: {item['item']}, Expected: {item['expected']}, Actual: {item['actual']}")
            print(f"  Recommendation: {item['recommendation']}")

    # Save JSON report
    report_file = os.path.join(REPORTS_DIR, f"{hostname}_report.json")
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=4)
    print(f"\nDetailed JSON report saved to {report_file}")


def main():
    devices = load_yaml(DEVICE_INVENTORY_FILE)
    for device in devices.get('devices', []):
        hostname = device['hostname']
        username = device['username']
        password = device['password']

        print(f"\nConnecting to {hostname}...")
        try:
            client = ssh_connect(hostname, username, password)
            extracted = extract_config(client)
            client.close()

            # Load baseline for this device type
            baseline_file = os.path.join(BASELINE_DIR, f"{device['type']}_baseline.yaml")
            baseline = load_yaml(baseline_file)

            violations = compare_to_baseline(extracted, baseline)
            score = calculate_security_score(violations)
            generate_report(hostname, violations, score)

        except Exception as e:
            print(f"Error connecting to {hostname}: {e}")


if __name__ == "__main__":
    main()
