import os
import sys
import subprocess
import json

def get_journal_logs():
    log_methods = [
        ('journalctl', lambda: read_journalctl()),
        ('syslog', lambda: read_syslog()),
        ('messages', lambda: read_messages())
    ]
    
    for method_name, method_func in log_methods:
        try:
            return method_func()
        except Exception:
            continue
    
    print("No working log source found (tried journalctl, /var/log/syslog, /var/log/messages)")
    sys.exit(1)

def read_journalctl():
    cmd = ['journalctl', '-b', '--no-pager']
    return subprocess.check_output(cmd, universal_newlines=True)

def read_syslog():
    with open('/var/log/syslog', 'r') as f:
        return f.read()

def read_messages():
    with open('/var/log/messages', 'r') as f:
        return f.read()

def analyze_logs(logs):
    login_attempts = 0
    failed_auth_attempts = 0
    system_reboots = 0
    log_entries = []

    for line in logs.split('\n'):
        line_lower = line.strip().lower()
        if not line_lower:
            continue

        timestamp = line[:15] if len(line) >= 15 else 'Unknown'
        message = line[16:] if len(line) >= 16 else line
        syslog_id = 'Unknown'
        priority = 'Unknown'
        
        if 'login' in line_lower or 'sshd' in line_lower:
            login_attempts += 1
        
        if 'failed password' in line_lower or 'authentication failure' in line_lower:
            failed_auth_attempts += 1
        
        if any(x in line_lower for x in [
            'reboot', 'system is rebooting', 'shutting down for reboot',
            'systemd-logind: system is rebooting', 'systemd[1]: started reboot'
        ]):
            system_reboots += 1
        
        log_entries.append({"timestamp": timestamp, "syslog_id": syslog_id, "priority": priority, "message": message})
    
    print("\n\033[1mLog Analysis Results:\033[0m")
    print(f"Total Login Attempts: {login_attempts}")
    print(f"Total Failed Authentication Attempts: {failed_auth_attempts}")
    print(f"Total System Reboots: {system_reboots}")
    
    return {
        "login_attempts": login_attempts,
        "failed_auth_attempts": failed_auth_attempts,
        "system_reboots": system_reboots,
        "log_entries": log_entries
    }

def get_disk_usage():
    cmd = ['df', '-h']
    return subprocess.check_output(cmd, universal_newlines=True)

def get_network_usage():
    cmd = ['ip', '-s', 'link'] if os.path.exists('/sbin/ip') else ['netstat', '-i']
    return subprocess.check_output(cmd, universal_newlines=True)

def get_most_accessed_files():
    cmd = ['lsof', '-Fn'] if os.path.exists('/usr/bin/lsof') else ['ls', '-lt', '/var/log']
    try:
        output = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
        # Split output into lines and filter out warnings/empty lines
        lines = [line.strip() for line in output.split('\n') if line.strip() and 'WARNING' not in line]
        
        # Parse lsof output (example parsing logic)
        if cmd[0] == 'lsof':
            files = []
            for line in lines:
                if line.startswith('n'):
                    files.append(line[1:])  # Extract filename from lsof output
            return files
        else:  # For ls -lt output
            files = []
            for line in lines[1:]:  # Skip header line
                parts = line.split()
                if len(parts) >= 9:
                    files.append(' '.join(parts[8:]))  # Extract filename
            return files
    except subprocess.CalledProcessError:
        return ["Error retrieving accessed files."]

def system_monitoring():
    return {
        "disk_usage": get_disk_usage(),
        "network_usage": get_network_usage(),
        "most_accessed_files": get_most_accessed_files()
    }

def save_to_json(log_data, system_data):
    data = {
        "log_analysis": log_data,
        "system_monitoring": system_data
    }
    with open('system_monitoring_report.json', 'w') as jsonfile:
        json.dump(data, jsonfile, indent=4)

if __name__ == '__main__':
    logs = get_journal_logs()
    log_data = analyze_logs(logs)
    system_data = system_monitoring()
    save_to_json(log_data, system_data)
