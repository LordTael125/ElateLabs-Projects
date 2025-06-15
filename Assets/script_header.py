import os
import subprocess
import stat
from datetime import datetime




REPORT_FILE = "Report/Report.txt"

def report_add(seq):
    with open(REPORT_FILE, "a") as f:
        f.write(seq + "\n")


def check_firewall():
    print("Checking Firewall :-")
    report_add("### Firewall Check ###")
    try:
        output = subprocess.check_output(['sudo', 'ufw', 'status'], text=True)
        if "Status: active" in output:
            report_add("[OK] UFW is active.")
            print("Firewall check Completed")
            return 1
        else:
            report_add("[WARN] UFW is inactive.")
            print("Firewall check Completed")
            return 0
    except FileNotFoundError:
        try:
            subprocess.check_output(['sudo', 'iptables', '-L'], text=True)
            report_add("[INFO] iptables found.")
            return 0.5
        except:
            report_add("[FAIL] No firewall detected (ufw/iptables).")
            return 0
    except Exception as e:
        report_add(f"[ERROR] Firewall check error: {e}")
        return 0

def check_ssh_config():
    print("Scanning SSH Configs :")
    report_add("### SSH Configuration Check ###")
    score = 0
    try:
        with open("/etc/ssh/sshd_config", "r") as f:
            config = f.read()
            if "PermitRootLogin no" in config:
                report_add("[OK] Root login via SSH is disabled.")
                score += 0.5
            else:
                report_add("[WARN] Root login via SSH is allowed.")

            if "PasswordAuthentication no" in config:
                report_add("[OK] Password authentication is disabled.")
                score += 0.5
            else:
                report_add("[WARN] Password authentication is enabled.")

            print("SSH config files scanned\n")
    except Exception as e:
        report_add(f"[ERROR] SSH config check failed: {e}")
    return score

def check_file_permissions():
    print("Checking File permissions :-")
    report_add("### File Permissions Check ###")
    score = 0
    files = {
        "/etc/passwd": stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH,
        "/etc/shadow": stat.S_IRUSR,
    }

    for file, expected_mode in files.items():
        try:
            st = os.stat(file)
            actual_mode = stat.S_IMODE(st.st_mode)
            if actual_mode == expected_mode:
                report_add(f"[OK] {file} permissions are correct.")
                score += 0.5
            else:
                report_add(f"[WARN] {file} has incorrect permissions: {oct(actual_mode)}")
            print("File Permission checked \n")
        except Exception as e:
            report_add(f"[ERROR] Could not check {file}: {e}")
    return score

def check_services():
    print("Scanning services :-")
    report_add("### Services Check ###")
    try:
        services = subprocess.check_output(['systemctl', 'list-units', '--type=service', '--state=running'], text=True)
        suspect_services = [s for s in services.split('\n') if 'telnet' in s or 'ftp' in s or 'rsh' in s]
        if suspect_services:
            for s in suspect_services:
                report_add(f"[WARN] Unsecure service running: {s}")
                print("Servies Scanned Successfully")
            return 0
        else:
            report_add("[OK] No insecure services detected.")
            print("Servies Scanned Successfully")
            return 1
    except Exception as e:
        report_add(f"[ERROR] Service check failed: {e}")
        return 0

def check_rootkits():
    print("Scanning rootkit :-")
    report_add("### Rootkit Check ###")
    score = 0
    try:
        subprocess.check_output(['which', 'rkhunter'], text=True)
        report_add("[INFO] rkhunter installed. Running check...")
        output = subprocess.run(
            ['sudo', 'rkhunter', '--check',"--sk"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        print(output.stderr)
        if "0 suspect files" in output.stdout:
            report_add("[OK] No rootkits found.")
            score += 1
        else:
            report_add("[WARN] Possible rootkit issues. Review manually.")
        print("Rootkit Scanned successfully")
    except FileNotFoundError:
        report_add("[INFO] rkhunter not installed. Skipping.")
    return score

def generate_score(score, max_score):
    compliance = (score / max_score) * 100
    report_add("\n=== FINAL SCORE ===")
    report_add(f"Compliance Score: {compliance:.2f}%")

    report_add("\n=== RECOMMENDATIONS ===")
    if compliance < 50:
        report_add("System is critically vulnerable. Immediate hardening recommended.")
    elif compliance < 75:
        report_add("System has several issues. Consider applying hardening steps.")
    else:
        report_add("System is reasonably secure. Keep monitoring and updating.")

    return compliance

def main():
    print(os.getcwd(),"\n\n\n")

    if os.geteuid() != 0:
        print("This script must be run as root.")
        return

    with open(REPORT_FILE, "w") as f:
        f.write(f"Linux Hardening Audit Report - {datetime.now()}\n\n")

    max_score = 5  # Adjust as you add more checks
    total_score = 0
    total_score += check_firewall()
    total_score += check_ssh_config()
    total_score += check_file_permissions()
    total_score += check_services()
    total_score += check_rootkits()

    generate_score(total_score, max_score)
    print(f"Audit complete. Report saved to {REPORT_FILE}")

if __name__ == "__main__":
    main()
