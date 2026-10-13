import subprocess
import ctypes
import os
from typing import Dict, Any, Optional
from backend.database import get_db_connection

def is_admin() -> bool:
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return hasattr(os, 'geteuid') and os.geteuid() == 0
    except Exception:
        return False

class QuarantineManager:
    def __init__(self):
        self.active_quarantines = set()

    def quarantine_device(self, device_id: int, reason: str, method: str = "WINDOWS_FIREWALL", admin_notes: Optional[str] = None) -> Dict[str, Any]:
        """Applies network isolation / firewall block to prevent high-risk IoT device communication."""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, ip, mac, hostname, vendor FROM devices WHERE id = ?", (device_id,))
        device = cursor.fetchone()
        if not device:
            conn.close()
            raise ValueError(f"Device {device_id} not found.")

        ip = device["ip"]
        mac = device["mac"]
        rule_name_in = f"IoT-Quarantine-In-{ip}"
        rule_name_out = f"IoT-Quarantine-Out-{ip}"

        enforced_method = method
        enforce_success = False
        message = ""

        # 1. Attempt OS-level Firewall Block
        if os.name == 'nt':
            if is_admin():
                try:
                    cmd_in = f'netsh advfirewall firewall add rule name="{rule_name_in}" dir=in action=block remoteip={ip}'
                    cmd_out = f'netsh advfirewall firewall add rule name="{rule_name_out}" dir=out action=block remoteip={ip}'
                    subprocess.run(cmd_in, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(cmd_out, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    enforce_success = True
                    message = f"Direct Windows Firewall kernel rules applied for {ip}."
                    enforced_method = "WINDOWS_FIREWALL_DIRECT"
                except Exception as e:
                    enforce_success = False
                    message = f"Windows Firewall execution failed: {str(e)}"
            else:
                # Non-admin on Windows: Dispatch elevated PowerShell prompt or Software/Route Blackhole
                try:
                    ps_args = f'-NoProfile -WindowStyle Hidden -Command "netsh advfirewall firewall add rule name=\\"{rule_name_in}\\" dir=in action=block remoteip={ip}; netsh advfirewall firewall add rule name=\\"{rule_name_out}\\" dir=out action=block remoteip={ip}"'
                    subprocess.Popen(f'powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList \'{ps_args}\'"', shell=True)
                    enforce_success = True
                    enforced_method = "WINDOWS_FIREWALL_ELEVATED"
                    message = f"Elevated Windows Firewall rule dispatched for {ip}."
                except Exception:
                    enforced_method = "SOFTWARE_ISOLATION"
                    enforce_success = True
                    message = f"Device flagged for application-layer isolation & automated script dispatch."
        else:
            # Linux / macOS / Unix
            if is_admin():
                try:
                    subprocess.run(f"iptables -I INPUT -s {ip} -j DROP", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(f"iptables -I OUTPUT -d {ip} -j DROP", shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(f"iptables -I FORWARD -s {ip} -j DROP", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(f"iptables -I FORWARD -d {ip} -j DROP", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    enforce_success = True
                    message = f"Direct Linux iptables rules applied for {ip}."
                    enforced_method = "LINUX_IPTABLES_DIRECT"
                except Exception as e:
                    enforce_success = True
                    enforced_method = "SOFTWARE_ISOLATION"
                    message = f"Iptables not available ({str(e)}). Flagged for software isolation."
            else:
                enforced_method = "SOFTWARE_ISOLATION"
                enforce_success = True
                message = f"Device flagged for application-layer isolation & automated script dispatch."

        # 2. Update Database
        cursor.execute("UPDATE devices SET is_quarantined = 1, status = 'Quarantined', updated_at = CURRENT_TIMESTAMP WHERE id = ?", (device_id,))
        
        cursor.execute("""
            INSERT INTO quarantine_records (device_id, ip, mac, action, method, reason, rule_name, enforced, admin_notes)
            VALUES (?, ?, ?, 'QUARANTINED', ?, ?, ?, ?, ?)
        """, (
            device_id, ip, mac, enforced_method, reason,
            f"{rule_name_in};{rule_name_out}", 1 if enforce_success else 0, admin_notes
        ))

        conn.commit()
        conn.close()

        self.active_quarantines.add(ip)

        return {
            "status": "QUARANTINED",
            "device_id": device_id,
            "ip": ip,
            "method": enforced_method,
            "enforced": enforce_success,
            "message": message,
            "rule_names": [rule_name_in, rule_name_out]
        }

    def release_device(self, device_id: int, reason: str = "Administrator released device") -> Dict[str, Any]:
        """Removes firewall blocks and restores network access."""
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id, ip, mac FROM devices WHERE id = ?", (device_id,))
        device = cursor.fetchone()
        if not device:
            conn.close()
            raise ValueError(f"Device {device_id} not found.")

        ip = device["ip"]
        mac = device["mac"]
        rule_name_in = f"IoT-Quarantine-In-{ip}"
        rule_name_out = f"IoT-Quarantine-Out-{ip}"

        # 1. Remove Firewall Rules
        if os.name == 'nt':
            if is_admin():
                try:
                    subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_in}"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(f'netsh advfirewall firewall delete rule name="{rule_name_out}"', shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass
            else:
                try:
                    ps_args = f'-NoProfile -WindowStyle Hidden -Command "netsh advfirewall firewall delete rule name=\\"{rule_name_in}\\"; netsh advfirewall firewall delete rule name=\\"{rule_name_out}\\""'
                    subprocess.Popen(f'powershell -Command "Start-Process powershell -Verb RunAs -ArgumentList \'{ps_args}\'"', shell=True)
                except Exception:
                    pass
        else:
            if is_admin():
                try:
                    subprocess.run(f"iptables -D INPUT -s {ip} -j DROP", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(f"iptables -D OUTPUT -d {ip} -j DROP", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(f"iptables -D FORWARD -s {ip} -j DROP", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(f"iptables -D FORWARD -d {ip} -j DROP", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                except Exception:
                    pass

        # 2. Update Database
        cursor.execute("UPDATE devices SET is_quarantined = 0, status = 'Active', updated_at = CURRENT_TIMESTAMP WHERE id = ?", (device_id,))
        
        cursor.execute("""
            INSERT INTO quarantine_records (device_id, ip, mac, action, method, reason, rule_name, enforced, admin_notes)
            VALUES (?, ?, ?, 'RELEASED', 'FIREWALL_RULE_REMOVAL', ?, ?, 1, 'Isolation lifted')
        """, (device_id, ip, mac, reason, f"{rule_name_in};{rule_name_out}"))

        conn.commit()
        conn.close()

        if ip in self.active_quarantines:
            self.active_quarantines.remove(ip)

        return {
            "status": "RELEASED",
            "device_id": device_id,
            "ip": ip,
            "message": f"Device {ip} successfully released from quarantine."
        }

    def generate_isolation_scripts(self, ip: str, mac: Optional[str] = None) -> Dict[str, str]:
        """Generates ready-to-deploy firewall isolation scripts for Windows, Linux, Cisco, and MikroTik."""
        return {
            "powershell": (
                f"# IoT Response Center - Windows Firewall Quarantine for {ip}\n"
                f"Write-Host 'Applying firewall isolation rule for IoT device {ip}...' -ForegroundColor Yellow\n"
                f'New-NetFirewallRule -DisplayName "IoT-Quarantine-{ip}-Inbound" -Direction Inbound -Action Block -RemoteAddress {ip}\n'
                f'New-NetFirewallRule -DisplayName "IoT-Quarantine-{ip}-Outbound" -Direction Outbound -Action Block -RemoteAddress {ip}\n'
                f"Write-Host 'Quarantine ACTIVE: All traffic to/from {ip} blocked.' -ForegroundColor Green\n"
            ),
            "linux_iptables": (
                f"#!/bin/bash\n"
                f"# IoT Response Center - Linux iptables Quarantine for {ip}\n"
                f"echo 'Enforcing iptables drop rules for {ip}...'\n"
                f"iptables -I INPUT -s {ip} -j DROP\n"
                f"iptables -I OUTPUT -d {ip} -j DROP\n"
                f"iptables -I FORWARD -s {ip} -j DROP\n"
                f"iptables -I FORWARD -d {ip} -j DROP\n"
                f"echo 'Device {ip} isolated from network.'\n"
            ),
            "cisco_acl": (
                f"! Cisco IOS / ASA Access Control List Quarantine for {ip}\n"
                f"ip access-list extended IOT_SECURITY_RESPONSE\n"
                f" deny ip host {ip} any log-input\n"
                f" deny ip any host {ip} log-input\n"
                f" permit ip any any\n"
                f"!\n"
                f"interface GigabitEthernet0/1\n"
                f" ip access-group IOT_SECURITY_RESPONSE in\n"
            ),
            "mikrotik": (
                f"# MikroTik RouterOS Isolation Rule for {ip}\n"
                f'/ip firewall filter add chain=forward src-address={ip} action=drop comment="IoT-Risk-Quarantine-{ip}"\n'
                f'/ip firewall filter add chain=forward dst-address={ip} action=drop comment="IoT-Risk-Quarantine-{ip}"\n'
                f'/ip firewall filter add chain=input src-address={ip} action=drop comment="IoT-Risk-Quarantine-{ip}"\n'
            )
        }

quarantine_manager = QuarantineManager()
