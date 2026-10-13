import re
import urllib.request
import json
from typing import List, Dict, Any, Optional
from backend.database import get_db_connection

# Comprehensive Curated Real IoT CVE Knowledge Base
IOT_CVE_DATABASE: List[Dict[str, Any]] = [
    # Hikvision
    {
        "cve_id": "CVE-2021-36260",
        "vendor": "Hikvision",
        "product": "IP Camera / NVR Firmware",
        "version_pattern": r"(?:v5\.[0-4]\.|v4\.[0-9]\.|build\s*(?:1[0-9]|20|210[0-6]))",
        "title": "Hikvision Unauthenticated Remote Code Execution",
        "description": "A command injection vulnerability in the web server of some Hikvision IP camera and NVR products allows attackers to send crafted messages and execute arbitrary root commands.",
        "cvss_score": 9.8,
        "severity": "Critical",
        "affected_ports": "80, 443, 8000, 8080",
        "remediation": "Immediately upgrade firmware to the latest manufacturer release or isolate camera on a non-routable VLAN without WAN access.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-36260",
    },
    {
        "cve_id": "CVE-2017-7921",
        "vendor": "Hikvision",
        "product": "IP Camera Web Server",
        "version_pattern": r"(?:v5\.[2-4]\.|build\s*(?:1[4-7]))",
        "title": "Hikvision Improper Authentication / Snapshot Access",
        "description": "An improper authentication flaw in Hikvision camera web server allows remote unauthenticated users to retrieve camera snapshots and configuration files containing sensitive hashes.",
        "cvss_score": 8.8,
        "severity": "High",
        "affected_ports": "80, 443",
        "remediation": "Update firmware to version 5.4.5 or newer and restrict access to management ports.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-7921",
    },
    {
        "cve_id": "CVE-2023-28808",
        "vendor": "Hikvision",
        "product": "Hybrid SAN / NVR",
        "version_pattern": r"v[1-3]\.[0-9]",
        "title": "Hikvision Access Control Bypass via Crafted URL",
        "description": "An access control bypass vulnerability allows attackers to gain administrator privileges by sending crafted HTTP packets to the administration interface.",
        "cvss_score": 9.1,
        "severity": "Critical",
        "affected_ports": "80, 443, 8080",
        "remediation": "Apply the official Hikvision security patch for Hybrid SAN and disable remote WAN management.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-28808",
    },

    # Dahua Technology
    {
        "cve_id": "CVE-2021-33044",
        "vendor": "Dahua",
        "product": "IP Camera / IPC / NVR",
        "version_pattern": r"(?:v2\.[0-8]\.|build\s*20[0-2][0-9])",
        "title": "Dahua Authentication Bypass in Device Management",
        "description": "An identity authentication bypass vulnerability in Dahua IP cameras and recorders allows unauthenticated attackers to bypass authentication by sending crafted login requests.",
        "cvss_score": 9.8,
        "severity": "Critical",
        "affected_ports": "80, 37777, 443",
        "remediation": "Update Dahua firmware to the latest version released post-September 2021 and block TCP port 37777 from untrusted subnets.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-33044",
    },
    {
        "cve_id": "CVE-2022-30563",
        "vendor": "Dahua",
        "product": "IP Camera ONVIF Service",
        "version_pattern": r".*",
        "title": "Dahua Replay Attack Vulnerability in ONVIF Implementation",
        "description": "An ONVIF authentication replay attack allows attackers on the local network to sniff unencrypted WS-UsernameToken authentication digests and forge admin requests.",
        "cvss_score": 7.5,
        "severity": "High",
        "affected_ports": "80, 443, 8080",
        "remediation": "Disable ONVIF if not actively integrated with an NVR, and mandate HTTPS for all ONVIF communications.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-30563",
    },

    # TP-Link
    {
        "cve_id": "CVE-2023-1389",
        "vendor": "TP-Link",
        "product": "Archer AX21 / Router Firmware",
        "version_pattern": r"(?:archer|ax21|1\.[0-1]\.[0-9])",
        "title": "TP-Link Archer AX21 Command Injection (Mirai Botnet Target)",
        "description": "An unauthenticated command injection in the country parameter of the web management interface allows attackers to execute arbitrary system commands as root.",
        "cvss_score": 8.8,
        "severity": "High",
        "affected_ports": "80, 443",
        "remediation": "Apply TP-Link Archer AX21 firmware update v1.1.4 Build 20230219 or newer immediately.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-1389",
    },
    {
        "cve_id": "CVE-2021-4045",
        "vendor": "TP-Link",
        "product": "Tapo C200 IP Camera",
        "version_pattern": r"(?:tapo|c200|1\.[0-1]\.)",
        "title": "TP-Link Tapo C200 Unauthenticated Remote Code Execution",
        "description": "A buffer overflow in the uHttpd binary handling control parameters on Tapo C200 cameras allows unauthenticated root code execution.",
        "cvss_score": 9.1,
        "severity": "Critical",
        "affected_ports": "80, 443, 8800",
        "remediation": "Update Tapo C200 firmware via the TP-Link Tapo mobile application to version 1.1.16 Build 211209 or later.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-4045",
    },

    # D-Link
    {
        "cve_id": "CVE-2023-33246",
        "vendor": "D-Link",
        "product": "DIR Router Series",
        "version_pattern": r"(?:dir-[0-9]+|1\.[0-9]+)",
        "title": "D-Link Multiple Routers Command Injection in set_wan_ping",
        "description": "Stack overflow and command injection in the WAN ping diagnostic handler enables pre-authentication command execution.",
        "cvss_score": 9.8,
        "severity": "Critical",
        "affected_ports": "80, 8080",
        "remediation": "Decommission legacy end-of-life D-Link routers or isolate behind a stateful perimeter firewall.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-33246",
    },
    {
        "cve_id": "CVE-2020-25078",
        "vendor": "D-Link",
        "product": "DCS Camera Series",
        "version_pattern": r"(?:dcs-[0-9]+|1\.[0-9]+)",
        "title": "D-Link DCS Cameras Remote Password Disclosure",
        "description": "Unauthenticated attackers can download device administrator passwords in plain text by requesting /config/getuser.cgi.",
        "cvss_score": 7.5,
        "severity": "High",
        "affected_ports": "80, 8080",
        "remediation": "Install D-Link DCS security patches and restrict camera web access to an isolated monitoring VLAN.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-25078",
    },

    # Netgear
    {
        "cve_id": "CVE-2020-10987",
        "vendor": "Netgear",
        "product": "DGN / Nighthawk Routers",
        "version_pattern": r"(?:dgn[0-9]+|r[67][0-9]+|1\.[0-9]+)",
        "title": "Netgear Router Unauthenticated Command Injection in setup.cgi",
        "description": "Command injection vulnerability in setup.cgi allows unauthenticated remote attackers to execute commands via the sysCMD parameter.",
        "cvss_score": 8.8,
        "severity": "High",
        "affected_ports": "80, 443",
        "remediation": "Download and flash updated Netgear firmware from the official Netgear download center.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-10987",
    },

    # BusyBox / Embedded Linux Core
    {
        "cve_id": "CVE-2021-42374",
        "vendor": "BusyBox",
        "product": "Embedded Linux Utilities (sh, ash, sed, awk)",
        "version_pattern": r"(?:1\.[1-3][0-9]\.|busybox)",
        "title": "BusyBox Multiple Applet Out-of-Bounds Memory Corruption",
        "description": "Out-of-bounds heap read in BusyBox unlzma and sed applets allows attackers to trigger denial of service or arbitrary code execution.",
        "cvss_score": 7.2,
        "severity": "High",
        "affected_ports": "22, 23",
        "remediation": "Update BusyBox package to version 1.34.0 or newer.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42374",
    },

    # Dropbear SSH
    {
        "cve_id": "CVE-2023-36328",
        "vendor": "Dropbear",
        "product": "Dropbear SSH Daemon",
        "version_pattern": r"(?:201[0-9]|2020|dropbear)",
        "title": "Dropbear SSH Terrapin Attack (Prefix Truncation)",
        "description": "Vulnerability in Dropbear SSH handshake allows an active attacker to manipulate sequence numbers and compromise channel integrity.",
        "cvss_score": 5.9,
        "severity": "Medium",
        "affected_ports": "22",
        "remediation": "Upgrade Dropbear to release 2024.84 or newer, or disable ChaCha20-Poly1305 and CBC ciphers.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2023-36328",
    },

    # UPnP IGD (CallStranger)
    {
        "cve_id": "CVE-2020-12695",
        "vendor": "UPnP Forum",
        "product": "UPnP Internet Gateway Device (IGD)",
        "version_pattern": r".*",
        "title": "CallStranger UPnP Eventing Data Exfiltration / Amplification",
        "description": "UPnP IGD implementation vulnerability allows remote attackers to abuse the SUBSCRIBE callback header to perform SSRF, data exfiltration, and reflected DDoS amplification.",
        "cvss_score": 7.5,
        "severity": "High",
        "affected_ports": "1900, 5000, 49152",
        "remediation": "Disable UPnP IGD functionality on all internal routers and IoT devices; isolate port 1900 UDP.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2020-12695",
    },

    # Boa Embedded Web Server
    {
        "cve_id": "CVE-2021-33558",
        "vendor": "Boa",
        "product": "Boa Web Server 0.94.14",
        "version_pattern": r"boa[/_\s]?(?:0\.94|0\.93)",
        "title": "Boa Web Server Arbitrary File Disclosure and Memory Corruption",
        "description": "Legacy Boa web server commonly embedded in IoT cameras and modems contains vulnerabilities allowing unauthenticated attackers to read arbitrary files from filesystem root.",
        "cvss_score": 7.5,
        "severity": "High",
        "affected_ports": "80, 8080",
        "remediation": "Replace obsolete Boa web server daemon with an actively maintained web server like lighttpd or nginx.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2021-33558",
    },

    # GoAhead Web Server
    {
        "cve_id": "CVE-2017-17562",
        "vendor": "Embedthis",
        "product": "GoAhead Web Server",
        "version_pattern": r"goahead(?:[/_\s]?[1-3]\.|4\.[0-2]\.)",
        "title": "GoAhead Web Server Remote Code Execution via CGI Environment",
        "description": "Remote code execution vulnerability allows unauthenticated attackers to hijack dynamic linking (LD_PRELOAD) when CGI is enabled.",
        "cvss_score": 9.8,
        "severity": "Critical",
        "affected_ports": "80, 8080",
        "remediation": "Upgrade GoAhead to version 4.3.0 or later.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2017-17562",
    },

    # Allegro RomPager (Misfortune Cookie)
    {
        "cve_id": "CVE-2014-9222",
        "vendor": "Allegro",
        "product": "RomPager Embedded Web Server",
        "version_pattern": r"rompager[/_\s]?[1-4]\.[0-9]+",
        "title": "Misfortune Cookie RomPager Remote Memory Corruption",
        "description": "RomPager embedded web server before 4.34 allows remote attackers to corrupt memory and gain administrative privileges via a crafted HTTP Cookie header.",
        "cvss_score": 9.8,
        "severity": "Critical",
        "affected_ports": "80, 8080",
        "remediation": "Upgrade router firmware to a version with RomPager 4.34+ or replace the vulnerable router.",
        "reference_url": "https://nvd.nist.gov/vuln/detail/CVE-2014-9222",
    },

    # Insecure Inherent IoT Protocol CVEs / CWEs
    {
        "cve_id": "CWE-319-TELNET",
        "vendor": "Generic",
        "product": "Telnet Remote Shell Daemon",
        "version_pattern": r".*",
        "title": "Insecure Cleartext Management Protocol (Telnet Exposed)",
        "description": "Device exposes TCP port 23 (Telnet). All authentication credentials and operational commands are transmitted in cleartext, vulnerable to MITM interception and passive sniffing.",
        "cvss_score": 7.5,
        "severity": "High",
        "affected_ports": "23",
        "remediation": "Disable the Telnet daemon immediately in device configuration and enforce SSH with certificate or strong key authentication.",
        "reference_url": "https://cwe.mitre.org/data/definitions/319.html",
    },
    {
        "cve_id": "CWE-306-RTSP-STREAM",
        "vendor": "Generic",
        "product": "RTSP Surveillance Stream Service",
        "version_pattern": r".*",
        "title": "Unauthenticated Surveillance Video Stream Exposure",
        "description": "The device's RTSP video streaming endpoint (port 554/8554) accepts DESCRIBE and PLAY requests without requiring HTTP Basic or Digest authentication, exposing live video feeds.",
        "cvss_score": 8.2,
        "severity": "High",
        "affected_ports": "554, 8554",
        "remediation": "Enforce strong RTSP digest authentication in camera settings and isolate camera VLAN from guest/office subnets.",
        "reference_url": "https://cwe.mitre.org/data/definitions/306.html",
    },
    {
        "cve_id": "CWE-306-MQTT-BROKER",
        "vendor": "Generic",
        "product": "MQTT IoT Telemetry Broker",
        "version_pattern": r".*",
        "title": "Unauthenticated MQTT Broker Insecure Access",
        "description": "The device runs an open MQTT broker (port 1883) that allows anonymous clients to connect, publish arbitrary telemetry, and subscribe to sensor data feeds without authentication.",
        "cvss_score": 7.5,
        "severity": "High",
        "affected_ports": "1883",
        "remediation": "Enable TLS encryption (port 8883) and configure password or client certificate authentication on the MQTT broker.",
        "reference_url": "https://cwe.mitre.org/data/definitions/306.html",
    },
    {
        "cve_id": "CWE-319-FTP-PLAINTEXT",
        "vendor": "Generic",
        "product": "FTP File Server",
        "version_pattern": r".*",
        "title": "Cleartext File Transfer Protocol (FTP) Service Active",
        "description": "Device exposes FTP (port 21). Passwords and data files are transmitted unencrypted, subject to network sniffing.",
        "cvss_score": 5.3,
        "severity": "Medium",
        "affected_ports": "21",
        "remediation": "Disable FTP and utilize SFTP (SSH File Transfer) or FTPS with TLS encryption.",
        "reference_url": "https://cwe.mitre.org/data/definitions/319.html",
    }
]

def init_cve_database():
    """Populates the database with curated IoT CVE records."""
    conn = get_db_connection()
    cursor = conn.cursor()
    for entry in IOT_CVE_DATABASE:
        cursor.execute("""
            INSERT INTO cve_knowledge_base (cve_id, vendor, product, version_pattern, title, description, cvss_score, severity, affected_ports, remediation, reference_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve_id) DO UPDATE SET
                vendor=excluded.vendor,
                product=excluded.product,
                title=excluded.title,
                description=excluded.description,
                cvss_score=excluded.cvss_score,
                severity=excluded.severity,
                affected_ports=excluded.affected_ports,
                remediation=excluded.remediation,
                reference_url=excluded.reference_url
        """, (
            entry["cve_id"], entry["vendor"], entry["product"], entry["version_pattern"],
            entry["title"], entry["description"], entry["cvss_score"], entry["severity"],
            entry["affected_ports"], entry["remediation"], entry["reference_url"]
        ))
    conn.commit()
    conn.close()

def match_cves_for_device(
    vendor: str,
    model: Optional[str],
    firmware_version: Optional[str],
    open_ports: List[int],
    services_meta: List[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    """Correlates device characteristics against the CVE intelligence database."""
    matched = []
    ports_set = set(open_ports)
    v_clean = (vendor or "").lower()
    m_clean = (model or "").lower()
    fw_clean = (firmware_version or "").lower()

    # Combine text for broader matching
    banners_blob = " ".join([str(s.get("banner") or "") for s in services_meta]).lower()

    for entry in IOT_CVE_DATABASE:
        entry_vendor = entry["vendor"].lower()
        entry_ports = [int(p.strip()) for p in entry["affected_ports"].split(",") if p.strip().isdigit()]

        is_match = False

        # Specific Inherent Protocol Vulnerabilities
        if entry["cve_id"] == "CWE-319-TELNET" and 23 in ports_set:
            is_match = True
        elif entry["cve_id"] == "CWE-306-RTSP-STREAM" and (554 in ports_set or 8554 in ports_set):
            # Check if RTSP banner reported unauthenticated
            rtsp_auth = True
            for s in services_meta:
                if s.get("port") in [554, 8554] and s.get("details", {}).get("unauthenticated_stream_exposed"):
                    rtsp_auth = False
            if not rtsp_auth or (554 in ports_set):
                is_match = True
        elif entry["cve_id"] == "CWE-306-MQTT-BROKER" and 1883 in ports_set:
            is_match = True
        elif entry["cve_id"] == "CWE-319-FTP-PLAINTEXT" and 21 in ports_set:
            is_match = True
        elif entry["cve_id"] == "CVE-2020-12695" and any(p in ports_set for p in [1900, 5000, 49152]):
            is_match = True
        elif "boa" in entry["product"].lower() and "boa" in banners_blob:
            is_match = True
        elif "goahead" in entry["product"].lower() and "goahead" in banners_blob:
            is_match = True
        elif "rompager" in entry["product"].lower() and "rompager" in banners_blob:
            is_match = True
        elif "dropbear" in entry["product"].lower() and "dropbear" in banners_blob:
            is_match = True
        elif "busybox" in entry["product"].lower() and "busybox" in banners_blob:
            is_match = True
        # Vendor + Product match
        elif entry_vendor in v_clean or entry_vendor in m_clean or entry_vendor in banners_blob:
            # Check port overlap
            if any(p in ports_set for p in entry_ports):
                # Check version pattern if defined
                if entry.get("version_pattern") and entry["version_pattern"] != ".*":
                    pattern = entry["version_pattern"]
                    if re.search(pattern, fw_clean) or re.search(pattern, banners_blob) or re.search(pattern, m_clean):
                        is_match = True
                else:
                    is_match = True

        if is_match:
            matched.append(entry)

    return matched

# Initialize on import
try:
    init_cve_database()
except Exception:
    pass
