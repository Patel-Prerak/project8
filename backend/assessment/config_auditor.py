from typing import List, Dict, Any, Optional

def audit_device_configuration(
    open_ports: List[int],
    services_meta: List[Dict[str, Any]],
    banners: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Performs observable security configuration checks across all discovered interfaces."""
    checks = []
    ports_set = set(open_ports)

    # 1. Telnet Protocol Check
    if 23 in ports_set:
        checks.append({
            "check_id": "CONF-01-TELNET",
            "category": "Management Security",
            "title": "Cleartext Telnet Management Daemon Active",
            "description": "Port 23 (Telnet) is open and accepting connections. All administrative commands and passwords are sent unencrypted.",
            "status": "FAIL",
            "severity": "Critical",
            "recommendation": "Disable Telnet in the device configuration portal. Configure SSH v2 with strong cryptographic keys.",
            "details": f"Port 23 is accessible."
        })
    else:
        checks.append({
            "check_id": "CONF-01-TELNET",
            "category": "Management Security",
            "title": "Insecure Telnet Service Inactive",
            "description": "Port 23 is closed. No legacy cleartext remote shell service detected.",
            "status": "PASS",
            "severity": "Low",
            "recommendation": "Keep Telnet disabled.",
            "details": "Port 23 closed."
        })

    # 2. HTTP Transport Encryption Check
    has_plain_http = (80 in ports_set or 8080 in ports_set)
    has_https = (443 in ports_set or 8443 in ports_set)
    if has_plain_http and not has_https:
        checks.append({
            "check_id": "CONF-02-HTTP-ENCRYPT",
            "category": "Transport Encryption",
            "title": "Unencrypted HTTP Management Interface",
            "description": "Device management UI is served solely over cleartext HTTP without HTTPS support. Session cookies and credentials can be intercepted.",
            "status": "FAIL",
            "severity": "High",
            "recommendation": "Enable HTTPS / TLS certificate on the device and redirect all port 80 requests to port 443.",
            "details": f"Ports open: {[p for p in [80, 8080] if p in ports_set]}"
        })
    elif has_plain_http and has_https:
        checks.append({
            "check_id": "CONF-02-HTTP-ENCRYPT",
            "category": "Transport Encryption",
            "title": "Dual HTTP/HTTPS Exposed Without Enforced Redirect",
            "description": "Both plain HTTP and HTTPS are open. If HTTP does not strictly redirect to HTTPS, users may connect insecurely.",
            "status": "WARN",
            "severity": "Medium",
            "recommendation": "Enforce automatic 301 Redirect to HTTPS and enable HSTS header.",
            "details": "HTTP (80) and HTTPS (443) both active."
        })
    elif has_https:
        checks.append({
            "check_id": "CONF-02-HTTP-ENCRYPT",
            "category": "Transport Encryption",
            "title": "Encrypted Web Management (HTTPS)",
            "description": "Management web interface operates via TLS/HTTPS.",
            "status": "PASS",
            "severity": "Low",
            "recommendation": "Maintain TLS certificate renewal and modern cipher suites.",
            "details": "HTTPS active."
        })

    # 3. RTSP Surveillance Stream Exposure
    if 554 in ports_set or 8554 in ports_set:
        unauth_stream = False
        for s in services_meta:
            if s.get("port") in [554, 8554] and s.get("details", {}).get("unauthenticated_stream_exposed"):
                unauth_stream = True

        if unauth_stream:
            checks.append({
                "check_id": "CONF-03-RTSP-AUTH",
                "category": "Surveillance Security",
                "title": "Unauthenticated RTSP Surveillance Video Stream",
                "description": "RTSP video stream responds to DESCRIBE requests without 401 Unauthorized challenge, allowing unauthenticated live surveillance video viewing.",
                "status": "FAIL",
                "severity": "Critical",
                "recommendation": "Configure Digest authentication for RTSP in the camera admin panel and change default stream URLs.",
                "details": "RTSP DESCRIBE accepted without authentication."
            })
        else:
            checks.append({
                "check_id": "CONF-03-RTSP-AUTH",
                "category": "Surveillance Security",
                "title": "RTSP Video Stream Authentication Enforced",
                "description": "RTSP service is active and returned 401 Unauthorized for unauthenticated DESCRIBE requests.",
                "status": "PASS",
                "severity": "Low",
                "recommendation": "Ensure strong, unique passwords for camera stream accounts.",
                "details": "Authentication challenge verified."
            })

    # 4. MQTT Broker Security
    if 1883 in ports_set:
        is_open_broker = False
        for s in services_meta:
            if s.get("port") == 1883 and s.get("details", {}).get("open_broker"):
                is_open_broker = True

        if is_open_broker:
            checks.append({
                "check_id": "CONF-04-MQTT-AUTH",
                "category": "IoT Messaging",
                "title": "Unauthenticated MQTT Telemetry Broker",
                "description": "MQTT broker on port 1883 accepted an unauthenticated connection. Attackers can publish rogue sensor data or sniff smart home events.",
                "status": "FAIL",
                "severity": "High",
                "recommendation": "Require client username/password authentication and migrate communication to MQTTS (port 8883) with TLS.",
                "details": "Anonymous MQTT CONNECT allowed."
            })
        else:
            checks.append({
                "check_id": "CONF-04-MQTT-AUTH",
                "category": "IoT Messaging",
                "title": "MQTT Broker Running Cleartext",
                "description": "MQTT port 1883 is active in cleartext. Transport is vulnerable to local network sniffing.",
                "status": "WARN",
                "severity": "Medium",
                "recommendation": "Migrate to MQTTS port 8883 with TLS certificates.",
                "details": "Port 1883 active."
            })

    # 5. FTP File Service Check
    if 21 in ports_set:
        anon_allowed = False
        for s in services_meta:
            if s.get("port") == 21 and s.get("details", {}).get("anonymous_allowed"):
                anon_allowed = True

        if anon_allowed:
            checks.append({
                "check_id": "CONF-05-FTP-SERVICE",
                "category": "File Transfer",
                "title": "Anonymous FTP Access Permitted",
                "description": "FTP daemon on port 21 allows anonymous login. Attackers can view or upload files without authentication.",
                "status": "FAIL",
                "severity": "Critical",
                "recommendation": "Disable anonymous FTP access immediately in server configuration or turn off FTP service.",
                "details": "USER anonymous returned 230 Login Successful."
            })
        else:
            checks.append({
                "check_id": "CONF-05-FTP-SERVICE",
                "category": "File Transfer",
                "title": "Cleartext FTP Daemon Active",
                "description": "FTP server requires credentials but transmits them unencrypted over cleartext TCP.",
                "status": "WARN",
                "severity": "Medium",
                "recommendation": "Disable plain FTP; migrate to SFTP (SSH File Transfer Protocol).",
                "details": "Port 21 open with auth requirement."
            })

    # 6. UPnP IGD Check
    if any(p in ports_set for p in [1900, 5000, 49152]):
        checks.append({
            "check_id": "CONF-06-UPNP-EXPOSURE",
            "category": "Perimeter Exposure",
            "title": "UPnP Discovery / IGD Endpoints Exposed",
            "description": "UPnP services are active. Insecure UPnP implementations can allow malicious local software to punch open firewall ports or exfiltrate metadata.",
            "status": "WARN",
            "severity": "Medium",
            "recommendation": "Disable UPnP IGD in router settings if automatic port mapping is not strictly required.",
            "details": f"UPnP ports active: {[p for p in [1900, 5000, 49152] if p in ports_set]}"
        })

    # 7. Information Disclosure in Web Banners
    server_hdr = banners.get("server")
    if server_hdr and any(c.isdigit() for c in server_hdr):
        checks.append({
            "check_id": "CONF-07-BANNER-DISCLOSURE",
            "category": "Information Disclosure",
            "title": "Granular Software Version Disclosed in HTTP Banner",
            "description": f"The HTTP Server header explicitly leaks the underlying software version: '{server_hdr}', aiding automated exploit profiling.",
            "status": "WARN",
            "severity": "Low",
            "recommendation": "Configure web server tokens to 'Prod' or 'Minimal' to suppress exact version disclosure.",
            "details": f"Server header: {server_hdr}"
        })
    else:
        checks.append({
            "check_id": "CONF-07-BANNER-DISCLOSURE",
            "category": "Information Disclosure",
            "title": "Minimal Software Version Disclosure",
            "description": "No granular software version numbers disclosed in root HTTP banners.",
            "status": "PASS",
            "severity": "Low",
            "recommendation": "Maintain banner masking.",
            "details": "Clean or masked server banner."
        })

    return checks
