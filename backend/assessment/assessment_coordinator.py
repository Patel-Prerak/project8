import asyncio
import json
from typing import Dict, Any, List, Optional
from backend.database import get_db_connection
from backend.assessment.service_scanner import scan_device_ports
from backend.assessment.banner_grabber import (
    grab_http_banner, grab_rtsp_banner, grab_ssh_banner,
    grab_telnet_banner, grab_ftp_banner, grab_mqtt_status
)
from backend.assessment.firmware_detector import extract_firmware_and_model
from backend.assessment.cve_engine import match_cves_for_device
from backend.assessment.config_auditor import audit_device_configuration
from backend.assessment.network_exposure import analyze_network_exposure
from backend.assessment.behavior_monitor import behavior_monitor
from backend.assessment.risk_correlator import correlate_device_risk

async def run_full_device_assessment(device_id: int) -> Dict[str, Any]:
    """Orchestrates comprehensive multi-layer assessment across Services, Firmware, CVEs, Config, Exposure, and Behavior."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    device_row = cursor.fetchone()
    if not device_row:
        conn.close()
        raise ValueError(f"Device with ID {device_id} not found.")

    ip = device_row["ip"]
    vendor_hint = device_row["vendor"]
    mac = device_row["mac"]

    # 1. Services Scan
    open_services = await scan_device_ports(ip)
    open_ports = [s["port"] for s in open_services]

    # 2. Deep Banner Grabbing
    services_enriched = []
    banners_dict = {}

    for s in open_services:
        p = s["port"]
        details = {}
        banner_str = None
        auth_req = True

        if p in [80, 8080]:
            http_res = await grab_http_banner(ip, p, use_ssl=False)
            banner_str = http_res.get("server") or http_res.get("title")
            auth_req = http_res.get("auth_required", False)
            details = http_res
            banners_dict["http"] = http_res
            banners_dict["server"] = http_res.get("server")
            banners_dict["title"] = http_res.get("title")
        elif p in [443, 8443]:
            https_res = await grab_http_banner(ip, p, use_ssl=True)
            banner_str = https_res.get("server") or https_res.get("title")
            auth_req = https_res.get("auth_required", False)
            details = https_res
            banners_dict["https"] = https_res
            banners_dict["server"] = banners_dict.get("server") or https_res.get("server")
            banners_dict["title"] = banners_dict.get("title") or https_res.get("title")
        elif p in [554, 8554]:
            rtsp_res = await grab_rtsp_banner(ip, p)
            banner_str = rtsp_res.get("server")
            auth_req = rtsp_res.get("auth_required", True)
            details = rtsp_res
            banners_dict["rtsp"] = rtsp_res
        elif p == 22:
            ssh_banner = await grab_ssh_banner(ip, p)
            banner_str = ssh_banner
            auth_req = True
            details = {"ssh_banner": ssh_banner}
            banners_dict["ssh"] = ssh_banner
        elif p == 23:
            telnet_banner = await grab_telnet_banner(ip, p)
            banner_str = telnet_banner
            auth_req = False # Often weak / cleartext
            details = {"telnet_banner": telnet_banner}
            banners_dict["telnet"] = telnet_banner
        elif p == 21:
            ftp_res = await grab_ftp_banner(ip, p)
            banner_str = ftp_res.get("banner")
            auth_req = not ftp_res.get("anonymous_allowed", False)
            details = ftp_res
            banners_dict["ftp"] = ftp_res
        elif p == 1883:
            mqtt_res = await grab_mqtt_status(ip, p)
            banner_str = mqtt_res.get("details")
            auth_req = mqtt_res.get("auth_required", True)
            details = mqtt_res
            banners_dict["mqtt"] = mqtt_res
        else:
            banner_str = s.get("desc")
            auth_req = True

        services_enriched.append({
            "device_id": device_id,
            "port": p,
            "protocol": s["protocol"],
            "service_name": s["service_name"],
            "banner": banner_str,
            "is_insecure": s["is_insecure"],
            "auth_required": auth_req,
            "details": details
        })

    # 3. Firmware, Model, OS Detection
    fw_info = extract_firmware_and_model(
        vendor_hint=vendor_hint,
        server_banner=banners_dict.get("server"),
        html_title=banners_dict.get("title"),
        ssh_banner=banners_dict.get("ssh"),
        rtsp_server=banners_dict.get("rtsp", {}).get("server") if isinstance(banners_dict.get("rtsp"), dict) else None
    )

    detected_vendor = fw_info["vendor"] or vendor_hint
    detected_model = fw_info["model"] or device_row["model"]
    detected_firmware = fw_info["firmware_version"] or device_row["firmware_version"]
    detected_os = fw_info["os_info"] or device_row["os_info"]

    # 4. CVE Matching
    matched_cves = match_cves_for_device(
        vendor=detected_vendor,
        model=detected_model,
        firmware_version=detected_firmware,
        open_ports=open_ports,
        services_meta=services_enriched
    )

    # 5. Configuration Audit
    config_checks = audit_device_configuration(
        open_ports=open_ports,
        services_meta=services_enriched,
        banners=banners_dict
    )

    # 6. Network Exposure Analysis
    insecure_count = sum(1 for s in services_enriched if s.get("is_insecure"))
    exposure_result = analyze_network_exposure(
        ip=ip,
        open_ports=open_ports,
        insecure_services_count=insecure_count
    )

    # 7. Behavior & Traffic Analysis
    traffic_profile = behavior_monitor.get_device_traffic(ip)
    anomalies = [a for a in behavior_monitor.get_all_anomalies() if a.get("device_ip") == ip]

    # 8. Multi-Layer Risk Correlation
    risk_posture = correlate_device_risk(
        services=services_enriched,
        vulnerabilities=matched_cves,
        config_checks=config_checks,
        exposure=exposure_result,
        behavior_anomalies=anomalies
    )

    # 9. Update Database Persistence
    # Clear old services & vulnerabilities for this device to prevent duplicate stacking
    cursor.execute("DELETE FROM services WHERE device_id = ?", (device_id,))
    for s in services_enriched:
        cursor.execute("""
            INSERT INTO services (device_id, port, protocol, service_name, banner, is_insecure, auth_required, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            device_id, s["port"], s["protocol"], s["service_name"],
            s["banner"], 1 if s["is_insecure"] else 0, 1 if s["auth_required"] else 0,
            json.dumps(s["details"])
        ))

    cursor.execute("DELETE FROM vulnerabilities WHERE device_id = ?", (device_id,))
    for v in matched_cves:
        cursor.execute("""
            INSERT INTO vulnerabilities (device_id, cve_id, title, description, severity, cvss_score, affected_component, remediation, reference_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            device_id, v["cve_id"], v["title"], v["description"], v["severity"],
            v["cvss_score"], v.get("product"), v["remediation"], v["reference_url"]
        ))

    cursor.execute("DELETE FROM config_checks WHERE device_id = ?", (device_id,))
    for c in config_checks:
        cursor.execute("""
            INSERT INTO config_checks (device_id, check_id, category, title, description, status, severity, recommendation, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            device_id, c["check_id"], c["category"], c["title"], c["description"],
            c["status"], c["severity"], c["recommendation"], c["details"]
        ))

    cursor.execute("""
        INSERT INTO exposure_metrics (device_id, reachability, is_routed, vlan_id, subnet, attack_surface_score, exposed_ports_count, insecure_services_count, notes, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(device_id) DO UPDATE SET
            reachability=excluded.reachability,
            is_routed=excluded.is_routed,
            vlan_id=excluded.vlan_id,
            subnet=excluded.subnet,
            attack_surface_score=excluded.attack_surface_score,
            exposed_ports_count=excluded.exposed_ports_count,
            insecure_services_count=excluded.insecure_services_count,
            notes=excluded.notes,
            updated_at=CURRENT_TIMESTAMP
    """, (
        device_id, exposure_result["reachability"], 1 if exposure_result["is_routed"] else 0,
        exposure_result["vlan_id"], exposure_result["subnet"], exposure_result["attack_surface_score"],
        exposure_result["exposed_ports_count"], exposure_result["insecure_services_count"], exposure_result["notes"]
    ))

    # Update devices table with calculated risk, vendor, model, firmware
    cursor.execute("""
        UPDATE devices
        SET vendor = ?,
            model = ?,
            firmware_version = ?,
            os_info = ?,
            risk_score = ?,
            risk_level = ?,
            risk_breakdown = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    """, (
        detected_vendor, detected_model, detected_firmware, detected_os,
        risk_posture["total_score"], risk_posture["risk_level"],
        json.dumps(risk_posture), device_id
    ))

    conn.commit()
    conn.close()

    return {
        "device_id": device_id,
        "ip": ip,
        "vendor": detected_vendor,
        "model": detected_model,
        "firmware_version": detected_firmware,
        "os_info": detected_os,
        "services": services_enriched,
        "vulnerabilities": matched_cves,
        "config_checks": config_checks,
        "exposure": exposure_result,
        "traffic_profile": traffic_profile,
        "anomalies": anomalies,
        "risk_posture": risk_posture
    }
