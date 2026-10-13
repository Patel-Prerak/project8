import json
import csv
import io
from typing import Dict, Any, List
from datetime import datetime
from backend.database import get_db_connection

def generate_json_report() -> Dict[str, Any]:
    """Compiles the entire system posture, device list, CVEs, and quarantine status into structured JSON."""
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices ORDER BY risk_score DESC")
    devices = [dict(row) for row in cursor.fetchall()]

    for d in devices:
        dev_id = d["id"]
        cursor.execute("SELECT * FROM services WHERE device_id = ?", (dev_id,))
        d["services"] = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM vulnerabilities WHERE device_id = ?", (dev_id,))
        d["vulnerabilities"] = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM config_checks WHERE device_id = ?", (dev_id,))
        d["config_checks"] = [dict(r) for r in cursor.fetchall()]

        cursor.execute("SELECT * FROM exposure_metrics WHERE device_id = ?", (dev_id,))
        exp = cursor.fetchone()
        d["exposure"] = dict(exp) if exp else None

    cursor.execute("SELECT * FROM quarantine_records ORDER BY timestamp DESC")
    quarantine_logs = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM behavior_events ORDER BY timestamp DESC LIMIT 50")
    behavior_events = [dict(r) for r in cursor.fetchall()]

    conn.close()

    total_devices = len(devices)
    crit_count = sum(1 for d in devices if d.get("risk_level") == "Critical")
    high_count = sum(1 for d in devices if d.get("risk_level") == "High")
    quarantined_count = sum(1 for d in devices if d.get("is_quarantined"))

    return {
        "report_title": "IoT Security Assessment and Response Report",
        "generated_at": datetime.now().isoformat(),
        "summary": {
            "total_devices": total_devices,
            "critical_risk_devices": crit_count,
            "high_risk_devices": high_count,
            "quarantined_devices": quarantined_count,
            "overall_posture": "Critical Attention Required" if crit_count > 0 else "Moderate" if high_count > 0 else "Healthy"
        },
        "devices": devices,
        "quarantine_audit": quarantine_logs,
        "behavioral_alerts": behavior_events
    }

def generate_csv_report() -> str:
    """Generates CSV inventory and vulnerability matrix."""
    output = io.StringIO()
    writer = csv.writer(output)

    writer.writerow([
        "Device ID", "IP Address", "MAC Address", "Hostname", "Vendor", "Device Type",
        "Model", "Firmware Version", "Risk Score", "Risk Level", "Quarantined Status",
        "Open Ports", "CVEs Count", "Config Failures"
    ])

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices ORDER BY risk_score DESC")
    devices = cursor.fetchall()

    for d in devices:
        dev_id = d["id"]
        cursor.execute("SELECT port FROM services WHERE device_id = ?", (dev_id,))
        ports = [str(r["port"]) for r in cursor.fetchall()]

        cursor.execute("SELECT count(*) as cnt FROM vulnerabilities WHERE device_id = ?", (dev_id,))
        cve_cnt = cursor.fetchone()["cnt"]

        cursor.execute("SELECT count(*) as cnt FROM config_checks WHERE device_id = ? AND status = 'FAIL'", (dev_id,))
        fail_cnt = cursor.fetchone()["cnt"]

        writer.writerow([
            d["id"], d["ip"], d["mac"] or "N/A", d["hostname"] or "N/A",
            d["vendor"] or "Unknown", d["device_type"] or "Generic",
            d["model"] or "N/A", d["firmware_version"] or "N/A",
            d["risk_score"], d["risk_level"], "YES" if d["is_quarantined"] else "NO",
            ";".join(ports), cve_cnt, fail_cnt
        ])

    conn.close()
    return output.getvalue()

def generate_html_report() -> str:
    """Generates an executive-ready, print-formatted HTML security dossier."""
    data = generate_json_report()
    summary = data["summary"]
    devices = data["devices"]

    devices_rows_html = ""
    for d in devices:
        risk_color = "#ef4444" if d["risk_level"] == "Critical" else "#f59e0b" if d["risk_level"] == "High" else "#3b82f6" if d["risk_level"] == "Medium" else "#10b981"
        quarantine_badge = '<span style="color:#ef4444;font-weight:bold;">QUARANTINED</span>' if d["is_quarantined"] else '<span style="color:#10b981;">ACTIVE</span>'
        
        cve_items = "".join([f"<li><b>{v['cve_id']}</b> (CVSS {v['cvss_score']}): {v['title']}</li>" for v in d.get("vulnerabilities", [])]) or "<li>No known CVEs matched.</li>"
        
        ports_str = ", ".join([str(s["port"]) for s in d.get("services", [])]) or "None detected"

        devices_rows_html += f"""
        <tr style="border-bottom:1px solid #e2e8f0;">
            <td style="padding:12px;font-family:monospace;font-weight:600;">{d['ip']}<br><span style="font-size:11px;color:#64748b;">{d.get('mac') or 'Unknown MAC'}</span></td>
            <td style="padding:12px;"><b>{d.get('vendor') or 'Unknown'}</b><br><span style="font-size:12px;color:#64748b;">{d.get('device_type')} ({d.get('model') or 'Unspecified Model'})</span></td>
            <td style="padding:12px;font-family:monospace;font-size:12px;">{ports_str}</td>
            <td style="padding:12px;"><span style="background:{risk_color}22;color:{risk_color};padding:4px 8px;border-radius:4px;font-weight:700;">{d['risk_score']} - {d['risk_level']}</span></td>
            <td style="padding:12px;">{quarantine_badge}</td>
            <td style="padding:12px;font-size:12px;">
                <ul style="margin:0;padding-left:16px;">{cve_items}</ul>
            </td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>IoT Risk Assessment & Response Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background:#f8fafc; color:#0f172a; margin:0; padding:40px; }}
        .container {{ max-width:1100px; margin:0 auto; background:#ffffff; padding:40px; border-radius:12px; box-shadow:0 4px 6px -1px rgba(0,0,0,0.1); }}
        .header {{ display:flex; justify-content:space-between; align-items:center; border-bottom:2px solid #e2e8f0; padding-bottom:24px; margin-bottom:32px; }}
        .title h1 {{ margin:0 0 8px 0; font-size:26px; color:#0f172a; }}
        .title p {{ margin:0; color:#64748b; font-size:14px; }}
        .stats-grid {{ display:grid; grid-template-columns:repeat(4, 1fr); gap:16px; margin-bottom:32px; }}
        .stat-card {{ background:#f1f5f9; padding:20px; border-radius:8px; border-left:4px solid #3b82f6; }}
        .stat-card.danger {{ border-left-color:#ef4444; }}
        .stat-card.warning {{ border-left-color:#f59e0b; }}
        .stat-card.success {{ border-left-color:#10b981; }}
        .stat-card h3 {{ margin:0 0 6px 0; font-size:12px; text-transform:uppercase; color:#64748b; }}
        .stat-card .val {{ font-size:28px; font-weight:800; color:#0f172a; margin:0; }}
        table {{ width:100%; border-collapse:collapse; margin-top:20px; text-align:left; }}
        th {{ background:#f8fafc; padding:12px; font-size:12px; text-transform:uppercase; color:#475569; border-bottom:2px solid #cbd5e1; }}
        @media print {{
            body {{ background:#fff; padding:0; }}
            .container {{ box-shadow:none; padding:0; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="title">
                <h1>IoT Security Assessment & Response Report</h1>
                <p>Enterprise Assessment Pipeline & Response Record | Generated: {data['generated_at']}</p>
            </div>
            <div>
                <button onclick="window.print()" style="background:#0f172a;color:#fff;border:none;padding:10px 18px;border-radius:6px;cursor:pointer;font-weight:600;">Print / Save as PDF</button>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Devices Audited</h3>
                <p class="val">{summary['total_devices']}</p>
            </div>
            <div class="stat-card danger">
                <h3>Critical Risk Devices</h3>
                <p class="val">{summary['critical_risk_devices']}</p>
            </div>
            <div class="stat-card warning">
                <h3>High Risk Devices</h3>
                <p class="val">{summary['high_risk_devices']}</p>
            </div>
            <div class="stat-card danger">
                <h3>Devices Quarantined</h3>
                <p class="val">{summary['quarantined_devices']}</p>
            </div>
        </div>

        <h2>Audited IoT Assets & Vulnerability Posture</h2>
        <table>
            <thead>
                <tr>
                    <th>Device Address</th>
                    <th>Identity & Model</th>
                    <th>Open Ports</th>
                    <th>Risk Posture</th>
                    <th>Quarantine</th>
                    <th>Matched CVEs & Flaws</th>
                </tr>
            </thead>
            <tbody>
                {devices_rows_html}
            </tbody>
        </table>
    </div>
</body>
</html>
"""
