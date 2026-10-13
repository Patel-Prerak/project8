import asyncio
import os
import json
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, BackgroundTasks, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse

from backend.database import init_db, get_db_connection
from backend.models import ScanRequest, QuarantineRequest, ReleaseRequest
from backend.discovery.scanner import NetworkDiscoveryEngine, get_network_interfaces
from backend.assessment.assessment_coordinator import run_full_device_assessment
from backend.assessment.behavior_monitor import behavior_monitor
from backend.quarantine.quarantine_manager import quarantine_manager, is_admin
from backend.reports.report_generator import generate_json_report, generate_csv_report, generate_html_report
from backend.assessment.cve_engine import IOT_CVE_DATABASE

# Initialize database schema
init_db()

app = FastAPI(title="IoT Risk Assessment and Response Platform", version="2.0.0")

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

discovery_engine = NetworkDiscoveryEngine()

# Active WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: Dict[str, Any]):
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)

ws_manager = ConnectionManager()

# ----------------- SYSTEM & DISCOVERY ----------------- #

@app.get("/api/system/status")
async def get_system_status():
    admin_mode = is_admin()
    return {
        "status": "ONLINE",
        "admin_privileges": admin_mode,
        "firewall_hook": "DIRECT_OS_KERNEL" if admin_mode else "ELEVATED_DISPATCH",
        "behavior_monitor_active": behavior_monitor.is_running,
        "active_ws_clients": len(ws_manager.active_connections)
    }

@app.get("/api/discovery/interfaces")
async def get_interfaces():
    return get_network_interfaces()

@app.get("/api/discovery/status")
async def get_discovery_status():
    return {
        "is_scanning": discovery_engine.is_scanning,
        "progress": discovery_engine.progress,
        "found_count": len(discovery_engine.found_devices)
    }

@app.post("/api/discovery/start")
async def start_discovery(req: ScanRequest):
    if discovery_engine.is_scanning:
        raise HTTPException(status_code=400, detail="A discovery scan is already in progress.")

    async def run_scan_coro():
        async def progress_cb(data: Dict[str, Any]):
            await ws_manager.broadcast({"type": "DISCOVERY_UPDATE", "data": data})

        try:
            await discovery_engine.run_discovery(
                target_cidr=req.cidr,
                scan_type=req.scan_type,
                progress_callback=progress_cb
            )
        except Exception as e:
            discovery_engine.is_scanning = False
            await ws_manager.broadcast({"type": "DISCOVERY_UPDATE", "data": {"status": "FAILED", "progress": 0, "message": f"Scan failed: {str(e)}"}})

    asyncio.create_task(run_scan_coro())
    return {"status": "STARTED", "message": f"Discovery scan initiated on {req.cidr or 'auto-detected subnets'}."}

# ----------------- DEVICE INVENTORY ----------------- #

@app.get("/api/devices")
async def list_devices(search: Optional[str] = None, risk_filter: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()

    query = "SELECT * FROM devices WHERE 1=1"
    params = []

    if search:
        query += " AND (ip LIKE ? OR mac LIKE ? OR hostname LIKE ? OR vendor LIKE ? OR model LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term, term, term])

    if risk_filter and risk_filter != "ALL":
        query += " AND risk_level = ?"
        params.append(risk_filter)

    query += " ORDER BY risk_score DESC, id DESC"
    cursor.execute(query, params)
    rows = cursor.fetchall()

    devices = []
    for r in rows:
        d = dict(r)
        dev_id = d["id"]

        # Counts
        cursor.execute("SELECT count(*) as cnt FROM services WHERE device_id = ?", (dev_id,))
        d["services_count"] = cursor.fetchone()["cnt"]

        cursor.execute("SELECT count(*) as cnt FROM services WHERE device_id = ? AND is_insecure = 1", (dev_id,))
        d["insecure_services_count"] = cursor.fetchone()["cnt"]

        cursor.execute("SELECT count(*) as cnt FROM vulnerabilities WHERE device_id = ?", (dev_id,))
        d["cve_count"] = cursor.fetchone()["cnt"]

        if d.get("risk_breakdown"):
            try:
                d["risk_breakdown"] = json.loads(d["risk_breakdown"])
            except Exception:
                pass

        devices.append(d)

    conn.close()
    return devices

@app.post("/api/devices")
async def add_custom_device(ip: str, vendor: Optional[str] = "Generic IoT", device_type: Optional[str] = "Generic IoT"):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO devices (ip, vendor, device_type, status, last_seen, updated_at)
        VALUES (?, ?, ?, 'Active', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ON CONFLICT(ip) DO UPDATE SET vendor=excluded.vendor, updated_at=CURRENT_TIMESTAMP
    """, (ip, vendor, device_type))
    conn.commit()
    cursor.execute("SELECT id FROM devices WHERE ip = ?", (ip,))
    row = cursor.fetchone()
    conn.close()
    return {"status": "CREATED", "device_id": row["id"], "ip": ip}

@app.get("/api/devices/{device_id}")
async def get_device_detail(device_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    device_row = cursor.fetchone()
    if not device_row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    device = dict(device_row)
    if device.get("risk_breakdown"):
        try:
            device["risk_breakdown"] = json.loads(device["risk_breakdown"])
        except Exception:
            pass

    # Services
    cursor.execute("SELECT * FROM services WHERE device_id = ? ORDER BY port ASC", (device_id,))
    services = []
    for s in cursor.fetchall():
        s_dict = dict(s)
        if s_dict.get("details"):
            try:
                s_dict["details"] = json.loads(s_dict["details"])
            except Exception:
                pass
        services.append(s_dict)
    device["services"] = services

    # Vulnerabilities
    cursor.execute("SELECT * FROM vulnerabilities WHERE device_id = ? ORDER BY cvss_score DESC", (device_id,))
    device["vulnerabilities"] = [dict(r) for r in cursor.fetchall()]

    # Config Checks
    cursor.execute("SELECT * FROM config_checks WHERE device_id = ? ORDER BY severity ASC", (device_id,))
    device["config_checks"] = [dict(r) for r in cursor.fetchall()]

    # Exposure
    cursor.execute("SELECT * FROM exposure_metrics WHERE device_id = ?", (device_id,))
    exp = cursor.fetchone()
    device["exposure"] = dict(exp) if exp else None

    # Behavior traffic & anomalies
    device["traffic_profile"] = behavior_monitor.get_device_traffic(device["ip"])
    cursor.execute("SELECT * FROM behavior_events WHERE device_id = ? OR device_ip = ? ORDER BY timestamp DESC LIMIT 20", (device_id, device["ip"]))
    device["behavior_events"] = [dict(r) for r in cursor.fetchall()]

    # Quarantine History
    cursor.execute("SELECT * FROM quarantine_records WHERE device_id = ? ORDER BY timestamp DESC", (device_id,))
    device["quarantine_history"] = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return device

@app.delete("/api/devices/{device_id}")
async def delete_device(device_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM devices WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()
    return {"status": "DELETED", "device_id": device_id}

# ----------------- SECURITY ASSESSMENT ----------------- #

@app.post("/api/devices/{device_id}/assess")
async def trigger_device_assessment(device_id: int):
    try:
        await ws_manager.broadcast({"type": "ASSESSMENT_STARTED", "device_id": device_id})
        result = await run_full_device_assessment(device_id)
        await ws_manager.broadcast({"type": "ASSESSMENT_COMPLETED", "device_id": device_id, "data": result})
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/devices/assess-all")
async def assess_all_devices(background_tasks: BackgroundTasks):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM devices WHERE status = 'Active'")
    device_ids = [row["id"] for row in cursor.fetchall()]
    conn.close()

    async def batch_runner():
        for dev_id in device_ids:
            try:
                await ws_manager.broadcast({"type": "ASSESSMENT_PROGRESS", "device_id": dev_id, "message": f"Assessing device #{dev_id}"})
                await run_full_device_assessment(dev_id)
            except Exception:
                pass
        await ws_manager.broadcast({"type": "BATCH_ASSESSMENT_COMPLETED", "message": f"Completed assessment of {len(device_ids)} devices."})

    background_tasks.add_task(batch_runner)
    return {"status": "SCHEDULED", "device_count": len(device_ids), "message": "Batch multi-layer security assessment started."}

# ----------------- CVE KNOWLEDGE BASE ----------------- #

@app.get("/api/cve/database")
async def get_cve_database(search: Optional[str] = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if search:
        term = f"%{search}%"
        cursor.execute("SELECT * FROM cve_knowledge_base WHERE cve_id LIKE ? OR vendor LIKE ? OR title LIKE ? OR product LIKE ? ORDER BY cvss_score DESC", (term, term, term, term))
    else:
        cursor.execute("SELECT * FROM cve_knowledge_base ORDER BY cvss_score DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ----------------- BEHAVIOR MONITORING ----------------- #

@app.get("/api/behavior/status")
async def get_behavior_status():
    return {
        "is_running": behavior_monitor.is_running,
        "monitored_ips_count": len(behavior_monitor.stats),
        "total_anomalies_detected": len(behavior_monitor.recent_events)
    }

@app.post("/api/behavior/start")
async def start_behavior_monitor():
    behavior_monitor.start()
    await ws_manager.broadcast({"type": "MONITOR_STATUS", "is_running": True})
    return {"status": "STARTED", "message": "Real-time traffic capture and anomaly detection running."}

@app.post("/api/behavior/stop")
async def stop_behavior_monitor():
    behavior_monitor.stop()
    await ws_manager.broadcast({"type": "MONITOR_STATUS", "is_running": False})
    return {"status": "STOPPED", "message": "Traffic monitor stopped."}

@app.get("/api/behavior/anomalies")
async def list_behavior_anomalies():
    return behavior_monitor.get_all_anomalies()

@app.post("/api/behavior/simulate-anomaly")
async def simulate_anomaly(ip: str, anomaly_type: str = "PORT_SCAN_DETECTED"):
    """Enables testing behavior monitoring alerting in real-time."""
    titles = {
        "PORT_SCAN_DETECTED": ("Suspicious Network Reconnaissance / Port Scan", "Device contacted 15 distinct ports across the subnet, characteristic of worm propagation."),
        "SUSPICIOUS_C2_COMMUNICATION": ("Suspicious Outbound Port Communication (Potential C2)", "Device initiated unauthorized connection to 198.51.100.23:4444 (Metasploit/Mirai command listener)."),
        "TRAFFIC_SPIKE_DETECTED": ("Abnormal Traffic Flood Spike", "Device emitted 450 packets/sec over UDP port 53 / 1900, potential reflection attack.")
    }
    title, details = titles.get(anomaly_type, ("Anomalous Behavior Flagged", "Unusual traffic pattern observed."))
    behavior_monitor._log_anomaly(ip, anomaly_type, "High" if anomaly_type != "SUSPICIOUS_C2_COMMUNICATION" else "Critical", title, details)
    await ws_manager.broadcast({"type": "ANOMALY_ALERT", "ip": ip, "title": title, "severity": "High"})
    return {"status": "SIMULATED", "ip": ip, "title": title}

# ----------------- QUARANTINE & RESPONSE ----------------- #

@app.get("/api/quarantine/status")
async def get_quarantine_status():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, ip, mac, hostname, vendor, device_type, risk_score, risk_level, updated_at FROM devices WHERE is_quarantined = 1")
    active = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM quarantine_records ORDER BY timestamp DESC LIMIT 50")
    audit = [dict(r) for r in cursor.fetchall()]
    conn.close()

    return {
        "active_quarantined_count": len(active),
        "active_quarantined_devices": active,
        "quarantine_audit_logs": audit
    }

@app.post("/api/quarantine/isolate")
async def isolate_device(req: QuarantineRequest):
    try:
        res = quarantine_manager.quarantine_device(
            device_id=req.device_id,
            reason=req.reason,
            method=req.method or "WINDOWS_FIREWALL",
            admin_notes=req.admin_notes
        )
        await ws_manager.broadcast({"type": "DEVICE_QUARANTINED", "device_id": req.device_id, "data": res})
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/quarantine/release")
async def release_device(req: ReleaseRequest):
    try:
        res = quarantine_manager.release_device(
            device_id=req.device_id,
            reason=req.reason or "Released by administrator"
        )
        await ws_manager.broadcast({"type": "DEVICE_RELEASED", "device_id": req.device_id, "data": res})
        return res
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/quarantine/{device_id}/scripts")
async def get_isolation_scripts(device_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT ip, mac FROM devices WHERE id = ?", (device_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Device not found")

    scripts = quarantine_manager.generate_isolation_scripts(ip=row["ip"], mac=row["mac"])
    return {"device_id": device_id, "ip": row["ip"], "scripts": scripts}

# ----------------- REPORTS & EXPORT ----------------- #

@app.get("/api/reports/json")
async def download_json_report():
    return generate_json_report()

@app.get("/api/reports/csv")
async def download_csv_report():
    csv_data = generate_csv_report()
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=iot_risk_assessment_report.csv"}
    )

@app.get("/api/reports/html", response_class=HTMLResponse)
async def view_html_report():
    return HTMLResponse(content=generate_html_report())

# ----------------- WEBSOCKET ----------------- #

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Heartbeat ping/pong or client commands
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# Mount frontend static files
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
