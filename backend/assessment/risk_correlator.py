from typing import Dict, Any, List

def correlate_device_risk(
    services: List[Dict[str, Any]],
    vulnerabilities: List[Dict[str, Any]],
    config_checks: List[Dict[str, Any]],
    exposure: Dict[str, Any],
    behavior_anomalies: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Combines findings across all 5 assessment layers into an explainable 0-100 risk score and recommendations."""
    
    # 1. Services Risk (Max 25 pts)
    service_risk = 0.0
    insecure_services = [s for s in services if s.get("is_insecure")]
    service_risk += min(20.0, len(insecure_services) * 6.5)
    if any(s.get("port") == 23 for s in services):
        service_risk += 5.0 # Telnet penalty
    service_risk = min(25.0, round(service_risk, 1))

    # 2. Firmware & CVE Risk (Max 35 pts)
    cve_risk = 0.0
    if vulnerabilities:
        max_cvss = max([v.get("cvss_score", 0.0) for v in vulnerabilities], default=0.0)
        crit_count = sum(1 for v in vulnerabilities if v.get("severity") == "Critical")
        high_count = sum(1 for v in vulnerabilities if v.get("severity") == "High")
        
        cve_risk = (max_cvss / 10.0) * 22.0 + (crit_count * 7.0) + (high_count * 3.5)
    cve_risk = min(35.0, round(cve_risk, 1))

    # 3. Configuration Risk (Max 20 pts)
    config_risk = 0.0
    failed_checks = [c for c in config_checks if c.get("status") == "FAIL"]
    warn_checks = [c for c in config_checks if c.get("status") == "WARN"]
    
    config_risk = (len(failed_checks) * 6.0) + (len(warn_checks) * 2.0)
    config_risk = min(20.0, round(config_risk, 1))

    # 4. Network Exposure Risk (Max 10 pts)
    exposure_risk = 0.0
    attack_surface = exposure.get("attack_surface_score", 1.0)
    exposure_risk = (attack_surface / 10.0) * 8.0
    if exposure.get("isolation_recommended"):
        exposure_risk += 2.0
    exposure_risk = min(10.0, round(exposure_risk, 1))

    # 5. Behavior Anomaly Risk (Max 10 pts)
    behavior_risk = 0.0
    if behavior_anomalies:
        crit_behaviors = [b for b in behavior_anomalies if b.get("severity") in ["Critical", "High"]]
        behavior_risk = min(10.0, len(crit_behaviors) * 5.0 + len(behavior_anomalies) * 2.0)
    behavior_risk = min(10.0, round(behavior_risk, 1))

    # Aggregate Total Risk Score
    total_score = round(min(100.0, service_risk + cve_risk + config_risk + exposure_risk + behavior_risk), 1)

    # Classify Risk Tier
    if total_score >= 70.0:
        risk_level = "Critical"
    elif total_score >= 45.0:
        risk_level = "High"
    elif total_score >= 20.0:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # Actionable Recommendations
    recommendations = []

    if total_score >= 70.0:
        recommendations.append("URGENT: Isolate / Quarantine device immediately via network firewall rule to stop potential lateral movement.")

    for v in vulnerabilities:
        if v.get("severity") in ["Critical", "High"] and v.get("remediation"):
            recommendations.append(f"[{v.get('cve_id')}] {v.get('remediation')}")

    for c in failed_checks:
        if c.get("recommendation"):
            recommendations.append(f"[{c.get('category')}] {c.get('recommendation')}")

    if exposure.get("isolation_recommended"):
        recommendations.append("[VLAN Isolation] Relocate device from default management subnet to an isolated IoT guest VLAN (VLAN 20) with ACL inspection.")

    for b in behavior_anomalies:
        recommendations.append(f"[Traffic Alert] Investigate anomalous outbound traffic: {b.get('title')}")

    if not recommendations:
        recommendations.append("Device exhibits a secure baseline posture. Continue periodic automated assessments.")

    # Deduplicate recommendations while preserving order
    deduped_recs = []
    seen = set()
    for r in recommendations:
        if r not in seen:
            seen.add(r)
            deduped_recs.append(r)

    return {
        "service_risk": service_risk,
        "cve_risk": cve_risk,
        "config_risk": config_risk,
        "exposure_risk": exposure_risk,
        "behavior_risk": behavior_risk,
        "total_score": total_score,
        "risk_level": risk_level,
        "recommendations": deduped_recs[:8]
    }
