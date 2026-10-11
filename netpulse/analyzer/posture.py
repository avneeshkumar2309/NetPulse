"""
Network Posture and Host Security Assessment Engine.
Computes host-level and network-wide risk scores, grades, and remediation priority.
"""

from typing import List, Dict, Any
from .risk_rules import evaluate_port_risk


def evaluate_host_security(host_res: Any) -> None:
    """
    Mutate HostResult to calculate risk score, assign grade, and compile security issues.
    """
    score = 100
    issues: List[Dict[str, str]] = []

    for port_res in host_res.ports:
        if port_res.state != "open":
            continue

        risk = evaluate_port_risk(port_res.port, port_res.banner)
        port_res.risk_level = risk["severity"]
        port_res.recommendation = risk["remediation"]

        if risk["severity"] != "Info":
            issues.append({
                "port": str(port_res.port),
                "service": port_res.service,
                "severity": risk["severity"],
                "title": risk["title"],
                "remediation": risk["remediation"]
            })

        # Score penalties
        if risk["severity"] == "Critical":
            score -= 30
        elif risk["severity"] == "High":
            score -= 15
        elif risk["severity"] == "Medium":
            score -= 8
        elif risk["severity"] == "Low":
            score -= 3

    # Floor score
    score = max(5 if any(i["severity"] == "Critical" for i in issues) else 10, min(100, score))
    host_res.risk_score = score

    # Assign Letter Grade
    if score >= 90:
        host_res.risk_grade = "A"
    elif score >= 80:
        host_res.risk_grade = "B"
    elif score >= 70:
        host_res.risk_grade = "C"
    elif score >= 60:
        host_res.risk_grade = "D"
    else:
        host_res.risk_grade = "F"

    host_res.issues = sorted(
        issues,
        key=lambda x: {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}.get(x["severity"], 4)
    )

    # OS Heuristic Detection if not set
    if not host_res.os_guess:
        host_res.os_guess = infer_os(host_res)


def infer_os(host_res: Any) -> str:
    """Infer Operating System based on open ports, banners, and vendor hints."""
    open_p_nums = {p.port for p in host_res.ports if p.state == "open"}

    # Vendor hints
    if host_res.vendor:
        v_low = host_res.vendor.lower()
        if "apple" in v_low:
            return "Apple macOS / iOS"
        if "raspberry" in v_low:
            return "Raspberry Pi OS (Linux)"
        if "espressif" in v_low:
            return "Espressif IoT Device (ESP32/ESP8266)"
        if "cisco" in v_low:
            return "Cisco IOS / Network Device"
        if "vmware" in v_low:
            return "VMware Virtual Machine"
        if "virtualbox" in v_low:
            return "VirtualBox VM"

    # Port combination heuristics
    if 135 in open_p_nums or 445 in open_p_nums or 3389 in open_p_nums:
        return "Microsoft Windows"

    if 22 in open_p_nums:
        for p in host_res.ports:
            if p.port == 22 and p.banner:
                b_low = p.banner.lower()
                if "ubuntu" in b_low:
                    return "Linux (Ubuntu)"
                if "debian" in b_low:
                    return "Linux (Debian)"
                if "centos" in b_low or "redhat" in b_low:
                    return "Linux (RHEL / CentOS)"
        return "Linux / Unix"

    if 554 in open_p_nums:
        return "Network Camera / RTSP Device"

    if open_p_nums:
        return "Generic Network Host"

    return "Unknown OS"
