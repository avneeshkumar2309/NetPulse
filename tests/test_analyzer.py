"""
Tests for NetPulse security analyzer, vulnerability rules, and posture scoring.
"""

from netpulse.analyzer.risk_rules import evaluate_port_risk
from netpulse.analyzer.posture import evaluate_host_security, infer_os
from netpulse.engine.hybrid import HostResult, PortResult


def test_evaluate_port_risk():
    # Telnet should be Critical
    telnet_risk = evaluate_port_risk(23)
    assert telnet_risk["severity"] == "Critical"

    # SMB 445 should be High
    smb_risk = evaluate_port_risk(445)
    assert smb_risk["severity"] == "High"

    # HTTP 80 should be Low
    http_risk = evaluate_port_risk(80)
    assert http_risk["severity"] == "Low"


def test_banner_override_risk():
    # Redis with confirmed no auth should escalate to Critical
    redis_risk = evaluate_port_risk(6379, banner="Redis (EXPOSED: No Auth Required / Accessible!)")
    assert redis_risk["severity"] == "Critical"
    assert "CONFIRMED" in redis_risk["title"]


def test_host_security_posture_clean():
    # Host with only HTTPS 443 open
    host = HostResult(
        ip="192.168.1.50",
        ports=[PortResult(port=443, state="open", service="HTTPS", risk_level="Info")]
    )
    evaluate_host_security(host)
    assert host.risk_score >= 90
    assert host.risk_grade in ["A", "B"]


def test_host_security_posture_critical():
    # Host with Telnet (23) and Redis (6379)
    host = HostResult(
        ip="192.168.1.100",
        ports=[
            PortResult(port=23, state="open", service="Telnet"),
            PortResult(port=6379, state="open", service="Redis", banner="Redis (EXPOSED: No Auth Required / Accessible!)")
        ]
    )
    evaluate_host_security(host)
    assert host.risk_score <= 50
    assert host.risk_grade in ["D", "F"]
    assert len(host.issues) >= 2


def test_infer_os():
    # Windows
    win_host = HostResult(ip="10.0.0.5", ports=[PortResult(port=445, state="open")])
    assert infer_os(win_host) == "Microsoft Windows"

    # Linux Ubuntu
    linux_host = HostResult(
        ip="10.0.0.6",
        ports=[PortResult(port=22, state="open", banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")]
    )
    assert "Ubuntu" in infer_os(linux_host)
