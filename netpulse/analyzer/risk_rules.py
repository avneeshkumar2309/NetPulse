"""
Vulnerability & Security Risk Catalog for Network Ports and Services.
Provides structured severity rankings, vulnerability descriptions, and remediation guidance.
"""

from typing import Dict, Any, Optional

VULN_CATALOG: Dict[int, Dict[str, Any]] = {
    23: {
        "severity": "Critical",
        "title": "Unencrypted Telnet Service Exposed",
        "description": "Telnet transmits all communications including usernames and passwords in plaintext over the wire, vulnerable to interception and session hijacking.",
        "remediation": "Disable Telnet daemon immediately and migrate all remote management to SSH (Port 22) with key-based authentication."
    },
    2375: {
        "severity": "Critical",
        "title": "Unauthenticated Docker REST API Exposed",
        "description": "Exposing Docker daemon over TCP without TLS/mTLS allows any unauthenticated network actor to spawn root containers and gain full host compromise.",
        "remediation": "Disable TCP socket or bind to 127.0.0.1, or configure mutual TLS (mTLS) with client certificates on port 2376."
    },
    5555: {
        "severity": "Critical",
        "title": "Android Debug Bridge (ADB) Exposed Over Network",
        "description": "Port 5555 enables wireless ADB debugging. If left unsecured, attackers can gain an interactive shell and install malicious packages without physical access.",
        "remediation": "Disable TCP ADB ('adb usb') or restrict interface binding to trusted networks."
    },
    6379: {
        "severity": "Critical",
        "title": "Exposed Redis In-Memory Database",
        "description": "Redis instances default to binding without authentication. Exposed Redis servers are heavily targeted for cryptominers and SSH key injection.",
        "remediation": "Set strong 'requirepass' password in redis.conf, bind to 127.0.0.1, and enable Protected Mode."
    },
    27017: {
        "severity": "Critical",
        "title": "Exposed MongoDB Database",
        "description": "Exposed MongoDB instances without mandatory auth are frequently ransomed or leaked.",
        "remediation": "Enable authentication (--auth) and bind to localhost or a private VPC subnet."
    },
    9200: {
        "severity": "High",
        "title": "Elasticsearch REST API Exposed",
        "description": "Elasticsearch exposes document search and cluster metadata. Unsecured instances lead to broad data exfiltration.",
        "remediation": "Enable Elastic Security (X-Pack) with RBAC and TLS, or place behind a reverse proxy with authentication."
    },
    445: {
        "severity": "High",
        "title": "Exposed Server Message Block (SMB)",
        "description": "SMB is a prime vector for lateral movement, credential relay (NTLMv2), and exploits (EternalBlue MS17-010).",
        "remediation": "Block inbound port 445 from untrusted subnets. Enable SMB signing and mandate SMBv3."
    },
    139: {
        "severity": "High",
        "title": "NetBIOS Session Service Exposed",
        "description": "Legacy Windows file sharing protocol with high susceptibility to network enumeration and MITM attacks.",
        "remediation": "Disable NetBIOS over TCP/IP in adapter settings and use modern SMB."
    },
    3389: {
        "severity": "High",
        "title": "Remote Desktop Protocol (RDP) Exposed",
        "description": "RDP is aggressively targeted by automated ransomware bots for brute-force and credential stuffing.",
        "remediation": "Enforce Network Level Authentication (NLA), mandate multi-factor authentication (MFA), and place behind a VPN or gateway."
    },
    5900: {
        "severity": "High",
        "title": "Virtual Network Computing (VNC) Exposed",
        "description": "Standard VNC sessions lack encryption and often rely on weak passwords (DES max 8 chars).",
        "remediation": "Tunnel VNC sessions over SSH or SSH/TLS VPN. Never expose port 5900 directly to the LAN/WAN."
    },
    21: {
        "severity": "Medium",
        "title": "Cleartext FTP Service Running",
        "description": "Standard FTP transmits credentials and files in unencrypted plaintext.",
        "remediation": "Upgrade to SFTP (over SSH) or FTPS with explicit TLS."
    },
    161: {
        "severity": "Medium",
        "title": "SNMP Agent Running",
        "description": "SNMPv1 and SNMPv2c transmit community strings in cleartext and allow deep system reconnaissance.",
        "remediation": "Upgrade to SNMPv3 with encryption (USM/AES) or restrict access via access control lists (ACLs)."
    },
    80: {
        "severity": "Low",
        "title": "Plaintext HTTP Web Server",
        "description": "Web traffic is served without TLS encryption, susceptible to eavesdropping and session cookie tampering.",
        "remediation": "Configure automatic 301 redirect from HTTP to HTTPS (port 443) and enable HSTS."
    },
    22: {
        "severity": "Info",
        "title": "SSH Remote Administration Accessible",
        "description": "Secure remote shell protocol. Ensure hardened configuration.",
        "remediation": "Disable root login ('PermitRootLogin no') and disable password authentication ('PasswordAuthentication no')."
    }
}


def evaluate_port_risk(port: int, banner: Optional[str] = None) -> Dict[str, str]:
    """
    Evaluate risk level and recommendation for an open port and its extracted banner.
    """
    entry = VULN_CATALOG.get(port)
    if entry:
        risk_level = entry["severity"]
        title = entry["title"]
        rec = entry["remediation"]
    else:
        risk_level = "Info"
        title = "Open Service"
        rec = "Audit service to verify it is intended to be open and up-to-date."

    # Dynamic banner checks
    if banner:
        b_lower = banner.lower()
        if "no auth" in b_lower or "accessible" in b_lower:
            risk_level = "Critical"
            title = f"{title} (CONFIRMED UNPROTECTED)"
            rec = "IMMEDIATE ACTION REQUIRED: The service responded without requiring authentication."
        elif "expired" in b_lower:
            risk_level = "High"
            title = "Expired TLS Certificate Detected"
            rec = "Renew the SSL/TLS certificate to prevent browser warnings and MITM susceptibility."

    return {
        "severity": risk_level,
        "title": title,
        "remediation": rec
    }
