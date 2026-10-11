"""
Raw packet engine using Scapy for Layer-2 ARP sweeps, ICMP burst pings, and SYN stealth scans.
Gracefully detects if elevated permissions or Scapy are unavailable.
"""

import sys
import logging
from typing import List, Dict, Optional, Tuple

logger = logging.getLogger("netpulse.raw_scanner")

SCAPY_AVAILABLE = False
try:
    from scapy.all import Ether, ARP, IP, ICMP, TCP, srp, sr1, send, conf
    # Suppress scapy runtime warnings
    conf.verb = 0
    SCAPY_AVAILABLE = True
except (ImportError, Exception):
    SCAPY_AVAILABLE = False


class RawEngineUnavailableError(Exception):
    """Raised when Scapy or root/administrator privileges are unavailable."""
    pass


class RawScanner:
    """
    Elevated raw packet crafting scanner.
    """

    def __init__(self, timeout: float = 2.0):
        self.timeout = timeout
        self.available = SCAPY_AVAILABLE

    @staticmethod
    def is_elevated() -> bool:
        """Check if current process has root/admin privileges."""
        try:
            if sys.platform == "win32":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                import os
                return os.geteuid() == 0
        except Exception:
            return False

    def arp_scan(self, network: str) -> List[Dict[str, str]]:
        """
        Perform an ARP sweep across a local subnet to discover MAC and IP addresses.
        """
        if not SCAPY_AVAILABLE:
            raise RawEngineUnavailableError("Scapy is not installed. Install via 'pip install scapy'.")

        try:
            # Craft ARP broadcast
            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            ans, _ = srp(packet, timeout=self.timeout, verbose=False)
            clients: List[Dict[str, str]] = []
            for sent, received in ans:
                clients.append({
                    "ip": received.psrc,
                    "mac": received.hwsrc.lower()
                })
            return clients
        except PermissionError:
            raise RawEngineUnavailableError("Root/Administrator permissions required for raw ARP scanning.")
        except Exception as e:
            logger.error(f"ARP scan error: {e}")
            raise RawEngineUnavailableError(f"ARP scan failed: {e}")

    def icmp_ping(self, target: str) -> bool:
        """
        Send raw ICMP echo request packet.
        """
        if not SCAPY_AVAILABLE:
            raise RawEngineUnavailableError("Scapy is not installed.")

        try:
            pkt = IP(dst=target) / ICMP()
            resp = sr1(pkt, timeout=self.timeout, verbose=False)
            return resp is not None
        except Exception as e:
            logger.debug(f"ICMP ping error on {target}: {e}")
            return False

    def syn_scan(self, target: str, ports: List[int]) -> Dict[int, str]:
        """
        Stealth TCP SYN port scan using Scapy.
        """
        if not SCAPY_AVAILABLE:
            raise RawEngineUnavailableError("Scapy is not installed.")

        results: Dict[int, str] = {}
        for port in ports:
            try:
                pkt = IP(dst=target) / TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=self.timeout, verbose=False)
                if resp is None:
                    results[port] = "filtered"
                elif resp.haslayer(TCP):
                    flags = resp.getlayer(TCP).flags
                    if flags == 0x12:  # SYN-ACK -> open
                        results[port] = "open"
                        # Send RST to tear down connection cleanly without handshake completion
                        rst = IP(dst=target) / TCP(dport=port, flags="R")
                        send(rst, verbose=False)
                    elif flags == 0x14:  # RST-ACK -> closed
                        results[port] = "closed"
                    else:
                        results[port] = "filtered"
                else:
                    results[port] = "filtered"
            except Exception as e:
                logger.debug(f"SYN scan error on port {port}: {e}")
                results[port] = "error"

        return results
