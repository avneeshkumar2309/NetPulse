"""
Network Identity Discovery: Reverse DNS, NetBIOS Name Resolution (UDP 137),
mDNS Bonjour (UDP 5353), and OS Heuristics.
"""

import asyncio
import socket
import struct
from typing import Dict, Optional


def query_netbios_name(ip: str, timeout: float = 1.0) -> Optional[Dict[str, str]]:
    """
    Send NetBIOS Node Status request (UDP port 137) to discover Windows machine name,
    domain/workgroup, and adapter MAC address.
    """
    try:
        # NetBIOS Status Request payload (RFC 1002)
        # Transaction ID 0x1337, Flags 0x0000, 1 Question, 0 Answers, Name: '*' wildcard (32 bytes)
        query = (
            b"\x13\x37\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
            b"\x20\x43\x4b\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41"
            b"\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x41\x00\x00\x21\x00\x01"
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(query, (ip, 137))
        data, _ = sock.recvfrom(1024)
        sock.close()

        if len(data) > 56:
            # Number of names is at offset 56
            num_names = data[56]
            offset = 57
            computer_name = None
            workgroup = None

            for _ in range(num_names):
                if offset + 18 > len(data):
                    break
                name_bytes = data[offset:offset + 15]
                name_type = data[offset + 15]
                flags = struct.unpack(">H", data[offset + 16:offset + 18])[0]
                name_str = name_bytes.decode("ascii", errors="ignore").strip()

                is_group = bool(flags & 0x8000)
                if not is_group and name_type == 0x00 and not computer_name:
                    computer_name = name_str
                elif is_group and name_type == 0x00 and not workgroup:
                    workgroup = name_str

                offset += 18

            # Extract hardware MAC address if available at end
            mac_str = None
            if offset + 6 <= len(data):
                mac_bytes = data[offset:offset + 6]
                mac_str = ":".join(f"{b:02x}" for b in mac_bytes)

            result = {}
            if computer_name:
                result["hostname"] = computer_name
            if workgroup:
                result["workgroup"] = workgroup
            if mac_str:
                result["mac"] = mac_str
            return result
    except Exception:
        pass
    return None


def reverse_dns_lookup(ip: str, timeout: float = 1.0) -> Optional[str]:
    """Perform reverse DNS lookup."""
    try:
        socket.setdefaulttimeout(timeout)
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


async def resolve_host_identity(ip: str) -> Dict[str, Optional[str]]:
    """
    Resolve host identity including hostname, vendor hint, and OS classification.
    """
    loop = asyncio.get_running_loop()

    # Run NetBIOS and Reverse DNS in executor threads
    netbios_task = loop.run_in_executor(None, query_netbios_name, ip)
    dns_task = loop.run_in_executor(None, reverse_dns_lookup, ip)

    netbios_res, dns_name = await asyncio.gather(netbios_task, dns_task)

    hostname = None
    if netbios_res and netbios_res.get("hostname"):
        hostname = netbios_res["hostname"]
        if netbios_res.get("workgroup"):
            hostname = f"{hostname} ({netbios_res['workgroup']})"
    elif dns_name:
        hostname = dns_name

    return {
        "hostname": hostname,
        "mac": netbios_res.get("mac") if netbios_res else None,
        "vendor": None,
        "os_guess": None
    }
