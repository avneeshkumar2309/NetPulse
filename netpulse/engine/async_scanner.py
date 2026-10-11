"""
High-speed asynchronous network scanner using native asyncio sockets.
Capable of scanning thousands of ports per second without requiring elevated root/admin privileges.
"""

import asyncio
import ipaddress
import socket
import time
from typing import List, Dict, Optional, Callable, Set, Union
from dataclasses import dataclass, field

# Common well-known port profiles
PORT_PROFILES = {
    "top-20": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 8080, 8443],
    "top-100": [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 119, 123, 135, 137, 138, 139, 143,
        161, 162, 179, 389, 443, 445, 465, 514, 515, 587, 636, 873, 990, 993, 995, 1080, 1194,
        1433, 1434, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087, 2181, 2222, 2375, 2376, 3000,
        3128, 3306, 3389, 4369, 5000, 5432, 5672, 5900, 5901, 5984, 6379, 7001, 8000, 8008, 8080,
        8081, 8088, 8443, 8888, 9000, 9090, 9092, 9200, 9300, 11211, 27017, 27018, 50000, 50070
    ],
    "web": [80, 443, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9443],
    "databases": [1433, 1521, 3306, 5432, 5984, 6379, 9200, 9300, 11211, 27017, 27018],
    "remote": [22, 23, 3389, 5900, 5901, 5985, 5986],
    "iot": [80, 554, 1883, 1900, 5000, 5353, 8080, 8883, 49152],
}


def parse_ports(ports_input: Union[str, int, List[int]]) -> List[int]:
    """
    Parse ports from string, integer, or profile name into a sorted list of unique ints.
    Examples:
        - "80,443,8080"
        - "1-1024"
        - "top-20" or "top-100" or "web"
        - 80
    """
    if isinstance(ports_input, int):
        return [ports_input]
    if isinstance(ports_input, list):
        return sorted(list(set(ports_input)))

    ports_str = str(ports_input).strip().lower()
    if ports_str in PORT_PROFILES:
        return sorted(PORT_PROFILES[ports_str])

    ports: Set[int] = set()
    for part in ports_str.split(','):
        part = part.strip()
        if not part:
            continue
        if part in PORT_PROFILES:
            ports.update(PORT_PROFILES[part])
            continue
        if '-' in part:
            s_str, e_str = part.split('-', 1)
            start, end = int(s_str.strip()), int(e_str.strip())
            if not (0 <= start <= 65535 and 0 <= end <= 65535):
                raise ValueError(f"Port range out of bounds [0-65535]: {part}")
            if start > end:
                start, end = end, start
            ports.update(range(start, end + 1))
        else:
            p = int(part)
            if not (0 <= p <= 65535):
                raise ValueError(f"Port out of bounds [0-65535]: {p}")
            ports.add(p)

    return sorted(list(ports))


@dataclass
class AsyncPortResult:
    port: int
    state: str  # "open", "closed", "filtered"
    latency_ms: Optional[float] = None
    service_guess: str = "unknown"
    banner: Optional[str] = None
    extra_info: Dict[str, str] = field(default_factory=dict)


class AsyncPortScanner:
    """
    Blazing fast asynchronous port scanner using asyncio.
    """

    def __init__(self, timeout: float = 1.0, max_concurrency: int = 500):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def scan_single_port(self, ip: str, port: int) -> AsyncPortResult:
        """Scan a single TCP port on an IP asynchronously."""
        async with self.semaphore:
            start_time = time.perf_counter()
            try:
                # Use loop.create_connection with timeout
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                latency = round((time.perf_counter() - start_time) * 1000, 2)

                # Attempt immediate light banner grab if open
                banner = None
                try:
                    # Give service 300ms to send welcome banner
                    line = await asyncio.wait_for(reader.read(512), timeout=0.3)
                    if line:
                        banner = line.decode('utf-8', errors='ignore').strip()
                except Exception:
                    pass
                finally:
                    writer.close()
                    try:
                        await writer.wait_closed()
                    except Exception:
                        pass

                return AsyncPortResult(
                    port=port,
                    state="open",
                    latency_ms=latency,
                    service_guess=self._guess_service(port),
                    banner=banner
                )
            except asyncio.TimeoutError:
                return AsyncPortResult(port=port, state="filtered", service_guess=self._guess_service(port))
            except (ConnectionRefusedError, OSError):
                return AsyncPortResult(port=port, state="closed", service_guess=self._guess_service(port))
            except Exception:
                return AsyncPortResult(port=port, state="error", service_guess=self._guess_service(port))

    async def scan_ports(
        self,
        ip: str,
        ports: List[int],
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[AsyncPortResult]:
        """
        Scan a list of ports on target IP with concurrent workers.
        """
        total = len(ports)
        completed = 0
        results: List[AsyncPortResult] = []

        async def worker(port: int):
            nonlocal completed
            res = await self.scan_single_port(ip, port)
            completed += 1
            if progress_callback:
                progress_callback(completed, total)
            return res

        tasks = [asyncio.create_task(worker(p)) for p in ports]
        results = await asyncio.gather(*tasks)
        return sorted(results, key=lambda x: x.port)

    @staticmethod
    def _guess_service(port: int) -> str:
        services = {
            20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 67: "DHCP", 68: "DHCP", 69: "TFTP", 80: "HTTP",
            88: "Kerberos", 110: "POP3", 111: "RPCBind", 123: "NTP",
            135: "MS-RPC", 137: "NetBIOS-NS", 138: "NetBIOS-DGM", 139: "NetBIOS-SSN",
            143: "IMAP", 161: "SNMP", 162: "SNMP-Trap", 389: "LDAP",
            443: "HTTPS", 445: "SMB", 465: "SMTPS", 514: "Syslog",
            587: "SMTP-Submission", 636: "LDAPS", 993: "IMAPS", 995: "POP3S",
            1433: "MSSQL", 1521: "Oracle", 1883: "MQTT", 2049: "NFS",
            3000: "Node/React-Dev", 3306: "MySQL", 3389: "RDP", 5000: "UPnP/Flask",
            5432: "PostgreSQL", 5672: "RabbitMQ", 5900: "VNC", 6379: "Redis",
            8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
            9092: "Kafka", 9200: "Elasticsearch", 11211: "Memcached", 27017: "MongoDB"
        }
        return services.get(port, "unknown")


class AsyncSubnetScanner:
    """
    Sweeps a subnet asynchronously to discover live hosts via TCP probing.
    """

    DISCOVERY_PORTS = [80, 443, 22, 445, 135, 8080, 53, 3389]

    def __init__(self, timeout: float = 0.8, max_concurrency: int = 300):
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def is_host_alive(self, ip: str) -> bool:
        """
        Check if host is alive by attempting quick connections on common discovery ports.
        """
        for port in self.DISCOVERY_PORTS:
            try:
                conn = asyncio.open_connection(ip, port)
                reader, writer = await asyncio.wait_for(conn, timeout=self.timeout)
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except (ConnectionRefusedError, OSError):
                # An immediate ConnectionRefused error PROVES the host is alive and responding with RST!
                return True
            except asyncio.TimeoutError:
                continue
            except Exception:
                continue
        return False

    async def sweep_subnet(
        self,
        cidr: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> List[str]:
        """
        Sweep all IP addresses in a CIDR block and return live IPs.
        """
        try:
            net = ipaddress.ip_network(cidr, strict=False)
            hosts = [str(ip) for ip in net.hosts()]
        except ValueError as e:
            raise ValueError(f"Invalid CIDR network: {cidr} ({e})")

        total = len(hosts)
        completed = 0
        live_hosts: List[str] = []

        async def check(ip_str: str):
            nonlocal completed
            async with self.semaphore:
                alive = await self.is_host_alive(ip_str)
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)
                if alive:
                    live_hosts.append(ip_str)

        tasks = [asyncio.create_task(check(h)) for h in hosts]
        await asyncio.gather(*tasks)
        return sorted(live_hosts, key=lambda x: ipaddress.ip_address(x))
