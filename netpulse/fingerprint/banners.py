"""
Protocol & Service Banner Inspector.
Extracts deep service fingerprints, HTTP headers, HTML titles, TLS certificates,
SSH versions, Redis status, and MySQL handshakes asynchronously.
"""

import asyncio
import re
import socket
import ssl
from typing import Optional, Dict


async def grab_raw_banner(ip: str, port: int, payload: bytes = b"", timeout: float = 1.2) -> Optional[str]:
    """Connect to a socket, optionally send a probe, and read the banner."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout
        )
        if payload:
            writer.write(payload)
            await writer.drain()

        data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if data:
            return data.decode("utf-8", errors="ignore").strip()
    except Exception:
        pass
    return None


async def inspect_http(ip: str, port: int, use_tls: bool = False, timeout: float = 1.5) -> Optional[str]:
    """Inspect HTTP/HTTPS endpoint to extract Server, Title, and status."""
    try:
        ssl_ctx = None
        if use_tls:
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ssl_ctx),
            timeout=timeout
        )

        req = f"GET / HTTP/1.1\r\nHost: {ip}:{port}\r\nUser-Agent: NetPulse/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        writer.write(req.encode())
        await writer.drain()

        raw_resp = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if not raw_resp:
            return None

        text = raw_resp.decode("utf-8", errors="ignore")
        headers_end = text.find("\r\n\r\n")
        header_part = text[:headers_end] if headers_end != -1 else text
        body_part = text[headers_end:] if headers_end != -1 else ""

        server = None
        m_server = re.search(r"server:\s*([^\r\n]+)", header_part, re.IGNORECASE)
        if m_server:
            server = m_server.group(1).strip()

        title = None
        m_title = re.search(r"<title[^>]*>([^<]+)</title>", body_part, re.IGNORECASE)
        if m_title:
            title = m_title.group(1).strip()

        first_line = header_part.splitlines()[0] if header_part.splitlines() else "HTTP Response"

        parts = []
        if server:
            parts.append(f"Server: {server}")
        if title:
            parts.append(f"Title: \"{title}\"")
        if not parts:
            parts.append(first_line)

        prefix = "HTTPS" if use_tls else "HTTP"
        return f"{prefix} [{', '.join(parts)}]"
    except Exception:
        return None


async def inspect_tls_cert(ip: str, port: int, timeout: float = 1.5) -> Optional[str]:
    """Inspect SSL/TLS certificate details."""
    loop = asyncio.get_running_loop()

    def sync_get_cert() -> Optional[str]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((ip, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        subject = dict(x[0] for x in cert.get("subject", []))
                        cn = subject.get("commonName", "Unknown CN")
                        expire = cert.get("notAfter", "")
                        return f"TLS Cert: CN={cn} (Expires {expire})"
                    # If binary form only (self-signed unverified)
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        return "TLS Enabled (Self-Signed / Untrusted Certificate)"
        except Exception:
            pass
        return None

    return await loop.run_in_executor(None, sync_get_cert)


async def inspect_redis(ip: str, port: int) -> Optional[str]:
    """Check Redis server banner and whether authentication is required."""
    res = await grab_raw_banner(ip, port, payload=b"PING\r\n")
    if res:
        if "+PONG" in res:
            return "Redis (EXPOSED: No Auth Required / Accessible!)"
        elif "NOAUTH" in res:
            return "Redis (Protected: Authentication Required)"
        return f"Redis: {res}"
    return None


async def inspect_mysql(ip: str, port: int) -> Optional[str]:
    """Extract MySQL server version from handshake packet."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.2)
        data = await asyncio.wait_for(reader.read(256), timeout=1.2)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        if len(data) > 5:
            # MySQL packet protocol: 1 byte protocol version, then null-terminated version string
            proto_ver = data[4]
            version_str = data[5:].split(b"\x00")[0].decode("ascii", errors="ignore")
            if version_str:
                return f"MySQL Protocol {proto_ver} (Version: {version_str})"
    except Exception:
        pass
    return None


async def inspect_service_banner(ip: str, port: int, initial_banner: Optional[str] = None) -> Optional[str]:
    """
    Intelligently inspect and fingerprint the service running on an open port.
    """
    # 1. Web Ports
    if port in [80, 8080, 8000, 8008, 8888, 3000, 5000, 9000, 9090]:
        res = await inspect_http(ip, port, use_tls=False)
        if res:
            return res

    if port in [443, 8443, 9443]:
        res = await inspect_http(ip, port, use_tls=True)
        if res:
            cert = await inspect_tls_cert(ip, port)
            return f"{res} | {cert}" if cert else res

    # 2. Redis
    if port == 6379:
        res = await inspect_redis(ip, port)
        if res:
            return res

    # 3. MySQL
    if port == 3306:
        res = await inspect_mysql(ip, port)
        if res:
            return res

    # 4. Standard welcome banners (SSH, FTP, SMTP)
    if initial_banner:
        clean = " ".join(initial_banner.splitlines())
        if len(clean) > 80:
            clean = clean[:77] + "..."
        return clean

    # 5. Fallback probe for generic text banners
    probe_banner = await grab_raw_banner(ip, port, payload=b"\r\n\r\n")
    if probe_banner:
        clean = " ".join(probe_banner.splitlines())
        if len(clean) > 80:
            clean = clean[:77] + "..."
        return clean

    return None
