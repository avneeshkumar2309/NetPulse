"""
Tests for NetPulse engine and port parser.
"""

import pytest
import asyncio
from netpulse.engine.async_scanner import parse_ports, AsyncPortScanner, PORT_PROFILES


def test_parse_single_port():
    assert parse_ports(80) == [80]
    assert parse_ports("443") == [443]


def test_parse_port_list():
    assert parse_ports("80,443,8080") == [80, 443, 8080]
    # Check duplicate removal and sorting
    assert parse_ports("8080, 80, 443, 80") == [80, 443, 8080]


def test_parse_port_range():
    assert parse_ports("20-25") == [20, 21, 22, 23, 24, 25]


def test_parse_named_profiles():
    top20 = parse_ports("top-20")
    assert len(top20) == 20
    assert 80 in top20
    assert 443 in top20

    web = parse_ports("web")
    assert 80 in web
    assert 8080 in web


def test_parse_invalid_ports():
    with pytest.raises(ValueError):
        parse_ports("70000")
    with pytest.raises(ValueError):
        parse_ports("abc")


def test_async_scanner_mock_closed():
    scanner = AsyncPortScanner(timeout=0.2, max_concurrency=10)
    # Port 49999 is almost certainly closed or filtered on loopback
    res = asyncio.run(scanner.scan_single_port("127.0.0.1", 49999))
    assert res.port == 49999
    assert res.state in ["closed", "filtered"]
