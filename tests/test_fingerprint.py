"""
Tests for NetPulse fingerprinting: OUI lookup and normalization.
"""

from netpulse.fingerprint.oui import lookup_mac_vendor, normalize_mac


def test_normalize_mac():
    assert normalize_mac("00:03:93:aa:bb:cc") == "00:03:93:aa:bb:cc"
    assert normalize_mac("00-03-93-AA-BB-CC") == "00:03:93:aa:bb:cc"
    assert normalize_mac("000393aabbcc") == "00:03:93:aa:bb:cc"
    assert normalize_mac("invalid_mac") is None


def test_oui_vendor_lookup():
    # Apple
    assert "Apple" in lookup_mac_vendor("00:03:93:11:22:33")
    # Raspberry Pi
    assert "Raspberry Pi" in lookup_mac_vendor("b8:27:eb:12:34:56")
    # Espressif
    assert "Espressif" in lookup_mac_vendor("24:6f:28:aa:bb:cc")
    # Intel
    assert "Intel" in lookup_mac_vendor("00:02:b3:00:11:22")


def test_randomized_mac_detection():
    # Locally administered bit set: first byte e.g. 02, 06, 0A, 0E, etc.
    res = lookup_mac_vendor("da:a1:19:11:22:33")
    assert "Randomized MAC" in res or "Locally Administered" in res
