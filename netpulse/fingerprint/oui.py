"""
IEEE Organizationally Unique Identifier (OUI) MAC vendor resolution.
Maps MAC address hardware prefixes to device manufacturers.
"""

import re
from typing import Optional, Dict

# Embedded database of major network hardware & IoT manufacturers
OUI_DATABASE: Dict[str, str] = {
    # Apple
    "00:03:93": "Apple, Inc.",
    "00:05:02": "Apple, Inc.",
    "00:0a:27": "Apple, Inc.",
    "00:0a:95": "Apple, Inc.",
    "00:0d:93": "Apple, Inc.",
    "00:11:24": "Apple, Inc.",
    "00:14:51": "Apple, Inc.",
    "00:16:cb": "Apple, Inc.",
    "00:17:f2": "Apple, Inc.",
    "00:19:e3": "Apple, Inc.",
    "00:1b:63": "Apple, Inc.",
    "00:1c:b3": "Apple, Inc.",
    "00:1d:4f": "Apple, Inc.",
    "00:1e:52": "Apple, Inc.",
    "00:1f:5b": "Apple, Inc.",
    "00:1f:f3": "Apple, Inc.",
    "00:21:e9": "Apple, Inc.",
    "00:22:41": "Apple, Inc.",
    "00:23:12": "Apple, Inc.",
    "00:24:36": "Apple, Inc.",
    "00:25:00": "Apple, Inc.",
    "00:25:bc": "Apple, Inc.",
    "00:26:08": "Apple, Inc.",
    "00:26:b0": "Apple, Inc.",
    "00:88:65": "Apple, Inc.",
    "18:af:61": "Apple, Inc.",
    "3c:07:54": "Apple, Inc.",
    "40:6c:8f": "Apple, Inc.",
    "60:f8:1d": "Apple, Inc.",
    "70:3e:ac": "Apple, Inc.",
    "88:66:a5": "Apple, Inc.",
    "ac:bc:32": "Apple, Inc.",
    "bc:d0:74": "Apple, Inc.",
    "f0:18:98": "Apple, Inc.",

    # Raspberry Pi Foundation
    "b8:27:eb": "Raspberry Pi Foundation",
    "dc:a6:32": "Raspberry Pi Trading Ltd",
    "e4:5f:01": "Raspberry Pi Trading Ltd",
    "28:cd:c1": "Raspberry Pi Trading Ltd",
    "d8:3a:dd": "Raspberry Pi Trading Ltd",

    # Espressif (ESP8266, ESP32 IoT microcontrollers)
    "18:fe:34": "Espressif Inc.",
    "24:0a:c4": "Espressif Inc.",
    "24:62:ab": "Espressif Inc.",
    "24:6f:28": "Espressif Inc.",
    "24:b2:de": "Espressif Inc.",
    "2c:3a:e8": "Espressif Inc.",
    "30:ae:a4": "Espressif Inc.",
    "3c:61:05": "Espressif Inc.",
    "3c:71:bf": "Espressif Inc.",
    "40:22:d8": "Espressif Inc.",
    "40:f5:20": "Espressif Inc.",
    "44:17:93": "Espressif Inc.",
    "48:27:e2": "Espressif Inc.",
    "4c:75:25": "Espressif Inc.",
    "54:43:b2": "Espressif Inc.",
    "5c:cf:7f": "Espressif Inc.",
    "60:01:94": "Espressif Inc.",
    "68:c6:3a": "Espressif Inc.",
    "80:7d:3a": "Espressif Inc.",
    "84:0d:8e": "Espressif Inc.",
    "84:f3:eb": "Espressif Inc.",
    "a0:20:a6": "Espressif Inc.",
    "ac:d0:74": "Espressif Inc.",
    "b4:e6:2d": "Espressif Inc.",
    "bc:dd:c2": "Espressif Inc.",
    "c4:4f:33": "Espressif Inc.",
    "cc:50:e3": "Espressif Inc.",

    # Intel
    "00:02:b3": "Intel Corporate",
    "00:03:47": "Intel Corporate",
    "00:04:23": "Intel Corporate",
    "00:0e:0c": "Intel Corporate",
    "00:13:02": "Intel Corporate",
    "00:13:e8": "Intel Corporate",
    "00:15:00": "Intel Corporate",
    "00:16:76": "Intel Corporate",
    "00:18:de": "Intel Corporate",
    "00:1b:21": "Intel Corporate",
    "00:1e:64": "Intel Corporate",
    "00:21:6a": "Intel Corporate",
    "00:22:fb": "Intel Corporate",
    "00:24:d7": "Intel Corporate",
    "28:b2:bd": "Intel Corporate",
    "34:13:e8": "Intel Corporate",
    "48:51:b7": "Intel Corporate",
    "70:cd:60": "Intel Corporate",
    "80:86:f2": "Intel Corporate",
    "a4:4c:c8": "Intel Corporate",

    # Dell
    "00:06:5b": "Dell Inc.",
    "00:08:74": "Dell Inc.",
    "00:0b:db": "Dell Inc.",
    "00:0d:56": "Dell Inc.",
    "00:11:43": "Dell Inc.",
    "00:12:3f": "Dell Inc.",
    "00:13:72": "Dell Inc.",
    "00:14:22": "Dell Inc.",
    "00:16:f0": "Dell Inc.",
    "00:18:8b": "Dell Inc.",
    "00:1a:a0": "Dell Inc.",
    "18:66:da": "Dell Inc.",
    "24:b6:fd": "Dell Inc.",
    "34:17:eb": "Dell Inc.",
    "84:7b:eb": "Dell Inc.",
    "b8:ac:6f": "Dell Inc.",
    "d4:be:d9": "Dell Inc.",
    "ec:f4:bb": "Dell Inc.",

    # Cisco Systems
    "00:00:0c": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:01:43": "Cisco Systems",
    "00:01:63": "Cisco Systems",
    "00:01:64": "Cisco Systems",
    "00:01:96": "Cisco Systems",
    "00:01:97": "Cisco Systems",
    "00:02:16": "Cisco Systems",
    "00:02:17": "Cisco Systems",
    "00:02:4a": "Cisco Systems",
    "00:02:4b": "Cisco Systems",
    "00:05:31": "Cisco Systems",
    "00:07:0d": "Cisco Systems",
    "00:08:e3": "Cisco Systems",
    "00:0c:85": "Cisco Systems",

    # TP-Link
    "00:1d:0f": "TP-Link Technologies",
    "14:cc:20": "TP-Link Technologies",
    "1c:3b:f3": "TP-Link Technologies",
    "30:b5:c2": "TP-Link Technologies",
    "50:c7:bf": "TP-Link Technologies",
    "60:32:b1": "TP-Link Technologies",
    "60:e3:27": "TP-Link Technologies",
    "70:4f:57": "TP-Link Technologies",
    "98:48:27": "TP-Link Technologies",
    "ac:84:c6": "TP-Link Technologies",
    "c0:25:e9": "TP-Link Technologies",
    "ec:08:6b": "TP-Link Technologies",
    "ec:17:2f": "TP-Link Technologies",

    # Samsung
    "00:00:f0": "Samsung Electronics",
    "00:02:78": "Samsung Electronics",
    "00:07:ab": "Samsung Electronics",
    "00:0d:ae": "Samsung Electronics",
    "00:12:47": "Samsung Electronics",
    "00:15:99": "Samsung Electronics",
    "00:16:32": "Samsung Electronics",
    "00:17:c9": "Samsung Electronics",
    "00:18:af": "Samsung Electronics",
    "00:1a:8a": "Samsung Electronics",
    "00:1e:7d": "Samsung Electronics",
    "08:08:c2": "Samsung Electronics",
    "14:bb:6e": "Samsung Electronics",
    "34:23:87": "Samsung Electronics",
    "50:01:d9": "Samsung Electronics",
    "84:25:19": "Samsung Electronics",
    "a8:7c:01": "Samsung Electronics",
    "cc:07:ab": "Samsung Electronics",

    # Google / Nest
    "00:1a:11": "Google, Inc.",
    "18:d6:c7": "Google, Inc.",
    "20:df:b9": "Google, Inc.",
    "3c:5a:37": "Google, Inc.",
    "54:60:09": "Google, Inc.",
    "64:16:66": "Google, Inc.",
    "a4:77:33": "Google, Inc.",
    "d8:6c:63": "Google, Inc.",
    "f4:03:04": "Google, Inc.",
    "f8:8f:ca": "Google, Inc.",

    # Amazon
    "00:fc:8b": "Amazon Technologies Inc.",
    "18:74:2e": "Amazon Technologies Inc.",
    "38:f7:3d": "Amazon Technologies Inc.",
    "40:b4:cd": "Amazon Technologies Inc.",
    "44:65:0d": "Amazon Technologies Inc.",
    "50:dc:e7": "Amazon Technologies Inc.",
    "68:37:e9": "Amazon Technologies Inc.",
    "68:54:fd": "Amazon Technologies Inc.",
    "74:c2:46": "Amazon Technologies Inc.",
    "88:71:e5": "Amazon Technologies Inc.",
    "ac:63:be": "Amazon Technologies Inc.",
    "fc:a6:67": "Amazon Technologies Inc.",

    # Microsoft
    "00:03:ff": "Microsoft Corporation",
    "00:0d:3a": "Microsoft Corporation",
    "00:12:5a": "Microsoft Corporation",
    "00:15:5d": "Microsoft Corporation (Hyper-V)",
    "00:17:fa": "Microsoft Corporation",
    "00:1d:d8": "Microsoft Corporation",
    "28:18:78": "Microsoft Corporation",
    "7c:ed:8d": "Microsoft Corporation",
    "dc:98:40": "Microsoft Corporation",

    # VMware & Virtualization
    "00:05:69": "VMware, Inc.",
    "00:0c:29": "VMware, Inc.",
    "00:1c:14": "VMware, Inc.",
    "00:50:56": "VMware, Inc.",
    "08:00:27": "Oracle VirtualBox",
    "52:54:00": "QEMU / KVM Virtual Machine",

    # Netgear
    "00:09:5b": "Netgear",
    "00:0f:b5": "Netgear",
    "00:14:6c": "Netgear",
    "00:18:4d": "Netgear",
    "00:1e:2a": "Netgear",
    "20:4e:7f": "Netgear",
    "2c:30:33": "Netgear",
    "84:1b:5e": "Netgear",
    "a0:40:a0": "Netgear",

    # ASUS
    "00:0c:6e": "ASUSTek Computer Inc.",
    "00:11:d8": "ASUSTek Computer Inc.",
    "00:15:f2": "ASUSTek Computer Inc.",
    "00:18:f3": "ASUSTek Computer Inc.",
    "00:1e:8c": "ASUSTek Computer Inc.",
    "04:d9:f5": "ASUSTek Computer Inc.",
    "1c:87:2c": "ASUSTek Computer Inc.",
    "2c:fd:a1": "ASUSTek Computer Inc.",
    "70:4d:7b": "ASUSTek Computer Inc.",

    # Ubiquiti
    "00:27:22": "Ubiquiti Networks",
    "04:18:d6": "Ubiquiti Networks",
    "24:a4:3c": "Ubiquiti Networks",
    "68:d7:9a": "Ubiquiti Networks",
    "78:8a:20": "Ubiquiti Networks",
    "80:2a:a8": "Ubiquiti Networks",
    "b4:fb:e4": "Ubiquiti Networks",
    "dc:9f:db": "Ubiquiti Networks",
    "e0:63:da": "Ubiquiti Networks",
    "f0:9f:c2": "Ubiquiti Networks",

    # Realtek & Network chips
    "00:e0:4c": "Realtek Semiconductor",
    "52:54:4c": "Realtek Semiconductor",
    "70:85:c2": "Realtek Semiconductor",
}


def normalize_mac(mac: str) -> Optional[str]:
    """Normalize MAC address into standard lowercase colon-delimited format."""
    cleaned = re.sub(r"[^a-fA-F0-9]", "", mac.lower())
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i:i+2] for i in range(0, 12, 2))


def lookup_mac_vendor(mac: str) -> Optional[str]:
    """
    Look up the vendor / manufacturer for a given MAC address.
    """
    normalized = normalize_mac(mac)
    if not normalized:
        return None

    # Check 3-byte prefix (OUI)
    prefix_24 = normalized[:8]
    if prefix_24 in OUI_DATABASE:
        return OUI_DATABASE[prefix_24]

    # Heuristic for randomized/private MAC addresses
    # If bit 1 of the first octet is 1 (e.g. x2, x6, xA, xE), it is locally administered / randomized
    first_octet = int(normalized[:2], 16)
    if first_octet & 0x02:
        return "Locally Administered / Randomized MAC (iOS/Android Private Wi-Fi)"

    return "Unknown Vendor"
