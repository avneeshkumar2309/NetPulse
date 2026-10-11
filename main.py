#!/usr/bin/env python3
"""
NetPulse - Main entry point.
Run directly via:
    python main.py scan 127.0.0.1
    python main.py scan 192.168.1.0/24 --html
    python main.py watch 192.168.1.0/24
    python main.py oui 00:03:93:11:22:33
"""
import sys
from pathlib import Path

# Ensure package directory is in sys.path
root_dir = Path(__file__).parent.resolve()
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))

from netpulse.cli import main

if __name__ == "__main__":
    main()
