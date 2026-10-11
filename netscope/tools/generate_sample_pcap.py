#!/usr/bin/env python3
"""Generate the NetScope demo capture.  Usage: python tools/generate_sample_pcap.py [out.pcap]"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.sample_data import generate  # noqa: E402

if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "data" / "network_traffic.pcap"
    print(f"Wrote {generate(out)} ({out.stat().st_size:,} bytes)")
