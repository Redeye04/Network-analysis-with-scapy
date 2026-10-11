#!/usr/bin/env python3
"""Terminal report:  python tools/report.py capture.pcap [--json out.json]"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.analyzer import AnalysisError, analyze_file  # noqa: E402


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:,.0f} {unit}" if unit == "B" else f"{n:,.1f} {unit}"
        n /= 1024
    return f"{n:,.1f} TB"


def main() -> int:
    ap = argparse.ArgumentParser(description="Analyze a pcap and print a summary.")
    ap.add_argument("pcap")
    ap.add_argument("--json", help="also write the full analysis to this file")
    args = ap.parse_args()
    try:
        r = analyze_file(args.pcap)
    except AnalysisError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    s = r["summary"]
    print(f"{r['meta']['file']}: {s['packets']:,} packets, {human(s['bytes'])}, "
          f"{s['duration_seconds']:.1f}s, {s['unique_hosts']} hosts")
    print(f"Risk: {s['risk_level']} ({s['risk_score']}/100), {s['findings']} findings\n")
    print("Protocols:", ", ".join(f"{p['name']} {p['packets']}" for p in r["protocols"]))
    print("\nTop hosts by volume:")
    for h in r["hosts"][:8]:
        print(f"  {h['ip']:<18}{human(h['total_bytes']):>10}  {h['os_guess']}")
    print("\nFindings:")
    for f in r["security"]["findings"]:
        print(f"  [{f['severity'].upper():<8}] {f['title']}: {', '.join(f['hosts'])}")
    if args.json:
        Path(args.json).write_text(json.dumps(r, indent=2))
        print(f"\nFull analysis written to {args.json}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
