# NetScope

A Flask dashboard that turns a packet capture (`.pcap` / `.pcapng`) into something you can read: protocol mix, traffic over time, busiest hosts, DNS and web activity, security findings, and a **network map that shows packet routes between devices**.

It grew out of a 50-line script that counted TCP/UDP/ARP packets and the top 10 IP pairs. That endpoint still exists (`/api/network-data`) and still returns the same keys.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python run.py            # http://127.0.0.1:5000
```

On first start, if `data/` has no captures, a synthetic demo capture (`network_traffic.pcap`) is generated so there is something to explore straight away. Put your own captures in `data/`, or upload them in the UI (button or drag-and-drop).

```bash
python -m pytest                                  # 40 tests
python tools/report.py data/network_traffic.pcap  # terminal summary (+ --json out.json)
python tools/generate_sample_pcap.py out.pcap     # regenerate the demo capture
docker build -t netscope . && docker run -p 5000:5000 -v "$PWD/data:/data" netscope
```

## What you get

| Tab | Contents |
| --- | --- |
| Overview | KPIs, protocol and application mix, TCP flags, traffic over time (packets or bits/s), busiest hosts, top server ports, packet-size histogram, top communications |
| Network map | Numbered device nodes, lines for conversations, animated dots for packets travelling in each direction, click-to-isolate routes, "Copy graph JSON" |
| Hosts | Scope (private/public), OS guess from TTL, MAC addresses, services offered, volumes, per-host drill-down with its conversations and findings |
| Conversations | Bidirectional flows with per-direction bytes and duration |
| DNS | Query volume, top names, query types, response codes, resolved addresses, suspicious domains |
| Web & TLS | Plain HTTP requests (query strings stripped), user agents, status codes, TLS server names from the ClientHello SNI |
| Security | Risk score, findings with evidence, ARP table with conflicts, cleartext services, ICMP types |

### The network map

Nodes are devices, numbered by traffic volume. The graph data has the same shape common graph components use, and **Copy graph JSON** exports it:

```json
{
  "nodes": [{ "label": 0, "center": { "x": 125.7, "y": 212.1 } }],
  "edges": [{ "source": 0, "target": 2 }]
}
```

Positions come from a Fruchterman–Reingold layout (`layoutGraph` in `app/static/js/app.js`) that runs to completion, so the picture is stable. Line width scales with packet count, dot colour with protocol (TCP, UDP, ICMP, ARP), and a red ring marks devices named in a security finding. To plug in a different renderer, feed it the output of `buildMapModel()`.

## Detections

All are heuristics. They point at traffic worth a closer look and are not proof of compromise. Thresholds live in `app/analyzer/detections.py` (`DEFAULT_THRESHOLDS`) and can be overridden with `Config.THRESHOLDS`.

| Finding | Trigger |
| --- | --- |
| ARP spoofing | One IP claimed by two or more MAC addresses |
| TCP port scan | One source sends SYNs to 15+ ports on one host (also reports ports that answered) |
| Internal host sweep | One source probes 10+ private hosts via ICMP echo or SYN |
| DNS tunnelling | 5+ long or high-entropy names under one base domain |
| NXDOMAIN burst | 10+ "no such domain" answers to one client |
| Credentials over HTTP | Password field or Basic-auth header in a plain HTTP request. The value is never stored. |
| Cleartext protocols | Telnet, FTP, TFTP (medium); HTTP, POP3, IMAP, SMTP, SNMP (low) |
| Suspicious ports | Connections to ports such as 4444, 31337, 6667 |
| Beaconing | 8+ connections to one destination at a steady interval |
| Large upload | 10 MB+ from a private host to one public address |
| TCP reset bursts | A host sending many RSTs |

## API

| Endpoint | Description |
| --- | --- |
| `GET /api/files` | List captures |
| `POST /api/upload` | Upload (`file` form field). Extension and magic-number checked, then test-parsed. |
| `DELETE /api/files/<name>` | Delete an uploaded capture (the default one is protected) |
| `GET /api/analysis?file=` | Full analysis (cached by file path, mtime and size) |
| `GET /api/analysis/<section>` | One section, e.g. `hosts`, `dns`, `graph`, `security` |
| `GET /api/network-data` | Original endpoint, extended with `summary`, `protocol_detail`, `top_hosts` |
| `GET /api/export/json` · `/api/export/csv?section=hosts\|conversations\|findings\|dns\|ports` | Downloads |

`file` defaults to `network_traffic.pcap`, falling back to the newest capture.

## Layout

```
run.py                  dev entry point
app/__init__.py         app factory, security headers, error handlers
app/api.py              endpoints, upload validation, CSV export
app/config.py           settings (env vars: NETSCOPE_DATA_DIR, NETSCOPE_MAX_UPLOAD_MB, NETSCOPE_MAX_PACKETS, ...)
app/analyzer/           core.py (single-pass analyzer), detections.py, utils.py, cache.py
app/sample_data.py      synthetic capture with a scan, ARP spoof, DNS tunnel, beaconing, ...
app/static, templates   dashboard (Chart.js is vendored, so it works offline)
tests/                  pytest suite
tools/                  report.py, generate_sample_pcap.py
```

## Design notes

- **Streaming.** Captures are read packet by packet with `PcapReader` instead of `rdpcap()` loading everything into memory. Set `NETSCOPE_MAX_PACKETS` to cap very large files.
- **Untrusted input.** Hostnames, user agents and paths come from the capture, so the UI escapes everything it renders, CSV cells that start with `=`, `+`, `-` or `@` are neutralised, uploads are sanitised and checked, file names can't traverse out of `data/`, and a strict CSP allows only same-origin scripts.
- **Privacy.** HTTP query strings and credential values are discarded during parsing and never reach the API output.
- **Limits.** TLS payloads are not decrypted (only SNI is read), HTTP is parsed per packet rather than per reassembled stream, and "OS guess" is a TTL heuristic.
- **Production.** `run.py` is for development. The Dockerfile uses gunicorn. There is no authentication, so put it behind a reverse proxy if it is reachable by others.
- **Chart.js** is MIT licensed; its licence is in `app/static/vendor/`.
