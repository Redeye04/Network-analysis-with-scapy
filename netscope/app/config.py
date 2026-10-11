import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent


class Config:
    # Where capture files live (uploads are saved here too).
    DATA_DIR = Path(os.environ.get("NETSCOPE_DATA_DIR", BASE_DIR / "data"))
    DEFAULT_PCAP = os.environ.get("NETSCOPE_DEFAULT_PCAP", "network_traffic.pcap")
    ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}
    MAX_CONTENT_LENGTH = int(os.environ.get("NETSCOPE_MAX_UPLOAD_MB", 200)) * 1024 * 1024
    # Stop after this many packets (0 = unlimited) to keep memory/CPU bounded.
    MAX_PACKETS = int(os.environ.get("NETSCOPE_MAX_PACKETS", 0))
    CACHE_SIZE = 8
    # Create a demo capture on first start when the data folder has none.
    AUTO_SAMPLE = os.environ.get("NETSCOPE_AUTO_SAMPLE", "1") == "1"
    # Overrides for app.analyzer.DEFAULT_THRESHOLDS.
    THRESHOLDS: dict = {}
    JSON_SORT_KEYS = False
