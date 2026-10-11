#!/usr/bin/env python3
"""Development entry point:  python run.py  ->  http://127.0.0.1:5000"""
import os

from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(host=os.environ.get("NETSCOPE_HOST", "127.0.0.1"),
            port=int(os.environ.get("NETSCOPE_PORT", 5000)),
            debug=os.environ.get("NETSCOPE_DEBUG", "0") == "1")
