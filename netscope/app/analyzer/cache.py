"""Tiny thread-safe LRU cache keyed on file identity (path + mtime + size)."""
from __future__ import annotations

import threading
from collections import OrderedDict
from pathlib import Path
from typing import Callable


class AnalysisCache:
    def __init__(self, maxsize: int = 8):
        self.maxsize = maxsize
        self._items: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    @staticmethod
    def _key(path: Path):
        st = path.stat()
        return (str(path.resolve()), st.st_mtime_ns, st.st_size)

    def get_or_compute(self, path: Path, compute: Callable[[], dict]) -> tuple[dict, bool]:
        """Return (result, cache_hit)."""
        key = self._key(path)
        with self._lock:
            if key in self._items:
                self._items.move_to_end(key)
                return self._items[key], True
        result = compute()
        with self._lock:
            self._items[key] = result
            self._items.move_to_end(key)
            while len(self._items) > self.maxsize:
                self._items.popitem(last=False)
        return result, False

    def clear(self) -> None:
        with self._lock:
            self._items.clear()
