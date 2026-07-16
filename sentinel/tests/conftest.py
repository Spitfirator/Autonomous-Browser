"""Sentinel test path setup (the app is intentionally not a Python package)."""

import sys
from pathlib import Path

SENTINEL_DIR = Path(__file__).resolve().parents[1]
BROWSER_USE_DIR = SENTINEL_DIR.parent / 'browser-use'
for path in (SENTINEL_DIR, BROWSER_USE_DIR):
	if str(path) not in sys.path:
		sys.path.insert(0, str(path))
