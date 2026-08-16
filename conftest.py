"""
conftest.py — pytest configuration for blind-signature-protocol.

Adds src/ to sys.path so that all test files can import from
common, client, server and verifier cleanly.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))