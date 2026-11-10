"""Pytest configuration and python path setup."""

import sys
from pathlib import Path

# Add backend directory to sys.path so 'app' module imports resolve cleanly
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))
