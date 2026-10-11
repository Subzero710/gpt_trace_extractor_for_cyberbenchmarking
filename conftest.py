"""Expose the same shared transport/source packages to the existing pytest suite."""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for path in [ROOT / "shared", ROOT / "scripts", *sorted((ROOT / "apps").glob("*/src"))]:
    sys.path.insert(0, str(path))
