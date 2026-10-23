"""Compatibility entry point; maintained tests live in ANOTA-tests/."""
from pathlib import Path
import runpy

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).resolve().parent / "ANOTA-tests" / Path(__file__).name), run_name="__main__")
