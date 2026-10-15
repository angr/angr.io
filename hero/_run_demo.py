"""
Run a demo script for the website's CLI recordings: `python symexec.py`, minus
angr's library logging (the same prelude the notebook generator applies), so the
cast shows the demo's own output rather than analysis warnings.

Usage:  python hero/_run_demo.py hero/demos/c/symexec.py
"""
import logging
import runpy
import sys

logging.disable(logging.WARNING)

script = sys.argv[1]
sys.argv = sys.argv[1:]
runpy.run_path(script, run_name="__main__")
