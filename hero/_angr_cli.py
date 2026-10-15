"""
Thin wrapper around the angr CLI used only for recording the website demos.

angr picks ASCII control-flow edges when `sys.stdout.encoding` isn't exactly
"utf-8" — which happens while rich's progress bars are active. We want BOTH the
progress bars and the pretty unicode edges, so force the edge renderer to
unicode before handing off to the real CLI.

It also keeps angr's library logging (warnings/errors from analyses on library
code the demo never shows) out of the recording, like the notebooks do.

Usage:  python hero/_angr_cli.py disassemble fauxware
"""
import logging
import sys

logging.disable(logging.ERROR)

from angr.utils import formatting as _fmt  # noqa: E402
from angr.analyses import disassembly as _dis  # noqa: E402

_orig_add_edge = _fmt.add_edge_to_buffer


def _force_unicode_edges(*args, **kwargs):
    if kwargs.get("ascii_only") is None:
        kwargs["ascii_only"] = False
    return _orig_add_edge(*args, **kwargs)


# Patch both the source and the name already imported into disassembly.
_fmt.add_edge_to_buffer = _force_unicode_edges
_dis.add_edge_to_buffer = _force_unicode_edges

from angr.__main__ import main  # noqa: E402

main()
