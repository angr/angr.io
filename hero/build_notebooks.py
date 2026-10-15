#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["angr"]
# ///
"""
Build the static IPython-notebook data shown in the angr.io hero.

Runs each demo in `demos/` cell by cell (blank-line-separated) with real angr,
capturing — per cell — the input code, any streamed output (print/pp), and the
final expression's repr (the `Out[n]`), exactly like IPython would. The result
is written to src/assets/hero/notebooks.json, which the website renders as a
static, syntax-highlighted notebook carousel.

Needs angr + the test binaries (fauxware, go/age, rust/grex) from
angr/binaries' tests/x86_64. Run from that directory (or set FAUXWARE_DIR=/path):

    cd /path/to/binaries/tests/x86_64
    python /path/to/angr.io/hero/build_notebooks.py

Commit the regenerated notebooks.json.
"""
import ast
import contextlib
import html
import io
import json
import os
import re
import sys

# Force angr to emit real ANSI color from pp() even though we're not a TTY, so
# we can faithfully reproduce the terminal's own coloring (and ONLY its coloring
# — plain output like a decompiled string stays plain).
import angr  # noqa: E402
from angr.analyses import disassembly as _disassembly  # noqa: E402
from angr.utils import formatting as _formatting  # noqa: E402

_disassembly.ansi_color_enabled = True

# angr draws unicode control-flow edges only when sys.stdout.encoding is exactly
# "utf-8"; we capture to a StringIO (encoding=None), so force unicode edges.
_orig_add_edge = _formatting.add_edge_to_buffer


def _force_unicode_edges(*args, **kwargs):
    if kwargs.get("ascii_only") is None:
        kwargs["ascii_only"] = False
    return _orig_add_edge(*args, **kwargs)


_formatting.add_edge_to_buffer = _force_unicode_edges
_disassembly.add_edge_to_buffer = _force_unicode_edges

HERE = os.path.dirname(os.path.abspath(__file__))
DEMOS = os.path.join(HERE, "demos")
OUT = os.path.join(HERE, "..", "src", "assets", "hero", "notebooks.json")

# angr/binaries' tests/x86_64, so demos can `angr.Project("fauxware")` (and
# "go/age", "rust/...") no matter what directory you run this from. Override
# with FAUXWARE_DIR.
BIN_DIR = os.environ.get(
    "FAUXWARE_DIR",
    os.path.normpath(os.path.join(HERE, "..", "..", "binaries", "tests", "x86_64")),
)

# Demos to include, in carousel order. Each maps to demos/<id>.py.
ORDER = ["decompile", "go_decompile", "rust_decompile", "disasm", "symexec"]

_META = re.compile(r"#\s*(title|terminal):\s*(.*)", re.IGNORECASE)
_SGR = re.compile(r"\x1b\[([0-9;]*)m")


def ansi_to_html(text):
    """Convert a string with ANSI SGR color codes into HTML spans.

    Maps the 16 standard ANSI colors to `.a0`–`.a15` classes (themed in CSS).
    Text with no escape codes comes back as plain, escaped text — so we never
    invent coloring the terminal didn't actually produce.
    """
    out = []
    pos = 0
    open_span = False
    for m in _SGR.finditer(text):
        out.append(html.escape(text[pos : m.start()]))
        pos = m.end()
        codes = [int(c) for c in m.group(1).split(";") if c != ""] or [0]
        idx = None
        reset = False
        for c in codes:
            if c == 0 or c == 39:
                reset = True
            elif 30 <= c <= 37:
                idx = c - 30
            elif 90 <= c <= 97:
                idx = c - 90 + 8
        if open_span:
            out.append("</span>")
            open_span = False
        if idx is not None and not (reset and idx is None):
            out.append(f'<span class="a{idx}">')
            open_span = True
    out.append(html.escape(text[pos:]))
    if open_span:
        out.append("</span>")
    return "".join(out)


def parse(path):
    """Return ({"title": ..., "terminal": ...}, body_lines).

    Only the `# title:` / `# terminal:` meta lines are removed; all other
    comments are kept so they show up in the notebook as the annotations they are.
    """
    meta = {}
    body = []
    for ln in open(path).read().splitlines():
        m = _META.match(ln)
        if m and m.group(1).lower() not in meta:
            meta[m.group(1).lower()] = m.group(2).strip()
            continue
        body.append(ln)
    while body and body[0].strip() == "":
        body.pop(0)
    while body and body[-1].strip() == "":
        body.pop()
    return meta, body


def cells_of(body):
    """Split body into cells on blank lines."""
    cells, cur = [], []
    for ln in body:
        if ln.strip() == "":
            if cur:
                cells.append("\n".join(cur))
                cur = []
        else:
            cur.append(ln)
    if cur:
        cells.append("\n".join(cur))
    return cells


def run_cell(ns, src):
    """Execute a cell, returning (stream_output, out_repr) like a REPL.

    stream_output keeps any ANSI color the program actually emitted.
    """
    tree = ast.parse(src)
    buf = io.StringIO()
    out_repr = None
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        body = tree.body
        if body and isinstance(body[-1], ast.Expr):
            head, last = body[:-1], body[-1]
            if head:
                exec(compile(ast.Module(head, []), "<cell>", "exec"), ns)
            value = eval(compile(ast.Expression(last.value), "<cell>", "eval"), ns)
            if value is not None:
                out_repr = repr(value)
        else:
            exec(compile(tree, "<cell>", "exec"), ns)
    return buf.getvalue().rstrip("\n"), out_repr


def run_demo(path):
    meta, body = parse(path)
    ns = {}
    # Hidden setup, not part of the shown session: keep angr's log records out of the output.
    exec("import logging; logging.disable(logging.CRITICAL)", ns)

    cells = []
    for n, src in enumerate(cells_of(body), start=1):
        stream, out = run_cell(ns, src)
        cells.append(
            {
                "n": n,
                "code": src,
                # Faithful terminal output: real ANSI color -> HTML, plain stays plain.
                "streamHtml": ansi_to_html(stream) if stream else "",
                "out": out,
            }
        )

    return {
        "id": os.path.splitext(os.path.basename(path))[0],
        "title": meta.get("title", ""),
        # shown in the window title bar as "<terminal> — ipython"
        "terminal": meta.get("terminal", "fauxware"),
        "cells": cells,
    }


def _up_to_date(output, *sources):
    """True if `output` exists and is at least as new as every source file."""
    try:
        out_mtime = os.path.getmtime(output)
    except OSError:
        return False
    return all(os.path.getmtime(s) <= out_mtime for s in sources)


def main():
    # Skip regenerating if the output is newer than this script and every demo
    # it reads — like `make`. Pass --force to rebuild regardless.
    sources = [os.path.abspath(__file__)] + [
        os.path.join(DEMOS, f"{name}.py") for name in ORDER
    ]
    if "--force" not in sys.argv and _up_to_date(OUT, *sources):
        print(f"{os.path.basename(OUT)} is up to date — skipping (--force to rebuild)")
        return
    if os.path.isdir(BIN_DIR):
        os.chdir(BIN_DIR)  # so demos resolve the fauxware binary
    notebooks = [run_demo(os.path.join(DEMOS, f"{name}.py")) for name in ORDER]
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(os.path.abspath(OUT), "w") as f:
        json.dump(notebooks, f, indent=2)
        f.write("\n")
    print(f"wrote {OUT} ({len(notebooks)} notebooks)")


if __name__ == "__main__":
    main()
