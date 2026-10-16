#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["angr[unicorn]"]
# ///
"""
Build the static IPython-notebook data shown on angr.io (the hero window's
IPython tiles).

Runs each demo in `demos/<lang>/<mode>.py` cell by cell (blank-line-separated)
with real angr, capturing — per cell — the input code, any streamed output
(print/pp), and the final expression's repr (the `Out[n]`), exactly like
IPython would. Each demo runs with `binaries/<lang>/` as its working directory,
so `angr.Project("fauxware")` resolves to that language's build of fauxware.
The result is written to src/assets/hero/notebooks.json.

    python hero/build_notebooks.py            # skips if up to date
    python hero/build_notebooks.py --force

Commit the regenerated notebooks.json.
"""
import ast
import contextlib
import io
import json
import os
import sys

# Force angr to emit real ANSI color from pp() even though we're not a TTY, so
# we can faithfully reproduce the terminal's own coloring (and ONLY its coloring
# — plain output like a decompiled string stays plain).
import angr  # noqa: E402
from _ansi import ansi_to_html  # noqa: E402
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
BIN_DIR = os.path.join(HERE, "binaries")
OUT = os.path.normpath(os.path.join(HERE, "..", "src", "assets", "hero", "notebooks.json"))

# The hero matrix: every language × every analysis. Each entry maps to
# demos/<lang>/<mode>.py, run against binaries/<lang>/fauxware. Order here is
# display order.
LANGS = ["c", "go", "rust"]
MODES = [
    ("decompile", "Decompilation"),
    ("disasm", "Disassembly"),
    ("symexec", "Symbolic Execution"),
]


def parse(path):
    """Return the demo's lines, trimmed of leading/trailing blank lines.

    Comments are kept: they show up in the notebook as the annotations they are.
    """
    body = open(path).read().splitlines()
    while body and body[0].strip() == "":
        body.pop(0)
    while body and body[-1].strip() == "":
        body.pop()
    return body


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


def run_demo(lang, mode, title):
    path = os.path.join(DEMOS, lang, f"{mode}.py")
    body = parse(path)
    ns = {}
    # Keep angr's library logging out of the capture (it goes to stderr in a
    # real session; the notebooks show only what the demo prints).
    exec("import logging; logging.disable(logging.ERROR)", ns)
    os.chdir(os.path.join(BIN_DIR, lang))  # so `angr.Project("fauxware")` resolves

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
        "id": f"{lang}-{mode}",
        "lang": lang,
        "mode": mode,
        "title": title,
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
    sources = [os.path.abspath(__file__)]
    for lang in LANGS:
        sources.append(os.path.join(BIN_DIR, lang, "fauxware"))
        sources += [os.path.join(DEMOS, lang, f"{mode}.py") for mode, _ in MODES]
    if "--force" not in sys.argv and _up_to_date(OUT, *sources):
        print(f"{os.path.basename(OUT)} is up to date — skipping (--force to rebuild)")
        return
    notebooks = []
    for lang in LANGS:
        for mode, title in MODES:
            print(f"  {lang}/{mode}", flush=True)
            notebooks.append(run_demo(lang, mode, title))
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "w") as f:
        json.dump(notebooks, f, indent=2)
        f.write("\n")
    print(f"wrote {OUT} ({len(notebooks)} notebooks)")


if __name__ == "__main__":
    main()
