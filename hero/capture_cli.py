#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["angr[unicorn]"]
# ///
"""
Capture real angr command-line sessions as static transcripts for the website's
CLI tiles. For every language in `binaries/` it captures three tabs:

  decompile    $ angr decompile fauxware [--go|--rust] --functions ...
  disassemble  $ angr disassemble fauxware --functions ...
  symexec      $ cat symexec.py && python symexec.py   (the demos/<lang> script)

Each command runs for real, with a pseudo-terminal on stdout and stderr like an
interactive shell would give it, and its stdout is kept verbatim. The progress
bars angr draws on stderr are drained and dropped — the tile shows the finished
output, and the page types the command itself.

    python hero/capture_cli.py           # -> src/assets/cli/transcripts.json
    python hero/capture_cli.py --force   # re-capture even if up to date

Commit the regenerated transcripts.
"""
import fcntl
import json
import os
import pty
import select
import struct
import subprocess
import sys
import termios

from _ansi import SGR, ansi_to_html

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "src", "assets", "cli", "transcripts.json"))
BIN_DIR = os.path.join(HERE, "binaries")
DEMOS = os.path.join(HERE, "demos")

COLS, ROWS = 110, 50

_PY = sys.executable
# Wrapper that keeps unicode CFG edges even while progress bars are on.
_WRAP = os.path.join(HERE, "_angr_cli.py")
# Runs a demo script with angr's library logging silenced (the `python x.py` tabs).
_RUN = os.path.join(HERE, "_run_demo.py")

LANGS = ["c", "go", "rust"]
# Functions to show per language, and the CLI flag that picks the matching
# decompilation flavor (angr decompiles Go binaries back to Go and Rust
# binaries back to Rust). Rust symbols are mangled, so those are resolved to
# addresses at capture time (see rust_funcs) — the CLI matches `--functions`
# names against the raw symbol table.
FUNCS = {
    "c": ["main", "authenticate", "rejected", "accepted"],
    "go": ["main.main", "main.authenticate"],
    "rust": ["fauxware::main", "fauxware::authenticate"],
}
FLAVOR = {"c": [], "go": ["--go"], "rust": ["--rust"]}


def rust_funcs(names):
    """Resolve demangled Rust function names to `0x...` addresses with angr."""
    import logging

    logging.disable(logging.ERROR)
    import angr

    proj = angr.Project(os.path.join(BIN_DIR, "rust", "fauxware"), auto_load_libs=False)
    cfg = proj.analyses.CFGFast(normalize=True)
    by_name = {f.demangled_name: f.addr for f in cfg.functions.values()}
    return [f"{by_name[n]:#x}" for n in names]


def build_demos():
    """One transcript per (language, tab) — the hero window's CLI column.

    Each step is (what the prompt shows, what actually runs, how to render the
    output): "ansi" keeps the terminal's own 16-color output; "c"/"go"/"rust"
    hands the plain text to the site's syntax highlighter. The CLI highlights
    decompiled code with a fixed truecolor theme (rich), which can't follow the
    site's light/dark palette — so the decompile tab is captured with
    `--no-colors` and highlighted at build time instead, like IPython input.
    """
    demos = []
    for lang in LANGS:
        cwd = os.path.join(BIN_DIR, lang)
        funcs = rust_funcs(FUNCS[lang]) if lang == "rust" else FUNCS[lang]
        flags = FLAVOR[lang]
        demos.append(
            {
                "id": f"{lang}-decompile",
                "lang": lang,
                "mode": "decompile",
                "title": "Decompile",
                "cwd": cwd,
                "steps": [
                    (
                        "angr decompile fauxware " + " ".join([*flags, "--functions", *funcs]),
                        [_PY, _WRAP, "decompile", "fauxware", *flags, "--no-colors", "--functions", *funcs],
                        lang,
                    )
                ],
            }
        )
        demos.append(
            {
                "id": f"{lang}-disasm",
                "lang": lang,
                "mode": "disasm",
                "title": "Disassemble",
                "cwd": cwd,
                "steps": [
                    (
                        "angr disassemble fauxware --functions " + " ".join(funcs),
                        [_PY, _WRAP, "disassemble", "fauxware", "--functions", *funcs],
                        "ansi",
                    )
                ],
            }
        )
        script = os.path.join(DEMOS, lang, "symexec.py")
        demos.append(
            {
                "id": f"{lang}-symexec",
                "lang": lang,
                "mode": "symexec",
                "title": "Symbolic execution",
                "cwd": cwd,
                "steps": [
                    ("cat symexec.py", ["cat", script], "ansi"),
                    ("python symexec.py", [_PY, _RUN, script], "ansi"),
                ],
            }
        )
    return demos


def _pty():
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    return master, slave


def capture(argv, cwd):
    """Run argv with a pty on stdout and stderr; return stdout as text.

    angr only colors its output when *both* streams are terminals, so each
    gets its own pty. stderr (rich's progress bars, the "Decompiled N
    functions" summary) is drained and dropped.
    """
    env = dict(
        os.environ,
        TERM="xterm-256color",
        COLUMNS=str(COLS),
        LINES=str(ROWS),
        PYTHONUNBUFFERED="1",
        # angr draws unicode control-flow edges only when stdout.encoding is
        # exactly "utf-8"; force it so we don't fall back to ASCII edges.
        PYTHONIOENCODING="utf-8",
    )
    out_m, out_s = _pty()
    err_m, err_s = _pty()
    proc = subprocess.Popen(
        argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, stdout=out_s, stderr=err_s
    )
    os.close(out_s)
    os.close(err_s)
    bufs = {out_m: bytearray(), err_m: bytearray()}
    open_fds = set(bufs)
    while open_fds:
        ready, _, _ = select.select(list(open_fds), [], [], 1.0)
        for fd in ready:
            try:
                data = os.read(fd, 65536)
            except OSError:  # EIO once the child closes its end
                data = b""
            if not data:
                open_fds.discard(fd)
                os.close(fd)
            else:
                bufs[fd] += data
    code = proc.wait()
    out = bufs[out_m].decode("utf-8", "replace").replace("\r\n", "\n")
    # Fail loudly instead of baking an error into the transcript — this is what
    # makes `gen:cli` a real validation gate when a demo breaks against angr.
    if code != 0:
        err = SGR.sub("", bufs[err_m].decode("utf-8", "replace")).replace("\r\n", "\n")
        tail = "\n".join(err.strip().splitlines()[-15:])
        raise SystemExit(f"command exited with {code}: {' '.join(argv)}\n{tail}")
    return out.strip("\n")


def capture_demo(demo):
    steps = []
    for display, argv, render in demo["steps"]:
        text = capture(argv, demo["cwd"])
        step = {"cmd": display}
        if render == "ansi":
            step["html"] = ansi_to_html(text)
        else:
            step["code"] = SGR.sub("", text)
            step["lang"] = render
        steps.append(step)
    print(f"  {demo['id']}  ({sum(len(s.get('html') or s.get('code')) for s in steps)} chars)", flush=True)
    return {k: demo[k] for k in ("id", "lang", "mode", "title")} | {
        "display": " && ".join(d for d, _, _ in demo["steps"]),
        "steps": steps,
    }


def _up_to_date(output, *sources):
    """True if `output` exists and is at least as new as every source file."""
    try:
        out_mtime = os.path.getmtime(output)
    except OSError:
        return False
    return all(os.path.getmtime(s) <= out_mtime for s in sources)


def main():
    # Skip re-capturing if the transcripts are newer than this script, the CLI
    # wrapper, the binaries and the symexec demos — like `make`. --force rebuilds.
    sources = [os.path.abspath(__file__), _WRAP, _RUN, os.path.join(HERE, "_ansi.py")]
    for lang in LANGS:
        sources.append(os.path.join(BIN_DIR, lang, "fauxware"))
        sources.append(os.path.join(DEMOS, lang, "symexec.py"))
    if "--force" not in sys.argv and _up_to_date(OUT, *sources):
        print("CLI transcripts are up to date — skipping (--force to rebuild)")
        return
    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    transcripts = [capture_demo(d) for d in build_demos()]
    with open(OUT, "w") as f:
        json.dump(transcripts, f, indent=2)
        f.write("\n")
    print(f"wrote {OUT} ({len(transcripts)} transcripts)")


if __name__ == "__main__":
    main()
