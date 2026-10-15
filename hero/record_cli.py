#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["angr[unicorn]"]
# ///
"""
Record real angr command-line sessions to asciicasts for the website's CLI
tiles. For every language in `binaries/` it records three tabs:

  decompile    $ angr decompile fauxware [--go|--rust] --functions ...
  disassemble  $ angr disassemble fauxware --functions ...
  symexec      $ cat symexec.py && python symexec.py   (the demos/<lang> script)

Each demo "types" its command, then runs the real thing under a pseudo-terminal
and captures its colored output verbatim.

    python hero/record_cli.py            # -> src/assets/cli/*.cast + manifest.json
    python hero/record_cli.py --force    # re-record even if up to date

Commit the regenerated casts + manifest.
"""
import fcntl
import json
import os
import pty
import select
import struct
import sys
import termios
import time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.normpath(os.path.join(HERE, "..", "src", "assets", "cli"))
BIN_DIR = os.path.join(HERE, "binaries")
DEMOS = os.path.join(HERE, "demos")

COLS, ROWS = 110, 26
MAX_IDLE = 1.0  # clamp the analysis pause so playback stays snappy
MAX_RUN = 7.0  # fast-forward a command's run (progress bars) to at most this long
HOLD = 5.0  # seconds to rest on the final output before the loop restarts
PROMPT = "\x1b[38;5;203m$\x1b[0m "  # crimson `$`
CHAR_DELAY = 0.025

_PY = sys.executable
# Wrapper that keeps unicode CFG edges even while progress bars are on.
_WRAP = os.path.join(HERE, "_angr_cli.py")
# Runs a demo script with angr's library logging silenced (the `python x.py` tabs).
_RUN = os.path.join(HERE, "_run_demo.py")

LANGS = ["c", "go", "rust"]
# Functions to show per language, and the CLI flag that picks the matching
# decompilation flavor (angr decompiles Go binaries back to Go and Rust
# binaries back to Rust). Rust symbols are mangled, so those are resolved to
# addresses at record time (see rust_funcs) — the CLI matches `--functions`
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
    """One recording per (language, tab) — the hero window's CLI column."""
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
                        [_PY, _WRAP, "decompile", "fauxware", *flags, "--functions", *funcs],
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
                    ("cat symexec.py", ["cat", script]),
                    ("python symexec.py", [_PY, _RUN, script]),
                ],
            }
        )
    return demos


def type_events(display, start):
    """asciicast events that type the prompt + command, char by char."""
    events = [[round(start, 4), "o", PROMPT]]
    t = start + 0.3
    for ch in display:
        events.append([round(t, 4), "o", ch])
        t += CHAR_DELAY
    t += 0.4
    events.append([round(t, 4), "o", "\r\n"])
    return events, t


def record_cmd(argv, cwd, start):
    """Run argv under a pty; return (events offset to begin at `start`, end time)."""
    env = dict(
        os.environ,
        TERM="xterm-256color",
        COLUMNS=str(COLS),
        LINES=str(ROWS),
        PYTHONUNBUFFERED="1",
        FORCE_COLOR="1",
        # angr draws unicode control-flow edges only when stdout.encoding is
        # exactly "utf-8"; force it so we don't fall back to ASCII edges.
        PYTHONIOENCODING="utf-8",
    )
    events = []
    pid, fd = pty.fork()
    if pid == 0:  # child
        os.chdir(cwd)
        os.execvpe(argv[0], argv, env)
        os._exit(127)

    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
    t0 = time.time()
    last = t0
    while True:
        try:
            r, _, _ = select.select([fd], [], [], 3)
        except (InterruptedError, OSError):
            break
        if fd not in r:
            continue
        try:
            data = os.read(fd, 65536)
        except OSError:
            break
        if not data:
            break
        now = time.time()
        if now - last > MAX_IDLE:
            t0 += (now - last) - MAX_IDLE
        last = now
        events.append([now - t0, "o", data.decode("utf-8", "replace")])
    os.close(fd)
    status = 0
    try:
        _, status = os.waitpid(pid, 0)
    except OSError:
        pass
    # Fail loudly instead of baking an error message into the cast — this is what
    # makes `gen:cli` a real validation gate when a demo breaks against angr.
    code = os.waitstatus_to_exitcode(status)
    if code != 0:
        raise SystemExit(f"command exited with {code}: {' '.join(argv)}")
    # Whole-binary analyses on the Go/Rust builds take a while (lots of runtime
    # code); fast-forward the run so a tab never spends ages on progress bars.
    dur = events[-1][0] if events else 0.0
    scale = min(1.0, MAX_RUN / dur) if dur > 0 else 1.0
    out = [[round(start + t * scale, 4), "o", data] for t, _, data in events]
    return out, (out[-1][0] if out else start)


def record_demo(demo):
    events = []
    t = 0.0
    for display, argv in demo["steps"]:
        typed, t = type_events(display, t)
        events += typed
        run, t = record_cmd(argv, demo["cwd"], t + 0.3)
        events += run
        t += 0.6
    # Rest on the final output for a while before the player loops back, so the
    # result is actually readable instead of flashing past.
    if events:
        events.append([round(events[-1][0] + HOLD, 4), "o", "\x1b[0m"])
    header = {
        "version": 2,
        "width": COLS,
        "height": ROWS,
        "env": {"TERM": "xterm-256color"},
        "title": f"angr {demo['id']}",
    }
    path = os.path.join(OUT_DIR, demo["id"] + ".cast")
    with open(path, "w") as f:
        f.write(json.dumps(header) + "\n")
        for ev in events:
            f.write(json.dumps(ev) + "\n")
    dur = events[-1][0] if events else 0
    print(f"  {demo['id']}.cast  ({len(events)} events, {dur:.1f}s)", flush=True)
    return {k: demo[k] for k in ("id", "lang", "mode", "title")} | {
        "display": " && ".join(d for d, _ in demo["steps"])
    }


def _up_to_date(output, *sources):
    """True if `output` exists and is at least as new as every source file."""
    try:
        out_mtime = os.path.getmtime(output)
    except OSError:
        return False
    return all(os.path.getmtime(s) <= out_mtime for s in sources)


def main():
    # Skip re-recording if the casts are newer than this script, the CLI wrapper,
    # the binaries and the symexec demos — like `make`. --force rebuilds anyway.
    out = os.path.join(OUT_DIR, "manifest.json")
    sources = [os.path.abspath(__file__), _WRAP, _RUN]
    for lang in LANGS:
        sources.append(os.path.join(BIN_DIR, lang, "fauxware"))
        sources.append(os.path.join(DEMOS, lang, "symexec.py"))
    if "--force" not in sys.argv and _up_to_date(out, *sources):
        print("CLI casts are up to date — skipping (--force to rebuild)")
        return
    os.makedirs(OUT_DIR, exist_ok=True)
    for stale in os.listdir(OUT_DIR):
        if stale.endswith(".cast"):
            os.remove(os.path.join(OUT_DIR, stale))
    manifest = [record_demo(d) for d in build_demos()]
    with open(out, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")
    print(f"wrote {OUT_DIR}/manifest.json ({len(manifest)} demos)")


if __name__ == "__main__":
    main()
