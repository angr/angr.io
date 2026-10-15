# Hero demos — angr in action

The demos shown on angr.io come from **real angr scripts in this folder**. They
feed two different surfaces:

| Surface | Rendered as | Built by | Output |
| --- | --- | --- | --- |
| Hero (top of page) | a static IPython-notebook carousel | `build_notebooks.py` | `src/assets/hero/notebooks.json` |
| CLI section | an animated [asciinema](https://asciinema.org) playback | `record_cli.py` (+ `_angr_cli.py`, `play.py`) | `src/assets/cli/*.cast` + `manifest.json` |

Both are generated from the same kind of source — plain angr code — and the
generated artifacts are committed, so the website build never needs angr. Only
re-generating does.

```
hero/
├── demos/
│   ├── symexec.py      # hero notebook: symbolic execution
│   ├── decompile.py    # hero notebook: decompilation
│   ├── go_decompile.py   # hero notebook: Go decompilation (binaries: go/age)
│   ├── rust_decompile.py # hero notebook: Rust decompilation (binaries: rust/grex)
│   ├── disasm.py       # hero notebook: disassembly
│   └── fauxware.py     # full guided session (for the CLI asciinema playback)
├── build_notebooks.py  # demos/*.py -> notebooks.json  (static hero)
├── record_cli.py       # records the CLI section tabs -> src/assets/cli/*.cast
├── _angr_cli.py        # wrapper that forces unicode CFG edges in the CLI
├── play.py             # replay a demo as a typed REPL session (REPL tab)
└── README.md
```

## Writing a demo

Each demo is ordinary angr code, written the way you'd type it into IPython:

- Lines are executed in a persistent namespace; expression results are echoed
  (like a REPL) and `print()` output appears inline.
- **Blank lines separate cells.** In the hero notebook each cell becomes an
  `In [n]:` block with its output beneath.
- A `# title:` line sets the carousel tab label, and an optional `# terminal:`
  line sets the window title (`<terminal> — ipython`; default `fauxware`).
  Every other comment is kept and shown.
- Keep input lines short-ish — the hero column is narrow.

To add a notebook to the hero, drop a `demos/<id>.py` and add `<id>` to `ORDER`
in `build_notebooks.py`.

## Updating the page

The workflow is: **edit a demo → regenerate → the page picks it up.**

1. Edit (or add) a file in `hero/demos/`.
2. Regenerate the data from the repo root:

   ```bash
   npm run gen             # rebuild only what changed (skips up-to-date output)
   npm run gen:force       # rebuild everything, ignoring timestamps
   npm run gen:hero        # just the hero notebooks (skips if up to date)
   npm run gen:cli         # just the CLI casts (skips if up to date)
   ```

   The generators are timestamp-aware: each skips itself when its output is newer
   than the generator and the demos it reads. So editing one hero demo won't
   re-record the CLI casts — whose nondeterministic timing would otherwise churn
   in git for no reason. Pass `--force` (or `npm run gen:force`) to rebuild
   regardless.

   These run via **uv** by default — no setup, no venv: angr is provisioned from
   each script's PEP 723 inline metadata. To generate against a specific angr
   instead (e.g. the angr-dev editable venv), set `PYTHON`:

   ```bash
   PYTHON=../venv/bin/python npm run gen
   ```

   They find the test binaries (`fauxware`, `go/age`, `rust/grex`) automatically
   in the angr-dev layout (`binaries/tests/x86_64`); point `FAUXWARE_DIR=...` at
   that directory otherwise.

3. If `npm run dev` is running, the page hot-reloads as soon as
   `notebooks.json` changes. For a production build, `npm run build`.

Commit the regenerated artifacts (`notebooks.json`, `src/assets/cli/*.cast`).

To add a new demo to the carousel, drop `hero/demos/<id>.py` and add `<id>` to
the `ORDER` list in `build_notebooks.py`.

Preview a demo in your own terminal without the website:

```bash
uv run hero/play.py hero/demos/symexec.py
../venv/bin/python hero/play.py hero/demos/symexec.py   # or your angr-dev venv
```

### CLI asciinema casts (the CLI section)

```bash
npm run gen:cli         # records src/assets/cli/*.cast + manifest.json
```

This drives the angr command-line interface under a PTY (one tab per entry in
`DEMOS` in `record_cli.py`). The `repl` tab replays `demos/fauxware.py` through
`play.py`; the `decompile`/`disassemble` tabs run the real `angr` CLI via the
`_angr_cli.py` wrapper, which forces unicode control-flow edges (angr only draws
them when `stdout.encoding` is exactly `utf-8`). Commit the regenerated casts +
`manifest.json` — tab order follows `DEMOS`.

## Validating

The demos are real angr code, so an angr API change can silently break them —
the committed artifacts would still serve, but they'd be stale/wrong. There's no
separate validator: **regenerating *is* the check.** Both generators re-run every
demo against the installed angr and fail on error — `build_notebooks.py` lets the
demo exceptions propagate, and `record_cli.py` exits non-zero if a recorded
command fails (rather than baking an error into the cast). So:

```bash
npm run gen:force        # force a rebuild even if nothing changed
# or against a specific angr (e.g. the angr-dev venv):
PYTHON=../venv/bin/python npm run gen:force
```

Use the **force** form — plain `npm run gen` would skip up-to-date artifacts and
validate nothing. CI runs the generators with `--force` (via uv, with the
`fauxware` binary fetched from `angr/binaries`) on every PR **and daily on a
schedule** — so a breaking angr release turns CI red within a day even with no
code change. There it just
discards the regenerated output; the point is whether it runs clean. The check
runs independently of the build/deploy jobs, so a demo break never blocks
shipping unrelated site changes; it just flags that the demos need attention.

## Faithful output

`build_notebooks.py` reproduces what a real terminal shows, and nothing more:

- It forces angr's `pp()` color on (`ansi_color_enabled`) and converts the real
  ANSI it emits into themed `.a0`–`.a15` spans — so disassembly is colored
  exactly the way angr colors it.
- Plain output (e.g. `print(dec.codegen.text)`, which is just a string) stays
  plain. We don't invent syntax highlighting the terminal wouldn't produce.
- Input code *is* highlighted, matching IPython's own input highlighting.

## Notes

- `record_cli.py` is a tiny dependency-free `asciinema rec` (pty + asciicast v2).
- `play.py` colors typed code with Pygments if it's installed (ships with
  IPython); otherwise it types plain text.
- The asciinema player and its theme power the CLI section; the hero uses the
  static notebooks (no player).
