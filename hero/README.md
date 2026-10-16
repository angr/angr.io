# Demos — angr in action

Everything angr-related shown on angr.io comes from **real angr runs driven by
the scripts in this folder**. They feed the hero's 3 × 3 × 3 picker
(interface × language × analysis):

| Tile | Rendered as | Built by | Output |
| --- | --- | --- | --- |
| IPython | a static IPython-notebook | `build_notebooks.py` | `src/assets/hero/notebooks.json` |
| CLI | a static transcript of the real `angr` CLI (the page types the command) | `capture_cli.py` (+ `_angr_cli.py`, `_run_demo.py`) | `src/assets/cli/transcripts.json` |
| GUI | an angr-management screenshot (light + dark) | `shoot_gui.py` | `src/assets/gui/*.png` |

All three run against the same program — the classic `fauxware` backdoor —
built from C, Go and Rust (`binaries/`). The generated artifacts are
committed, so the website build never needs angr. Only re-generating does.

```
hero/
├── binaries/
│   ├── c/      fauxware + fauxware.c   (the canonical one from angr/binaries)
│   ├── go/     fauxware + fauxware.go  (built by build.sh)
│   ├── rust/   fauxware + fauxware.rs  (built by build.sh)
│   └── build.sh                        rebuilds the Go/Rust binaries via nix
├── demos/
│   ├── c/      decompile.py  disasm.py  symexec.py    # one notebook each
│   ├── go/     …
│   └── rust/   …
├── build_notebooks.py  # demos/<lang>/<mode>.py -> notebooks.json  (IPython tiles)
├── capture_cli.py      # captures the CLI tiles -> src/assets/cli/transcripts.json
├── _ansi.py            # ANSI 16-color -> themed HTML spans (shared by both)
├── _angr_cli.py        # wrapper: unicode CFG edges + quiet logging for the angr CLI
├── _run_demo.py        # wrapper: runs `python symexec.py` with quiet logging
├── shoot_gui.py        # drives angr-management headless -> src/assets/gui/*.png
└── README.md
```

## Writing a demo

Each demo is ordinary angr code, written the way you'd type it into IPython:

- Lines are executed in a persistent namespace; expression results are echoed
  (like a REPL) and `print()` output appears inline.
- **Blank lines separate cells.** In the notebook each cell becomes an
  `In [n]:` block with its output beneath.
- Comments are kept — they show up as annotations.
- Demos run with `binaries/<lang>/` as their working directory, so
  `angr.Project("fauxware")` resolves to that language's build.
- `symexec.py` doubles as the script the CLI tile runs (`cat symexec.py &&
  python symexec.py`), so it should `print()` its result rather than rely on
  the REPL echo.
- Keep input lines short-ish — the hero column is narrow.

The matrix is fixed by `LANGS`/`MODES` in the generators; to change which
function each GUI screenshot focuses on, edit `plan()` in `shoot_gui.py`.

## Updating the page

The workflow is: **edit a demo → regenerate → the page picks it up.**

1. Edit (or add) a file in `hero/demos/<lang>/`.
2. Regenerate the data from the repo root:

   ```bash
   npm run gen             # rebuild only what changed (skips up-to-date output)
   npm run gen:force       # rebuild everything, ignoring timestamps
   npm run gen:hero        # just the notebooks (skips if up to date)
   npm run gen:cli         # just the CLI transcripts (skips if up to date)
   npm run gen:gui         # just the angr-management screenshots
   ```

   The generators are timestamp-aware: each skips itself when its output is
   newer than the generator, the binaries and the demos it reads. So editing one
   notebook demo won't re-run the whole-binary CLI analyses for nothing. Pass
   `--force` (or `npm run gen:force`) to rebuild regardless.

   These run via **uv** by default — no setup, no venv: angr is provisioned from
   each script's PEP 723 inline metadata. To generate against a specific angr
   instead (e.g. the angr-dev editable venv), set `PYTHON`:

   ```bash
   PYTHON=../venv/bin/python npm run gen
   ```

3. If `npm run dev` is running, the page hot-reloads as soon as the artifacts
   change. For a production build, `npm run build`.

Commit the regenerated artifacts (`notebooks.json`, `transcripts.json`,
`src/assets/gui/*.png`).

### CLI transcripts

```bash
npm run gen:cli         # captures src/assets/cli/transcripts.json
```

This runs the angr command-line interface for real: per language a `decompile`
tab (`--go` / `--rust` pick the matching decompilation flavor), a `disassemble`
tab, and a `symexec` tab that `cat`s and runs the language's
`demos/<lang>/symexec.py`. Each command gets a pseudo-terminal on stdout *and*
stderr (angr only colors its output when both are terminals); stdout is kept
verbatim, stderr — rich's progress bars and summaries — is drained and dropped.
The page shows the finished output and types the command itself.

The CLI runs through the `_angr_cli.py` wrapper, which forces unicode
control-flow edges (angr only draws them when `stdout.encoding` is exactly
`utf-8`) and keeps library logging out of the transcript; `_run_demo.py` does
the same for the script tab.

The disassembly keeps angr's own 16-color ANSI output (rendered through the
same themed `.a0`–`.a15` spans as the notebooks). The decompile tab is the one
exception: the CLI highlights decompiled code with rich's fixed truecolor
theme, which can't follow the site's light/dark palette, so it is captured with
`--no-colors` and highlighted at build time by the site's highlighter — the
same treatment IPython input gets. The prompt still shows the command you'd
actually type.

Rust symbols are mangled, so the Rust tabs address functions by address — the
capture resolves `fauxware::main` etc. with angr first.

### GUI screenshots (angr-management)

```bash
npm run gen:gui         # -> src/assets/gui/<lang>-<mode>-<light|dark>.png
```

`shoot_gui.py` runs the real angr-management headless (Qt's `offscreen`
platform, 2× scale): it loads each binary, lets the app run its own CFG
recovery, then opens the disassembly graph, the pseudocode view, or sets up
and runs a symbolic exploration in the Symbolic Execution view, and saves the
window. One shot per site theme, using angr-management's Light and Dark color
schemes.

The PySide6 wheel needs X11/xcb libraries the host may not have. The repo's
nix shell (`shell.nix`) provides them (plus Python, uv, node, go, rustc):

```bash
nix-shell -I nixpkgs=channel:nixpkgs-unstable   # shell.nix at the repo root
npm run gen:gui
```

### The binaries

`binaries/c/fauxware` is the canonical test binary from
[angr/binaries](https://github.com/angr/binaries) (source alongside).
`binaries/go` and `binaries/rust` are line-for-line ports — same backdoor, same
prompts. The Go port does its I/O through raw syscalls so symbolic execution can
start at `main.main` without bootstrapping the Go runtime; both ports keep
`authenticate`/`accepted`/`rejected` as real functions so the demos have
something to point at. Rebuild them with `npm run gen:bin` (needs nix), then
regenerate everything — addresses move when a binary changes.

## Validating

The demos are real angr code, so an angr API change can silently break them —
the committed artifacts would still serve, but they'd be stale/wrong. There's no
separate validator: **regenerating *is* the check.** The generators re-run every
demo against the installed angr and fail on error — `build_notebooks.py` lets
the demo exceptions propagate, and `capture_cli.py` exits non-zero if a captured
command fails (rather than baking an error into the transcript). So:

```bash
npm run gen:force        # force a rebuild even if nothing changed
# or against a specific angr (e.g. the angr-dev venv):
PYTHON=../venv/bin/python npm run gen:force
```

Use the **force** form — plain `npm run gen` would skip up-to-date artifacts and
validate nothing. CI runs the notebook and CLI generators with `--force` (via
uv) on every PR **and daily on a schedule** — so a breaking angr release turns
CI red within a day even with no code change. There it just discards the
regenerated output; the point is whether it runs clean. The GUI screenshots are
not part of that job (they need a Qt runtime); regenerate them locally when the
demos or angr-management change.

## Faithful output

`build_notebooks.py` reproduces what a real terminal shows, and nothing more:

- It forces angr's `pp()` color on (`ansi_color_enabled`) and converts the real
  ANSI it emits into themed `.a0`–`.a15` spans — so disassembly is colored
  exactly the way angr colors it.
- Plain output (e.g. `print(dec.codegen.text)`, which is just a string) stays
  plain. We don't invent syntax highlighting the terminal wouldn't produce.
- Input code *is* highlighted, matching IPython's own input highlighting.
- The one liberty taken everywhere: angr's library logging (warnings about
  unconstrained memory, errors from analyses of runtime code the demo never
  shows) is silenced, so the tiles show the demo's own output.

## Notes

- All three tile kinds are static: the page ships no player or runtime
  dependency for them, just the typed-prompt animation in `Hero.astro`.
