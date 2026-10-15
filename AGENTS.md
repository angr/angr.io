# AGENTS.md

Guidance for AI agents working on the angr.io website. Humans: see
[README.md](README.md) and [hero/README.md](hero/README.md) for the full story —
this file is the short list of things that are easy to get wrong.

## What this is

A statically-generated marketing site for angr, built with **Astro 5** +
**Tailwind v4**, deployed to **GitHub Pages** on push to `main`/`master`
(`.github/workflows/deploy.yml`). Zero runtime JS by default; everything is
build-time. All fonts/images are self-hosted — **never add a CDN/third-party
runtime request.**

## Layout

```
src/components/   one .astro file per page section (Hero, Features, …)
src/pages/        index.astro (section order lives here), 404.astro
src/data/         content arrays (features, ecosystem)
src/styles/       global.css — design tokens + themes + shared components
src/lib/icons.ts  the inline-SVG icon set (add an icon here before using it)
hero/             generators for the hero + CLI demos (see below)
src/assets/       logo, screenshots, and GENERATED demo artifacts
```

## The one rule that bites: generated artifacts

These files are **generated from real angr** and committed. The site build never
runs angr — it just imports the committed output. **Do not hand-edit them:**

| Artifact | Generated from | Command |
| --- | --- | --- |
| `src/assets/hero/notebooks.json` | `hero/demos/<lang>/*.py` | `npm run gen:hero` |
| `src/assets/cli/*.cast` + `manifest.json` | `hero/demos/<lang>/symexec.py` + the angr CLI, via `record_cli.py` | `npm run gen:cli` |
| `src/assets/gui/*.png` | angr-management driven by `hero/shoot_gui.py` | `npm run gen:gui` |
| `hero/binaries/{go,rust}/fauxware` | `fauxware.go` / `fauxware.rs` | `npm run gen:bin` (nix) |

All three tile kinds cover the same matrix — languages `c`/`go`/`rust` ×
modes `decompile`/`disasm`/`symexec` — and `Showcase.astro` looks artifacts up
by `<lang>-<mode>` id, so keep the three generators' `LANGS`/`MODES` in sync.

Workflow is always **edit a `hero/demos/<lang>/*.py` → regenerate → commit the output.**
If you change a demo and forget to regenerate, the site won't reflect it. If you
edit the JSON/cast by hand, the next regen silently overwrites you. `npm run gen`
is timestamp-driven: each generator skips itself when its output is newer than its
inputs, so editing one demo won't re-record unrelated casts. `npm run gen:force`
(or `--force`) rebuilds regardless.

- The generators run via **uv** by default — `uv run` provisions angr from each
  script's PEP 723 inline metadata, no venv needed. Override with `PYTHON=…` to
  use a specific interpreter, e.g. `PYTHON=../venv/bin/python` for the angr-dev
  venv.
- `gen:gui` runs the real angr-management headless (PySide6). It needs X11/xcb
  runtime libraries the wheel doesn't bundle; `nix-shell` (the repo's `shell.nix`)
  provides them (plus Python/uv/go/rustc). It is not run in CI.
- Regenerating *is* the validation: both generators re-run every demo and fail
  on error (no separate validator). Use the **force** form to actually re-run —
  `npm run gen:force` (or `--force`); plain `gen` skips up-to-date artifacts. CI
  runs the generators with `--force` via uv on PRs and daily, so a breaking angr
  release is caught even with no code change.
- The binaries live in `hero/binaries/<lang>/fauxware` (C is the canonical
  angr/binaries one; Go and Rust are ports built by `hero/binaries/build.sh`).
  Rebuilding a binary moves addresses — regenerate everything afterwards.
- The hero carousel shows the `c` row of `notebooks.json`; the showcase's
  order follows `LANGS`/`MODES` in the generators.
- **Unicode CFG edges** only render when `stdout.encoding == "utf-8"`. That's why
  `record_cli.py` sets `PYTHONIOENCODING=utf-8` and the decompile/disassemble
  tabs run through `_angr_cli.py`, and why `build_notebooks.py` monkeypatches the
  edge writer. Don't remove these or the graph edges fall back to ASCII.
- The wrappers (`_angr_cli.py`, `_run_demo.py`) and the notebook builder
  silence angr's library logging so tiles show the demo's own output. Keep
  that; the Rust analyses in particular log tracebacks for std functions.

## Verify visually before claiming done

Changes to layout/theming aren't done until you've looked at them. With the dev
server running (`npm run dev`, http://localhost:4321), drive Playwright to
screenshot the affected section in **both themes** (toggle via the
`data-theme="light|dark"` attribute on `<html>`) and read the image back. Both
the light and dark palettes ship — a change that looks right in one can break the
other.

Helper scripts (run against a `npm run preview` server): `scripts/shoot.mjs`
writes light/dark + desktop/mobile shots to `screenshots/`, and `scripts/og.mjs`
regenerates the `public/og.png` social card.

## Theming

Color is CSS custom properties that flip on `data-theme` (`light`|`dark`), set
before first paint. To recolor, edit the token blocks at the top of
`src/styles/global.css` — don't hardcode hex values in components.

## Before you finish

- `npm run check` (typecheck) and `npm run build` must both pass — CI runs
  exactly these from a clean checkout, on every push and PR.
- **`git status` — make sure new components and generated artifacts are staged.**
  A file imported by the site but left untracked builds locally and fails in CI.
- Don't commit/push unless asked.

## Environment note

There is no system Node here; it's a local install (`~/.local/bin`, also
`../venv` for Python/angr). `export PATH="$HOME/.local/bin:$PATH"` before npm.
This install (and the Playwright browser in `~/.cache`) has been observed to not
survive reboots — if `node` or the browser goes missing, run
`./scripts/bootstrap.sh` to reinstall everything, then re-export PATH.
