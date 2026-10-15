# angr.io

The website for the [angr](https://github.com/angr/angr) binary analysis
platform.

## Stack

- **[Astro](https://astro.build)** — static site generation, zero JS by default,
  build-time syntax highlighting (Shiki), view transitions.
- **[Tailwind CSS v4](https://tailwindcss.com)** — utility styling layered on a
  small custom design-token system (see `src/styles/global.css`).
- **Self-hosted assets** — variable fonts ([Inter](https://rsms.me/inter/) +
  [JetBrains Mono](https://www.jetbrains.com/lp/mono/)) and all images are
  bundled locally. No third-party/CDN requests at runtime.

## Develop

```bash
npm install          # install dependencies
npm run dev          # local dev server at http://localhost:4321
npm run check        # astro check (typecheck) — same gate CI runs
npm run build        # production build → dist/
npm run preview      # serve the production build locally
```

No system Node? `./scripts/bootstrap.sh` installs Node, the dependencies, and
the Playwright browser in one idempotent step.

## Structure

```
hero/            demo generators + the fauxware binaries (see hero/README.md)
src/
  assets/        logo, screenshots, generated notebooks (json), CLI casts, GUI shots
  components/    one .astro file per section (Hero, Features, …)
  data/          content: feature cards, code demos, ecosystem links
  layouts/       Base.astro — <head>, SEO/OG meta, theme init, scroll-reveal
  lib/           icon set (inline SVG line icons)
  pages/         index.astro, 404.astro
  styles/        global.css — design tokens, themes, components, animations
```

## Demos: the hero and the showcase

The hero and the showcase section ("Any interface. Any language. Any
analysis.") are generated from **real angr runs** driven by
[`hero/`](hero/). The showcase is a 3 × 3 × 3 picker — CLI / IPython / GUI ×
C / Go / Rust × decompile / disassemble / symbolic execution — over the same
`fauxware` program built from each language:

- **IPython** tiles (and the hero carousel) are static notebooks, built by
  `build_notebooks.py` → `src/assets/hero/notebooks.json`.
- **CLI** tiles are animated
  [asciinema-player](https://github.com/asciinema/asciinema-player) playback,
  built by `record_cli.py` → `src/assets/cli/*.cast` + `manifest.json`.
- **GUI** tiles are angr-management screenshots (light + dark), taken headless
  by `shoot_gui.py` → `src/assets/gui/*.png`.

The generated artifacts are committed, so the site build never needs angr
installed — only re-generating does. See [hero/README.md](hero/README.md) for the
edit → regenerate → commit workflow (`npm run gen`, or `gen:hero` / `gen:cli` /
`gen:gui`).

## Theming

Color is driven by CSS custom properties that flip on the `data-theme`
attribute (`light` | `dark`). The theme is set before first paint (no flash)
and persisted to `localStorage`, defaulting to the OS preference. To adjust the
palette, edit the token blocks at the top of `src/styles/global.css`.

## Deploy

`.github/workflows/deploy.yml` typechecks and builds on every push and PR, and
publishes `dist/` to GitHub Pages on push to `main`. The custom domain comes from
[`public/CNAME`](public/CNAME). Enable Pages → "GitHub Actions" once.
