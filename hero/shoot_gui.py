#!/usr/bin/env python3
# /// script
# requires-python = ">=3.12"
# dependencies = ["angr[unicorn]", "angr-management"]
# ///
"""
Screenshot angr-management for the hero window's GUI tiles.

Drives the real angr-management (headless, Qt "offscreen" platform) for each
binary in `binaries/` and each analysis — disassembly graph, decompilation,
symbolic execution — and saves the window as a HiDPI PNG:

    src/assets/gui/<lang>-<mode>-<theme>.png

Nothing is mocked: the app loads the binary, runs its own CFG recovery job,
decompiles through its own pseudocode view, and explores with its own
simulation-manager widget — the screenshot is whatever ends up on screen.

Needs the Qt runtime libraries the PySide6 wheel does not bundle; on a machine
without them, `nix-shell hero/shell.nix` provides everything (see hero/README).

    python hero/shoot_gui.py            # skips if up to date
    python hero/shoot_gui.py --force
"""
import gc
import glob
import os
import sys
import time

# angr-management runs with the cyclic GC disabled (it collects on a timer).
# Match that: with it enabled, the parent states in a path tree get collected
# between steps and their nodes lose their address (breaking the tree layout).
gc.disable()

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
os.environ.setdefault("QT_SCALE_FACTOR", "2")  # HiDPI capture, like a Retina screenshot
os.environ.setdefault("QT_LOGGING_RULES", "*.debug=false;qt.qpa.*=false")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT_DIR = os.path.normpath(os.path.join(HERE, "..", "src", "assets", "gui"))
BIN_DIR = os.path.join(HERE, "binaries")

# Logical window size (device pixels = this × QT_SCALE_FACTOR).
WIDTH, HEIGHT = 1440, 900
THEMES = ["light", "dark"]
THEME_NAMES = {"light": "Light", "dark": "Dark"}
LANGS = ["c", "go", "rust"]
MODES = ["decompile", "disasm", "symexec"]


def main_window_setup(theme: str):
    """Bring up angr-management the way its own entry point does, minus splash."""
    from PySide6.QtCore import QThread
    from PySide6.QtGui import QFontDatabase
    from PySide6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication(sys.argv)
    app.setApplicationDisplayName("angr management")

    import angr
    from angrmanagement.config import Conf
    from angrmanagement.config.color_schemes import BASE_SCHEME, COLOR_SCHEMES
    from angrmanagement.consts import FONT_LOCATION
    from angrmanagement.logic import GlobalInfo
    from angrmanagement.ui.css import refresh_theme
    from angrmanagement.ui.main_window import MainWindow

    # Apply one of the built-in color schemes exactly like the preferences dialog.
    name = THEME_NAMES[theme]
    scheme = COLOR_SCHEMES[name] if name == BASE_SCHEME else {**COLOR_SCHEMES[BASE_SCHEME], **COLOR_SCHEMES[name]}
    for prop, value in scheme.items():
        setattr(Conf, prop, value)
    Conf.theme_name = name
    Conf.base_theme_name = name
    refresh_theme()

    for font_file in glob.glob(os.path.join(FONT_LOCATION, "*.ttf")):
        QFontDatabase.addApplicationFont(font_file)
    Conf.init_font_config()
    app.setFont(Conf.ui_default_font)
    angr.procedures.definitions.load_all_definitions()

    # Headless: nobody can answer the first-run "register angr:// URL scheme?"
    # question, so mark it as already asked.
    Conf.prompted_for_url_scheme_registration = True

    GlobalInfo.gui_thread = QThread.currentThread()
    mw = MainWindow(app=app, show=False, use_daemon=False, use_mcp=False)
    mw.resize(WIDTH, HEIGHT)
    mw.show()
    mw.initialized = True
    mw.workspace.view_manager.main_window_initialized()
    pump(app, 0.5)
    return app, mw


def pump(app, seconds: float) -> None:
    """Process Qt events for a while (lets views lay out and paint)."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.01)


def wait_jobs(app, mw, timeout: float = 600.0) -> None:
    """Block until angr-management's job queue has drained (CFG, decompile, ...)."""
    end = time.monotonic() + timeout
    jm = mw.workspace.job_manager
    while time.monotonic() < end:
        jm.join_all_jobs(wait_period=0.3)
        if not jm.jobs:
            return
    raise SystemExit("timed out waiting for angr-management jobs")


def load_binary(app, mw, path: str):
    """Open a binary the way File → Open does, minus the modal load dialog.

    Setting the project on the instance is what the load job does once the
    dialog is accepted; it then triggers the default analyses (CFG, ...) on
    angr-management's own job queue.
    """
    import angr

    inst = mw.workspace.main_instance
    inst.binary_path = path
    inst.original_binary_path = path
    proj = angr.Project(path, auto_load_libs=False, load_options={"load_debug_info": True})
    inst._reset_containers()
    inst.project.am_obj = proj
    inst.project.am_event()
    pump(app, 0.5)
    # Wait for CFG recovery (and whatever else the default configuration runs).
    end = time.monotonic() + 900
    while time.monotonic() < end:
        wait_jobs(app, mw)
        if not inst.cfg.am_none and len(inst.project.kb.functions) > 0 and not mw.workspace.job_manager.jobs:
            break
        pump(app, 0.2)
    pump(app, 1.0)
    return inst.project


def demangled(proj):
    """Map demangled name -> Function (Rust symbols are mangled in the kb)."""
    return {f.demangled_name: f for f in proj.kb.functions.values()}


# Which function each (language, mode) focuses on, and how symexec is set up.
# Rust/Go: start at the program's own main (skipping the language runtime's
# bootstrap) — the same recipe the IPython/CLI demos use.
def plan(lang: str, proj):
    funcs = demangled(proj)
    sym = lambda n: proj.loader.find_symbol(n).rebased_addr  # noqa: E731
    if lang == "c":
        return {
            "decompile": proj.kb.functions["main"],
            "disasm": proj.kb.functions["authenticate"],
            "start": None,  # entry state
            "find": sym("accepted"),
            "avoid": [],
        }
    if lang == "go":
        return {
            "decompile": proj.kb.functions["main.main"],
            "disasm": proj.kb.functions["main.authenticate"],
            "start": sym("main.main"),
            "find": sym("main.accepted"),
            "avoid": [sym("runtime.morestack_noctxt.abi0")],
        }
    if lang == "rust":
        return {
            "decompile": funcs["fauxware::main"],
            "disasm": funcs["fauxware::authenticate"],
            "start": funcs["fauxware::main"].addr,
            "find": funcs["fauxware::accepted"].addr,
            "avoid": [],
        }
    raise ValueError(lang)


def shoot_disasm(app, mw, func) -> None:
    from PySide6.QtCore import QPointF

    ws = mw.workspace
    ws.show_graph_disassembly_view()
    pump(app, 0.3)
    ws.jump_to(func.addr)
    pump(app, 1.5)
    # Zoom the graph out so the whole function is in view (never in, and not
    # below a readable size — then show it from the top, like a user would).
    view = ws.view_manager.first_view_in_category("disassembly")
    graph = view.current_graph
    rect = graph.scene().itemsBoundingRect()
    vp = graph.viewport().rect()
    if rect.width() > 0 and rect.height() > 0:
        fit_w = vp.width() / rect.width()
        scale = min(fit_w, vp.height() / rect.height(), 1.0)
        if scale < 0.5:
            # Too tall to fit at a readable size: fit the width, scroll vertically.
            scale = max(min(fit_w, 1.0), 0.4)
        graph.resetTransform()
        graph.scale(scale, scale)
        if rect.height() * scale <= vp.height():
            graph.centerOn(rect.center())
        else:
            graph.centerOn(QPointF(rect.center().x(), rect.top() + vp.height() / (2 * scale)))
    pump(app, 1.0)


def shoot_decompile(app, mw, func) -> None:
    ws = mw.workspace
    ws.decompile_function(func)
    wait_jobs(app, mw)
    pump(app, 1.5)
    # Rust/Go output opens with the recovered type definitions; scroll so the
    # function itself is what's on screen.
    view = ws.view_manager.first_view_in_category("pseudocode")
    te = view.textedit if view is not None else None
    if te is not None:
        needle = f"{func.demangled_name}("
        block = te.document().begin()
        while block.isValid():
            text = block.text()
            if needle in text and text[:1] not in (" ", "\t"):
                te.verticalScrollBar().setValue(max(0, block.blockNumber() - 1))
                break
            block = block.next()
    pump(app, 1.0)


def shoot_symexec(app, mw, proj, start, find, avoid) -> None:
    from angrmanagement.ui.views.symexec_view import SymexecView

    ws = mw.workspace
    # New state — what the "New State" dialog would build.
    if start is None:
        state = proj.factory.entry_state()
        name = "entry"
    else:
        state = proj.factory.blank_state(addr=start)
        name = f"main @ {start:#x}"
    state.gui_data.base_name = name
    state.gui_data.is_base = True
    state.gui_data.name = name
    # Same as Workspace.create_simulation_manager, except the hierarchy keeps
    # a strong reference to every state it sees. angr frees a state once it
    # has been stepped; the PathTree only holds weak references, so by the
    # time it draws, the fork points have no state (and no address) left and
    # the layout aborts (angr-management #1644 territory). Holding on to them
    # gives the tree the branch nodes a user sees when stepping by hand.
    from angr.state_hierarchy import StateHierarchy
    from angrmanagement.data.object_container import ObjectContainer

    inst = ws.main_instance
    hierarchy = StateHierarchy()
    keep = []
    _add_state = hierarchy.add_state
    hierarchy.add_state = lambda s: (keep.append(s), _add_state(s))[1]
    simgr = proj.factory.simulation_manager(state, hierarchy=hierarchy)
    simgr_container = ObjectContainer(simgr, name=name)
    inst.simgrs.append(simgr_container)
    inst.simgrs.am_event(src="new_path")
    ws.show_symexec_view()
    view = ws.view_manager.first_view_in_category("symexec")
    view.select_simgr(simgr_container)
    ws.raise_view(view)
    view._keep_states_alive = keep
    assert isinstance(view, SymexecView)
    view.find_addr_in_exec(find)
    for a in avoid:
        view.avoid_addr_in_exec(a)
    pump(app, 0.3)
    # Press "Explore".
    view._simgrs._on_explore_clicked()
    wait_jobs(app, mw)
    pump(app, 1.0)
    # Select the found state so the inspector shows it.
    simgr = view.current_simgr.am_obj.am_obj
    found = simgr.stashes.get("found", [])
    if found:
        view.select_states(found[:1])
        view.current_state.am_obj = found[0]
        view.current_state.am_event(src="shoot")
    pump(app, 1.5)


def grab(mw, path: str) -> None:
    pix = mw.grab()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    pix.save(path, "PNG")
    print(f"  {os.path.relpath(path)}  ({pix.width()}x{pix.height()})", flush=True)


def _up_to_date(outputs, *sources):
    try:
        out_mtime = min(os.path.getmtime(o) for o in outputs)
    except (OSError, ValueError):
        return False
    return all(os.path.getmtime(s) <= out_mtime for s in sources)


def main() -> None:
    only = [a for a in sys.argv[1:] if not a.startswith("--")]
    outputs = [os.path.join(OUT_DIR, f"{l}-{m}-{t}.png") for l in LANGS for m in MODES for t in THEMES]
    sources = [os.path.abspath(__file__)] + [os.path.join(BIN_DIR, l, "fauxware") for l in LANGS]
    if "--force" not in sys.argv and not only and _up_to_date(outputs, *sources):
        print("GUI screenshots are up to date — skipping (--force to rebuild)")
        return

    for theme in THEMES:
        for lang in LANGS:
            wanted = [m for m in MODES if not only or f"{lang}-{m}-{theme}" in only or f"{lang}-{m}" in only]
            if not wanted:
                continue
            # A fresh window per binary: views (and their state watchers) are
            # per-project, and reusing them across projects leaves stale ones.
            app, mw = main_window_setup(theme)
            proj = load_binary(app, mw, os.path.join(BIN_DIR, lang, "fauxware"))
            p = plan(lang, proj)
            for mode in wanted:
                if mode == "disasm":
                    shoot_disasm(app, mw, p["disasm"])
                elif mode == "decompile":
                    shoot_decompile(app, mw, p["decompile"])
                else:
                    shoot_symexec(app, mw, proj, p["start"], p["find"], p["avoid"])
                grab(mw, os.path.join(OUT_DIR, f"{lang}-{mode}-{theme}.png"))
            mw.workspace.close_project()
            pump(app, 0.5)
            mw.close()
            pump(app, 0.5)
    print(f"wrote screenshots to {OUT_DIR}")


if __name__ == "__main__":
    main()
