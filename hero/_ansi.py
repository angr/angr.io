"""
ANSI → HTML for the website's generated terminal output (shared by the
notebook builder and the CLI capture).
"""
import html
import re

SGR = re.compile(r"\x1b\[([0-9;]*)m")


def ansi_to_html(text):
    """Convert a string with ANSI SGR color codes into HTML spans.

    Maps the 16 standard ANSI colors to `.a0`–`.a15` classes (themed in CSS).
    Text with no escape codes comes back as plain, escaped text — so we never
    invent coloring the terminal didn't actually produce.
    """
    out = []
    pos = 0
    open_span = False
    for m in SGR.finditer(text):
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
