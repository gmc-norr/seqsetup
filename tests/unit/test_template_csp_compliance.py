"""CSP-compliance guard for Jinja templates.

The app ships a strict Content-Security-Policy (``script-src 'self'
'unsafe-eval'`` — no ``'unsafe-inline'``; see ``security_headers.py``). Under
that policy the browser BLOCKS:

  * inline event-handler attributes (``onclick=``, ``ondrop=``, ``oninput=`` …)
  * inline ``<script>`` blocks (a ``<script>`` without a ``src``)
  * ``javascript:`` URIs

A 2026-06 security pass added the CSP without auditing the templates' inline
handlers, which silently broke drag-drop index assignment, sample selection and
the entire bulk-action panel in the run editor. They were migrated to
event delegation in ``static/js/app.js``; these tests stop the regression from
ever coming back. If one fails, wire the behaviour up via delegation /
``addEventListener`` in a static JS file (or an HTMX/Alpine attribute, which run
under ``'unsafe-eval'``) instead of an inline handler.
"""

import re
from pathlib import Path

TEMPLATES_DIR = Path(__file__).resolve().parents[2] / "src" / "seqsetup" / "templates"

# Every standard HTML attribute that begins with "on" is an event handler, so
# matching ` on<word>=` precisely catches inline handlers with no false positives.
_INLINE_HANDLER = re.compile(r"\son[a-z]+\s*=", re.IGNORECASE)
# A <script ...> opening tag that carries no src= attribute → inline script.
_INLINE_SCRIPT = re.compile(r"<script(?![^>]*\ssrc=)[^>]*>", re.IGNORECASE)
_JS_URI = re.compile(r"""["'(]\s*javascript:""", re.IGNORECASE)


def _templates():
    return sorted(TEMPLATES_DIR.rglob("*.html"))


def _hits(pattern):
    found = []
    for tpl in _templates():
        text = tpl.read_text(encoding="utf-8")
        for n, line in enumerate(text.splitlines(), start=1):
            if pattern.search(line):
                found.append(f"{tpl.relative_to(TEMPLATES_DIR)}:{n}: {line.strip()}")
    return found


def test_no_inline_event_handlers():
    """No template may use an inline on*= handler (CSP-blocked)."""
    hits = _hits(_INLINE_HANDLER)
    assert not hits, (
        "Inline event-handler attributes are blocked by the app CSP. "
        "Wire these via event delegation in static/js (or an Alpine/HTMX "
        "attribute) instead:\n  " + "\n  ".join(hits)
    )


def test_no_inline_scripts():
    """No template may embed an inline <script> block (CSP-blocked)."""
    hits = _hits(_INLINE_SCRIPT)
    assert not hits, (
        "Inline <script> blocks are blocked by the app CSP (script-src 'self'). "
        "Move the code into a file under static/js/ and load it with "
        "<script src=...>:\n  " + "\n  ".join(hits)
    )


def test_no_javascript_uris():
    """No template may use a javascript: URI (CSP-blocked)."""
    hits = _hits(_JS_URI)
    assert not hits, (
        "javascript: URIs are blocked by the app CSP:\n  " + "\n  ".join(hits)
    )


def test_guard_regex_actually_detects_a_handler():
    """Self-check: the handler regex must catch a real inline handler."""
    assert _INLINE_HANDLER.search('<button onclick="x()">')
    assert _INLINE_SCRIPT.search("<script>alert(1)</script>")
    assert not _INLINE_SCRIPT.search('<script defer src="/x.js"></script>')
