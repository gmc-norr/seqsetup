"""Every audit() argument that carries a web address is cleaned strictly.

audit() cleans addresses inside free text only when they are unambiguous
(``://`` or ``//``). A configured URL may have neither
(``svc:PASSWORD@lims.example.com?api_token=...``), so it must travel under a
details key named like ``url`` / ``*_url`` (cleaned by key) or be wrapped in
``redact_url(...)``. This test reads every audit() call in src/, so a new
call site cannot forget.
"""

import ast
from pathlib import Path

from seqsetup.services.audit_log import _ADDRESS_KEY_RE

SRC = Path(__file__).resolve().parents[2] / "src" / "seqsetup"


def _url_arguments():
    """(where, name, source, node) for each non-constant audit() argument
    whose source text mentions 'url'."""
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text()
        for node in ast.walk(ast.parse(text)):
            if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "audit"):
                continue
            named = [("target", a) for i, a in enumerate(node.args) if i == 2]
            named += [(k.arg or "**", k.value) for k in node.keywords]
            for name, value in named:
                if isinstance(value, ast.Constant):
                    continue
                source = ast.get_source_segment(text, value) or ""
                if "url" in source.lower():
                    yield f"{path.relative_to(SRC)}:{node.lineno}", name, source, value


class TestAuditCallSites:
    """Configured web addresses reach audit() only in a strictly cleaned form."""

    def test_the_known_url_arguments_are_found(self):
        # 4 details keys (server_url, repo_url, 2x base_url) + 4 targets
        # (lims.url_blocked, 3x scheduled sync). Fewer means the scan is blind.
        assert len(list(_url_arguments())) >= 8

    def test_url_arguments_are_cleaned_strictly(self):
        offenders = []
        for where, name, source, value in _url_arguments():
            wrapped = (isinstance(value, ast.Call)
                       and getattr(value.func, "id", None) == "redact_url")
            by_key = name not in ("target", "**") and _ADDRESS_KEY_RE.fullmatch(name.lower())
            if not (wrapped or by_key):
                offenders.append(f"{where} {name}={source}")
        assert offenders == []
