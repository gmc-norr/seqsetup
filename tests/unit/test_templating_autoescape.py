"""Every template escapes what it prints, whatever its file name (group 3b).
Starlette 1.x turns autoescape on only for names ending .html, .htm or .xml;
SeqSetup keeps it on for every template, as Starlette 0.x did."""

import pytest

from seqsetup.templating import templates


class TestTemplatesEscape:
    """templates.env, the one Jinja2 environment for HTML routes."""

    @pytest.mark.parametrize("name", ["page.html", "note.txt", "mail.j2", "noext"])
    def test_autoescape_is_on_for_every_name(self, name):
        autoescape = templates.env.autoescape
        assert (autoescape(name) if callable(autoescape) else autoescape) is True
