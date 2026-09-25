"""Run templates can be found from the sidebar.

/templates (and its "New run" per template) was only reachable by saving
a template first; nothing linked to it.
"""

import re


class TestTemplatesInSidebar:
    def test_every_page_links_to_templates(self, logged_in_standard_client):
        page = logged_in_standard_client.get("/").text
        nav = page.split('<nav class="sidebar">', 1)[1].split("</nav>", 1)[0]
        assert 'href="/templates"' in nav

    def test_templates_page_marks_its_link_current(self, logged_in_client):
        page = logged_in_client.get("/templates").text
        assert re.search(r'href="/templates"[^>]*aria-current="page"', page)
