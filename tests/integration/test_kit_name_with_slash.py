"""A kit whose name holds a "/" can be opened, downloaded and deleted.

The shipped ``IDT for Illumina DNA/RNA UD Indexes Set A`` (idt_udi_set_a.yaml)
answered 404 on its detail page and its download, and its Delete missed,
because each route took the name as one path segment: the "/" in the name made
an extra segment, so nothing matched. The kit stayed usable in runs, so a lab
could not see what it contained or remove it. The version is the last segment
of the path now, and the name is everything before it.
"""

from pathlib import Path
from urllib.parse import quote

import pytest

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexType
from seqsetup.services.index_kit_sync_parser import IndexKitSyncParser

ORIGIN = {"Origin": "http://testserver"}
SHIPPED = Path(__file__).resolve().parents[2] / "config" / "indexes" / "idt_udi_set_a.yaml"
SLASH_NAME = "IDT for Illumina DNA/RNA UD Indexes Set A"


@pytest.fixture
def slash_kit(fresh_app):
    """The shipped kit whose name holds a "/", stored as it ships."""
    _app, ctx, _db = fresh_app
    kit = IndexKitSyncParser.parse(SHIPPED.read_text(), SHIPPED.name)
    assert kit.name == SLASH_NAME, kit.name
    ctx.index_kit_repo.save(kit)
    return kit


def _plain_kit(ctx) -> IndexKit:
    kit = IndexKit(
        name="Plain kit", version="1", index_mode=IndexMode.SINGLE,
        i7_indexes=[Index(name="A", sequence="ACGTACGT", index_type=IndexType.I7)],
    )
    ctx.index_kit_repo.save(kit)
    return kit


def _paths(kit):
    """The path as the list page writes it (Jinja's urlencode leaves "/"),
    and with the name fully percent-encoded."""
    return [
        ("as the page links it", f"{quote(kit.name)}/{quote(kit.version)}"),
        ("percent-encoded", f"{quote(kit.name, safe='')}/{quote(kit.version, safe='')}"),
    ]


class TestTheDetailPage:
    @pytest.mark.parametrize("label,path", _paths(
        IndexKit(name=SLASH_NAME, version="1.0.0")), ids=lambda v: str(v)[:20])
    def test_it_opens(self, logged_in_client, slash_kit, label, path):
        resp = logged_in_client.get(f"/indexes/detail/{path}")

        assert resp.status_code == 200, resp.text[:200]
        assert "RNA UD Indexes Set A" in resp.text

    def test_a_name_without_a_slash_still_opens(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        kit = _plain_kit(ctx)

        resp = logged_in_client.get(f"/indexes/detail/{quote(kit.name)}/{kit.version}")

        assert resp.status_code == 200, resp.text[:200]
        assert "Plain kit" in resp.text

    def test_a_kit_that_is_not_there_is_still_404(self, logged_in_client, fresh_app):
        resp = logged_in_client.get("/indexes/detail/No%20such/kit/1.0.0")

        assert resp.status_code == 404


class TestTheDownload:
    @pytest.mark.parametrize("label,path", _paths(
        IndexKit(name=SLASH_NAME, version="1.0.0")), ids=lambda v: str(v)[:20])
    def test_it_sends_the_yaml(self, logged_in_client, slash_kit, label, path):
        resp = logged_in_client.get(f"/indexes/download/{path}")

        assert resp.status_code == 200, resp.text[:200]
        assert f"name: {SLASH_NAME}" in resp.text
        assert "attachment" in resp.headers["content-disposition"]

    def test_a_kit_that_is_not_there_is_still_404(self, logged_in_client, fresh_app):
        assert logged_in_client.get("/indexes/download/No%20such/kit/1.0.0").status_code == 404


class TestTheDelete:
    def test_it_removes_the_kit(self, logged_in_client, fresh_app, slash_kit):
        _app, ctx, _db = fresh_app
        path = f"{quote(slash_kit.name)}/{quote(slash_kit.version)}"

        resp = logged_in_client.request("DELETE", f"/indexes/kits/{path}", headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:200]
        assert ctx.index_kit_repo.get_by_name_and_version(SLASH_NAME, "1.0.0") is None

    def test_it_removes_the_kit_when_the_name_is_percent_encoded(
            self, logged_in_client, fresh_app, slash_kit):
        _app, ctx, _db = fresh_app
        path = f"{quote(slash_kit.name, safe='')}/{slash_kit.version}"

        resp = logged_in_client.request("DELETE", f"/indexes/kits/{path}", headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:200]
        assert ctx.index_kit_repo.get_by_name_and_version(SLASH_NAME, "1.0.0") is None

    def test_a_name_without_a_slash_still_deletes(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        kit = _plain_kit(ctx)

        resp = logged_in_client.request(
            "DELETE", f"/indexes/kits/{quote(kit.name)}/{kit.version}", headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:200]
        assert ctx.index_kit_repo.get_by_name_and_version("Plain kit", "1") is None

    def test_a_kit_that_is_not_there_is_still_404(self, logged_in_client, fresh_app):
        resp = logged_in_client.request(
            "DELETE", "/indexes/kits/No%20such/kit/1.0.0", headers=ORIGIN)

        assert resp.status_code == 404


class TestTheListPage:
    def test_its_links_reach_the_kit(self, logged_in_client, slash_kit):
        page = logged_in_client.get("/indexes").text
        links = [line.split('href="', 1)[1].split('"', 1)[0]
                 for line in page.splitlines() if 'href="/indexes/detail/' in line]
        assert links

        for link in links:
            assert logged_in_client.get(link).status_code == 200, link
