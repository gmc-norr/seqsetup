"""GET /admin/audit: admin-only, newest first, filters, pages."""

import html
import re
from datetime import datetime, timedelta, timezone

from seqsetup.models.audit_event import AuditEvent

T0 = datetime(2026, 9, 20, 12, 0, 0, tzinfo=timezone.utc)


def _seed(ctx, n, **kw):
    for i in range(n):
        ctx.audit_event_repo.append(AuditEvent(
            timestamp=T0 + timedelta(minutes=i),
            event=kw.get("event", "seed.event"),
            actor=kw.get("actor", "seeder"),
            target=f"{kw.get('prefix', 'tgt')}-{i:03d}",
        ))


def _older_url(page: str) -> str:
    m = re.search(r'href="(/admin/audit\?[^"]*before_ts=[^"]+)"', page)
    return html.unescape(m.group(1)) if m else ""


class TestAuditPageAccess:
    """Only admins see the trail."""

    def test_renders_for_admin(self, logged_in_client):
        r = logged_in_client.get("/admin/audit")
        assert r.status_code == 200
        assert 'id="audit-page"' in r.text
        assert "Audit trail" in r.text

    def test_htmx_gets_the_fragment(self, logged_in_client):
        r = logged_in_client.get("/admin/audit", headers={"HX-Request": "true"})
        assert r.status_code == 200
        assert "<html" not in r.text
        assert 'id="audit-page"' in r.text

    def test_standard_user_is_refused(self, logged_in_standard_client):
        assert logged_in_standard_client.get("/admin/audit").status_code == 403

    def test_anonymous_is_sent_to_login(self, client):
        r = client.get("/admin/audit", follow_redirects=False)
        assert r.status_code in (302, 303)
        assert "/login" in r.headers["location"]

    def test_admin_nav_links_to_it(self, logged_in_client):
        # /admin/users: a page with no Audit-trail link of its own (the Logs
        # page has one in its text, which would hide a missing nav link).
        page = logged_in_client.get("/admin/users").text
        assert 'href="/admin/audit" class="nav-item' in page


class TestAuditPageFilters:
    """Each filter narrows the list; the search boxes allow the field's full length."""

    def test_event_prefix(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _seed(ctx, 2, event="kit.uploaded", prefix="kit")
        _seed(ctx, 2, event="run.deleted", prefix="run")
        page = logged_in_client.get("/admin/audit", params={"event": "kit"}).text
        assert "kit-000" in page and "run-000" not in page

    def test_actor(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _seed(ctx, 1, actor="carol", prefix="carols")
        _seed(ctx, 1, actor="dave", prefix="daves")
        page = logged_in_client.get("/admin/audit", params={"actor": "carol"}).text
        assert "carols-000" in page and "daves-000" not in page

    def test_long_target_is_found_by_exact_search(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        long_target = "https://lims.example.com/" + "p" * 275
        assert len(long_target) == 300
        ctx.audit_event_repo.append(AuditEvent(timestamp=T0, event="seed.long", target=long_target))
        page = logged_in_client.get("/admin/audit", params={"target": long_target}).text
        assert "seed.long" in page

    def test_date_range_is_inclusive(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        for day in (19, 20, 21):
            ctx.audit_event_repo.append(AuditEvent(
                timestamp=datetime(2026, 9, day, 23, 59, tzinfo=timezone.utc),
                event="seed.day", target=f"day-{day}"))
        page = logged_in_client.get(
            "/admin/audit", params={"date_from": "2026-09-20", "date_to": "2026-09-20"}).text
        assert "day-20" in page and "day-19" not in page and "day-21" not in page

    def test_bad_date_shows_a_message(self, logged_in_client):
        r = logged_in_client.get("/admin/audit", params={"date_from": "26/09/2026"})
        assert r.status_code == 200
        assert "Dates must be real dates, written like 2026-09-26." in r.text

    def test_last_possible_date_shows_a_message(self, logged_in_client):
        """The day after 9999-12-31 does not exist; that is a message, not a 500."""
        r = logged_in_client.get("/admin/audit", params={"date_to": "9999-12-31"})
        assert r.status_code == 200
        assert "Dates must be real dates, written like 2026-09-26." in r.text

    def test_no_match_says_so(self, logged_in_client):
        page = logged_in_client.get("/admin/audit", params={"actor": "nobody-at-all"}).text
        assert "No audit events match." in page


class TestAuditPagePaging:
    """100 per page, newest first; Older walks back without gaps."""

    def test_older_link_pages_back(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _seed(ctx, 105, actor="pager", prefix="pg")
        first = logged_in_client.get("/admin/audit", params={"actor": "pager"}).text
        assert "pg-104" in first and "pg-005" in first and "pg-004" not in first
        older = _older_url(first)
        assert "actor=pager" in older
        second = logged_in_client.get(older).text
        assert "pg-004" in second and "pg-000" in second and "pg-005" not in second
        assert _older_url(second) == ""

    def test_half_cursor_is_refused(self, logged_in_client):
        r = logged_in_client.get("/admin/audit", params={"before_ts": "2026-09-20T12:00:00"})
        assert r.status_code == 400
