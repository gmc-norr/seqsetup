"""The problems the input rules find reach the admin: on the sync's answer,
the sync page and every sync's audit row, each within its store's size
(docs/design/2026-10-18-input-rules-design.md, "6. Where problems are shown").

Before, a refused instrument file left one joined-up message, a manual sync's
audit row held the outcome and a count only, and a warning went to the log
alone.
"""

from pathlib import Path

import bson
import pytest

from seqsetup.models.audit_event import MAX_DETAILS_BYTES
from seqsetup.services.scheduler import ProfileSyncScheduler

from .test_group_a4 import _fake_github, _test_yaml

ORIGIN = {"Origin": "http://testserver"}
CONFIG = Path(__file__).resolve().parents[2] / "config"
GOOD = (CONFIG / "instruments" / "novaseq-x-series.yaml").read_text()
TESTS = {"WGS.yaml": _test_yaml("1.0.0")}


def _typo():
    rows = GOOD.splitlines(keepends=True)
    lanes = next(i for i, row in enumerate(rows) if row.strip().startswith("lanes:"))
    indent = rows[lanes][:len(rows[lanes]) - len(rows[lanes].lstrip())]
    rows.insert(lanes + 1, f"{indent}lane: 2\n")
    return "".join(rows), lanes + 2


LANE_TYPO, TYPO_LINE = _typo()


def _service(ctx, monkeypatch, files):
    return _fake_github(ctx, monkeypatch, TESTS, instrument_files=files)


def _scheduled(ctx, service):
    config = ctx.profile_sync_config_repo.get()
    config.sync_enabled = True
    config.last_sync_at = None
    ctx.profile_sync_config_repo.save(config)
    ProfileSyncScheduler(service, ctx.profile_sync_config_repo)._check_and_sync()


def _audit_rows(ctx, prefix):
    return ctx.audit_event_repo.search(limit=20, event_prefix=prefix)


class TestTheSyncAnswersWithItsProblems:

    def test_a_refused_file_s_problem_has_its_file_and_line(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        result = _service(ctx, monkeypatch, {"nx.yaml": LANE_TYPO}).sync()

        ok, message, _count = result
        assert not ok
        (problem,) = [p for p in result.problems if p.level == "error"]
        assert (problem.file, problem.line, problem.path[-1]) == ("instruments/nx.yaml", TYPO_LINE, "lane")
        assert f"instruments/nx.yaml:{TYPO_LINE}:" in message

    def test_a_good_sync_has_none(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        result = _service(ctx, monkeypatch, {"nx.yaml": GOOD}).sync()

        assert result[0], result[1]
        assert result.problems == []


class TestTheMessageKeepsEveryRefusal:
    """A refused instrument file once put every one of its problems (up to
    1,000) in the sync's message, so the cut to fit the store dropped what
    came after: the kit and profile refusals, and "Mark Ready stays paused",
    which the scheduler reads to wait its interval. The message names the
    file and its first problem; the list of problems has them all."""

    def test_a_file_with_many_problems_gives_one_short_line(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        junk = "".join(f"k{i}: 1\n" for i in range(300))

        ok, message, _count = _service(ctx, monkeypatch, {"nx.yaml": GOOD + junk}).sync()

        assert not ok
        assert message.count("instruments/nx.yaml:") == 1
        assert "and more problems in this file: see the list of problems" in message
        assert "k0: is not a key" in message and "k1: is not a key" not in message


class TestTheSyncPage:

    def test_lists_each_problem_with_its_file_line_and_place(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _service(ctx, monkeypatch, {"nx.yaml": LANE_TYPO}).sync()

        page = logged_in_client.get("/admin/config-sync").text

        table = page[page.index('id="sync-problems"'):]
        table = table[:table.index("</table>")]
        assert "instruments/nx.yaml" in table
        assert f">{TYPO_LINE}<" in table
        assert "lane" in table and "is not a key this file can have" in table

    def test_says_how_many_are_not_shown_when_none_fit(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        config = ctx.profile_sync_config_repo.get()
        config.last_sync_status = "error"
        config.last_sync_problems = []
        config.last_sync_problem_count = config.last_sync_problems_left_out = 7
        ctx.profile_sync_config_repo.save(config)

        page = logged_in_client.get("/admin/config-sync").text

        assert "7 problems are not shown here" in page

    def test_shows_a_warning_from_a_good_sync(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        teal = GOOD.replace('dye_channels: ["Blue", "Green"]', 'dye_channels: ["Blue", "Teal"]')
        assert teal != GOOD
        ok, _message, _count = _service(ctx, monkeypatch, {"nx.yaml": teal}).sync()
        assert ok

        page = logged_in_client.get("/admin/config-sync").text

        table = page[page.index('id="sync-problems"'):]
        assert "warning" in table[:table.index("</table>")]


class TestEverySyncsAuditRow:

    def test_a_sync_started_by_hand(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _service(ctx, monkeypatch, {"nx.yaml": LANE_TYPO})

        logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)

        (row,) = _audit_rows(ctx, "config_sync.triggered")
        assert row.details["problem_count"] == 1
        (record,) = row.details["problems"]
        assert (record["file"], record["line"]) == ("instruments/nx.yaml", TYPO_LINE)
        assert "instruments/nx.yaml" in row.details["message"]

    def test_a_sync_started_by_the_scheduler(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        _scheduled(ctx, _service(ctx, monkeypatch, {"nx.yaml": LANE_TYPO}))

        (row,) = _audit_rows(ctx, "config_sync.scheduled.completed")
        assert row.outcome == "failure"
        assert row.details["problem_count"] == 1
        assert row.details["problems"][0]["line"] == TYPO_LINE


class TestAKeyNoStoreCanHold:
    """A key past MongoDB's 64 bits, or half a character, once stopped the
    sync after it had written the reference data: a sync started by hand
    left no audit row, and a scheduled one no finish time, so the scheduler
    synced again on every check."""

    JUNK = [
        "reagent_kit_max_cycles: {99999999999999999999: 0x10}\n",
        'reagent_kit_max_cycles: {"\\ud800": 1, "\\ud800": 2}\n',
    ]

    @pytest.mark.parametrize("junk", JUNK)
    def test_a_sync_started_by_hand(self, logged_in_client, fresh_app, monkeypatch, junk):
        _app, ctx, _db = fresh_app
        _service(ctx, monkeypatch, {"nx.yaml": GOOD + junk})

        logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)

        config = ctx.profile_sync_config_repo.get()
        assert config.last_sync_status == "error"
        assert config.last_sync_problem_count >= 1
        (row,) = _audit_rows(ctx, "config_sync.triggered")
        assert row.details["problem_count"] >= 1

    @pytest.mark.parametrize("junk", JUNK)
    def test_a_sync_started_by_the_scheduler(self, fresh_app, monkeypatch, junk):
        _app, ctx, _db = fresh_app
        _scheduled(ctx, _service(ctx, monkeypatch, {"nx.yaml": GOOD + junk}))

        assert ctx.profile_sync_config_repo.get().last_sync_at is not None
        (row,) = _audit_rows(ctx, "config_sync.scheduled.completed")
        assert row.details["problem_count"] >= 1


class TestALongReportStillFits:
    """Five files of 1,500 long unknown keys each: 7,500 problems, cut at
    1,000 per file (and once about 1.3 MB of message)."""

    @staticmethod
    def _files():
        junk = "".join(f"{'k' * 190}{i:05d}: 1\n" for i in range(1500))
        return {f"f{n}.yaml": GOOD + junk for n in range(5)}

    def test_the_sync_status_keeps_its_counts_within_its_budget(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        result = _service(ctx, monkeypatch, self._files()).sync()

        config = ctx.profile_sync_config_repo.get()
        assert len(result.problems) == 5 * 1001
        assert config.last_sync_problem_count == 5 * 1001
        assert config.last_sync_problems_left_out == 5 * 1001 - len(config.last_sync_problems)
        stored = {"m": config.last_sync_message, "p": config.last_sync_problems}
        assert len(bson.encode(stored)) <= 1024 * 1024
        assert all(config.last_sync_message.count(f"instruments/f{n}.yaml:") == 1 for n in range(5))
        assert "[cut:" not in config.last_sync_message

    def test_an_audit_row_keeps_its_details_after_addresses_are_cleaned(
            self, logged_in_client, fresh_app, monkeypatch):
        """audit() writes each web address in a text as "[address removed]",
        so 2,000 keys of "//[ //[ ..." once grew a report cut to its budget
        past the row's limit, and the row kept no details at all."""
        _app, ctx, _db = fresh_app
        junk = "".join(f"{'//[ ' * 40}{i}: 1\n" for i in range(2000))
        service = _service(ctx, monkeypatch, {"nx.yaml": GOOD + junk})

        logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)
        _scheduled(ctx, service)

        for prefix in ("config_sync.triggered", "config_sync.scheduled.completed"):
            (row,) = _audit_rows(ctx, prefix)
            assert "details_omitted" not in row.details, prefix
            assert row.details["problem_count"] == 1001

    def test_both_audit_rows_keep_their_details(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        service = _service(ctx, monkeypatch, self._files())

        logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)
        _scheduled(ctx, service)

        for prefix in ("config_sync.triggered", "config_sync.scheduled.completed"):
            (row,) = _audit_rows(ctx, prefix)
            assert "details_omitted" not in row.details, prefix
            assert row.details["problem_count"] == 5 * 1001
            assert len(bson.encode({"details": row.details})) <= MAX_DETAILS_BYTES
