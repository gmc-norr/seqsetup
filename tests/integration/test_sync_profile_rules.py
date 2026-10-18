"""The sync reads profiles through the input rules
(docs/design/2026-10-18-input-rules-design.md, "Step 2: application and test
profiles"): each problem, with its file, line and place, reaches the sync's
answer, the Config Sync page and the audit row, and a refused file keeps the
stored profiles as before.

Before, TestType: 5 passed the validator and stopped the sync with "'int'
object has no attribute 'lower'", naming no file, and an unknown key such as
Setings: was ignored.
"""

from .test_group_a4 import _fake_github, _test_yaml
from .test_sheet_followups import _app_profile_yaml

ORIGIN = {"Origin": "http://testserver"}
GOOD_TEST = _test_yaml("1.0.0")
GOOD_APP = _app_profile_yaml("GuardProfile", '"4.3.6"')


def _errors(result):
    return [p for p in result.problems if p.level == "error"]


class TestARefusedTestProfile:

    def test_test_type_5_is_refused_with_its_file_and_line(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        bad = GOOD_TEST.replace("TestType: WGS", "TestType: 5").replace("TestName: WGS", "TestName: Bad")
        result = _fake_github(ctx, monkeypatch, {"WGS.yaml": GOOD_TEST, "Bad.yaml": bad}).sync()

        ok, message, _count = result
        assert not ok
        (problem,) = _errors(result)
        assert (problem.file, problem.line, problem.path) == ("profiles/test_profiles/Bad.yaml", 1, ("TestType",))
        assert "profiles/test_profiles/Bad.yaml:1:11: TestType: must be text: put it in quotes" in message

    def test_a_refused_file_keeps_the_stored_profiles(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        ok, _message, _count = _fake_github(ctx, monkeypatch, {"WGS.yaml": GOOD_TEST}).sync()
        assert ok
        stored = [(p.test_type, p.version) for p in ctx.test_profile_repo.list_all()]

        result = _fake_github(ctx, monkeypatch, {"WGS.yaml": GOOD_TEST + "Owner: lab\n"}).sync()

        assert not result[0]
        assert [p.path for p in _errors(result)] == [("Owner",)]
        assert [(p.test_type, p.version) for p in ctx.test_profile_repo.list_all()] == stored


class TestARefusedApplicationProfile:

    def test_an_unknown_key_is_refused_with_its_line(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        apps = {"Guard.yaml": GOOD_APP + "Setings:\n  X: 1\n"}

        result = _fake_github(ctx, monkeypatch, {"WGS.yaml": GOOD_TEST}, app_files=apps).sync()

        assert not result[0]
        (problem,) = _errors(result)
        assert (problem.file, problem.path, problem.line) == (
            "profiles/application_profiles/Guard.yaml", ("Setings",), len(GOOD_APP.splitlines()) + 1)

    def test_a_file_with_many_problems_gives_one_line_in_the_message(self, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        apps = {"Guard.yaml": GOOD_APP + "".join(f"K{i}: 1\n" for i in range(50))}

        ok, message, _count = _fake_github(ctx, monkeypatch, {"WGS.yaml": GOOD_TEST}, app_files=apps).sync()

        assert not ok
        assert message.count("profiles/application_profiles/Guard.yaml:") == 1
        assert "and more problems in this file: see the list of problems" in message

    def test_a_linked_file_is_refused_as_github_serves_it(self, fresh_app, monkeypatch):
        """GitHub lists a link to a file as a file and serves its target
        path; the settings command reads it so too."""
        _app, ctx, _db = fresh_app
        apps = {"Guard.yaml": GOOD_APP, "Link.yaml": "Guard.yaml"}

        result = _fake_github(ctx, monkeypatch, {"WGS.yaml": GOOD_TEST}, app_files=apps).sync()

        (problem,) = _errors(result)
        assert (problem.file, problem.message) == (
            "profiles/application_profiles/Link.yaml", "must be a map of keys and values")


class TestTheAuditRowAndThePage:

    def test_a_sync_started_by_hand_audits_a_profile_problem(self, logged_in_client, fresh_app, monkeypatch):
        _app, ctx, _db = fresh_app
        bad = GOOD_TEST.replace("TestType: WGS", "TestType: 5")
        _fake_github(ctx, monkeypatch, {"WGS.yaml": bad})

        logged_in_client.post("/admin/config-sync/sync", headers=ORIGIN)

        (row,) = ctx.audit_event_repo.search(limit=20, event_prefix="config_sync.triggered")
        (record,) = row.details["problems"]
        assert (record["file"], record["line"], record["path"]) == (
            "profiles/test_profiles/WGS.yaml", 1, ["TestType"])
        page = logged_in_client.get("/admin/config-sync").text
        table = page[page.index('id="sync-problems"'):]
        assert "profiles/test_profiles/WGS.yaml" in table[:table.index("</table>")]
