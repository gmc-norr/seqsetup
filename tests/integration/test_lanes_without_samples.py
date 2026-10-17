"""A lane of the flow cell with no sample on it (design note
docs/design/2026-10-17-lanes-without-samples-design.md).

The Sample Sheet names no sample on such a lane, so no read from it can be
assigned to a sample, and nothing said so: a 2-lane run whose samples were
put in every lane kept lanes 1 and 2 when its flow cell became an 8-lane
one, and a paste starts in lane 1. Check now names the lanes, and Mark Ready
asks before going on, as it does for a color balance error; the answer
counts only for the run version and the lanes it was shown.
"""

import html
import re

import pytest

from seqsetup.models.sequencing_run import RunStatus
from seqsetup.services.validation import ValidationService

from .conftest import mark_ready, nothing_stored, run_version
from .test_index_safety_net import _seed_profiles
from .test_lane_out_of_range import EIGHT_LANES, ORIGIN, TWO_LANES, _draft

ALL_EIGHT = list(range(1, 9))


def _result(ctx, run_id):
    run = ctx.run_repo.get_by_id(run_id)
    return ValidationService.validate_run(
        run, test_profile_repo=ctx.test_profile_repo, app_profile_repo=ctx.app_profile_repo,
        instrument_config=ctx.instrument_config)


def _warnings(ctx, run_id):
    return [e for e in _result(ctx, run_id).configuration_errors
            if e.category == "lanes_without_samples"]


def _fields(page):
    """The hidden fields of the question's form, as the browser sends them."""
    return dict(re.findall(r'name="((?:color_balance|lanes_without_samples)[a-z_]*)" '
                           r'value="([^"]*)"', page))


def _post(client, run_id, data=None):
    return client.post(f"/runs/{run_id}/status/ready", data=data or {}, headers=ORIGIN)


def _ask(client, run_id, data=None):
    """Mark Ready, answering the color balance question if it comes first:
    two samples, as these runs have, give a lane color balance errors."""
    resp = _post(client, run_id, data)
    if "Color balance errors" in resp.text:
        resp = _post(client, run_id, {**(data or {}), **_fields(resp.text)})
    return resp


def _events(ctx, prefix):
    return ctx.audit_event_repo.search(limit=50, event_prefix=prefix)


def _asks_about_lanes(resp, lanes_text):
    page = html.unescape(resp.text)
    return (resp.headers.get("HX-Retarget") == "#ready-message"
            and "Lanes without samples" in page and lanes_text in page)


@pytest.fixture(autouse=True)
def _profiles(fresh_app):
    _app, ctx, _db = fresh_app
    _seed_profiles(ctx)


class TestTheCheckNamesTheLanes:

    def test_the_lanes_no_sample_is_on_are_named(self, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "empty-2-8", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1])

        (warning,) = _warnings(ctx, "empty-2-8")

        assert warning.severity.value == "warning"
        assert warning.message == (
            "Lanes 2, 3, 4, 5, 6, 7 and 8 have no samples: the Sample Sheet names no "
            "sample on them, so no read from them can be assigned to a sample.")
        assert _result(ctx, "empty-2-8").lanes_without_samples == [2, 3, 4, 5, 6, 7, 8]

    def test_one_lane_is_named_as_one(self, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "empty-2", TWO_LANES, s1_lanes=[1], s2_lanes=[1])

        (warning,) = _warnings(ctx, "empty-2")

        assert warning.message == (
            "Lane 2 has no samples: the Sample Sheet names no sample on it, so no read "
            "from it can be assigned to a sample.")

    def test_every_lane_with_a_sample_gives_none(self, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "full", TWO_LANES, s1_lanes=[1], s2_lanes=[2])

        assert _warnings(ctx, "full") == []
        assert _result(ctx, "full").lanes_without_samples == []

    def test_a_sample_with_no_lane_is_on_every_lane(self, fresh_app):
        """No lane means every lane: the sheet has no Lane column for it, or
        the plan refuses it (lanes_not_picked)."""
        _app, ctx, _db = fresh_app
        _draft(ctx, "no-lane", EIGHT_LANES, s1_lanes=[], s2_lanes=[1])

        assert _result(ctx, "no-lane").lanes_without_samples == []

    def test_a_run_with_no_samples_names_no_lane(self, fresh_app):
        """No samples is an error of its own, and Check waits for samples."""
        _app, ctx, _db = fresh_app
        run = _draft(ctx, "no-samples", EIGHT_LANES, s1_lanes=[1])
        run.samples = []
        ctx.run_repo.save(run)

        assert _result(ctx, "no-samples").lanes_without_samples == []
        assert _warnings(ctx, "no-samples") == []

    def test_a_lane_outside_the_flowcell_fills_no_lane(self, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "lane-3-of-2", TWO_LANES, s1_lanes=[3], s2_lanes=[1])

        assert _result(ctx, "lane-3-of-2").lanes_without_samples == [2]

    def test_the_validation_page_shows_it(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "empty-page", TWO_LANES, s1_lanes=[1], s2_lanes=[1])

        page = html.unescape(logged_in_client.get("/runs/empty-page/validation").text)

        assert "Lanes without samples: " in page
        assert "Lane 2 has no samples: the Sample Sheet names no sample on it" in page

    def test_the_check_panel_says_mark_ready_will_ask(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "empty-panel", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1, 2])

        panel = html.unescape(logged_in_client.get("/runs/empty-panel/validate-panel").text)

        assert "Lanes without samples: 3, 4, 5, 6, 7, 8 · Mark Ready will ask" in panel

    def test_the_check_panel_says_nothing_when_every_lane_has_a_sample(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "full-panel", TWO_LANES, s1_lanes=[1], s2_lanes=[2])

        panel = logged_in_client.get("/runs/full-panel/validate-panel").text

        assert "Lanes without samples" not in panel


class TestMarkReadyAsks:

    def test_it_asks_and_stores_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "ask", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1])

        resp = _ask(logged_in_client, "ask")

        assert resp.status_code == 200
        assert _asks_about_lanes(resp, "Lanes 2, 3, 4, 5, 6, 7, 8"), resp.text[:600]
        assert "Mark Ready anyway" in resp.text
        run = ctx.run_repo.get_by_id("ask")
        assert run.status == RunStatus.DRAFT and nothing_stored(ctx, run)
        (event,) = [e for e in _events(ctx, "run.status.denied")
                    if e.details["reason"] == "lanes_without_samples_unconfirmed"]
        assert event.details["reason"] == "lanes_without_samples_unconfirmed"
        assert event.details["lanes_without_samples"] == [2, 3, 4, 5, 6, 7, 8]

    def test_the_answer_marks_it_ready_and_is_recorded(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "yes", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1])
        question = _ask(logged_in_client, "yes")

        resp = _post(logged_in_client, "yes", _fields(question.text))

        assert "HX-Retarget" not in resp.headers, html.unescape(resp.text)[:600]
        assert ctx.run_repo.get_by_id("yes").status == RunStatus.READY
        (event,) = _events(ctx, "run.status.changed")
        assert event.details["lanes_without_samples_accepted"] == [2, 3, 4, 5, 6, 7, 8]

    def test_an_answer_for_an_older_version_asks_again(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "stale", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1])
        fields = _fields(_ask(logged_in_client, "stale").text)
        assert "lanes_without_samples" in fields
        assert logged_in_client.post("/runs/stale/name", data={"run_name": "Edited"},
                                     headers=ORIGIN).status_code == 200

        resp = _ask(logged_in_client, "stale", fields)

        assert _asks_about_lanes(resp, "Lanes 2, 3, 4, 5, 6, 7, 8"), resp.text[:600]
        assert ctx.run_repo.get_by_id("stale").status == RunStatus.DRAFT

    def test_an_answer_for_other_lanes_asks_again(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "other", EIGHT_LANES, s1_lanes=[1], s2_lanes=[1])
        fields = _fields(_ask(logged_in_client, "other").text)
        fields["lanes_without_samples"] = "2,3"

        resp = _post(logged_in_client, "other", fields)

        assert _asks_about_lanes(resp, "Lanes 2, 3, 4, 5, 6, 7, 8"), resp.text[:600]
        assert ctx.run_repo.get_by_id("other").status == RunStatus.DRAFT

    def test_a_run_with_a_sample_on_every_lane_is_not_asked(self, logged_in_client, fresh_app):
        """Asked about color balance only: two samples give every lane
        color balance errors."""
        _app, ctx, _db = fresh_app
        _draft(ctx, "every", EIGHT_LANES, s1_lanes=ALL_EIGHT, s2_lanes=ALL_EIGHT)

        first = _post(logged_in_client, "every")
        assert "Color balance errors" in first.text, first.text[:600]
        resp = _post(logged_in_client, "every", _fields(first.text))

        assert "Lanes without samples" not in first.text + resp.text
        assert ctx.run_repo.get_by_id("every").status == RunStatus.READY, (
            html.unescape(resp.text)[:600])


class TestAFlowcellWithMoreLanes:
    """The flow cell route keeps every sample's lanes, so samples put in
    every lane of a 2-lane flow cell are on 2 of the 8 lanes of the new one."""

    def test_mark_ready_asks_about_the_new_lanes(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "grow", TWO_LANES, s1_lanes=[1, 2], s2_lanes=[1, 2])
        assert _warnings(ctx, "grow") == []

        resp = logged_in_client.post(
            "/runs/grow/flowcell",
            data={"flowcell_type": EIGHT_LANES, "run_version": run_version(ctx, "grow")},
            headers=ORIGIN)
        assert resp.status_code == 200, resp.text[:300]
        assert ctx.run_repo.get_by_id("grow").get_sample("id-S1").lanes == [1, 2]

        resp = _ask(logged_in_client, "grow")

        assert _asks_about_lanes(resp, "Lanes 3, 4, 5, 6, 7, 8"), resp.text[:600]
        assert ctx.run_repo.get_by_id("grow").status == RunStatus.DRAFT


class TestWithAColorBalanceQuestion:
    """One sample alone in a lane gives that lane color balance errors, so
    this run is asked both: color balance first, then the empty lanes. The
    second question carries the first answer, so answering it does not ask
    the first again."""

    def test_both_are_asked_one_after_the_other(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _draft(ctx, "both", EIGHT_LANES, s1_lanes=[1], s2_lanes=[2])

        first = _post(logged_in_client, "both")
        assert "Color balance errors" in first.text, first.text[:600]
        assert "Lanes without samples" not in first.text

        second = _post(logged_in_client, "both", _fields(first.text))
        assert _asks_about_lanes(second, "Lanes 3, 4, 5, 6, 7, 8"), second.text[:600]
        assert "color_balance_lanes" in _fields(second.text)

        resp = _post(logged_in_client, "both", _fields(second.text))

        assert ctx.run_repo.get_by_id("both").status == RunStatus.READY, (
            html.unescape(resp.text)[:600])
        (event,) = _events(ctx, "run.status.changed")
        assert event.details["color_balance_accepted_lanes"] == [1, 2]
        assert event.details["lanes_without_samples_accepted"] == [3, 4, 5, 6, 7, 8]

    def test_the_test_helper_answers_both(self, logged_in_client, fresh_app):
        """conftest.mark_ready answers whichever questions come back, for
        tests about something else."""
        _app, ctx, _db = fresh_app
        _draft(ctx, "helper", EIGHT_LANES, s1_lanes=[1], s2_lanes=[2])

        mark_ready(logged_in_client, "helper", ORIGIN)

        assert ctx.run_repo.get_by_id("helper").status == RunStatus.READY
