"""The bulk panel's Override Cycles Apply with its box empty saves nothing.

Apply sent the empty box as "", which the route reads as Auto: every ticked
sample's OverrideCycles was rebuilt from its index and the run's cycles, so a
typed UMI read U8Y143;I10;I10;Y151 came back Y151;I10;I10;Y151 with a 200
and no word (project review of 7d970c7, 2026-10-21, EDITING-2). The new
value fits the run, so Mark Ready could not see it. Auto is its own button;
the panel now says which one was pressed (``mode``), as the Mismatches row
does, and a request that does not say is an Apply.
"""

import html
import json

import pytest

from .page_shows import shown_override_cycles
from .test_missing_field_not_defaulted import (AUTO_OVERRIDE, ORIGIN, RUN_ID, UMI_OVERRIDE, _pair,
                                               _run, _stored)

REFUSED = ("Type an Override Cycles to apply, or use Auto to work each sample's out from its "
           "index and the run's cycles. Nothing was saved.")


def _post(client, value, **extra):
    return client.post(
        f"/runs/{RUN_ID}/samples/set-override-cycles", headers=ORIGIN,
        data={"sample_ids": json.dumps(["s1"]), "override_cycles": value,
              "target_override_cycles": shown_override_cycles(client, RUN_ID, ["s1"]), **extra})


class TestApplyWithNothingTyped:

    @pytest.mark.parametrize("value", ["", "   "])
    @pytest.mark.parametrize("mode", [{"mode": "apply"}, {}])
    def test_is_refused_and_keeps_the_typed_value(self, logged_in_client, fresh_app, value, mode):
        _app, ctx, _db = fresh_app
        _run(ctx, override_cycles=UMI_OVERRIDE, index_pair=_pair())
        before = _stored(ctx).updated_at

        resp = _post(logged_in_client, value, **mode)

        assert resp.status_code == 400
        assert REFUSED in html.unescape(resp.text)
        stored = _stored(ctx)
        assert stored.get_sample("s1").override_cycles == UMI_OVERRIDE
        assert stored.updated_at == before

    def test_a_typed_value_is_still_applied(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, index_pair=_pair())

        resp = _post(logged_in_client, UMI_OVERRIDE, mode="apply")

        assert resp.status_code == 200, resp.text
        assert _stored(ctx).get_sample("s1").override_cycles == UMI_OVERRIDE


class TestAuto:

    def test_works_each_value_out_again(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _run(ctx, override_cycles=UMI_OVERRIDE, index_pair=_pair())

        resp = _post(logged_in_client, "", mode="auto")

        assert resp.status_code == 200, resp.text
        assert _stored(ctx).get_sample("s1").override_cycles == AUTO_OVERRIDE

    def test_ignores_a_value_sent_with_it(self, logged_in_client, fresh_app):
        """Auto works the value out; it never stores text that came with it."""
        _app, ctx, _db = fresh_app
        _run(ctx, override_cycles=UMI_OVERRIDE, index_pair=_pair())

        resp = _post(logged_in_client, "Y100;I10;I10;Y100", mode="auto")

        assert resp.status_code == 200, resp.text
        assert _stored(ctx).get_sample("s1").override_cycles == AUTO_OVERRIDE
