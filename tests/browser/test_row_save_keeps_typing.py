"""Saving one setting of a sample row keeps what is being typed (outside
review of f490536, finding F3).

Each Override Cycles and mismatch box on the run page saves on ``change``,
and its answer once replaced the whole row: a value typed into the next box
of that row while the save was on its way was thrown away without a word,
the row's tick with it, and a second save sent before the first answer
landed was stored while the row went on showing the old value. A correction
typed into the same box while its save was on its way was never sent, and a
save still waiting its turn when something else redrew the row (an index
drop or clear, a bulk Apply, the Check's Set test) was dropped. A lost
Override Cycles typed by hand fits the run, so no check could see it.

The first save (or load) of the run is held, as a slow database or a large
run would hold it; the keys are the ones a person presses."""

import threading
import time

import pytest
from playwright.sync_api import expect

TYPED_OVERRIDE = "Y150N1;I8;I8;Y151"


@pytest.fixture
def slow_first_save(app_ctx, mutable_run_id, monkeypatch):
    """The first save of the run waits 0.8 s, as a slow database would."""
    real_save = app_ctx.run_repo.save
    held = []

    def save(run):
        if run.id == mutable_run_id and not held:
            held.append(run.id)
            time.sleep(0.8)
        return real_save(run)

    monkeypatch.setattr(app_ctx.run_repo, "save", save)
    return held


@pytest.fixture
def slow_next_load(app_ctx, mutable_run_id, monkeypatch):
    """Once armed, the next load of the run waits 1.5 s, as a slow database
    would; ``holding`` is set while it waits."""
    real_get = app_ctx.run_repo.get_by_id
    lock = threading.Lock()
    state = {"armed": False, "holding": threading.Event()}

    def get_by_id(run_id, *args, **kwargs):
        with lock:
            hold = run_id == mutable_run_id and state["armed"]
            state["armed"] = state["armed"] and not hold
        if hold:
            state["holding"].set()
            time.sleep(1.5)
        return real_get(run_id, *args, **kwargs)

    monkeypatch.setattr(app_ctx.run_repo, "get_by_id", get_by_id)
    return state


def _row(page, run_id, n=1):
    return page.locator(f"#sample-row-{run_id}-s{n}")


def _open(page, base_url, run_id):
    page.goto(f"{base_url}/runs/{run_id}")
    page.wait_for_load_state("networkidle")


def _a_settings_answer(response):
    return response.url.endswith("/settings")


def _handled(page):
    """Every request of the page has been answered and its answer handled
    (htmx takes its htmx-request class off once it has handled the answer,
    and sends a save waiting in the row's queue in the same step)."""
    page.wait_for_function("() => !document.querySelector('.htmx-request')")


def _redraw_row(page, run_id):
    """Redraw the first row as its index Clear button does."""
    sample = f"{run_id}-s1"
    with page.expect_response(lambda r: r.url.endswith("/clear-index")):
        page.evaluate("""([run, sample]) => htmx.ajax(
            'POST', `/runs/${run}/samples/${sample}/clear-index`,
            {target: `#sample-row-${sample}`, swap: 'outerHTML'})""", [run_id, sample])


def _stored(app_ctx, run_id):
    return app_ctx.run_repo.get_by_id(run_id).samples[0]


@pytest.mark.browser
class TestARowSaveKeepsWhatIsBeingTypedNextToIt:

    def test_a_mismatch_typed_while_the_neighbour_saves_is_kept(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_first_save):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        row = _row(page, mutable_run_id)
        i5 = row.locator('input[name="barcode_mismatches_index2"]')

        row.locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        with page.expect_response(_a_settings_answer):
            page.keyboard.press("Tab")      # change: the i7 save starts
            page.keyboard.type("2")         # Tab selected the i5 box's value
        _handled(page)                      # the i7 answer has landed
        shown = i5.input_value()
        with page.expect_response(_a_settings_answer):
            page.keyboard.press("Tab")      # leave the i5 box, as a person would
        _handled(page)

        stored = _stored(app_ctx, mutable_run_id)
        assert stored.barcode_mismatches_index1 == 0, "the first save did not land"
        assert (shown, stored.barcode_mismatches_index2) == ("2", 2), (
            "the i5 mismatch typed while the i7 one saved was lost")

    def test_an_override_typed_while_a_mismatch_saves_is_kept(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_first_save):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        row = _row(page, mutable_run_id)
        override = row.locator('input[name="override_cycles"]')

        row.locator('input[name="barcode_mismatches_index2"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        with page.expect_response(_a_settings_answer):
            override.click()                # blur: the i5 save starts
            page.keyboard.press("Control+A")
            page.keyboard.type(TYPED_OVERRIDE)
        _handled(page)
        shown = override.input_value()
        with page.expect_response(_a_settings_answer):
            page.keyboard.press("Tab")
        _handled(page)

        stored = _stored(app_ctx, mutable_run_id)
        assert stored.barcode_mismatches_index2 == 0, "the first save did not land"
        assert (shown, stored.override_cycles) == (TYPED_OVERRIDE, TYPED_OVERRIDE), (
            "the Override Cycles typed while a mismatch saved was lost")

    def test_a_mismatch_typed_while_the_override_saves_is_kept(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_first_save):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        row = _row(page, mutable_run_id)
        i7 = row.locator('input[name="barcode_mismatches_index1"]')

        row.locator('input[name="override_cycles"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type(TYPED_OVERRIDE)
        with page.expect_response(_a_settings_answer):
            page.keyboard.press("Tab")      # change: the Override Cycles save starts
            page.keyboard.type("0")         # Tab selected the i7 box's value
        _handled(page)
        shown = i7.input_value()
        with page.expect_response(_a_settings_answer):
            page.keyboard.press("Tab")
        _handled(page)

        stored = _stored(app_ctx, mutable_run_id)
        assert stored.override_cycles == TYPED_OVERRIDE, "the first save did not land"
        assert (shown, stored.barcode_mismatches_index1) == ("0", 0), (
            "the i7 mismatch typed while the Override Cycles saved was lost")

    def test_a_second_save_sent_before_the_first_answer_shows_what_was_stored(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_first_save):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        row = _row(page, mutable_run_id)

        row.locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        page.keyboard.press("Tab")          # the i7 save starts (held 0.8 s)
        page.keyboard.type("2")
        page.keyboard.press("Tab")          # the i5 save is sent before the i7 answer
        _handled(page)

        stored = _stored(app_ctx, mutable_run_id)
        assert (stored.barcode_mismatches_index1, stored.barcode_mismatches_index2) == (0, 2)
        assert row.locator('input[name="barcode_mismatches_index1"]').input_value() == "0"
        assert row.locator('input[name="barcode_mismatches_index2"]').input_value() == "2"

    def test_the_saves_of_one_row_go_one_after_another(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_first_save):
        """The second save is sent only once the first is answered, so two
        saves of one run never race each other's version check."""
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        row = _row(page, mutable_run_id)
        events = []
        page.on("request", lambda r: events.append("sent") if r.url.endswith("/settings") else None)
        page.on("response",
                lambda r: events.append("answered") if r.url.endswith("/settings") else None)

        row.locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        page.keyboard.press("Tab")          # the i7 save starts (held 0.8 s)
        page.keyboard.type("2")
        page.keyboard.press("Tab")          # the i5 save waits for the i7 answer
        _handled(page)

        assert events == ["sent", "answered", "sent", "answered"], events

    def test_the_rows_tick_survives_a_setting_save(
            self, logged_in_page, base_url, mutable_run_id, app_ctx):
        """Unticked, a bulk action pressed next would leave this sample out."""
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        row = _row(page, mutable_run_id)
        row.locator(".sample-checkbox").check()
        expect(page.locator("#selected-sample-count")).to_have_text("1")

        row.locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        with page.expect_response(lambda r: r.url.endswith("/settings")):
            page.keyboard.press("Tab")
        _handled(page)

        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index1 == 0
        assert row.locator(".sample-checkbox").is_checked(), "the save's answer unticked the row"
        expect(page.locator("#selected-sample-count")).to_have_text("1")

    def test_a_cleared_override_shows_the_value_the_server_stored(
            self, logged_in_page, base_url, mutable_run_id, app_ctx):
        """The saved box still shows what the server made of it: a cleared
        Override Cycles is worked out from the run and the indexes."""
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        override = _row(page, mutable_run_id).locator('input[name="override_cycles"]')

        override.click()
        page.keyboard.press("Control+A")
        page.keyboard.type(TYPED_OVERRIDE)
        with page.expect_response(lambda r: r.url.endswith("/settings")):
            page.keyboard.press("Tab")
        _handled(page)
        override.click()
        page.keyboard.press("Control+A")
        page.keyboard.press("Delete")
        with page.expect_response(lambda r: r.url.endswith("/settings")):
            page.keyboard.press("Tab")
        _handled(page)

        stored = _stored(app_ctx, mutable_run_id).override_cycles
        assert stored and stored != TYPED_OVERRIDE
        assert override.input_value() == stored

    def test_control_the_same_keys_save_each_value_when_typed_after_each_answer(
            self, logged_in_page, base_url, mutable_run_id, app_ctx):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        row = _row(page, mutable_run_id)
        for name, value in (("barcode_mismatches_index1", "0"),
                            ("barcode_mismatches_index2", "2"),
                            ("override_cycles", TYPED_OVERRIDE)):
            row.locator(f'input[name="{name}"]').click()
            page.keyboard.press("Control+A")
            page.keyboard.type(value)
            with page.expect_response(lambda r: r.url.endswith("/settings")):
                page.keyboard.press("Tab")
            _handled(page)

        stored = _stored(app_ctx, mutable_run_id)
        assert (stored.barcode_mismatches_index1, stored.barcode_mismatches_index2,
                stored.override_cycles) == (0, 2, TYPED_OVERRIDE)


@pytest.mark.browser
class TestACorrectionTypedWhileTheBoxSaves:

    def test_a_value_being_typed_in_the_box_is_kept_when_its_save_answers(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_first_save):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        i7 = _row(page, mutable_run_id).locator('input[name="barcode_mismatches_index1"]')

        i7.click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        with page.expect_response(_a_settings_answer):
            page.keyboard.press("Tab")      # the save of 0 starts (held 0.8 s)
            page.keyboard.press("Shift+Tab")  # back into the same box
            page.keyboard.press("Control+A")
            page.keyboard.type("1")         # still typing when the answer lands
        _handled(page)
        shown = i7.input_value()
        with page.expect_response(_a_settings_answer):
            page.keyboard.press("Tab")
        _handled(page)

        assert (shown, _stored(app_ctx, mutable_run_id).barcode_mismatches_index1) == ("1", 1)

    @pytest.mark.parametrize("key", ["Tab", "Enter"])
    def test_a_correction_typed_while_the_box_saves_is_stored_and_shown(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_first_save, key):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        i7 = _row(page, mutable_run_id).locator('input[name="barcode_mismatches_index1"]')
        sent = []
        page.on("request", lambda r: sent.append(r.post_data) if _a_settings_answer(r) else None)

        i7.click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        page.keyboard.press(key)            # the save of 0 starts (held 0.8 s)
        if key == "Tab":
            page.keyboard.press("Shift+Tab")  # back into the same box
        page.keyboard.press("Control+A")
        page.keyboard.type("1")             # the person corrects it
        page.keyboard.press(key)            # before the first answer
        _handled(page)

        assert sent == ["barcode_mismatches_index1=0", "barcode_mismatches_index1=1"], sent
        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index1 == 1
        assert i7.input_value() == "1"


@pytest.mark.browser
class TestARowRedrawnWhileASaveIsOnItsWay:
    """An index drop or clear, a bulk Apply or the Check's Set test redraws
    the row while a save of one of its boxes is on its way or waiting its
    turn. Here the i7 save's load is held, the i5 save waits behind it, and
    the row is redrawn as its index Clear button does."""

    def _save_two_and_redraw(self, page, base_url, run_id, slow_next_load):
        _open(page, base_url, run_id)
        row = _row(page, run_id)
        row.locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        slow_next_load["armed"] = True
        page.keyboard.press("Tab")          # the i7 save starts; its load is held
        page.keyboard.type("2")
        page.keyboard.press("Tab")          # the i5 save waits its turn
        assert slow_next_load["holding"].wait(5), "the i7 save never reached its load"
        _redraw_row(page, run_id)           # answered while the i7 load is held

    def test_a_save_still_waiting_is_named_as_not_saved(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_next_load):
        page = logged_in_page
        sent = []
        page.on("request", lambda r: sent.append(r.post_data) if _a_settings_answer(r) else None)

        self._save_two_and_redraw(page, base_url, mutable_run_id, slow_next_load)

        banner = page.locator("#error-banner")
        expect(banner).to_contain_text("MM i5 of MUT-01")
        expect(banner).to_contain_text("was not saved")
        with page.expect_response(_a_settings_answer):
            pass                            # the held i7 save is answered
        _handled(page)
        assert sent == ["barcode_mismatches_index1=0"], sent
        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index2 == 1, (
            "the banner says the i5 change was not saved, but it was")

    def test_an_answer_after_the_redraw_asks_for_a_reload(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_next_load):
        """The redrawn row shows the i7 mismatch as it was before the held
        save stored 0; the answer of that save has no box left to fill."""
        page = logged_in_page

        self._save_two_and_redraw(page, base_url, mutable_run_id, slow_next_load)
        with page.expect_response(_a_settings_answer):
            pass
        _handled(page)

        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index1 == 0
        i7 = _row(page, mutable_run_id).locator('input[name="barcode_mismatches_index1"]')
        assert i7.input_value() == "1", "the redrawn row was drawn after the save"
        expect(page.locator("#error-banner")).to_contain_text("MM i7 of MUT-01")
        expect(page.locator("#error-banner")).to_contain_text("reload the page")

    def test_control_a_redraw_after_the_saves_are_answered_says_nothing(
            self, logged_in_page, base_url, mutable_run_id, app_ctx):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        row = _row(page, mutable_run_id)
        row.locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        with page.expect_response(_a_settings_answer):
            page.keyboard.press("Tab")
        _handled(page)

        _redraw_row(page, mutable_run_id)
        _handled(page)

        expect(page.locator("#error-banner")).to_be_empty()
        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index1 == 0
