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
        saves of one row never race each other's version check (saves of two
        rows still can: the one refused says so in the banner)."""
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

        banner = page.locator("#row-setting-notes")
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
        expect(page.locator("#row-setting-notes")).to_contain_text("MM i7 of MUT-01")
        expect(page.locator("#row-setting-notes")).to_contain_text("reload the page")

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
        expect(page.locator("#row-setting-notes")).to_be_empty()
        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index1 == 0

    def test_a_save_lost_to_a_bulk_apply_is_named(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_next_load):
        """Apply redraws the whole table; the Override Cycles change waits
        behind the held i7 save, as the click on Apply commits it."""
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        row = _row(page, mutable_run_id)
        _row(page, mutable_run_id, 2).locator(".sample-checkbox").check()
        page.locator('.bulk-lane-checkbox[value="2"]').check()
        row.locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        slow_next_load["armed"] = True
        page.keyboard.press("Tab")          # the i7 save starts; its load is held
        assert slow_next_load["holding"].wait(5), "the i7 save never reached its load"
        row.locator('input[name="override_cycles"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type(TYPED_OVERRIDE)
        with page.expect_response(lambda r: r.url.endswith("/samples/set-lanes")):
            page.locator('[data-action="bulk-apply-lanes"]').click()

        expect(page.locator("#main")).to_contain_text("Override Cycles of MUT-01")
        expect(page.locator("#main")).to_contain_text("was not saved")
        assert _stored(app_ctx, mutable_run_id).override_cycles != TYPED_OVERRIDE

    def test_a_later_failure_keeps_the_not_saved_note(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_next_load):
        page = logged_in_page
        self._save_two_and_redraw(page, base_url, mutable_run_id, slow_next_load)
        expect(page.locator("#main")).to_contain_text("MM i5 of MUT-01")
        with page.expect_response(_a_settings_answer):
            pass                            # the held i7 save is answered
        _handled(page)

        i7 = _row(page, mutable_run_id).locator('input[name="barcode_mismatches_index1"]')
        i7.click()
        page.keyboard.press("Control+A")
        page.keyboard.type("5")
        with page.expect_response(lambda r: _a_settings_answer(r) and r.status == 400):
            page.keyboard.press("Tab")
        expect(page.locator("#error-banner")).to_contain_text("0, 1 or 2")

        expect(page.locator("#main")).to_contain_text("MM i5 of MUT-01")

    def test_the_not_saved_note_goes_once_the_change_is_saved(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_next_load):
        page = logged_in_page
        self._save_two_and_redraw(page, base_url, mutable_run_id, slow_next_load)
        expect(page.locator("#main")).to_contain_text("MM i5 of MUT-01")
        with page.expect_response(_a_settings_answer):
            pass
        _handled(page)

        i5 = _row(page, mutable_run_id).locator('input[name="barcode_mismatches_index2"]')
        i5.click()
        page.keyboard.press("Control+A")
        page.keyboard.type("2")             # entered again, as the note asks
        with page.expect_response(_a_settings_answer):
            page.keyboard.press("Tab")
        _handled(page)

        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index2 == 2
        expect(page.locator("#main")).not_to_contain_text("MM i5 of MUT-01")


@pytest.mark.browser
class TestLeavingWhileASaveWaits:
    """Done editing, Mark Ready and leaving the page come right after typing:
    the click that does them commits the box, whose save then waits behind
    the one on its way."""

    def _type_two(self, page, base_url, run_id):
        _open(page, base_url, run_id)
        _row(page, run_id).locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        page.keyboard.press("Tab")          # the i7 save starts (held 0.8 s)
        page.keyboard.type("2")             # the i5 box, not yet left

    def test_done_editing_waits_for_the_rows_saves(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_first_save):
        page = logged_in_page
        answers = []
        page.on("response", lambda r: answers.append((r.url.rsplit("/", 1)[-1], r.status))
                if _a_settings_answer(r) or r.url.endswith("/edit-lock") else None)
        self._type_two(page, base_url, mutable_run_id)

        with page.expect_navigation():
            page.get_by_role("button", name="Done editing").click()
        page.wait_for_load_state("networkidle")

        assert answers == [("settings", 200), ("settings", 200), ("edit-lock", 200)], answers
        stored = _stored(app_ctx, mutable_run_id)
        assert (stored.barcode_mismatches_index1, stored.barcode_mismatches_index2) == (0, 2)

    def test_mark_ready_waits_for_the_rows_saves(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_first_save):
        page = logged_in_page
        events = []
        page.on("request", lambda r: events.append(("sent", r.url.rsplit("/", 1)[-1]))
                if _a_settings_answer(r) or r.url.endswith("/status/ready") else None)
        page.on("response", lambda r: events.append(("answered", r.url.rsplit("/", 1)[-1]))
                if _a_settings_answer(r) or r.url.endswith("/status/ready") else None)
        self._type_two(page, base_url, mutable_run_id)

        with page.expect_response(lambda r: r.url.endswith("/status/ready")):
            page.get_by_role("button", name="Mark Ready").click()

        assert events.index(("sent", "ready")) > max(
            i for i, e in enumerate(events) if e == ("answered", "settings")), events
        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index2 == 2

    def test_leaving_the_page_while_a_save_waits_asks_first(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_first_save):
        page = logged_in_page
        dialogs = []

        def stay(dialog):
            dialogs.append(dialog.type)
            dialog.dismiss()

        page.on("dialog", stay)
        self._type_two(page, base_url, mutable_run_id)
        page.keyboard.press("Tab")          # the i5 save waits behind the i7 one
        page.get_by_role("link", name="Dashboard").click()
        _handled(page)

        assert dialogs == ["beforeunload"], dialogs
        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index2 == 2

    def test_control_leaving_once_the_saves_are_answered_asks_nothing(
            self, logged_in_page, base_url, mutable_run_id, app_ctx):
        page = logged_in_page
        dialogs = []
        page.on("dialog", lambda d: (dialogs.append(d.type), d.dismiss()))
        _open(page, base_url, mutable_run_id)
        _row(page, mutable_run_id).locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        with page.expect_response(_a_settings_answer):
            page.keyboard.press("Tab")
        _handled(page)

        with page.expect_navigation():
            page.get_by_role("link", name="Dashboard").click()

        assert dialogs == []


@pytest.mark.browser
class TestAWaitingActionWhenASaveDoesNotLand:
    """Done editing and Mark Ready wait for the row's saves (the class above).
    A fresh review of b425b0b found that the wait ends when the saves are
    *answered*, not when they are *stored*: a refused save released Done
    editing, whose redirect took the error banner with it, so the person
    landed on a read-only run with the typed value gone and nothing on
    screen. The wait was also invisible and had no end: a save whose answer
    never comes held the click for ever."""

    def _done_editing_form(self, page):
        return page.locator('form[data-after-row-saves][hx-delete]')

    def _type_a_refused_mismatch(self, page, base_url, run_id, slow_next_load):
        _open(page, base_url, run_id)
        _row(page, run_id).locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("5")             # only 0, 1 or 2 are accepted
        slow_next_load["armed"] = True      # the refusal is held, so the click waits

    def test_done_editing_is_not_done_when_a_row_save_is_refused(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_next_load):
        page = logged_in_page
        answers = []
        page.on("response", lambda r: answers.append((r.url.rsplit("/", 1)[-1], r.status))
                if _a_settings_answer(r) or r.url.endswith("/edit-lock") else None)
        self._type_a_refused_mismatch(page, base_url, mutable_run_id, slow_next_load)

        with page.expect_response(lambda r: _a_settings_answer(r) and r.status == 400):
            page.get_by_role("button", name="Done editing").click()
        _handled(page)

        assert answers == [("settings", 400)], answers
        expect(page.locator("#error-banner")).to_contain_text("0, 1 or 2")
        expect(page.locator("#row-setting-notes")).to_contain_text(
            "Done editing was not done")
        expect(page.locator("#run-status-bar")).to_contain_text("You are editing this run")
        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index1 != 5

    def test_mark_ready_is_not_done_when_a_row_save_is_refused(
            self, logged_in_page, base_url, mutable_run_id, slow_next_load):
        page = logged_in_page
        sent = []
        page.on("request", lambda r: sent.append(r.url.rsplit("/", 1)[-1])
                if r.url.endswith("/status/ready") else None)
        self._type_a_refused_mismatch(page, base_url, mutable_run_id, slow_next_load)

        with page.expect_response(lambda r: _a_settings_answer(r) and r.status == 400):
            page.get_by_role("button", name="Mark Ready").click()
        _handled(page)

        assert sent == [], sent
        expect(page.locator("#row-setting-notes")).to_contain_text(
            "Mark Ready was not done")

    def test_done_editing_is_not_done_when_a_change_was_lost_to_a_redraw(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_next_load):
        """The i5 save waits in the row's queue when the row is redrawn, so it
        is never sent: the run must not be left, nor marked Ready, with that
        change silently gone."""
        page = logged_in_page
        sent = []
        page.on("request", lambda r: sent.append(r.url.rsplit("/", 1)[-1])
                if r.url.endswith("/edit-lock") else None)
        _open(page, base_url, mutable_run_id)
        row = _row(page, mutable_run_id)
        row.locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        slow_next_load["armed"] = True
        page.keyboard.press("Tab")          # the i7 save starts; its load is held
        page.keyboard.type("2")
        page.keyboard.press("Tab")          # the i5 save waits its turn
        page.get_by_role("button", name="Done editing").click()
        assert slow_next_load["holding"].wait(5), "the i7 save never reached its load"
        _redraw_row(page, mutable_run_id)   # drops the queued i5 save
        with page.expect_response(_a_settings_answer):
            pass                            # the held i7 save is answered
        _handled(page)

        assert sent == [], sent
        notes = page.locator("#row-setting-notes")
        expect(notes).to_contain_text("MM i5 of MUT-01")
        expect(notes).to_contain_text("Done editing was not done")
        expect(page.locator("#run-status-bar")).to_contain_text("You are editing this run")
        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index2 == 1

    def test_a_waiting_action_shows_that_it_waits(
            self, logged_in_page, base_url, mutable_run_id, slow_first_save):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        _row(page, mutable_run_id).locator(
            'input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        page.keyboard.press("Tab")          # the i7 save starts (held 0.8 s)
        page.keyboard.type("2")             # the i5 box, not yet left

        button = page.get_by_role("button", name="Done editing")
        with page.expect_navigation():
            button.click()
            expect(button).to_be_disabled()
            expect(self._done_editing_form(page)).to_have_class("htmx-request")
        page.wait_for_load_state("networkidle")

    def test_a_waiting_action_gives_up_when_a_save_never_answers(
            self, logged_in_page, base_url, mutable_run_id):
        page = logged_in_page
        held = []
        sent = []
        page.on("request", lambda r: sent.append(r.url.rsplit("/", 1)[-1])
                if r.url.endswith("/edit-lock") else None)
        _open(page, base_url, mutable_run_id)
        page.evaluate("window.rowSaveWaitMs = 600")
        page.route("**/samples/**/settings", lambda route: held.append(route))
        try:
            _row(page, mutable_run_id).locator(
                'input[name="barcode_mismatches_index1"]').click()
            page.keyboard.press("Control+A")
            page.keyboard.type("0")
            page.keyboard.press("Tab")      # the save is never answered
            button = page.get_by_role("button", name="Done editing")
            button.click()

            expect(page.locator("#row-setting-notes")).to_contain_text(
                "Done editing was not done")
            expect(page.locator("#row-setting-notes")).to_contain_text(
                "taking too long to save")
            expect(button).to_be_enabled()
            assert sent == [], sent
        finally:
            page.unroute("**/samples/**/settings")
            for route in held:
                try:
                    route.abort()
                except Exception:          # the page may have gone meanwhile
                    pass

    def test_control_done_editing_is_done_once_the_refused_value_is_put_right(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_next_load):
        page = logged_in_page
        self._type_a_refused_mismatch(page, base_url, mutable_run_id, slow_next_load)
        with page.expect_response(lambda r: _a_settings_answer(r) and r.status == 400):
            page.get_by_role("button", name="Done editing").click()
        _handled(page)
        expect(page.locator("#row-setting-notes")).to_contain_text(
            "Done editing was not done")

        i7 = _row(page, mutable_run_id).locator('input[name="barcode_mismatches_index1"]')
        i7.click()
        page.keyboard.press("Control+A")
        page.keyboard.type("2")
        with page.expect_navigation():
            page.get_by_role("button", name="Done editing").click()
        page.wait_for_load_state("networkidle")

        expect(page.locator("#run-status-bar")).to_contain_text("Nobody is editing this run")
        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index1 == 2

    def test_control_a_refusal_before_the_click_does_not_stop_a_later_one(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_first_save):
        """The refusal is answered while nothing is waiting for it, so
        ``sendWhatWaitsForRowSaves`` returns before it can strike the
        not-stored note off: registering a waiter must reset it, or this
        refusal would stop every later Done editing on the page with a
        message saying a change was not saved when it was."""
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        i7 = _row(page, mutable_run_id).locator('input[name="barcode_mismatches_index1"]')
        i7.click()
        page.keyboard.press("Control+A")
        page.keyboard.type("5")
        with page.expect_response(lambda r: _a_settings_answer(r) and r.status == 400):
            page.keyboard.press("Tab")
        _handled(page)
        expect(page.locator("#error-banner")).to_contain_text("0, 1 or 2")
        expect(page.locator("#row-setting-notes")).not_to_contain_text("was not done")

        i7.click()
        page.keyboard.press("Control+A")
        page.keyboard.type("2")             # saved, and held 0.8 s, so the click waits
        with page.expect_navigation():
            page.get_by_role("button", name="Done editing").click()
        page.wait_for_load_state("networkidle")

        expect(page.locator("#run-status-bar")).to_contain_text("Nobody is editing this run")
        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index1 == 2


@pytest.mark.browser
class TestWhatTheGivenUpActionSaysAndLocks:
    """A second fresh review, of 0aba74b, found three things wrong with
    giving the action up: the not-stored note was one page-wide flag, so a
    refusal the person put right *while the click waited* still gave the
    click up and said a change was not saved when their value was stored;
    the note stayed on screen through a later action, so it could be read
    beside Status: Ready; and the other action's button stayed clickable
    while one waited, so Done editing and Mark Ready could both fire and
    the loser was refused 409 with its message taken away by the winner's
    redirect."""

    def _type_a_refused_mismatch(self, page, base_url, run_id, slow_next_load):
        _open(page, base_url, run_id)
        _row(page, run_id).locator('input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("5")             # only 0, 1 or 2 are accepted
        slow_next_load["armed"] = True      # the refusal is held, so the click waits

    def test_a_refusal_put_right_while_the_click_waits_lets_it_go(
            self, logged_in_page, base_url, mutable_run_id, app_ctx, slow_next_load):
        page = logged_in_page
        self._type_a_refused_mismatch(page, base_url, mutable_run_id, slow_next_load)
        page.get_by_role("button", name="Done editing").click()   # waits
        assert slow_next_load["holding"].wait(5), "the refusal never reached its load"

        i7 = _row(page, mutable_run_id).locator('input[name="barcode_mismatches_index1"]')
        i7.click()
        page.keyboard.press("Control+A")
        page.keyboard.type("2")             # put right while the click waits
        with page.expect_navigation():
            page.keyboard.press("Tab")
        page.wait_for_load_state("networkidle")

        assert _stored(app_ctx, mutable_run_id).barcode_mismatches_index1 == 2
        expect(page.locator("#run-status-bar")).to_contain_text("Nobody is editing this run")
        expect(page.locator("#row-setting-notes")).not_to_contain_text("was not done")

    def test_the_given_up_note_names_the_setting_and_the_sample(
            self, logged_in_page, base_url, mutable_run_id, slow_next_load):
        page = logged_in_page
        self._type_a_refused_mismatch(page, base_url, mutable_run_id, slow_next_load)
        with page.expect_response(lambda r: _a_settings_answer(r) and r.status == 400):
            page.get_by_role("button", name="Done editing").click()
        _handled(page)

        expect(page.locator("#row-setting-notes")).to_contain_text(
            "MM i7 of MUT-01 was not saved")

    def test_a_given_up_note_goes_when_the_next_action_is_clicked(
            self, logged_in_page, base_url, mutable_run_id, slow_next_load):
        """The note must not be left to be read beside a Ready run: the next
        action answers it, whether that action waits or goes straight away."""
        page = logged_in_page
        self._type_a_refused_mismatch(page, base_url, mutable_run_id, slow_next_load)
        with page.expect_response(lambda r: _a_settings_answer(r) and r.status == 400):
            page.get_by_role("button", name="Done editing").click()
        _handled(page)
        expect(page.locator("#row-setting-notes")).to_contain_text("was not done")

        with page.expect_response(lambda r: r.url.endswith("/status/ready")):
            page.get_by_role("button", name="Mark Ready", exact=True).click()
        _handled(page)

        expect(page.locator("#row-setting-notes")).not_to_contain_text("was not done")

    def test_the_other_action_cannot_be_clicked_while_one_waits(
            self, logged_in_page, base_url, mutable_run_id, slow_first_save):
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        _row(page, mutable_run_id).locator(
            'input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        page.keyboard.press("Tab")          # the save starts (held 0.8 s)

        done = page.get_by_role("button", name="Done editing")
        ready = page.get_by_role("button", name="Mark Ready", exact=True)
        with page.expect_navigation():
            done.click()
            expect(ready).to_be_disabled()
            expect(done).to_be_disabled()
        page.wait_for_load_state("networkidle")

    def test_both_buttons_work_again_after_a_refused_mark_ready(
            self, logged_in_page, base_url, mutable_run_id, slow_first_save):
        """Mark Ready is refused here (the run has Check errors), and its
        answer retargets #ready-message, so #run-status-bar is NOT replaced:
        whatever was disabled while the click waited must be undone before
        the request goes, or htmx leaves the button disabled for good."""
        page = logged_in_page
        _open(page, base_url, mutable_run_id)
        _row(page, mutable_run_id).locator(
            'input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        page.keyboard.press("Tab")          # the save starts (held 0.8 s)

        with page.expect_response(lambda r: r.url.endswith("/status/ready")):
            page.get_by_role("button", name="Mark Ready", exact=True).click()
        _handled(page)

        expect(page.locator("#ready-message")).to_contain_text("Cannot mark ready")
        expect(page.get_by_role("button", name="Mark Ready", exact=True)).to_be_enabled()
        expect(page.get_by_role("button", name="Done editing")).to_be_enabled()

    def test_the_other_action_is_refused_even_with_its_button_enabled(
            self, logged_in_page, base_url, mutable_run_id, slow_first_save):
        """The greyed-out button is the sign; the rule is at the click, so
        that anything redrawing the status bar while an action waits cannot
        let both of them fire."""
        page = logged_in_page
        sent = []
        page.on("request", lambda r: sent.append(r.url.rsplit("/", 1)[-1])
                if r.url.endswith("/status/ready") else None)
        _open(page, base_url, mutable_run_id)
        _row(page, mutable_run_id).locator(
            'input[name="barcode_mismatches_index1"]').click()
        page.keyboard.press("Control+A")
        page.keyboard.type("0")
        page.keyboard.press("Tab")          # the save starts (held 0.8 s)

        page.get_by_role("button", name="Done editing").click()
        page.evaluate("""() => document
            .querySelectorAll('[data-after-row-saves] button')
            .forEach(b => { b.disabled = false; })""")
        page.get_by_role("button", name="Mark Ready", exact=True).click()
        note = page.evaluate(
            "() => document.getElementById('row-setting-notes').textContent")
        page.wait_for_load_state("networkidle")

        assert "Done editing is already waiting" in note, note
        assert sent == [], sent
        expect(page.locator("#run-status-bar")).to_contain_text("Nobody is editing this run")
