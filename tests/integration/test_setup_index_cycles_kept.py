"""A stored Index cycle count the dropdown does not list is kept (outside
review of 7f858e0, finding 1; the user's choice "Show it, keep it",
2026-10-14).

Index 1 and Index 2 are picked from a fixed list. A stored count not in it
-- 6, 0 for no Index 2 read, or one a lab's instruments file has since
dropped -- matched no option, so the browser sent the list's first, 8,
with the next setup save (Back to Run, or a change to another cycle
count): the run's cycles and its sample sheet changed with no word. Now
the dropdown lists the stored count too, selected, marked "(not in the
usual list)".

Each save is built from the page as a browser sends it: a select sends
its selected option, or its first when none is selected.
"""

from ..sheet_through_profiles import sheet as _sheet

import re
from html.parser import HTMLParser

from seqsetup.data import instruments as instruments_module
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.cycle_calculator import CycleCalculator
from .conftest import hold_edit_lock

ORIGIN = {"Origin": "http://testserver", "HX-Request": "true"}
OFF_LIST = " (not in the usual list)"
_VOID = {"input", "br", "hr", "img", "meta", "link", "area", "base", "col", "embed", "source",
         "track", "wbr"}


class _BrowserForm(HTMLParser):
    """The fields a browser sends from inside the element whose id is
    ``root``: an input its value (a checkbox or radio only when checked), a
    textarea its text, a select its selected option, or its first when none
    is selected."""

    def __init__(self, root):
        super().__init__(convert_charrefs=True)
        self.root, self.depth, self.fields = root, 0, {}
        self._select = self._textarea = None
        self._options = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if not self.depth:
            if a.get("id") == self.root and tag == "input" and a.get("name"):
                self.fields[a["name"]] = a.get("value", "")
            elif a.get("id") == self.root and tag not in _VOID:
                self.depth = 1
            return
        if tag not in _VOID:
            self.depth += 1
        name = a.get("name")
        if not name and tag != "option" or "disabled" in a:
            return
        if tag == "input":
            if a.get("type") not in ("checkbox", "radio") or "checked" in a:
                self.fields[name] = a.get("value", "")
        elif tag == "textarea":
            self._textarea, self.fields[name] = name, ""
        elif tag == "select":
            self._select, self._options = name, []
        elif tag == "option" and self._select:
            self._options.append([a.get("value"), "selected" in a, "", "disabled" in a])

    def handle_data(self, data):
        if self._textarea:
            self.fields[self._textarea] += data
        elif self._select and self._options:
            self._options[-1][2] += data

    def handle_endtag(self, tag):
        if not self.depth or tag in _VOID:     # "<input .../>" ends here too
            return
        if tag == "textarea":
            self._textarea = None
        elif tag == "select" and self._select:
            chosen = [o for o in self._options if o[1]] or self._options[:1]
            if chosen and not chosen[0][3]:    # a disabled option sends nothing
                value, _sel, text, _off = chosen[0]
                self.fields[self._select] = value if value is not None else text.strip()
            self._select = None
        self.depth -= 1


def _sent(html, *roots):
    fields = {}
    for root in roots:
        form = _BrowserForm(root)
        form.feed(html)
        assert form.depth == 0 and form.fields, f"#{root} not read from the page"
        fields.update(form.fields)
    return fields


def _options(html, name):
    """Each option of the named select: (value, text, selected)."""
    select = re.search(rf'<select name="{name}"[^>]*>(.*?)</select>', html, re.S).group(1)
    return [(v, t.strip(), bool(s)) for v, s, t in re.findall(
        r'<option value="([^"]*)"\s*(selected)?\s*>([^<]*)</option>', select)]


def _run(ctx, cycles: RunCycles, i7: str, flowcell="10B", reagent_cycles=300) -> str:
    run = SequencingRun(
        run_name="Cycles run", instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type=flowcell, reagent_cycles=reagent_cycles, run_cycles=cycles,
    )
    pair = IndexPair(id="p1", name="P1", index1=Index(name="i7-1", sequence=i7, index_type=IndexType.I7))
    run.add_sample(Sample(id="s1", sample_id="S1", lanes=[1], index_pair=pair))
    CycleCalculator.update_all_sample_override_cycles(run)
    ctx.run_repo.save(run)
    hold_edit_lock(ctx, run.id)
    return run.id


def _state(ctx, run_id):
    """The four counts, the sample's OverrideCycles, and the sheet's Reads."""
    run = ctx.run_repo.get_by_id(run_id)
    rc = run.run_cycles
    reads = _sheet(run).split("[Reads]", 1)[1].split("\n\n", 1)[0]
    return ((rc.read1_cycles, rc.read2_cycles, rc.index1_cycles, rc.index2_cycles),
            run.samples[0].override_cycles, reads)


def _setup_page(client, run_id):
    return client.get(f"/runs/new/step/1?run_id={run_id}").text


class TestTheDropdownShowsTheStoredCount:
    """Index 1 and Index 2 list the run's own count, marked when the list
    does not have it."""

    def test_an_unlisted_count_is_listed_selected_and_marked(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 6, 0), "ACGTAC")

        page = _setup_page(logged_in_client, run_id)

        assert _options(page, "index1_cycles") == [
            ("6", "6" + OFF_LIST, True), ("8", "8", False), ("10", "10", False),
            ("12", "12", False), ("17", "17", False), ("24", "24", False)]
        assert _options(page, "index2_cycles")[0] == ("0", "0" + OFF_LIST, True)
        assert [o[2] for o in _options(page, "index2_cycles")] == [True] + [False] * 5

    def test_it_sits_in_number_order(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 11, 30), "ACGTACGTAC")

        page = _setup_page(logged_in_client, run_id)

        assert [o[0] for o in _options(page, "index1_cycles")] == ["8", "10", "11", "12", "17", "24"]
        assert [o[0] for o in _options(page, "index2_cycles")] == ["8", "10", "12", "17", "24", "30"]

    def test_a_listed_count_adds_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 10, 10), "ACGTACGTAC")

        page = _setup_page(logged_in_client, run_id)

        assert OFF_LIST not in page
        assert _options(page, "index1_cycles") == [
            ("8", "8", False), ("10", "10", True), ("12", "12", False),
            ("17", "17", False), ("24", "24", False)]


NOT_AVAILABLE = " (not available)"


class TestTheFlowcellAndKitShowTheRunsOwn:
    """The flowcell and reagent-kit selects showed the list's first when the
    run's own was not in it (review of 084943d, P2-1). Nothing was saved
    wrong -- each saves only on its own change -- but the page showed a
    flowcell or kit the run does not have, as the instrument and i5
    selects already do not."""

    def test_a_flowcell_the_instrument_does_not_list(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 10, 10), "ACGTACGTAC", flowcell="ZZ")

        options = _options(_setup_page(logged_in_client, run_id), "flowcell_type")

        assert ("ZZ", "ZZ" + NOT_AVAILABLE, True) in options
        assert [o[0] for o in options if o[2]] == ["ZZ"]

    def test_no_flowcell_at_all(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 10, 10), "ACGTACGTAC", flowcell="")

        options = _options(_setup_page(logged_in_client, run_id), "flowcell_type")

        assert ("", "No flowcell set" + NOT_AVAILABLE, True) in options
        assert [o[0] for o in options if o[2]] == [""]

    def test_a_kit_the_flowcell_does_not_list(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 10, 10), "ACGTACGTAC", reagent_cycles=999)

        options = _options(_setup_page(logged_in_client, run_id), "reagent_cycles")

        assert ("999", "999 cycles" + NOT_AVAILABLE, True) in options
        assert [o[0] for o in options if o[2]] == ["999"]

    def test_listed_ones_add_nothing(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 10, 10), "ACGTACGTAC")

        page = _setup_page(logged_in_client, run_id)

        assert [o[0] for o in _options(page, "flowcell_type") if o[2]] == ["10B"]
        assert [o[0] for o in _options(page, "reagent_cycles") if o[2]] == ["300"]
        assert NOT_AVAILABLE not in "".join(
            o[1] for name in ("flowcell_type", "reagent_cycles") for o in _options(page, name))

    def test_back_to_run_keeps_them(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 10, 10), "ACGTACGTAC", flowcell="ZZ",
                      reagent_cycles=999)

        form = _sent(_setup_page(logged_in_client, run_id), "run-setup-fields")
        resp = logged_in_client.post(f"/runs/{run_id}/setup", data=form, headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        run = ctx.run_repo.get_by_id(run_id)
        assert (run.flowcell_type, run.reagent_cycles) == ("ZZ", 999)


class TestASaveKeepsTheStoredCount:
    """The run, its OverrideCycles and its sheet's Reads stay as they were."""

    def test_back_to_run(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 6, 0), "ACGTAC")
        before = _state(ctx, run_id)

        form = _sent(_setup_page(logged_in_client, run_id), "run-setup-fields")
        resp = logged_in_client.post(f"/runs/{run_id}/setup", data=form, headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert _state(ctx, run_id) == before

    def test_a_count_the_instruments_file_no_longer_lists(self, logged_in_client, fresh_app,
                                                          monkeypatch):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 17, 17), "ACGTACGTAC")
        before = _state(ctx, run_id)
        monkeypatch.setattr(instruments_module, "_index_cycle_options", [8, 10, 12, 24])

        form = _sent(_setup_page(logged_in_client, run_id), "run-setup-fields")
        resp = logged_in_client.post(f"/runs/{run_id}/setup", data=form, headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert _state(ctx, run_id) == before

    def test_a_change_to_read_1_keeps_the_index_counts(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 6, 0), "ACGTAC")

        form = _sent(_setup_page(logged_in_client, run_id), "cycle-config", "run-version")
        form["read1_cycles"] = "101"
        resp = logged_in_client.post(f"/runs/{run_id}/cycles", data=form, headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert _state(ctx, run_id)[0] == (101, 151, 6, 0)

    def test_a_listed_count(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 10, 10), "ACGTACGTAC")
        before = _state(ctx, run_id)

        form = _sent(_setup_page(logged_in_client, run_id), "run-setup-fields")
        resp = logged_in_client.post(f"/runs/{run_id}/setup", data=form, headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert _state(ctx, run_id) == before

    def test_picking_a_listed_count_still_changes_it(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        run_id = _run(ctx, RunCycles(151, 151, 6, 0), "ACGTAC")

        form = _sent(_setup_page(logged_in_client, run_id), "cycle-config", "run-version")
        form["index1_cycles"] = "8"
        resp = logged_in_client.post(f"/runs/{run_id}/cycles", data=form, headers=ORIGIN)

        assert resp.status_code == 200, resp.text[:300]
        assert _state(ctx, run_id)[0] == (151, 151, 8, 0)
