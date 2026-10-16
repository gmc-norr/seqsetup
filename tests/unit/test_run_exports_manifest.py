"""A Ready run's ``exports`` manifest: kind -> {"id", "sha256", "size"}.

The files themselves live in their own records (``run_exports``); the run
document keeps only this manifest. It is checked on every assignment, not
only on construction, and it is a read-only mapping assigned whole: a
``run.exports[kind] = …`` that slipped past the check could point a Ready run
at bytes no check ever passed
(docs/design/2026-10-16-export-files-own-records-design.md).
"""

import pytest

from seqsetup.models.sequencing_run import EXPORT_KINDS, SequencingRun


ID = "0" * 32
SHA = "a" * 64


def _manifest(**kw) -> dict:
    entry = {"id": ID, "sha256": SHA, "size": 12}
    entry.update(kw)
    return {"samplesheet_v2": entry}


class TestTheManifestIsCheckedOnEveryAssignment:

    def test_a_draft_starts_with_an_empty_manifest(self):
        assert SequencingRun(run_name="D").exports == {}

    def test_the_five_kinds_are_the_only_ones(self):
        assert EXPORT_KINDS == (
            "samplesheet_v2", "samplesheet_v1", "json",
            "validation_json", "validation_pdf",
        )

    def test_a_whole_manifest_is_kept(self):
        run = SequencingRun(run_name="R")
        run.exports = _manifest()
        assert run.exports["samplesheet_v2"] == {"id": ID, "sha256": SHA, "size": 12}

    def test_a_kind_that_is_not_one_of_the_five_is_refused(self):
        run = SequencingRun(run_name="R")
        with pytest.raises(ValueError, match="kind"):
            run.exports = {"samplesheet_v3": {"id": ID, "sha256": SHA, "size": 1}}

    def test_an_id_that_is_not_32_hex_is_refused(self):
        run = SequencingRun(run_name="R")
        for bad in ("", "x" * 32, ID[:31], ID + "0", 0):
            with pytest.raises(ValueError, match="id"):
                run.exports = _manifest(id=bad)

    def test_a_sha256_that_is_not_64_hex_is_refused(self):
        run = SequencingRun(run_name="R")
        for bad in ("", "z" * 64, SHA[:63], SHA + "a", 0):
            with pytest.raises(ValueError, match="sha256"):
                run.exports = _manifest(sha256=bad)

    def test_a_size_that_is_not_a_whole_number_is_refused(self):
        run = SequencingRun(run_name="R")
        for bad in (-1, 1.5, "12", True, None):
            with pytest.raises(ValueError, match="size"):
                run.exports = _manifest(size=bad)

    def test_an_entry_with_a_missing_or_extra_key_is_refused(self):
        run = SequencingRun(run_name="R")
        with pytest.raises(ValueError):
            run.exports = {"json": {"id": ID, "sha256": SHA}}
        with pytest.raises(ValueError):
            run.exports = {"json": {"id": ID, "sha256": SHA, "size": 1, "extra": 1}}

    def test_something_that_is_not_a_mapping_is_refused(self):
        run = SequencingRun(run_name="R")
        for bad in ([], "json", None, 0):
            with pytest.raises(ValueError, match="exports"):
                run.exports = bad

    def test_the_kept_manifest_cannot_be_written_into(self):
        run = SequencingRun(run_name="R")
        run.exports = _manifest()
        with pytest.raises(TypeError):
            run.exports["json"] = {"id": ID, "sha256": SHA, "size": 1}

    def test_writing_into_the_dict_that_was_handed_in_changes_nothing(self):
        run = SequencingRun(run_name="R")
        handed = _manifest()
        run.exports = handed
        handed["json"] = {"id": ID, "sha256": SHA, "size": 1}
        assert set(run.exports) == {"samplesheet_v2"}


class TestTheManifestIsStoredAndLoaded:

    def test_it_round_trips_through_to_dict_and_from_dict(self):
        run = SequencingRun(run_name="R")
        run.exports = _manifest()
        loaded = SequencingRun.from_dict(run.to_dict())
        assert loaded.exports == run.exports

    def test_a_run_stored_before_this_change_loads_with_an_empty_manifest(self):
        doc = SequencingRun(run_name="R").to_dict()
        doc.pop("exports")
        assert SequencingRun.from_dict(doc).exports == {}

    def test_a_stored_manifest_that_is_malformed_makes_the_run_unreadable(self):
        """As an oversize sample id does (fix/long-ids): a run whose manifest
        cannot be trusted must not load and be served."""
        doc = SequencingRun(run_name="R").to_dict()
        doc["exports"] = {"samplesheet_v2": {"id": "nope", "sha256": SHA, "size": 1}}
        with pytest.raises(ValueError):
            SequencingRun.from_dict(doc)


class TestTheManifestIsAnOutputNotAnInput:
    """``exports`` is written by the very transition Mark Ready is trying to
    commit, and it is not a change to the run's setup: it belongs with the
    other export outputs in both denylists."""

    def test_the_export_fingerprint_ignores_it(self):
        from seqsetup.routes.runs import _FINGERPRINT_IGNORED_KEYS, _export_input_fingerprint
        assert "exports" in _FINGERPRINT_IGNORED_KEYS
        run = SequencingRun(run_name="R")
        before = _export_input_fingerprint(run)
        run.exports = _manifest()
        assert _export_input_fingerprint(run) == before

    def test_the_change_history_ignores_it(self):
        from seqsetup.services.run_diff import RUN_DIFF_IGNORED_KEYS, diff_run
        assert "exports" in RUN_DIFF_IGNORED_KEYS
        before = SequencingRun(run_name="R").to_dict()
        after = dict(before, exports={"json": {"id": ID, "sha256": SHA, "size": 1}})
        assert diff_run(before, after) == ([], [])
