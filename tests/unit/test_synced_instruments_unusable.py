"""When synced instrument records exist, only they count; when they cannot
be used, SeqSetup stops and says so, never falling back to the local file
(spec 2026-10-04 group A2, §5)."""

import logging

import pytest
from pymongo.errors import ServerSelectionTimeoutError

from seqsetup.data import instruments as instruments_module
from seqsetup.data.instruments import (
    SyncedInstrumentsUnusable,
    get_instrument_config,
    i5_workflow_names,
    is_instrument_enabled_by_name,
    no_settings_reason,
    reading_synced_records,
)
from seqsetup.models.instrument_definition import InstrumentDefinition, InstrumentRecordError

NOVASEQ_X = "NovaSeq X Series"
I100 = "MiSeq i100 Series"
REMEDY = (
    "Update the instrument files and run a config sync with Also sync instruments on "
    "(Admin > Config Sync)."
)
DATABASE = (
    "The synced instrument settings could not be read from the database. "
    "Try again, or ask an administrator to check the database."
)


def _definition(name: str = NOVASEQ_X) -> InstrumentDefinition:
    return InstrumentDefinition.from_yaml(
        dict(instruments_module._instruments[name], name=name), "instruments.yaml")


class _Repo:
    """A synced-instrument repository whose list_all returns or raises what
    each call is given."""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.calls = 0

    def list_all(self):
        self.calls += 1
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


@pytest.fixture
def use_repo():
    def _use(repo):
        instruments_module.set_instrument_definition_repo(repo)
        return repo
    yield _use
    instruments_module.set_instrument_definition_repo(None)
    instruments_module._last_logged_failure = None


class TestOnlySyncedInstrumentsCount:
    """While synced records exist, an instrument not among them has no
    settings: the local file is not read for it."""

    def test_an_instrument_left_out_has_no_settings(self, use_repo):
        use_repo(_Repo([_definition(NOVASEQ_X)]))
        assert get_instrument_config(I100) is None
        assert i5_workflow_names(I100) is None
        assert get_instrument_config(NOVASEQ_X)["runinfo_marks_i5_reversed"] is True

    def test_it_is_not_called_disabled(self, use_repo):
        use_repo(_Repo([_definition(NOVASEQ_X)]))
        assert is_instrument_enabled_by_name(I100) is True
        assert no_settings_reason(I100) == "MiSeq i100 Series is not among the synced instruments"

    def test_with_no_synced_records_the_local_file_is_used(self, use_repo):
        use_repo(_Repo([]))
        assert i5_workflow_names(I100) == ["Index-first", "Read-first"]
        assert no_settings_reason("No Such Sequencer") == (
            "No Such Sequencer is not in the local instruments file")


class TestRecordsThatCannotBeUsed:
    """A record error or a database error stops every lookup with the message."""

    def test_a_record_error(self, use_repo):
        use_repo(_Repo(InstrumentRecordError("NovaSeq X Series: i5_workflows: Required")))
        with pytest.raises(SyncedInstrumentsUnusable) as exc:
            get_instrument_config(I100)
        assert str(exc.value) == (
            "The synced instrument settings cannot be used: NovaSeq X Series: "
            f"i5_workflows: Required. {REMEDY}"
        )

    def test_a_database_error_does_not_show_the_drivers_text(self, use_repo, caplog):
        use_repo(_Repo(ServerSelectionTimeoutError("db-host-7:27017: timed out")))
        with caplog.at_level(logging.ERROR, logger="seqsetup.data.instruments"):
            with pytest.raises(SyncedInstrumentsUnusable) as exc:
                get_instrument_config(I100)
        assert str(exc.value) == DATABASE
        assert "db-host-7" in caplog.text

    def test_it_is_not_a_value_error(self):
        # So no `except ValueError` around an instrument read turns it into a 400.
        assert issubclass(SyncedInstrumentsUnusable, RuntimeError)
        assert not issubclass(SyncedInstrumentsUnusable, ValueError)

    def test_nothing_is_cached_while_it_fails(self, use_repo):
        repo = use_repo(_Repo(InstrumentRecordError("x: y"), [_definition(NOVASEQ_X)]))
        with pytest.raises(SyncedInstrumentsUnusable):
            get_instrument_config(NOVASEQ_X)
        assert get_instrument_config(NOVASEQ_X) is not None
        assert repo.calls == 2

    def test_a_programming_error_is_not_caught(self, use_repo):
        use_repo(_Repo(KeyError("name")))
        with pytest.raises(KeyError):
            get_instrument_config(NOVASEQ_X)

    def test_it_is_logged_once_per_change_of_state(self, use_repo, caplog):
        failure = InstrumentRecordError("x: y")
        use_repo(_Repo(failure, failure, [], failure))
        with caplog.at_level(logging.ERROR, logger="seqsetup.data.instruments"):
            for _ in range(2):
                with pytest.raises(SyncedInstrumentsUnusable):
                    get_instrument_config(NOVASEQ_X)
            get_instrument_config(NOVASEQ_X)  # usable again (no records)
            with pytest.raises(SyncedInstrumentsUnusable):
                get_instrument_config(NOVASEQ_X)
        assert [r.getMessage() for r in caplog.records].count(
            f"The synced instrument settings cannot be used: x: y. {REMEDY}") == 2


class TestADirectRead:
    """reading_synced_records: a read straight from the database (Mark Ready's
    switch re-read, the admin Instruments page) gives the same message."""

    @pytest.fixture(autouse=True)
    def _fresh_log_state(self):
        instruments_module._last_logged_failure = None
        yield
        instruments_module._last_logged_failure = None

    def test_a_database_error_is_the_fixed_sentence(self, caplog):
        with caplog.at_level(logging.ERROR, logger="seqsetup.data.instruments"):
            with pytest.raises(SyncedInstrumentsUnusable) as exc:
                with reading_synced_records():
                    raise ServerSelectionTimeoutError("db-host-7:27017: timed out")
        assert str(exc.value) == DATABASE
        assert isinstance(exc.value.__cause__, ServerSelectionTimeoutError)
        assert "db-host-7" in caplog.text

    def test_other_errors_pass_through(self):
        with pytest.raises(InstrumentRecordError):
            with reading_synced_records():
                raise InstrumentRecordError("x: y")

    def test_each_database_error_is_logged(self, caplog):
        # A direct read follows a user's action, and a lookup served from the
        # cache cannot tell that the database came back in between.
        with caplog.at_level(logging.ERROR, logger="seqsetup.data.instruments"):
            for host in ("db-host-7", "db-host-8"):
                with pytest.raises(SyncedInstrumentsUnusable):
                    with reading_synced_records():
                        raise ServerSelectionTimeoutError(f"{host}:27017: timed out")
        assert "db-host-7" in caplog.text
        assert "db-host-8" in caplog.text
