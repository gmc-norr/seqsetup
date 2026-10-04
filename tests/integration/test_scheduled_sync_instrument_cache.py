"""A config sync must be seen by the rest of the process at once.

The app caches the synced instrument definitions in memory. The manual
"Sync now" admin route cleared that cache, but the scheduled sync did not,
so after a background sync the app kept using the old instrument settings
until a restart — including the i5 orientation written to the Sample Sheet.
"""

from seqsetup.data import instruments as instruments_module
from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.instrument_definition import InstrumentDefinition
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import (
    InstrumentPlatform,
    RunCycles,
    SequencingRun,
)
from seqsetup.services.scheduler import ProfileSyncScheduler

from .conftest import disable_repos


ORIGIN = {"Origin": "http://testserver"}
INSTRUMENT = "NovaSeq X Series"
I5_FORWARD = "TATAGCCT"
I5_RC = "AGGCTATA"  # reverse complement of TATAGCCT


def _instrument(orientation: str) -> InstrumentDefinition:
    """NovaSeq X, which reads the i5 reversed. ``orientation`` is the i5
    the sheet gets: forward when RunInfo.xml marks the reversed read,
    reversed when it does not (spec 2026-10-04 group A2, §2)."""
    return InstrumentDefinition(
        name=INSTRUMENT,
        samplesheet_name="NovaSeqXSeries",
        version="1.0.0",
        chemistry_type="2-color",
        i5_workflows=[{"name": "Standard", "i5_read_orientation": "reverse-complement"}],
        runinfo_marks_i5_reversed=orientation == "forward",
    )


def _marks() -> bool:
    """The synced instrument's runinfo_marks_i5_reversed, as the app reads it."""
    return instruments_module.get_instrument_config(INSTRUMENT)["runinfo_marks_i5_reversed"]


def _scheduled_sync(ctx, monkeypatch, orientation: str) -> None:
    """Run one scheduled sync, as the background scheduler does, with the
    GitHub fetches replaced by a fixed instrument definition."""
    config = ctx.profile_sync_config_repo.get()
    config.github_repo_url = "https://github.com/example/config"
    config.sync_enabled = True
    config.sync_instruments_enabled = True
    config.sync_index_kits_enabled = False
    config.last_sync_at = None
    ctx.profile_sync_config_repo.save(config)

    service = ctx.get_github_sync_service()
    monkeypatch.setattr(
        service, "_fetch_profiles_recursive", lambda *a, **k: []
    )
    monkeypatch.setattr(
        service, "_fetch_instruments", lambda *a, **k: [_instrument(orientation)]
    )
    ProfileSyncScheduler(service, ctx.profile_sync_config_repo)._check_and_sync()
    assert ctx.profile_sync_config_repo.get().last_sync_status == "success"


def _seed_run(ctx, run_id: str) -> str:
    run = SequencingRun(
        id=run_id,
        run_name="SyncCache",
        instrument_platform=InstrumentPlatform.NOVASEQ_X,
        flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8),
    )
    run.add_sample(Sample(
        sample_id="S1",
        index_pair=IndexPair(
            id="p1", name="p1",
            index1=Index(name="i7", sequence="ATTACTCG", index_type=IndexType.I7),
            index2=Index(name="i5", sequence=I5_FORWARD, index_type=IndexType.I5),
        ),
    ))
    ctx.run_repo.save(run)
    return run.id


def _i5_cell(sheet: str) -> str:
    lines = sheet.split("\n")
    start = lines.index("[BCLConvert_Data]")
    header = lines[start + 1].split(",")
    row = lines[start + 2].split(",")
    return row[header.index("Index2")]


class TestScheduledSyncRefreshesInstruments:
    """After a scheduled sync, the app uses the new instrument definitions."""

    def test_scheduled_sync_updates_the_cached_instrument(
        self, fresh_app, monkeypatch
    ):
        _app, ctx, _db = fresh_app
        assert ctx.app_profile_repo.list_all() == []
        assert ctx.test_profile_repo.list_all() == []

        _scheduled_sync(ctx, monkeypatch, "forward")
        # Read once so the old value sits in the in-memory cache.
        assert _marks() is True

        _scheduled_sync(ctx, monkeypatch, "reverse-complement")

        assert _marks() is False

    def test_run_made_ready_after_scheduled_sync_exports_new_orientation(
        self, fresh_app, logged_in_client, monkeypatch
    ):
        _app, ctx, _db = fresh_app
        disable_repos(ctx, "test_profile", "app_profile")

        _scheduled_sync(ctx, monkeypatch, "forward")
        run_a = _seed_run(ctx, "sync-cache-a")
        assert logged_in_client.post(
            f"/runs/{run_a}/status/ready", headers=ORIGIN
        ).status_code == 200
        sheet_a = logged_in_client.get(f"/runs/{run_a}/export/samplesheet-v2").text
        assert _i5_cell(sheet_a) == I5_FORWARD

        _scheduled_sync(ctx, monkeypatch, "reverse-complement")
        run_b = _seed_run(ctx, "sync-cache-b")
        assert logged_in_client.post(
            f"/runs/{run_b}/status/ready", headers=ORIGIN
        ).status_code == 200
        sheet_b = logged_in_client.get(f"/runs/{run_b}/export/samplesheet-v2").text

        assert _i5_cell(sheet_b) == I5_RC

    def test_failed_scheduled_sync_keeps_the_cached_instrument(
        self, fresh_app, monkeypatch
    ):
        _app, ctx, _db = fresh_app
        _scheduled_sync(ctx, monkeypatch, "forward")
        assert _marks() is True

        # A fetch that returns no instruments is refused by the
        # destructive-replace guard; nothing in the database changes.
        service = ctx.get_github_sync_service()
        monkeypatch.setattr(service, "_fetch_instruments", lambda *a, **k: [])
        config = ctx.profile_sync_config_repo.get()
        config.last_sync_at = None
        ctx.profile_sync_config_repo.save(config)
        ProfileSyncScheduler(service, ctx.profile_sync_config_repo)._check_and_sync()

        assert ctx.profile_sync_config_repo.get().last_sync_status == "error"
        assert _marks() is True
