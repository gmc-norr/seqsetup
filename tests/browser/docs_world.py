"""A clean, made-up demo world for the documentation screenshots.

The docs module borrows the browser-test database: snapshot() what is
there, clear() it, seed_demo(), take the pictures, restore() it. Nothing
here is real: names, users and index sequences are invented.
"""

from datetime import datetime

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexPair, IndexType
from seqsetup.models.local_user import LocalUser
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, RunStatus, SequencingRun
from seqsetup.models.test_profile import TestProfile
from seqsetup.models.user import UserRole

DEMO_ADMIN = {"username": "dana.demo", "password": "Demo-Docs-2026!", "display_name": "Dana Demo"}
DEMO_STAFF = {"username": "sam.staff", "password": "Demo-Staff-2026!", "display_name": "Sam Staff"}
DEMO_KIT_NAME = "Demo UDI Set A"
DEMO_KIT_VERSION = "1.0"
_T = datetime(2026, 3, 2, 9, 0, 0)
_WELLS = [f"{row}{col:02d}" for col in (1, 2, 3) for row in "ABCDEFGH"]


def snapshot(db) -> dict[str, list[dict]]:
    return {name: list(db[name].find()) for name in db.list_collection_names()}


def clear(db) -> None:
    for name in db.list_collection_names():
        db[name].delete_many({})


def restore(db, snap: dict[str, list[dict]]) -> None:
    clear(db)
    for name, docs in snap.items():
        if docs:
            db[name].insert_many(docs)


def reset_caches() -> None:
    from seqsetup.data import instruments
    from seqsetup.services.validation import clear_validation_cache

    clear_validation_cache()
    instruments._synced_instruments_cache = None


def _seq(n: int, salt: int) -> str:
    """A made-up 8-bp index: distinct for distinct n (7919 is odd, so
    n -> n * 7919 mod 4**8 is one-to-one)."""
    v = (n * 7919 + salt * 104729) % (4 ** 8)
    return "".join("ACGT"[(v >> (2 * k)) & 3] for k in range(8))


def _pair(n: int) -> IndexPair:
    name = f"UDI{n:04d}"
    return IndexPair(
        id=f"{DEMO_KIT_NAME}_{name}", name=name, well_position=_WELLS[n - 1],
        index1=Index(name=name, sequence=_seq(n, 1), index_type=IndexType.I7),
        index2=Index(name=name, sequence=_seq(n, 2), index_type=IndexType.I5),
    )


def _run(run_id, name, status=RunStatus.DRAFT, samples=()) -> SequencingRun:
    run = SequencingRun(
        id=run_id, run_name=name,
        instrument_platform=InstrumentPlatform.NOVASEQ_X, flowcell_type="10B",
        run_cycles=RunCycles(151, 151, 8, 8), status=status,
        created_by=DEMO_ADMIN["username"], updated_by=DEMO_ADMIN["username"],
        created_at=_T, updated_at=_T,
    )
    for s in samples:
        run.add_sample(s)
    return run


def _sample(run_id, n, pair=None, lanes=(1,), test_id="WGS") -> Sample:
    return Sample(
        id=f"{run_id}-s{n:02d}", sample_id=f"SAMPLE-A{n:02d}", sample_name=f"Sample A{n:02d}",
        project="DEMO-PROJECT", test_id=test_id, lanes=list(lanes),
        index_pair=pair, index_kit_name=DEMO_KIT_NAME if pair else None,
    )


def seed_demo(ctx) -> dict[str, str]:
    for spec, role in ((DEMO_ADMIN, UserRole.ADMIN), (DEMO_STAFF, UserRole.STANDARD)):
        user = LocalUser(username=spec["username"], display_name=spec["display_name"],
                         email=f"{spec['username']}@example.org", role=role,
                         created_at=_T, updated_at=_T)
        user.set_password(spec["password"])
        user.updated_at = _T
        ctx.local_user_repo.save(user)

    ctx.index_kit_repo.save(IndexKit(
        name=DEMO_KIT_NAME, version=DEMO_KIT_VERSION, index_mode=IndexMode.UNIQUE_DUAL,
        description="Made-up unique dual index set for the documentation",
        index_pairs=[_pair(n) for n in range(1, 25)], created_by=DEMO_ADMIN["username"],
    ))
    ctx.test_profile_repo.save(TestProfile(
        id="demo-wgs", test_type="WGS", test_name="Whole Genome Sequencing",
        description="Demo test profile", version="1.0.0", synced_at=_T,
    ))

    ids = {"draft": "demo-run-01", "problem": "demo-run-02", "fill": "demo-run-05",
           "ready": "demo-run-03", "archived": "demo-run-04"}
    ctx.run_repo.save(_run(ids["draft"], "DEMO-RUN-01", samples=[
        _sample(ids["draft"], n, _pair(n) if n <= 4 else None) for n in range(1, 9)]))
    ctx.run_repo.save(_run(ids["problem"], "DEMO-RUN-02", samples=[
        _sample(ids["problem"], 1, _pair(1)), _sample(ids["problem"], 2, _pair(1)),
        _sample(ids["problem"], 3, None, test_id="")]))
    ctx.run_repo.save(_run(ids["fill"], "DEMO-RUN-05", samples=[
        _sample(ids["fill"], n) for n in range(1, 7)]))
    ctx.run_repo.save(_run(ids["ready"], "DEMO-RUN-03", RunStatus.READY, samples=[
        _sample(ids["ready"], n, _pair(n)) for n in range(1, 5)]))
    ctx.run_repo.save(_run(ids["archived"], "DEMO-RUN-04", RunStatus.ARCHIVED, samples=[
        _sample(ids["archived"], n, _pair(n)) for n in range(5, 9)]))
    return ids
