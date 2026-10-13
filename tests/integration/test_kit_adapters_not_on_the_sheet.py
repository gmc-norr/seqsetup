"""The kit page says plainly that a kit's adapter sequences are not written
to the Sample Sheet.

A kit stores Adapter R1 and R2, the index check validates them as DNA, the
kit's YAML download carries them back out, and the detail page shows them --
but no exporter reads them. The sheet's AdapterRead1/AdapterRead2 cells come
from the application profile, so a lab that fills the kit's adapter boxes and
reads the page gets no adapter trimming it did not already have. The page now
says so.
"""

from seqsetup.models.index import Index, IndexKit, IndexMode, IndexType

SAID_ON_THE_PAGE = "not written to the Sample Sheet"


def _kit(ctx, **changes) -> IndexKit:
    kit = IndexKit(
        name="Adapter kit", version="1.0", index_mode=IndexMode.SINGLE,
        i7_indexes=[Index(name="A01", sequence="ACGTACGT", index_type=IndexType.I7)],
        **changes,
    )
    ctx.index_kit_repo.save(kit)
    return kit


class TestTheKitPageOnAdapters:
    def test_a_kit_with_adapters_says_they_do_not_reach_the_sheet(
            self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _kit(ctx, adapter_read1="CTGTCTCTTATACACATCT",
             adapter_read2="CTGTCTCTTATACACATCT")

        resp = logged_in_client.get("/indexes/detail/Adapter%20kit/1.0")

        assert resp.status_code == 200, resp.text[:200]
        assert "CTGTCTCTTATACACATCT" in resp.text
        assert SAID_ON_THE_PAGE in resp.text

    def test_a_kit_without_adapters_says_it_too(self, logged_in_client, fresh_app):
        _app, ctx, _db = fresh_app
        _kit(ctx)

        resp = logged_in_client.get("/indexes/detail/Adapter%20kit/1.0")

        assert resp.status_code == 200, resp.text[:200]
        assert SAID_ON_THE_PAGE in resp.text
