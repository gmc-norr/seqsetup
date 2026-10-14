"""The check report draws each chart on its own figure, not through pyplot
(the user's choice "Side worker", 2026-10-14).

Mark Ready now runs on a side worker, so two people can draw reports at
once. pyplot keeps one list of figures and one "current figure" for the
whole app, and ``plt.tight_layout()`` lays out whichever figure is current:
the other person's, while both draw.
"""

import matplotlib.pyplot as plt

from seqsetup.models.index import Index, IndexPair, IndexType
from seqsetup.models.sample import Sample
from seqsetup.models.sequencing_run import InstrumentPlatform, RunCycles, SequencingRun
from seqsetup.services.validation import ValidationService
from seqsetup.services.validation_report import ValidationReportPDF


def _two_sample_run() -> SequencingRun:
    run = SequencingRun(run_name="charts", instrument_platform=InstrumentPlatform.NOVASEQ_X,
                        flowcell_type="10B", run_cycles=RunCycles(151, 151, 10, 10))
    for k, (i7, i5) in enumerate([("ATTACTCG", "TATAGCCT"), ("TCCGGAGA", "ATAGAGGC")]):
        run.add_sample(Sample(sample_id=f"S{k + 1}", lanes=[1], index_pair=IndexPair(
            id=f"p{k + 1}", name=f"p{k + 1}",
            index1=Index(name=f"i7_{k + 1}", sequence=i7, index_type=IndexType.I7),
            index2=Index(name=f"i5_{k + 1}", sequence=i5, index_type=IndexType.I5))))
    return run


class TestTheReportDrawsWithoutPyplot:

    def test_no_pyplot_figure_is_used(self, monkeypatch):
        def shared(*args, **kwargs):
            raise AssertionError("the report drew through pyplot's shared figures")

        for name in ("figure", "subplots", "tight_layout", "close", "gcf", "gca", "savefig"):
            monkeypatch.setattr(plt, name, shared)
        drawn = []

        def recording(name, real):
            def draw(cls, *args):
                image = real(*args)
                drawn.append((name, image is not None))
                return image
            return classmethod(draw)

        for name in ("_render_heatmap", "_render_color_balance"):
            monkeypatch.setattr(ValidationReportPDF, name,
                                recording(name, getattr(ValidationReportPDF, name)))
        run = _two_sample_run()

        pdf = ValidationReportPDF.export(run, ValidationService.validate_run(run))

        assert pdf.startswith(b"%PDF")
        assert ("_render_heatmap", True) in drawn
        assert ("_render_color_balance", True) in drawn
