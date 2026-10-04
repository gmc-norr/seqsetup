"""Times in the exports and the page filter follow the display zone (TZ):
the v1 Sample Sheet's Date is the lab's calendar day, the validation report
says when it was made in the lab's time, with the offset or the zone."""

import base64
import json
import re
import zlib
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import pytest

from seqsetup.models.sequencing_run import InstrumentPlatform, SequencingRun
from seqsetup.models.validation import ValidationResult
from seqsetup.services.samplesheet_v1_exporter import SampleSheetV1Exporter
from seqsetup.services.validation_report import ValidationReportJSON, ValidationReportPDF
from seqsetup.templating import templates

V1_PLATFORM = next(p for p in InstrumentPlatform if SampleSheetV1Exporter.supports(p))
STOCKHOLM = ZoneInfo("Europe/Stockholm")


@pytest.fixture
def stockholm(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/Stockholm")


def _pdf_text(pdf: bytes) -> str:
    text = b""
    for m in re.finditer(rb"stream\r?\n(.*?)endstream", pdf, re.S):
        try:
            text += zlib.decompress(base64.a85decode(m.group(1).strip(), adobe=True))
        except ValueError:
            continue
    return text.decode("latin-1")


class TestTheV1SheetDate:
    """[Header] Date: the day the run was made, in the lab's time zone."""

    def _sheet(self, created_at):
        return SampleSheetV1Exporter.export(SequencingRun(
            run_name="R", instrument_platform=V1_PLATFORM, created_at=created_at))

    def test_late_evening_utc_is_the_next_day_in_stockholm(self, stockholm):
        assert "Date,2026-01-16\n" in self._sheet(datetime(2026, 1, 15, 23, 30))

    def test_the_same_day_in_utc(self, monkeypatch):
        monkeypatch.setenv("TZ", "UTC")
        assert "Date,2026-01-15\n" in self._sheet(datetime(2026, 1, 15, 23, 30))


class TestTheValidationReport:
    def test_the_json_time_carries_the_lab_offset(self, stockholm):
        data = json.loads(ValidationReportJSON.export(SequencingRun(run_name="R"),
                                                      ValidationResult([], [], {})))
        made = datetime.fromisoformat(data["timestamp"])
        now = datetime.now(timezone.utc)
        assert made.utcoffset() == now.astimezone(STOCKHOLM).utcoffset()
        assert abs(made - now) < timedelta(seconds=30)

    def test_the_pdf_time_names_the_zone(self, stockholm):
        text = _pdf_text(ValidationReportPDF.export(SequencingRun(run_name="R"),
                                                    ValidationResult([], [], {})))
        made = re.search(r"\(Report Generated\).*?\((\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) (CES?T)\)",
                         text, re.S)
        assert made, text[:500]
        shown = datetime.strptime(made.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=STOCKHOLM)
        assert abs(shown - datetime.now(timezone.utc)) < timedelta(seconds=30)


class TestThePageFilter:
    """{{ value | localtime }} in every template."""

    def test_minutes(self, stockholm):
        page = templates.env.from_string("{{ t | localtime }}").render(t=datetime(2026, 7, 15, 12, 0))
        assert page == "2026-07-15 14:00 CEST"

    def test_seconds(self, stockholm):
        page = templates.env.from_string("{{ t | localtime(seconds=True) }}").render(
            t=datetime(2026, 1, 15, 12, 0, 5))
        assert page == "2026-01-15 13:00:05 CET"
