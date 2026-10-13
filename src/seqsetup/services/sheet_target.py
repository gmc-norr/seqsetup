"""Each stored Sample Sheet's target instrument and software (the user's
request, 2026-10-13).

Mark Ready saves it with the sheets: the i5 direction the sheets were
written with, and the BCL Convert version the v2 sheet itself states. It is
never worked out again later -- an administrator may change an instrument's
settings after the run is Ready, and the stored sheets do not change with
them.

Each target is a plain dict:

    instrument                  the run's instrument, e.g. "NovaSeq X Series"
    software                    "BCL Convert" (v2 sheet) or "bcl2fastq" (v1)
    software_version            the BCL Convert version the v2 sheet states,
                                or None (a v1 sheet states none)
    i5_workflow                 the run's i5 workflow
    index2_column               "forward" (each sample's i5 as stored),
                                "reverse-complement", or "none" (no sample
                                has an i5)
    needs_runinfo_reverse_mark  True when the sheet relies on BCL Convert
                                acting on the IsReverseComplement="Y" mark
                                RunInfo.xml puts on the i5 read
"""

from typing import Optional

from ..data.instruments import I5Direction


def bclconvert_software_version(samplesheet_v2: str) -> Optional[str]:
    """The SoftwareVersion in the sheet's [BCLConvert_Settings], or None."""
    section = ""
    for line in samplesheet_v2.splitlines():
        if line.startswith("["):
            section = line.strip()
        elif section == "[BCLConvert_Settings]" and line.startswith("SoftwareVersion,"):
            return line.split(",", 1)[1].strip()
    return None


def sheet_targets(
    instrument: str, direction: I5Direction, samplesheet_v2: str, samplesheet_v1: Optional[str],
    has_i5: bool = True,
) -> dict:
    """The targets of a run's v2 sheet and, when it has one, its v1 sheet.
    ``has_i5`` is whether any sample has an i5: with none, neither sheet
    writes one, and none relies on the RunInfo.xml mark."""

    def column(reversed_: bool) -> str:
        if not has_i5:
            return "none"
        return "reverse-complement" if reversed_ else "forward"

    return {
        "samplesheet_v2": {
            "instrument": instrument,
            "software": "BCL Convert",
            "software_version": bclconvert_software_version(samplesheet_v2),
            "i5_workflow": direction.workflow,
            "index2_column": column(direction.index2_column_reversed),
            "needs_runinfo_reverse_mark": has_i5 and direction.index2_mask_reversed,
        },
        # bcl2fastq compares the i5 as the workflow reads it, and reads no
        # mark in RunInfo.xml (samplesheet_v1_exporter).
        "samplesheet_v1": {
            "instrument": instrument,
            "software": "bcl2fastq",
            "software_version": None,
            "i5_workflow": direction.workflow,
            "index2_column": column(direction.reads_reversed),
            "needs_runinfo_reverse_mark": False,
        } if samplesheet_v1 else None,
    }
