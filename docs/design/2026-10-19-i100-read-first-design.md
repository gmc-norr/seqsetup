# The MiSeq i100 Series offers read-first runs only

## The problem

SeqSetup shipped two i5 workflows for the MiSeq i100 Series: **Index-first**,
the standard one (a new run gets it), and **Read-first**. Both write their
OverrideCycles in the order Read 1, Index 1, Index 2, Read 2, as SeqSetup does
for every instrument.

BCL Convert reads the OverrideCycles fields in the order the run's
`RunInfo.xml` lists its reads, and refuses a field whose cycle count or kind
(`Y` on a genomic read, `I` on an index read) does not fit (DRAGEN BCL Convert
for MiSeq i100 v1.1.8 release notes, document 200077130 00). So the order is
right only if the run's `RunInfo.xml` lists its reads in that order.

## What a real run shows

A `RunInfo.xml` from the lab's MiSeq i100 (2026-10-15; not kept in this
repository, as it names the instrument and the flow cell) lists:

| Read | Cycles | Index read | Reverse complement |
|---|---|---|---|
| 1 | 301 | N | N |
| 2 | 6 | Y | N |
| 3 | 6 | Y | Y |
| 4 | 301 | N | N |

That is a **read-first** run:

- Illumina's MiSeq i100 run order (NGI OpenLab MiSeq i100 Plus instruction,
  v3 2025-10-10, page 3, Illumina's picture): read first is Read 1, Index 1,
  paired-end turn, Index 2, Read 2; index first is Index 1, Index 2, Read 1,
  paired-end turn, Read 2.
- Illumina reads the i5 forward in an index-first run and as its reverse
  complement in a read-first run (knowledge articles 000001800 and 000005078),
  and the i100's `RunInfo.xml` carries the flag that tells BCL Convert so.
  Read 3 is marked reverse complement.
- Index-first is the instrument's default: a run is read-first when
  "Sequence Indexes First" is unticked on the Review Run page (knowledge
  article 000009499).

So for a read-first run the order SeqSetup writes is the order the run lists,
and the i5 marking is the one SeqSetup's i100 settings expect
(`runinfo_marks_i5_reversed: true`, Read-first reading the i5 reversed).

No `RunInfo.xml` of an index-first i100 run was found, the lab's or a public
one. Index-first sequences both index reads before Read 1, so its
`RunInfo.xml` very likely lists them first, and then SeqSetup's order would be
refused by BCL Convert at the start of the analysis. That is unverified.

## The decision

The user's (2026-10-19): the lab has not run index-first, so the shipped
MiSeq i100 Series lists **Read-first only**, in `config/instruments.yaml` and
in the sync example `config/instruments/miseq-i100-series.yaml`. Index-first
comes back only with a real index-first `RunInfo.xml` and the read order it
shows. The other option, keeping Index-first as a second choice behind a
Read-first standard, would keep a path whose sheets are probably refused.

## What changes

- **A new i100 run gets Read-first**, and the run setup page shows no i5
  workflow choice for the i100 (it shows one only when an instrument lists
  more than one workflow).
- **Sheets.** The Index2 column is written as the kit lists it in both
  workflows (the i100's `RunInfo.xml` marks the reversed read), so the column
  and the `IndexOrientation,Forward` header line do not change. The Index 2
  part of OverrideCycles is written reversed when the i5 is shorter than the
  Index 2 read, as for the NovaSeq X Series (see Instruments in the admin
  guide). Measured on the 78-sheet corpus (`tools/today_sheets.py` against
  the `cca4a12` sheets): one sheet differs, `MiSeq i100 Series|5M|8on10|dual|v2`,
  in its two OverrideCycles cells only, `Y151;I8N2;I8N2;Y151` becoming
  `Y151;I8N2;N2I8;Y151`. The 8-on-8 and 10-on-10 i100 sheets and every other
  instrument's sheets are unchanged.
- **A run stored with Index-first** keeps that name. The run setup page shows
  it "(not available)" beside Read-first, and the Check page and Mark Ready
  refuse it ("Index-first is not an i5 workflow of MiSeq i100 Series (it has:
  Read-first). Pick one in Run Setup.") until Read-first is picked. A Ready or
  Archived run keeps its sheets and the record of what they were written for.
  **A template stored with Index-first** makes no run ("Index-first is no
  longer an i5 workflow of MiSeq i100 Series; this template cannot be
  used."), as for any workflow its instrument no longer lists. SeqSetup is
  not deployed yet, so no lab run or template is stored with it.
- **On the instrument**, a run must be set up read-first: untick "Sequence
  Indexes First" on the Review Run page. The admin and user guides say so.
- **A lab's own instrument settings** (a synced instrument file or its own
  local file) keep whatever workflows they list; this changes only what ships.

## What does not change

- The i5 rule itself (`services/i5_rule.py`): a forward workflow on an
  instrument whose `RunInfo.xml` marks the i5 stays supported and tested, on
  a test instrument instead of the shipped i100.
- Every other shipped instrument's workflows.
- No code change: the instrument settings, the docs and the tests change.
