Instrument Configuration
========================

SeqSetup ships a built-in list of Illumina instruments and their flowcells in
``config/instruments.yaml`` -- read once at startup, and requiring a restart
(or the ``INSTRUMENTS_CONFIG`` environment variable, to point at a different
file) to change. This shipped list cannot be edited or individually disabled
from the UI.

**Admin > Instruments** lets an admin manage a *different*, additional set:
instrument definitions synced in from GitHub (see :doc:`profiles`). Until at
least one instrument has been synced, the page shows a note pointing at that
fallback file instead of a management table -- there is nothing to enable or
disable yet.

.. figure:: /_static/screenshots/admin/instruments.png
   :alt: The Synced Instruments table, with one instrument's Enabled checkbox outlined.

   The synced-instrument table, with one instrument's **Enabled** checkbox
   outlined.

.. warning::
   Syncing instrument definitions is **not additive**. As soon as any
   instrument has ever been synced, the New Run instrument dropdown offers
   *only* the synced set -- ``config/instruments.yaml`` stops being
   consulted for that dropdown entirely, even for instrument names the sync
   never mentioned. If your synced repository defines only a subset of the
   instruments your lab actually runs (say, just NovaSeq X Series), the rest
   disappear from **New Run** the moment that sync completes, until they are
   added to the synced set too. A run **already** using one of the
   now-unlisted instruments is unaffected -- its own settings still resolve
   correctly -- but nobody can start a *new* run on it until it is synced.

Enabling and disabling
--------------------------

Once at least one instrument is synced, each row has its own **Enabled**
checkbox, and there are **Enable All** / **Disable All** buttons above the
table. Toggling any of these takes effect immediately, with no
confirmation, and the resulting state is saved right away.

.. warning::
   Today, the **Enabled** checkbox (and **Enable All** / **Disable All**)
   has **no effect on what a user can choose when setting up a new run**.
   The New Run instrument list is never filtered by this flag, so
   disabling an instrument here does not remove it from **New Run** --
   any user can still select it and start a run on it. An administrator
   who disables a decommissioned or unvalidated instrument here and
   believes it is now unavailable is mistaken; nothing about the new-run
   flow has changed. The only thing that actually removes an instrument
   from **New Run** today is excluding it from what your synced source
   defines and re-syncing (see the "not additive" warning above), which
   drops the instrument from the synced set entirely rather than merely
   hiding it while it stays synced.

.. note::
   The checkbox's state does survive a later sync: SeqSetup matches the
   old and new instrument sets by their samplesheet name and carries the
   disabled flag forward, rather than resetting every instrument back to
   enabled on each sync. That persistence is all the flag does -- it is
   saved and it survives a sync, but it is not read anywhere that decides
   which instruments a new run may use.

i5 Read Orientation and SBS Chemistry
------------------------------------------

Each instrument definition also carries the physical details SeqSetup needs
to build a correct Sample Sheet:

**i5 read orientation**
   ``forward`` or ``reverse-complement`` -- the direction this instrument
   physically reads the i5 index.

**Sample Sheet v2 i5 orientation**
   ``forward`` or ``reverse-complement`` -- a separate field that decides
   what SeqSetup actually writes for Sample Sheet v2 (falling back to i5
   read orientation when not set explicitly), and it can disagree with
   the physical direction above: NovaSeq X Series physically reads i5 as
   reverse-complement, but its Sample Sheet v2 i5 orientation is
   ``forward``, so nothing is flipped for it. When this field is
   ``reverse-complement``, SeqSetup itself reverses the Index 2
   override-cycles segment (e.g. ``I8N2`` becomes ``N2I8``) and writes
   the i5 sequence already reverse-complemented -- it does not rely on
   BCL Convert to do either. See :doc:`/user-guide/export` for which
   shipped instruments this applies to.

**SBS chemistry**
   ``2-color`` or ``4-color``. Two-color chemistry has a "dark" base with no
   fluorescent signal, which is why SeqSetup runs a color-balance check for
   those instruments (see :doc:`/user-guide/validation`) and does not for
   four-color ones.

**Sample sheet name and onboard application names**
   The sample sheet name (e.g. ``NovaSeqXSeries``) is written on the Sample
   Sheet's ``InstrumentPlatform`` line, and each onboard application name
   (e.g. ``BCLConvert``) decides which application profiles the instrument
   can run. Both may only contain letters, digits, ``_`` and ``-``; an
   onboard application's ``software_version`` may also contain ``.``. A
   synced instrument file that breaks this is skipped, with the reason on
   :doc:`Admin > Logs <logs>`. As a second check, SeqSetup will not write a
   Sample Sheet whose ``InstrumentPlatform`` name, or whose application
   profile's ``ApplicationName`` (see :doc:`profiles`), breaks the rule, so
   a run cannot be marked Ready with one.

.. warning::
   A reagent kit's maximum total cycle count (Read 1 + Index 1 + Index 2 +
   Read 2) is an **optional** field on an instrument definition
   (``reagent_kit_max_cycles``), and the shipped
   ``config/instruments.yaml`` sets it for **no instrument at all** -- so
   the "too many cycles for this kit" check never fires unless an admin
   syncs an instrument definition that supplies it. If your lab relies on
   that check, it only ever exists after a GitHub sync brings in a
   definition that sets it.

Who can do this
-------------------

Viewing and changing which synced instruments are enabled requires the
**Admin** role. The shipped ``config/instruments.yaml`` file itself is
edited on the server's filesystem, outside the application.
