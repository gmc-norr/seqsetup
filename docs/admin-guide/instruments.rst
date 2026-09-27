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
checkbox; toggling it (or **Enable All** / **Disable All**) takes effect
immediately, with no confirmation. A disabled instrument is not offered when
setting up a new run, but a run already using it is unaffected.

.. note::
   Disabling and re-enabling an instrument survives a later sync: SeqSetup
   matches the old and new instrument sets by their samplesheet name and
   carries a disabled flag forward, rather than resetting everything back
   to enabled.

i5 Read Orientation and SBS Chemistry
------------------------------------------

Each instrument definition also carries the physical details SeqSetup needs
to build a correct Sample Sheet:

**i5 read orientation**
   ``forward`` or ``reverse-complement``. SeqSetup always stores index
   sequences in forward orientation; for a reverse-complement instrument, it
   reverses the Index 2 override-cycles segment at export time (e.g.
   ``I8N2`` becomes ``N2I8``) and lets BCL Convert handle the actual
   sequence reverse-complementing.

**SBS chemistry**
   ``2-color`` or ``4-color``. Two-color chemistry has a "dark" base with no
   fluorescent signal, which is why SeqSetup runs a color-balance check for
   those instruments (see :doc:`/user-guide/validation`) and does not for
   four-color ones.

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
