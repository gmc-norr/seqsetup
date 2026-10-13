Run Setup
=========

Selecting **+ New Run** creates a new Draft run right away and opens its
setup page. Everything on this page saves as you go -- there is no
separate "save" step until you leave it.

Starting from a template
-------------------------

If your organization has saved any run templates (see **Run Templates**
in the sidebar), a new run offers to start from one instead of blank
defaults:

.. figure:: /_static/screenshots/new-run/template-choice.png
   :alt: The "Or start from a template" selector on the New Run page, with a template chosen, outlined.

   Starting from a template, outlined.

Choosing a template and selecting **Use template** replaces the blank run
with a new Draft copying that template's instrument and cycles but no
samples (see :doc:`templates`), and discards the blank run this page had
just created. This section only appears for a brand-new run, and only
when at least one template exists.

Run name and description
--------------------------

.. figure:: /_static/screenshots/new-run/name-and-description.png
   :alt: The Run Name and Description fields, outlined.

   Run name and description, outlined.

**Run Name** and **Description** save automatically when you leave the
field; the run name also saves when you press Enter. The run name is
limited to 256 characters and the description to 4096. A line break in
either -- such as one made by pressing Enter in the description -- is
saved as a space. Neither may hold another hidden character, such as a
tab from pasted text --
**Mark Ready** refuses the run until it is removed (see :doc:`validation`).

Instrument, flowcell and reagent kit
--------------------------------------

.. figure:: /_static/screenshots/new-run/instrument-and-flowcell.png
   :alt: The Platform, Flowcell and Reagent Kit selects, outlined.

   Instrument configuration, outlined.

- **Platform** -- the sequencing instrument. Changing it refreshes the
  Flowcell and Reagent Kit choices to match. Only instruments an
  administrator has enabled are offered. If the run's own instrument is
  not one of them, it still shows, selected and marked: **(disabled)**
  means an administrator switched it off -- pick another, because
  **Mark Ready** refuses the run until you do; **(not available)** means
  the last instrument sync left it out (see :doc:`/admin-guide/instruments`),
  and **Mark Ready** refuses the run too until you pick another.
- **Flowcell** -- the flowcell type for that instrument. Changing it
  refreshes the Reagent Kit choices.
- **Reagent Kit (cycles)** -- the reagent kit. Changing it resets Read 1,
  Read 2, Index 1 and Index 2 below to that kit's default cycle counts.
- **i5 workflow** -- shown only for an instrument that reads the i5 in more
  than one way. As shipped: MiSeq i100 Series (**Index-first**, the
  instrument's default, or **Read-first**), MiniSeq (**Standard kits** or
  **Rapid kits**) and NovaSeq 6000 (**v1.5 reagents** or **v1.0
  reagents**). The standard one is marked **(standard)**; a new run, and a
  change of instrument, gets it. Pick the one the instrument will actually
  run: it decides how the i5 is written in the Sample Sheet and how the
  dark-start and colour-balance checks read it. The run's Setup panel
  shows the choice. A workflow the instrument no longer lists shows as
  **(not available)**, and **Mark Ready** refuses the run until you pick
  another.

Run cycle configuration
-------------------------

.. figure:: /_static/screenshots/new-run/cycle-config.png
   :alt: The Read 1, Read 2, Index 1 and Index 2 cycle fields with the running total below them, outlined.

   Cycle configuration, outlined.

The line below the fields adds up Read 1, Index 1, Index 2 and Read 2.
When no cycle limit is recorded for the reagent kit -- which is how
SeqSetup ships -- it says so: **Not checked: no cycle limit is set for
this kit.** A 300-cycle kit's defaults already add up to 322 cycles (151
+ 151 + 10 + 10), because the kit label understates its real capacity, so
a total a little over the label is normal.

Read 1 and Read 2 are typed as whole numbers from 0 to 600; an invalid
value is rejected and nothing is saved. Index 1 and Index 2 are chosen
from a fixed list of cycle counts -- 8, 10, 12, 17, or 24.

.. warning::
   When the selected reagent kit has a known cycle limit, going over it
   shows **Too many cycles for this kit.** in red next to the total:

   .. figure:: /_static/screenshots/new-run/cycle-limit-exceeded.png
      :alt: The cycle total line reading "Too many cycles for this kit." in red, outlined.

      The cycle-limit warning, outlined.

   This limit comes from the instrument's synced configuration (kept
   under **Admin > Config Sync**) and is only checked for kits that have
   one recorded.

.. warning::
   Until an administrator adds a cycle limit for your instrument's kit
   through **Admin > Config Sync**, nothing checks the total -- not the
   line above, and not **Mark Ready** -- and the line says so.

Finishing setup
----------------

.. figure:: /_static/screenshots/new-run/continue-button.png
   :alt: The Cancel and Continue to Run buttons at the bottom of the New Run page, outlined.

   Finishing setup, outlined.

- **Continue to Run** saves the run name, description and cycle counts
  together and opens the run, where you add samples, indexes and lanes.
  If any of those values is rejected, you stay on this page with the
  error shown and nothing is saved.
- **Cancel** (shown only for a run you just created) deletes this run,
  since it is still an empty Draft.

Opening an existing run's setup again shows **Run Setup** instead of
**New Run Configuration**, with **Back to Run** in place of **Continue to
Run**, and no template chooser -- but only while it is still a Draft
and you are the one editing it (see `One person edits a run at a time`_).
A Ready or Archived run's setup cannot be changed.

.. warning::
   This page carries the version of the run it showed. If the run changed
   in another window or on another computer since this page was opened,
   every save it makes -- **Continue to Run** / **Back to Run**, which saves
   the whole form, and the instrument, i5 workflow, flow cell, reagent kit
   and cycle saves -- is refused with *"This run was changed in another
   window. Reload to see the latest version; nothing was saved."* and
   nothing is written -- otherwise this page's older values would silently
   replace the other window's, and with the cycles every sample's Override
   Cycles. Reload the
   page to see where the run stands, then make your change again. Each save
   this page makes itself keeps its version current, so your own edits never
   cause this.

One person edits a run at a time
---------------------------------

Only one person edits a Draft at a time, so two people never add samples,
indexes or lanes to the same run at once. The status bar at the top of the
run page says where the run stands:

- **Nobody is editing this run** -- the run is shown read-only, with
  *"Press Edit run to make changes."* above the samples. Press **Edit run**.
- **Sam Staff is editing this run (since 2026-03-02 10:00 CET)** -- the
  run is shown read-only, with *"Sam Staff is editing this run. Only they
  can change it now."* above the samples. If Sam has left -- gone home
  with the page open, say -- press
  **Take over editing**. SeqSetup asks first and names them; once you
  take over, they can no longer save changes to the run.
- **You are editing this run** -- the page shows everything you can
  change: **Edit setup**, adding samples, indexes and lanes, the Check
  panel's fixes, and **Mark Ready**. Press **Done editing** when you have
  finished, so that others can edit the run.

.. figure:: /_static/screenshots/new-run/someone-editing.png
   :alt: The run status bar of a Draft, reading "Sam Staff is editing this run (since 2026-03-02 10:00 CET)" next to a Take over editing button, outlined.

   Someone else is editing the run, outlined.

Making a run -- a new one, a copy, or one from a template -- and **Return
to Draft** make you its editor at once. **Mark Ready** ends your editing.
The setup page opens only for the person editing the run; anyone else is
taken to the run page.

While you edit, your open page tells SeqSetup once a minute that you are
still there. About three minutes after you close the page -- or your
computer goes to sleep, or the browser puts the tab to sleep to save
power -- the run shows as free, and anyone can press **Edit run** without
being asked; SeqSetup records whose editing they took. Until someone
does, the run is still yours: come back to it and carry on.

An open edit page does not keep you signed in: if you do nothing for 30
minutes, your sign-in ends as on any other page (see
:doc:`authentication`), and the page says so in red.

If someone takes over while your page is open, a red line in the status
bar says so within a minute -- *"Sam Staff is editing this run now (since
...). Reload the page: your changes are no longer saved."* -- and anything
you try to save is refused with a message that names them. Reload the
page to see their changes.

Every **Edit run**, **Done editing** and **Take over editing** is kept in
the audit trail (see :doc:`/admin-guide/audit-trail`).
