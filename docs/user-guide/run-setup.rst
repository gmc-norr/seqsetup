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
Run**, and no template chooser -- but only while it is still a Draft. A
Ready or Archived run's setup cannot be changed.
