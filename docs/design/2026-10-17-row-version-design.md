# A sample row says which version of the run it was drawn from

## The problem

On the run page, a sample row's Override Cycles and mismatch boxes save on
their own and redraw nothing (F3, `hx-swap="none"`), while an index drop or
clear redraws the row and a bulk Apply redraws the whole table. A box's save
and a redraw of its row can be on their way at once, and their answers can
come back in the other order than the server stored them.

- **Redraw stored first, save answered first.** The redraw's answer then puts
  back a row drawn from before the save: the screen shows the old value, the
  database the new one, and nothing said so. A fresh review of 38ca108 found
  it (P2); it was put on the later list on 2026-10-15 because the database
  holds what the person typed and only the screen is old.
- **Save stored first, redraw answered first.** The save's answer finds its
  box replaced. The page compared the stored value with the redrawn row's and
  asked for a reload when they differed, but the redrawn row was the newer
  one: a clear wipes the Override Cycles, so the note named a value that was
  no longer stored, about a row that was right.

Writes are not at risk: every save from a row sends what the row showed
(`target_setting`, `target_indexes`, ...), so a change to a value the row
shows out of date is refused (design note 2026-10-17-stale-page-checks). The
risk is reading the page: a run checked on screen before Mark Ready should
show what its Sample Sheet will hold.

## The change

- Every sample row carries `data-run-version`: the run's `updated_at` when
  the row was drawn, written to the microsecond
  (`isoformat(timespec="microseconds")`), so every version has one length and
  text order is time order. `updated_at` moves on with every save, and a save
  is refused unless it was loaded from the version stored before it, so
  stored versions only grow (while the server's clock does not go back).
- The row template reads `run_updated_at`, which every caller passes: the
  single-row answers (`_render_sample_row`) and both tables. A caller that
  left it out would fail to render, not draw a row without a version.
- `app.js` keeps the newest version the page has shown for each row: a row
  drawn (page load, any swap), or a box's save answered in it. The rows one
  answer draws from an older version are named together in one note in
  `#row-setting-notes` (the first three, then a count: a whole table
  answered out of order would otherwise write a note per row), asking for a
  reload. The note goes once each of its rows is drawn again from a version
  at least as new, or is deleted.
- A save's answer that finds its box replaced asks for a reload only when the
  redrawn row is older than the save.

## Not done

- No answer is thrown away or put back automatically: the page cannot tell
  which cells of an older row are out of date, and a reload shows the stored
  run. This follows F3's rule that the page names a problem and the person
  acts on it.
- The Check panel is not redrawn by a row's answer, as before.
