# GUI Design-System Refresh — Design Spec

- **Date:** 2026-06-10
- **Status:** Draft (awaiting user review)
- **Scope:** Whole-app design-system refresh. Behavior-preserving. CSS/markup-class level only.
- **Chosen palette:** Direction B — *Deep Teal Clinical*.

## 1. Goal & scope

Make SeqSetup look like a deliberate, modern clinical product instead of a generic
admin template — by replacing ad-hoc styling with **one consistent design-token
system** and reconciling the two competing style layers (hand-written
`components.css` vs. inline Tailwind utilities).

User-confirmed scope (from brainstorming):

- **Ambition:** *Design-system refresh* — unify the CSS split; modernize cards,
  tables, forms, buttons, badges; improve hierarchy, spacing, typography. **Same
  layouts and same behavior.** Not a workflow/interaction redesign.
- **Priorities:** dated/plain look · cross-page inconsistency · usability friction.
- **Focus:** whole app — run editor, dashboard, wizard, validation, indexes,
  admin, login.
- **Direction:** refreshed palette (Direction B).

### Non-negotiable constraints (clinical software)

- **No behavior changes.** Every HTMX hook (`hx-*`, target IDs like `#sample-section`,
  `#form-errors`, `#error-banner`, `#toast-stack`), every Alpine binding
  (`x-data`/`x-show`/`x-for`, `toastStack`), every `on*`/drag-drop handler, every
  table column, input, and control is preserved. Edits touch only **visual
  properties of existing selectors** and additive ARIA/`title=`.
- Per CLAUDE.md "do less, not more": no new features beyond the cosmetic refresh
  and the explicitly-listed bug fixes. Anything that extends behavior is called
  out and kept minimal.

## 2. Problems this fixes (verified against the codebase)

1. **Three unsynchronized color systems** for the same semantic states: `:root`
   tokens, hard-coded Tailwind-100/800 badge hex (`components.css` ~1536–1550),
   and inline-Tailwind toasts in `_base.html`. A "success" is many different
   greens depending on where it appears.
2. **No design scale** beyond flat colors: 15 ad-hoc font sizes (0.6–2rem),
   9 radii, 21 spacing values, 5 one-off shadows.
3. **Stylesheet/page divergence:** dead CSS blocks (`.wizard-progress` stepper,
   `.login-card`/`.login-*`, `.run-list-row`/`.rl-*`, `.settings-tabs`) — *verified
   zero references in templates, JS, and routes* — because those pages reimplement
   them in inline Tailwind. Two competing truths.
4. **Broken core layout (run editor):** `runs/_sample_section.html:57` uses
   `.run-page-with-index-panel` / `.run-page-sample-panel`, which have **0 CSS rules**
   (verified). The index drag-palette stacks *above* the sample table instead of
   beside it — operators scroll between drag source and drop target.
5. **`.config-panel` is undefined** (verified: only a comment + the unrelated
   `.run-config-panel` exist) yet is on **6 run-editor fieldsets**
   (`instrument-config`, `cycle-config`, `samples`, `validate`, `details`,
   `export`). They fall back to the browser's grey groove `<fieldset>` border.
6. **Run-editor paste section is partly unstyled:** template uses `.paste-section`/
   `.paste-section-summary`/`.paste-section-content` (`runs/_sample_section.html:27`)
   but `components.css` only defines `.paste-details`/`.paste-form-content` — a
   name mismatch (0 CSS refs for the `.paste-section*` names).
7. **No `:focus-visible` ring on any button, app-wide** — keyboard focus invisible.
   Muted text `#64748b` fails WCAG AA (~4.4:1) at small sizes.
8. **Clinically-critical index sequences render at 0.6rem** and are silently
   truncated to 8 chars with no full-value affordance.
9. **Validation heatmap legend is factually wrong** (legend chip colors don't match
   cells; `dist-4` legend `#4ade80` vs cell `#a3e635`; only 5 of 11 distance steps
   labeled; broken `.channel-1-demo`/`.channel-2-demo` legend classes), and danger
   is encoded by color alone on a dated red→green "jet" ramp.
10. **Spreadsheet tables:** border-on-every-cell grid, no zebra/row-hover, no
    horizontal-scroll wrapper on wide validation/admin tables, 0.7–0.8rem text.
11. **Undefined `.success-message`/`.warning-message`** (verified 0 refs) — non-error
    inline banners from `_messages.html` render unstyled.

## 3. Design principles

- **Tokenize first, edit templates last.** `components.css` is `@import`-ed (not
  Tailwind-scanned), so adding tokens to `:root` and repointing the shared
  component classes re-skins most of the run editor, wizard, and validation
  screens **with zero template edits and no CSS rebuild**.
- **Semantic tokens, not literal.** Roles (`--primary`, `--surface`, `--danger-bg`)
  so a palette swap is a one-line edit.
- **Collapse onto values already most-used** (0.5rem spacing, 4px radius,
  0.8/0.875rem text) so migration is near-zero visual delta — then raise only the
  clinically-risky floors (index sequences) and add the missing primitives
  (focus ring, elevation, message colors).
- **One source of truth across both layers:** mirror the exact token hex into a
  Tailwind v4 `@theme` block so inline-Tailwind pages draw from the same palette.

## 4. Design tokens — Direction B (Deep Teal Clinical)

All added to the `components.css` `:root` block. Old names (`--primary`, `--card-bg`,
`--secondary`, …) are kept as **aliases** pointing at the new roles so nothing breaks.

### Color roles

```
/* Surfaces & structure */
--bg:             #f8fafc;   /* app/page background */
--surface:        #ffffff;   /* cards/panels (was --card-bg) */
--surface-sunken: #f1f5f9;   /* table headers, insets, wells */
--border:         #e2e8f0;   /* default hairline */
--border-strong:  #cbd5e1;   /* table dividers, input borders */

/* Text (AA on #f8fafc) */
--text:        #0f172a;
--text-muted:  #475569;      /* darkened from #64748b for AA at small sizes */
--text-subtle: #64748b;      /* large/decorative muted only, never <14px body */

/* Brand — teal */
--primary:       #0e7490;    /* teal-700, ≈5.8:1 on white */
--primary-hover: #155e75;
--primary-fg:    #ffffff;

/* Semantic states (fill / soft-bg / on-soft-bg text) */
--success: #15803d;  --success-bg: #dcfce7;  --success-fg: #166534;
--warning: #b45309;  --warning-bg: #fef3c7;  --warning-fg: #92400e;
--danger:  #dc2626;  --danger-bg:  #fef2f2;  --danger-fg:  #991b1b;
--info:    #0e7490;  --info-bg:    #cff5fb;  --info-fg:    #155e75;

/* Index color-coding (preserved exactly; tokenized so they stop aliasing brand) */
--accent-i7:   #2563eb;
--accent-i5:   #ea580c;
--accent-pair: #8b5cf6;

/* Sidebar (was raw hex literals) */
--sidebar-bg:     #1e293b;
--sidebar-fg:     #e2e8f0;
--sidebar-muted:  #94a3b8;
--sidebar-hover:  #334155;
--sidebar-accent: #2dd4bf;  /* teal-400 left-border on the active item (legible on dark) */

/* Focus — one perceptible ring for ALL inputs, buttons, chips, tabs */
--focus-ring: 0 0 0 3px rgba(14,116,144,0.40);
```

### Type scale

```
--fs-2xs:  0.75rem;   /* 12px — dense table cells, badges, chips, lane labels */
--fs-xs:   0.8125rem; /* 13px — index SEQUENCES & well chips (raised clinical floor) */
--fs-sm:   0.875rem;  /* 14px — body text, form inputs, secondary labels */
--fs-base: 1rem;      /* 16px — primary body, run/sample names */
--fs-lg:   1.125rem;  /* 18px — card legends, h3/h4 */
--fs-xl:   1.25rem;   /* 20px — subsection headings */
--fs-2xl:  1.5rem;    /* 24px — page titles, brand wordmark */

--lh-tight: 1.3;  --lh-base: 1.5;
--fw-normal: 400; --fw-medium: 500; --fw-semibold: 600; --fw-bold: 700;
--font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
/* sequence/lane numeric cells also get font-variant-numeric: tabular-nums */
```

### Spacing / radius / elevation

```
--space-1:.25rem; --space-2:.5rem; --space-3:.75rem; --space-4:1rem;
--space-5:1.5rem; --space-6:2rem;  --space-8:3rem;   /* off-grid one-offs snap to nearest */

--radius-sm:4px;     /* buttons, inputs, chips, badges, drop zones (absorbs 3px+4px) */
--radius-md:8px;     /* cards, panels, fieldsets, side panels (absorbs 6px+8px) */
--radius-pill:999px; /* status pills, segmented controls */
--radius-circle:50%; /* step numbers, color dots */

--shadow-xs: 0 1px 2px rgba(15,23,42,.06);                         /* resting cards/panels */
--shadow-sm: 0 1px 3px rgba(15,23,42,.08),0 1px 2px rgba(15,23,42,.06); /* hover, tiles */
--shadow-md: 0 4px 12px rgba(15,23,42,.10);                        /* dropdowns, drag-over, sticky headers */
--shadow-lg: 0 10px 30px rgba(15,23,42,.16);                       /* login card, modals */
```

Cards keep their 1px `--border` **and** gain `--shadow-xs` — border carries structure,
shadow carries hierarchy (pure-shadow cards lose definition on the `#f8fafc` bg).

## 5. Component refresh specs (behavior-preserving)

Each keeps its existing class names, IDs, markup structure, and JS/HTMX hooks.

- **Buttons** (`.btn`/`.btn-primary`/`-secondary`/`-danger`/`-warning`/`-small`/`-tiny`):
  repoint fills to tokens; add a hover to **every** variant (not just primary);
  add `--radius-sm`, a subtle `--shadow-sm` on hover, and a shared
  `:focus-visible { box-shadow: var(--focus-ring) }`. Same padding/size — no reflow.
- **Badges / status pills:** one `.badge` primitive (`--radius-pill`, `--fs-2xs`,
  `--fw-semibold`) with `--success/warning/danger/info/neutral` modifiers from the
  `--*-bg`/`--*-fg` pairs. Re-skin `.status-draft/ready/archived`,
  `.run-status-badge`, `.validate-status-badges` to compose it (same selectors).
  Raise draft/archived contrast to AA. Keep the validate-panel `::before` dot,
  enlarge slightly, add an `sr-only` state word.
- **Cards / panels:** **define `.config-panel`** (uppercase legend + 1px `--border` +
  `--radius-md` + `--shadow-xs`) — fixes all 6 run-editor fieldsets at once.
  Give `.config-column`, `.wizard-content`, index tiles `--shadow-xs` + `--radius-md`.
  Reconcile the `.paste-section*` ↔ `.paste-details*` name mismatch so the run-editor
  paste box is styled.
- **Dense sample table:** preserve every column, the `has-index` green tint, the
  `selected` blue tint, all inline inputs. Cell font → `--fs-2xs`, index/sequence →
  `--fs-xs` + tabular-nums; add row-hover (`--surface-sunken`) and a sticky header.
  Add `title=` (full value) to truncated Sample-ID/Test-ID/Worksheet/kit cells.
  `.mismatch-input`/`.override-cycles-input` get the shared focus ring.
- **Form inputs:** keep width/padding/size; replace the near-invisible 0.1-alpha
  ring with `--focus-ring`; `--border-strong` default border; add an
  `.is-invalid`/`:invalid` state (red border + `--danger-bg`).
- **Sidebar + header:** refactor the hard-coded sidebar hex onto the `--sidebar-*`
  tokens; give the **active** nav item a distinct treatment from hover (3px
  `--sidebar-accent` left-border + `--fw-semibold`); replace the `▶` CSS-triangle
  disclosure with an inline SVG chevron; header gains `--shadow-xs`; remove the dead
  `.app-header h1` rule; add a skip-link to `#main`. No nav restructuring.
- **Tabs** (dashboard status tabs, validation tabs): keep the underline-active
  pattern and all Alpine/HTMX bindings. Standardize active/inactive/disabled;
  render counts as `.badge--neutral` pills; add `role=tablist/tab/tabpanel` +
  `aria-selected`/`aria-controls` mirroring existing state (no roving-tabindex JS).
- **Wizard stepper:** the `.wizard-progress`/`.wizard-step` CSS is **dead** (wizard is
  one step). **Delete** it (~57 lines). Style the live `.wizard-content` card.
- **Validation heatmap:** keep the table, toggle pills, per-lane cards, and the
  numeric distance in each cell. **Fix the legend to match actual cell colors** and
  label the full range; replace the jet ramp with a single perceptual sequential
  scale (one hue, dark→light = risky→safe); **add a non-color cue** (glyph/heavy
  border) on dangerous cells. Wrap heatmap + color-balance + dark-cycle + log +
  run-list tables in `overflow-x:auto` with a sticky first column. Fix the broken
  `.channel-*-demo` legend classes. Add `title=` naming both samples per cell.
- **Drag/drop zones + index chips:** keep all `ondragstart/over/drop/onclick` hooks
  and the i7/i5 split, now from `--accent-i7/i5/pair`. Upgrade dashed boxes
  (`--radius-sm`, target icon, `--shadow-md` on drag-over). Add an `i7`/`i5` **text**
  pill so type is never color-only. Show full sequence on hover/focus via `title=`.
  Add `tabindex`/`role`/`aria-label` + focus ring so the existing click-to-assign
  path becomes keyboard-discoverable (focusability + ARIA only; no new JS behavior).
- **Toasts:** move the inline-Tailwind markup in `_base.html` to `.toast`/`.toast--*`
  classes from the same tokens (so a success toast matches success badges). Keep
  `toastStack()`, `x-for`/`:key`, the 4000ms lifetime, the 500-char clamp. Add
  `role=status`/`aria-live=polite` and a dismiss `×` (removes via the existing
  array — no new behavior path). Define the missing `.success-message`/
  `.warning-message`.
- **Login:** keep the centered-card layout and all hooks; re-skin with `--surface`,
  `--radius-md`, `--shadow-lg`, `--space-6`; shared focus ring; same `.btn-primary`.
  Delete the dead `.login-*`/`.btn-login` (purple-gradient) CSS. Keep the empty
  error-placeholder div.

## 6. Phased implementation plan

Each phase is independently shippable and gated on `pixi run test` +
`pixi run smoke-browser` + before/after screenshots.

- **Phase 0 — Baseline.** Run tests + smoke; capture before-screenshots of every
  page. Confirm `pixi run css` rebuilds `app.css` cleanly.
- **Phase 1a — Tokens.** Add all color/type/spacing/radius/shadow/focus tokens to
  `:root`; keep old names as aliases. Purely additive; no template churn; no rebuild
  (`components.css` is `@import`-ed).
- **Phase 1b — Migrate shared classes.** Mechanically repoint the ~63 raw hex
  literals onto tokens; collapse the size/radius/spacing sprawl. Re-skins buttons,
  badges, sample table, drop zones, config panels, index chips, validation tables
  with **no template edits.** Re-screenshot; any unintended delta is a `:root` bug.
- **Phase 1c — CSS-only bug fixes.** Define `.config-panel`; add the
  `.run-page-with-index-panel` grid (palette beside table); reconcile
  `.paste-section*`; add `.success-message`/`.warning-message`; add focus rings to
  buttons/links/chips/tabs; de-dupe doubly-defined selectors; **delete dead CSS**
  (`.wizard-progress`, `.login-*`, `.run-list-*`/`.rl-*`, `.settings-tabs`) — each
  re-grep-verified at delete time across `templates/`, `static/js/`, `routes/`.
  Keep `.ldap-config-form` (it **is** used).
- **Phase 2 — Tailwind `@theme` bridge.** Map Tailwind's color/spacing/radius scale
  to the **same** hex in `input.css`; `pixi run css`. Inline-Tailwind pages
  (dashboard, login, admin, indexes, validation header, toasts) pick up the palette
  with no template edits. Map to the exact current hex first (zero visual change),
  verify, before any further change.
- **Phase 3 — Markup-level reconciliation (one page at a time).** Toasts →
  component classes + `aria-live`; per-row status `.badge` on the dashboard list;
  spreadsheet tables → wrapped/divided/row-hover + `overflow-x:auto` + `scope` on
  `th`; box admin LDAP fieldsets; `role=tab` semantics on both tab systems. Smoke
  each page after its change.
- **Phase 4 — Palette + a11y verification.** Direction B is already the token
  default, so this is mainly verification: automated contrast check (WCAG 2.1 AA),
  `:focus-visible` on every interactive element, color-blind legibility of i7/i5 and
  the heatmap cues. Final full smoke + visual diff.

## 7. Risks & mitigations

- **Stale Tailwind build.** `app.css` is **gitignored** (built by `pixi run css`;
  `pixi run serve` builds it first), so regeneration produces **no committed diff** —
  but any change to inline Tailwind classes or `@theme` still requires a rebuild to
  take effect. *Mitigation:* Phase 1 avoids template/`input.css` edits entirely
  (`components.css` needs no rebuild); gate every later phase on a fresh `pixi run css`.
- **JS/HTMX hooks.** Alpine/HTMX target specific class names, IDs, and `on*`/`hx-*`
  attributes. *Mitigation:* only change visual properties of existing selectors;
  never rename/remove a class used as an HTMX target, `x-data`/`x-show`, or JS
  selector; grep each touched class before removal.
- **Semantic color drift.** Darkening muted text and adjusting badge tints changes
  perceived status — a clinical reviewer relies on these. *Mitigation:* keep the
  semantic mapping identical (draft=amber, ready=info/blue, archived=neutral,
  error=red, warning=amber, success=green); badge hues track the palette (the
  "ready" pill moves into the teal/info family) but the three run statuses stay
  mutually distinct, and no color's *meaning* is swapped. Adjust luminance for AA
  only. Verify on dashboard + validation specifically.
- **Heatmap ramp.** *Mitigation:* numeric distance stays in every cell (load-bearing
  datum); new ramp stays monotonic dark→light = risky→safe; non-color cue is
  **added**, not substituted. Confirm dist-0/1/2 still read as danger before shipping.
- **Index colors.** *Mitigation:* tokens alias current hex 1:1 (i7 `#2563eb`,
  i5 `#ea580c`, pair `#8b5cf6` kept).
- **Index-panel grid reflow.** Fixes a bug but is a visible reflow. *Mitigation:*
  CSS-only; no elements/inputs/handlers change; verify drag-drop still assigns via
  smoke + a manual drag on a real run.
- **Dead-CSS deletion.** Safe only if truly unreferenced. *Mitigation:* re-grep each
  class across `templates/`, `static/js/`, `routes/*.py` at delete time, not trusted
  blind. (`ldap-config-form` confirmed used → kept.)
- **Type/spacing collapse → row-height shift.** *Mitigation:* snap to nearest
  existing value; visually diff sample + validation tables at equal data volume.
- **ARIA.** *Mitigation:* add `aria-selected`/`aria-controls` mirroring existing
  Alpine state only; no roving-tabindex JS in this refresh.

## 8. Decisions & defaults

- **Palette:** Direction B — Deep Teal Clinical (confirmed).
- **Accessibility bar:** WCAG 2.1 AA.
- **Index sequences:** keep 8-char display + full value via `title=` on hover/focus
  (no column-width change).
- **Dashboard:** add a per-row status badge (small visible addition, improves
  consistency).
- **Toasts:** add dismiss button + `aria-live` (minimal behavior extension).
- **Min viewport:** laptop ~1366px and up; add horizontal-scroll wrappers to wide
  tables. No responsive sidebar / mobile work.
- **Dead CSS:** delete after per-class re-verification (vs. re-adopting in templates).

## 9. Out of scope

- Workflow/interaction redesign; navigation restructuring; collapsible/responsive
  sidebar; mobile layouts.
- New screens, new features, or data-model changes.
- A multi-step wizard / progress stepper (the stepper CSS is deleted, not revived;
  reintroduction would be a separate scoped decision).
- Always-visible full index sequences (would widen columns = layout change).
- Dark mode.
