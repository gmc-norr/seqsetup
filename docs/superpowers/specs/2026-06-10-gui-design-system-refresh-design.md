# GUI Design-System Refresh — Design Spec

- **Date:** 2026-06-10
- **Status:** Draft (revised after external review; awaiting user review)
- **Scope:** Whole-app design-system refresh. Behavior-preserving except for an
  explicit, enumerated list of approved exceptions (§1.1). CSS/markup-class level.
- **Chosen palette:** Direction B — *Deep Teal Clinical*.

## 0. Revision log (responses to external review)

This spec was revised to address an external code review. Changes:

- **Rebuild required (was wrong).** The browser loads only the compiled
  `static/css/app.css`; `input.css` `@import`s `components.css`, so **every** CSS
  edit needs `pixi run css`. Removed all "no rebuild needed" claims; every gate
  now builds CSS first (§3, §6).
- **Focus token failed AA.** `rgba(14,116,144,.40)` ≈ 1.8:1 on white (< 3:1).
  Replaced with an opaque double ring; added a foreground/background **contrast
  matrix** (§4.4).
- **ARIA without keyboard = broken widgets.** Dropped `role=tab`/`role=button`
  retrofits. Tabs stay native `<button>`s (already keyboard-operable). Click-to-
  assign index chips/drop zones get **real Enter/Space handlers** (§1.1, §5).
- **Tailwind bridge needs a real migration strategy.** Mirroring neutrals is safe;
  brand `blue-*` utilities are migrated to semantic classes per-page in Phase 3 —
  no global `blue` hijack (§6 Phase 2/3).
- **`.ldap-config-form` is dead as a class** (element uses `id="ldap-config-form"`).
  Repoint the selector to `#ldap-config-form` instead of claiming it's used (§5).
- **Gates didn't cover scope.** Phase 0 now builds a screenshot + a11y/keyboard
  verification harness with deterministic seed data (§6 Phase 0).
- **`:invalid` / `title=` caveats.** Use `:user-invalid`/`.is-invalid`, not global
  `:invalid`; `title=` is a supplement, paired with `aria-label`, never the sole
  affordance (§5).
- **Scope cuts:** dropped the dashboard per-row status badge (each tab is already
  single-status) and the toast dismiss button (kept `role=status`/`aria-live`).

## 1. Goal & scope

Make SeqSetup look like a deliberate, modern clinical product instead of a generic
admin template — by replacing ad-hoc styling with **one consistent design-token
system** and reconciling the two competing style layers (hand-written
`components.css` vs. inline Tailwind utilities).

User-confirmed scope (from brainstorming):

- **Ambition:** *Design-system refresh* — unify the CSS split; modernize cards,
  tables, forms, buttons, badges; improve hierarchy, spacing, typography. **Same
  layouts.** Not a workflow/interaction redesign.
- **Priorities:** dated/plain look · cross-page inconsistency · usability friction.
- **Focus:** whole app — run editor, dashboard, wizard, validation, indexes,
  admin, login.
- **Direction:** refreshed palette (Direction B). **Accessibility bar:** WCAG 2.1 AA,
  including **genuine keyboard operability** (not additive ARIA alone).

### 1.1 Behavior constraint and approved exceptions

**Default:** edits change only visual properties of existing selectors. Every HTMX
hook (`hx-*`, target IDs `#sample-section`, `#form-errors`, `#error-banner`,
`#toast-stack`, `#ldap-config-form`, …), every Alpine binding
(`x-data`/`x-show`/`x-for`, `toastStack`), every `on*`/drag-drop handler, every
table column, input, and control is preserved.

Per CLAUDE.md "do less, not more", the **only** behavior/markup changes allowed are
this explicit list (everything else is visual-only):

1. **Keyboard operability** of the click-to-assign index chips and drop zones: add
   `tabindex="0"` + an `onkeydown` that invokes the **existing** `handleIndexClick`
   on Enter/Space, plus `aria-label`. No new assign logic — it mirrors the current
   `onclick` path.
2. **Accessible names:** add/extend `title=` and add `aria-label` carrying the full
   index sequence (the compact chip already has a `title=`); add `title=` to
   truncated sample-table cells; add `sr-only` state words to glyph-only status.
3. **Toasts:** add `role=status`/`aria-live=polite` to the container; move the inline
   markup to `.toast` component classes. **No dismiss button** (kept out of scope).
4. **Heatmap non-color cue:** add a glyph/heavy-border to dangerous cells and fix the
   legend markup so chips match cells.
5. **Phase 3 per-page markup:** swap brand `blue-*` Tailwind utilities → semantic
   classes; wrap wide tables in `overflow-x:auto`; box admin fieldsets; add a
   skip-link to `#main`; replace the sidebar `▶` CSS-triangle with an inline SVG
   chevron; add `aria-current="page"` to the active nav item.
6. **Form validity state:** add `.is-invalid` styling and a `:user-invalid` (not
   global `:invalid`) hook.

Anything beyond this list (per-row dashboard badge, toast dismiss, multi-step
wizard, always-visible sequences, dark mode, responsive sidebar) is **out of scope**
(§9).

## 2. Problems this fixes (verified against the codebase)

1. **Three unsynchronized color systems** for the same semantic states: `:root`
   tokens, hard-coded Tailwind-100/800 badge hex (`components.css` ~1536–1550),
   and inline-Tailwind toasts in `_base.html`.
2. **No design scale** beyond flat colors: 15 ad-hoc font sizes (0.6–2rem),
   9 radii, 21 spacing values, 5 one-off shadows.
3. **Stylesheet/page divergence:** dead CSS — `.wizard-progress`/`.wizard-step`,
   `.login-card`/`.login-*`, `.run-list-row`/`.rl-*`, `.settings-tabs`/`.tab-btn`
   (**verified zero `class=` usages** in templates; class selectors only).
4. **Broken core layout (run editor):** `runs/_sample_section.html:57` uses
   `.run-page-with-index-panel` / `.run-page-sample-panel`, which have **0 CSS rules**
   (verified). The index palette stacks *above* the sample table instead of beside it.
5. **`.config-panel` is undefined** (verified: only a comment + the unrelated
   `.run-config-panel` exist) yet is on **6 run-editor fieldsets**.
6. **Run-editor paste section partly unstyled:** template uses `.paste-section*`
   (`runs/_sample_section.html:27`) but `components.css` only defines `.paste-details*`.
7. **No `:focus-visible` ring on any button, app-wide.** Muted text `#64748b` fails
   WCAG AA (~4.4:1) at small sizes.
8. **Index sequences render at 0.6rem** and truncate to 8 chars (a `title=` exists on
   the compact chip but not as a reliable keyboard/SR affordance).
9. **Validation heatmap legend is factually wrong** (`dist-4` legend `#4ade80` vs
   cell `#a3e635`; 5 of 11 steps labeled; broken `.channel-1-demo`/`.channel-2-demo`),
   and danger is color-only on a dated jet ramp.
10. **Spreadsheet tables:** border-on-every-cell, no zebra/row-hover, no
    horizontal-scroll wrapper, 0.7–0.8rem text.
11. **Undefined `.success-message`/`.warning-message`** (verified) → unstyled banners.
12. **`.ldap-config-form` CSS is dead** — the element is `id="ldap-config-form"`, so
    the class selector never matches; repoint to `#ldap-config-form`.

## 3. Design principles

- **Tokenize first; edit templates last.** Adding tokens to `:root` and repointing
  the shared component classes re-skins most of the run editor, wizard, and
  validation screens with **zero template edits** (lower risk of breaking
  markup/hooks). It still requires `pixi run css` to take effect — `components.css`
  is compiled into `app.css`, the only stylesheet the page loads.
- **Semantic tokens, not literal** — a palette swap is a one-line edit on the
  components.css side.
- **Collapse onto values already most-used** (0.5rem spacing, 4px radius,
  0.8/0.875rem text) so migration is near-zero visual delta — then raise only the
  clinically-risky floors (index sequences) and add missing primitives (focus ring,
  elevation, message colors).
- **One source of truth across layers:** mirror neutral tokens into a Tailwind `@theme`
  block and migrate brand utilities to semantic classes, so inline-Tailwind pages and
  `components.css` resolve to the same palette.

## 4. Design tokens — Direction B (Deep Teal Clinical)

Added to the `components.css` `:root` block. Old names (`--primary`, `--card-bg`,
`--secondary`, …) are kept as **aliases** so nothing breaks.

### 4.1 Color roles

```
/* Surfaces & structure */
--bg:             #f8fafc;
--surface:        #ffffff;   /* was --card-bg */
--surface-sunken: #f1f5f9;   /* table headers, insets, wells */
--border:         #e2e8f0;
--border-strong:  #cbd5e1;

/* Text */
--text:        #0f172a;
--text-muted:  #475569;      /* darkened from #64748b for AA at small sizes */
--text-subtle: #64748b;      /* large/decorative muted only (see matrix §4.4) */

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

/* Sidebar */
--sidebar-bg:     #1e293b;
--sidebar-fg:     #e2e8f0;
--sidebar-muted:  #94a3b8;
--sidebar-hover:  #334155;
--sidebar-accent: #2dd4bf;   /* teal-400 active left-border (legible on dark) */
```

### 4.2 Focus ring (revised — opaque, AA-compliant)

```
/* Double ring: inner gap separates the solid colored outer ring from the
   element. Outer ring is fully opaque --primary (#0e7490 ≈ 5.8:1 on white),
   clearing the 3:1 non-text contrast minimum. The old 0.40-alpha ring (~1.8:1)
   is removed. */
--focus-ring: 0 0 0 2px var(--surface), 0 0 0 4px var(--primary);
/* On dark surfaces (sidebar), a variant uses --sidebar-accent for the outer ring. */
```

Applied via `:focus-visible` to **all** buttons, links, inputs, chips, tabs, drop
zones, and the keyboard-operable index chips.

### 4.3 Type / spacing / radius / elevation

```
--fs-2xs: .75rem;    /* 12px — dense cells, badges, chips, lane labels */
--fs-xs:  .8125rem;  /* 13px — index SEQUENCES & well chips (raised floor) */
--fs-sm:  .875rem;   /* 14px — body text, inputs, secondary labels */
--fs-base:1rem;      /* 16px — primary body, run/sample names */
--fs-lg:  1.125rem;  /* 18px — card legends, h3/h4 */
--fs-xl:  1.25rem;   /* 20px — subsection headings */
--fs-2xl: 1.5rem;    /* 24px — page titles, brand wordmark */
--lh-tight:1.3; --lh-base:1.5;
--fw-normal:400; --fw-medium:500; --fw-semibold:600; --fw-bold:700;
--font-mono: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; /* + tabular-nums */

--space-1:.25rem; --space-2:.5rem; --space-3:.75rem; --space-4:1rem;
--space-5:1.5rem; --space-6:2rem;  --space-8:3rem;

--radius-sm:4px; --radius-md:8px; --radius-pill:999px; --radius-circle:50%;

--shadow-xs:0 1px 2px rgba(15,23,42,.06);
--shadow-sm:0 1px 3px rgba(15,23,42,.08),0 1px 2px rgba(15,23,42,.06);
--shadow-md:0 4px 12px rgba(15,23,42,.10);
--shadow-lg:0 10px 30px rgba(15,23,42,.16);
```

Cards keep their 1px `--border` **and** gain `--shadow-xs`.

### 4.4 Contrast matrix (WCAG 2.1 AA) — approved foreground/background pairings

Phase 4 certifies these with an automated checker; the design intent:

| Foreground | Allowed background(s) | Use | Target / note |
|---|---|---|---|
| `--text` #0f172a | bg, surface, surface-sunken | body, headings | ≥12:1 |
| `--text-muted` #475569 | bg, surface, surface-sunken | secondary labels, muted body | ≥4.5:1 (AA) |
| `--text-subtle` #64748b | **surface / bg only** | large/decorative (≥14px) muted | ~4.6:1 on #fff; **never** small essential text, **never** on surface-sunken (~4.3:1, fails) |
| `--primary` #0e7490 | surface, bg | links, active text | ~5.8:1 |
| `--primary-fg` #fff | `--primary` | button label | ~5.8:1 |
| `--success-fg` #166534 | `--success-bg` #dcfce7 | success text | AA |
| `--warning-fg` #92400e | `--warning-bg` #fef3c7 | warning text | AA |
| `--danger-fg` #991b1b | `--danger-bg` #fef2f2 | danger text | AA |
| `--info-fg` #155e75 | `--info-bg` #cff5fb | info text | AA |
| focus ring (solid `--primary`) | any light surface | focus indicator | ≥3:1 non-text (opaque 5.8:1) |

## 5. Component refresh specs (behavior-preserving except §1.1)

Each keeps its class names, IDs, markup structure, and JS/HTMX hooks.

- **Buttons:** repoint fills to tokens; hover on **every** variant; `--radius-sm`;
  `--shadow-sm` on hover; shared `:focus-visible { box-shadow: var(--focus-ring) }`.
  Same padding/size — no reflow.
- **Badges / status pills:** one `.badge` primitive with `--success/warning/danger/
  info/neutral` modifiers from the token pairs. Re-skin `.status-draft/ready/archived`,
  `.run-status-badge`, `.validate-status-badges`. Raise draft/archived to AA. Badge
  hues track the palette (ready → teal/info family) but the three statuses stay
  mutually distinct and no color's *meaning* changes. **No new per-row dashboard
  badge** (each tab is single-status; redundant).
- **Cards / panels:** **define `.config-panel`** (fixes all 6 run-editor fieldsets).
  `--shadow-xs` + `--radius-md` on cards/`.config-column`/`.wizard-content`/tiles.
  Reconcile `.paste-section*` ↔ `.paste-details*`. Repoint `.ldap-config-form` →
  `#ldap-config-form` so the admin auth form gets its panel styling.
- **Dense sample table:** preserve every column and the has-index/selected tints and
  all inline inputs. Cell font → `--fs-2xs`, index/sequence → `--fs-xs` + tabular-nums;
  row-hover (`--surface-sunken`); sticky header. Add `title=` to truncated cells.
  Shared focus ring on `.mismatch-input`/`.override-cycles-input`.
- **Form inputs:** keep width/padding/size; replace the 0.1-alpha ring with
  `--focus-ring`; `--border-strong` default border; add `.is-invalid` styling +
  a `:user-invalid` hook (not global `:invalid`, which would flag untouched fields).
- **Sidebar + header:** sidebar hex → `--sidebar-*` tokens; **active** nav item gets a
  3px `--sidebar-accent` left-border + `--fw-semibold` + `aria-current="page"` (distinct
  from hover); `▶` → inline SVG chevron; header gains `--shadow-xs`; remove dead
  `.app-header h1`; add a skip-link to `#main`. No nav restructuring.
- **Tabs (dashboard + validation):** **keep native `<button>` semantics** — they are
  already keyboard-operable (Tab + Enter/Space), so we do **not** add
  `role=tablist/tab` (which would require arrow-key roving-tabindex JS). Standardize
  active/inactive/disabled visuals + focus ring; render counts as `.badge--neutral`.
  Keep all Alpine/HTMX bindings.
- **Wizard stepper:** `.wizard-progress`/`.wizard-step` CSS is dead (wizard is one
  step) → **delete** (~57 lines). Style the live `.wizard-content` card.
- **Validation heatmap:** keep the table, toggle pills, per-lane cards, numeric
  distance per cell. **Fix the legend to match actual cell colors** + label the full
  range; replace the jet ramp with a single perceptual sequential scale; **add a
  non-color cue** (glyph/heavy border) on dangerous cells. Wrap heatmap +
  color-balance + dark-cycle + log + run-list tables in `overflow-x:auto` + sticky
  first column. Fix `.channel-*-demo`. Add `title=` naming both samples per cell.
- **Drag/drop zones + index chips:** keep all `ondragstart/over/drop/onclick` hooks
  and the i7/i5 split, now from `--accent-i7/i5/pair`. Upgrade dashed boxes
  (`--radius-sm`, target icon, `--shadow-md` on drag-over). Add an `i7`/`i5` **text**
  pill so type is never color-only. **Genuine keyboard operability** (§1.1 #1):
  `tabindex="0"` + `onkeydown` (Enter/Space → existing `handleIndexClick`) +
  `aria-label` (full sequence) + focus ring. `title=` stays as a mouse supplement,
  not the sole affordance.
- **Toasts:** move inline markup to `.toast`/`.toast--*` classes from the same tokens;
  add `role=status`/`aria-live=polite`. Keep `toastStack()`, `x-for`/`:key`, the
  4000ms lifetime, the 500-char clamp. **No dismiss button.** Define the missing
  `.success-message`/`.warning-message`.
- **Login:** keep layout + hooks; re-skin card (`--surface`/`--radius-md`/
  `--shadow-lg`/`--space-6`); shared focus ring; same `.btn-primary`. Delete dead
  `.login-*`/`.btn-login`.

## 6. Phased implementation plan

Each phase is independently shippable. **Every gate runs `pixi run css` first**, then
`pixi run test` + the browser checks + a visual diff.

- **Phase 0 — Baseline + verification harness.** (a) Run `pixi run css`, `pixi run
  test`, `pixi run smoke-browser`. (b) Build a Playwright **screenshot fixture** that
  logs in, seeds deterministic representative data (a draft run with indexed samples;
  a run whose validation yields index collisions for the heatmap; archived/ready
  runs; populated admin pages), and captures every target page/state — this is the
  regression oracle (the existing 3-check smoke suite does **not** cover these). (c)
  Add targeted a11y/keyboard checks: `:focus-visible` reachability on buttons/inputs,
  and Enter/Space activation of an index chip. Commit baseline screenshots.
- **Phase 1a — Tokens.** Add all tokens to `:root`; old names alias new roles.
  Additive; no template churn. `pixi run css`; diff = zero visual change expected.
- **Phase 1b — Migrate shared classes.** Repoint the ~63 raw hex literals onto tokens;
  collapse the size/radius/spacing sprawl. Re-skins buttons, badges, sample table,
  drop zones, config panels, index chips, validation tables — no template edits.
  `pixi run css`; re-screenshot; any unintended delta is a `:root` value bug.
- **Phase 1c — CSS-only bug fixes.** Define `.config-panel`; add the
  `.run-page-with-index-panel` grid; reconcile `.paste-section*`; repoint
  `#ldap-config-form`; add `.success-message`/`.warning-message`; add focus rings;
  de-dupe doubly-defined selectors; **delete dead CSS** (`.wizard-progress`,
  `.login-*`, `.run-list-*`/`.rl-*`, `.settings-tabs`/`.tab-btn`) — each re-grepped
  (class **and** id, across `templates/`, `static/js/`, `routes/`) at delete time.
  `pixi run css`; smoke per page.
- **Phase 2 — Tailwind `@theme` bridge (neutrals + semantic tokens).** In `input.css`,
  (a) map Tailwind's `slate-*` scale to the **exact** neutral hex (zero visual change —
  the inline pages' 100+ `slate-*` utilities now resolve through the system), and
  (b) define **semantic** theme colors (`--color-primary`, `--color-surface`,
  `--color-success`, …) so `bg-primary`/`text-primary` become available. **Do not**
  globally remap Tailwind's `blue` scale (it conflates brand/link/info and would
  surprise un-reviewed pages). `pixi run css`; re-screenshot inline pages — expect no
  change yet (brand still blue until Phase 3).
- **Phase 3 — Per-page markup reconciliation (one page at a time, each shippable).**
  Migrate the ~6 brand `blue-*` utility patterns (`bg-blue-600/700`, `text-blue-700`,
  `border-blue-300`, `ring-blue-300`, …) to the semantic classes from Phase 2 — this
  is the only step that recolors brand on inline pages, and it's explicit/reviewable
  per page. Also: toasts → `.toast` classes + `aria-live`; wide tables → wrapped +
  row-hover + `overflow-x:auto` + `scope` on `th`; box admin LDAP fieldset; skip-link;
  SVG chevron + `aria-current`. `pixi run css`; smoke each page after its change.
- **Phase 4 — Palette + a11y certification.** Direction B is already the token default,
  so this is verification: automated contrast check against the §4.4 matrix,
  `:focus-visible` on every interactive element, Enter/Space on index chips, and
  color-blind legibility of i7/i5 + heatmap cues. Final full smoke + visual diff.

## 7. Risks & mitigations

- **Stale build.** All CSS changes (`components.css` **and** `input.css`) need
  `pixi run css` to reach `app.css` (the only stylesheet served). `app.css` is
  **gitignored**, so rebuilds add no PR diff — but a forgotten rebuild ships an
  unchanged page. *Mitigation:* every phase gate builds CSS first;
  CI/`smoke-browser` runs after a fresh build.
- **JS/HTMX hooks.** *Mitigation:* change only visual properties of existing
  selectors; never rename/remove a class used as an HTMX target, Alpine binding, or
  JS selector; grep each touched class (class **and** id) before removal.
- **Semantic color drift.** *Mitigation:* keep the semantic mapping (draft=amber,
  ready=info, archived=neutral, error=red, warning=amber, success=green); badge hues
  track the palette but stay mutually distinct; adjust luminance for AA only. Verify
  on dashboard + validation.
- **Heatmap ramp.** *Mitigation:* numeric distance stays in every cell; new ramp
  monotonic dark→light = risky→safe; non-color cue **added**, not substituted.
  Confirm dist-0/1/2 still read as danger before shipping.
- **Index colors.** *Mitigation:* tokens alias current hex 1:1.
- **Index-panel grid reflow.** Fixes a bug but is a visible reflow. *Mitigation:*
  CSS-only; verify drag-drop + the new keyboard-assign path still assign correctly.
- **Keyboard retrofit correctness.** Adding `tabindex`+`onkeydown` to a `<div>` must
  exactly mirror the `onclick`. *Mitigation:* call the same `handleIndexClick`; test
  Enter/Space and mouse click produce identical assignment; no roving-tabindex.
- **Dead-CSS deletion.** *Mitigation:* re-grep each class (and id) across
  `templates/`, `static/js/`, `routes/*.py` at delete time; verified candidates have
  zero `class=` usages today.
- **Tailwind bridge surprises.** Mapping `slate` is safe (neutral→neutral, exact hex);
  brand migration is per-page and reviewed. *Mitigation:* map neutrals to exact
  current hex first (zero change), ship, then migrate brand utilities page-by-page —
  never combine the bridge and a color change in one step.
- **Type/spacing collapse → row-height shift.** *Mitigation:* snap to nearest existing
  value; visually diff sample + validation tables at equal data volume.

## 8. Decisions & defaults (current)

- **Palette:** Direction B — Deep Teal Clinical.
- **Accessibility:** WCAG 2.1 AA + **genuine keyboard operability**; §4.4 contrast
  matrix is the standard; opaque double focus ring.
- **Index sequences:** keep 8-char display; full value via `title=` **and**
  `aria-label` (not `title=` alone).
- **Dashboard per-row status badge:** **dropped** (redundant — tabs are single-status).
- **Toasts:** `role=status`/`aria-live` only; **no dismiss button**.
- **Tabs:** native `<button>` semantics (no `role=tab` retrofit).
- **Min viewport:** laptop ~1366px and up; horizontal-scroll wrappers on wide tables.
- **Dead CSS:** delete after per-class+id re-verification; `.ldap-config-form` is
  repointed to `#ldap-config-form`, not deleted.
- **Build:** `app.css` regenerated via `pixi run css` each phase; not committed
  (gitignored).

## 9. Out of scope

- Workflow/interaction redesign; navigation restructuring; collapsible/responsive
  sidebar; mobile layouts.
- New screens, features, or data-model changes.
- Per-row dashboard status badge; toast dismiss/pause-on-hover.
- A multi-step wizard / progress stepper (stepper CSS deleted, not revived).
- Always-visible full index sequences (would widen columns = layout change).
- Global remap of Tailwind's `blue` scale; `role=tablist` tab widgets.
- Dark mode.
