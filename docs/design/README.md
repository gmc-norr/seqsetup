# Design notes

Each file here records one design decision for SeqSetup: the problem, the
options considered, what was chosen and why. They are named
`YYYY-MM-DD-<topic>-design.md` after the day the decision was written down.

They are a history, not a manual:

- What the application does today is in the code, `CLAUDE.md` (the rules the
  code must keep) and the user and admin guides under `docs/`.
- A later note can change or replace an earlier one. When they disagree, the
  later note, and the code, win.
- Comments in the code and tests point to the note behind a rule, so a
  reviewer can see why the rule exists.
