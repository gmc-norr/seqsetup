# Long sample text is refused, never cut

Outside review of 7f858e0, finding 5 (P1). The user's choices, 2026-10-14:
"Refuse it" (not "Cut but warn"), and "Refuse on load too" (not "Keep
cutting on load, log it").

## The problem

Five Sample text fields are cut to 256 characters without a word:
`sample_id`, `sample_name`, `project`, `test_id`, `worksheet_id`. The cut
happens at every way in:

- the model, `Sample.__setattr__` (`models/sample.py`, the last branch);
- the paste parser, which cuts every cell (`_MAX_CELL_LEN`,
  `services/sample_parser.py`);
- the LIMS parser, which cuts every field it reads (`_MAX_FIELD_LEN`,
  `services/sample_api.py`, in `parse_api_samples`);
- the routes, through `sanitize_string(value, 256)`: single add, rename
  (`update_sample`), bulk set test, and the paste's default test.

A cut ID goes on the sheet. Two IDs that differ only after character 256
become one ID, and a cut ID no longer matches the LIMS. A run saved before
the cuts were added (2026-05-25) may still hold a longer value; today it is
cut when loaded.

## The rule

A value of one of the five fields longer than 256 characters, after
leading and trailing whitespace is stripped, is refused. Nothing is cut.
256 characters or fewer is accepted as today.

`index_kit_name` keeps its cut: it is not one of the five, it is not
written to any sheet, and the user's question did not include it.

## Where it is enforced

1. **Model (the backstop).** `Sample.__setattr__` raises `ValueError` for a
   string over 256 in one of the five fields, naming the field, the length,
   and the start of the value (`shown_value`, as the zero-ID rule does).
   This also applies when a run is loaded (`Sample.from_dict` builds through
   `__setattr__`), by the user's choice: such a run cannot be loaded. The
   dashboard already names a run whose document cannot be read
   (`RunRepository.list_all_readable`); opening it fails as any unreadable
   run does. No run can gain such a value from now on.

   Found by the review of 6d50fce (P3-1): as for any unreadable run, a
   Ready or Archived run holding such a value also makes the two listings
   with no per-run guard fail for every run -- `/api/runs?status=...` and
   the API Exports page (`RunRepository.list_by_status`) -- and its own
   API sheet endpoints answer 500 where they served its stored bytes. Only
   a run saved before 2026-05-25 can hold such a value, and none has been
   deployed.

2. **Paste parser.** The cells that become `sample_id` and `test_id` are not
   cut. A row whose sample ID or test is over 256 is collected, and the
   whole paste is refused with a `ValueError` naming the source lines, like
   a row with no sample ID:
   `Row(s) 3, 7: the sample_id is longer than 256 characters. SeqSetup does not shorten it; shorten it in the source.`
   (and the same with `the test`). Other cells keep today's cut: they do not
   reach the five fields. The add route and the preview show the message as
   they show today's parser refusals.

3. **LIMS parser.** `sample_id`, `test_id` and `worksheet_id` are not cut.
   Rows over 256 are collected per field and the whole worklist is refused,
   naming the row positions, after the existing missing-ID and zero-ID
   checks:
   `LIMS row(s) 2, 5: the sample_id is longer than 256 characters. SeqSetup does not shorten it. Fix the upstream record(s) before retrying.`
   (and `the test`, `the worksheet ID`). Other fields keep today's cut.

4. **Routes.** Single add (`sample_id`, `sample_name`, `project`,
   `test_id`), rename (`sample_id`, `sample_name`, `project`), bulk set test
   (`test_id`) and the paste's default test: a stripped value over 256 is a
   400 naming the field, and nothing is saved:
   `The sample ID is longer than 256 characters. Nothing was saved.`

## What does not change

- Values of 256 characters or fewer: stored, shown and written to the sheet
  exactly as today.
- The sheet for any run that loads today with values of 256 or fewer.
- `index_kit_name`, `description` (4096), and every other cut.
- The DRAGEN Sample_ID length some pipelines enforce is a separate gap,
  not handled here.

## Docs

- `CLAUDE.md`: the three lines on the 256 cap (Input sanitization, the two
  ingest-point lines, and the model line in Data integrity) say the five
  fields are refused over 256, not cut.
- `docs/admin-guide/sample-api.rst`: "capped at 256 characters" says the
  three LIMS fields are refused over 256.
- `docs/user-guide/samples.rst`: one sentence in the paste section and one
  in the LIMS section.

## Tests

New, each red before the change:

- the model refuses each of the five fields at 257 and accepts 256, on
  construction and on assignment, and `from_dict` refuses;
- a paste with a 257-character sample ID or test is refused whole, naming
  its lines, in the preview and on Add; 256 is accepted unchanged;
- a LIMS worklist with a 257-character sample ID, test or worksheet ID is
  refused whole, naming its rows, in the preview and on import;
- single add, rename, bulk set test and the paste's default test answer 400
  for 257 and save nothing;
- two IDs equal in their first 256 characters are both refused, not merged.

Changed, because they assert the cut:

- `tests/unit/test_model_validation.py`:
  `test_sample_id_long_string_clamped_at_model`,
  `test_sample_name_clamped_at_256`, `test_test_id_clamped_at_256`;
- `tests/integration/test_mark_ready_sample_text_line_breaks.py`:
  `test_sample_id_clamped_to_end_in_newline_is_refused` (the rename it
  sends is now refused at the rename, 400, and nothing is stored).
