"""What a paste and a LIMS worklist do today, case by case
(docs/design/2026-10-18-input-rules-design.md, "Step 5: pasted samples and
LIMS worklists").

These two inputs are the most patient-critical the app has and the strictest:
both refuse the whole input and name the rows, both refuse a column or field
that looks like an index or a lane but is not one they read, and both refuse
sample text over 256 characters rather than cut it. Step 5 of the input rules
would move the per-row checks onto one strict rulebook, and may do so **only
if it changes no outcome** -- which cannot be argued, only measured.

So this file is the measurement, and it stands on its own: every paste text
and worklist payload below, with the samples it gives or the words it is
refused with, recorded from the readers as they are. A change to either
reader either keeps every line of this file or is not made.

Recorded on 2026-10-19 from ``services/sample_parser.read_pasted_samples``
and ``services/sample_api.parse_api_samples``.
"""

from dataclasses import asdict

import pytest

from seqsetup.services.sample_api import parse_api_samples
from seqsetup.services.sample_parser import read_pasted_samples

# The fields a read sample carries, in the order they are compared.
FIELDS = ("sample_id", "test_id", "test_version", "index1_sequence", "index2_sequence",
          "index_pair_name", "index1_name", "index2_name", "line")

def paste_corpus():
    base_tab = "sample_id\ttest_id\nS1\tWGS\nS2\tWGS\n"
    base_csv = "sample_id,test_id,index,index2\nS1,WGS,ATTACTCG,TATAGCCT\n"
    headerless = "S1\tWGS\nS2\tPANEL\n"
    full = ("sample_id,test_id,test_version,index,index2,i7_name,i5_name,index_kit\n"
            "S1,WGS,1.2,ATTACTCG,TATAGCCT,D701,D501,Kit A\n")
    out = {
        "two columns, tabs": base_tab,
        "four columns, commas": base_csv,
        "no header row": headerless,
        "every column": full,
        "header in capitals": base_csv.replace("sample_id,test_id", "Sample_ID,Test"),
        "header with spaces": base_csv.replace("sample_id,test_id", "Sample ID,Test ID"),
        "columns reordered": "test_id,sample_id\nWGS,S1\n",
        "CRLF": base_csv.replace("\n", "\r\n"),
        "a byte order mark": "﻿" + base_csv,
        "trailing blank rows": base_csv + "\n\n\n",
        "quoted cells": 'sample_id,test_id\n"S1","WGS, extra"\n',
        "a number as an id": "sample_id,test_id\n12345,WGS\n",
        "an id of zeros": "sample_id,test_id\n000,WGS\n",
        "a row with no id": "sample_id,test_id\n,WGS\n",
        "an id of 256 characters": f"sample_id,test_id\n{'S' * 256},WGS\n",
        "an id of 257 characters": f"sample_id,test_id\n{'S' * 257},WGS\n",
        "a test of 257 characters": f"sample_id,test_id\nS1,{'T' * 257}\n",
        "a column that looks like an index": "sample_id,Index 3\nS1,ATTACTCG\n",
        "a column named barcode": "sample_id,barcode\nS1,ATTACTCG\n",
        "a column named lane": "sample_id,lane\nS1,1\n",
        "a column with no header name": "sample_id,\nS1,x\n",
        "a third column with no header at all": "S1\tWGS\tEXTRA\n",
        "a sequence that is not DNA": "sample_id,index\nS1,ATTAXTCG\n",
        "a lower-case sequence": "sample_id,index\nS1,attactcg\n",
        "a test version of four parts": "sample_id,test_id,test_version\nS1,WGS,1.2.3.4\n",
        "a test version that is text": "sample_id,test_id,test_version\nS1,WGS,one\n",
        "two sample columns": "sample_id,name,test_id\nS1,Other,WGS\n",
        "a lower-ranked sample column first": "name,sample_id,test_id\nOther,S1,WGS\n",
        "only a name column": "name,test_id\nS1,WGS\n",
        "an empty paste": "",
        "spaces only": "   \n  \n",
        "one cell": "S1\n",
        "a multi-line cell": 'sample_id,test_id\n"S1\nS2",WGS\n',
        "a row with more cells than the header": "sample_id,test_id\nS1,WGS,EXTRA\n",
        "a semicolon paste": "sample_id;test_id\nS1;WGS\n",
        "mixed tabs and commas": "sample_id\ttest_id\nS1,WGS\n",
    }
    return out

def worklist_corpus():
    return {
        "two fields": [{"sample_id": "S1", "test_id": "WGS"}],
        "every field": [{"sample_id": "S1", "test_id": "WGS", "test_version": "1.2",
                         "worksheet_id": "W1", "index_i7": "ATTACTCG",
                         "index_i5": "TATAGCCT", "i7_name": "D701", "i5_name": "D501",
                         "index_kit": "Kit A"}],
        "a sample id as a number": [{"sample_id": 12345, "test_id": "WGS"}],
        "the field is called id": [{"id": "S1", "test_id": "WGS"}],
        "the field is called id and holds a number": [{"id": 12345}],
        "the field is called sample": [{"sample": "S1"}],
        "the field is called name": [{"name": "S1"}],
        "a sample id of zeros": [{"sample_id": "000", "test_id": "WGS"}],
        "a sample id as the number 0": [{"sample_id": 0, "test_id": "WGS"}],
        "no sample id": [{"test_id": "WGS"}],
        "an empty sample id": [{"sample_id": "", "test_id": "WGS"}],
        "unrelated metadata": [{"sample_id": "S1", "patient": "x", "ordered": "2026-01-01"}],
        "a field that looks like an index": [{"sample_id": "S1", "Index 3": "ATTACTCG"}],
        "a field named barcode": [{"sample_id": "S1", "barcode": "ATTACTCG"}],
        "a field named lane": [{"sample_id": "S1", "lane": 1}],
        "two names for one index": [{"sample_id": "S1", "index_i7": "ATTACTCG",
                                     "i7": "TATAGCCT"}],
        "a sample id of 256 characters": [{"sample_id": "S" * 256}],
        "a sample id of 257 characters": [{"sample_id": "S" * 257}],
        "a test of 257 characters": [{"sample_id": "S1", "test_id": "T" * 257}],
        "a sequence that is not DNA": [{"sample_id": "S1", "index_i7": "ATTAXTCG"}],
        "a lower-case sequence": [{"sample_id": "S1", "index_i7": "attactcg"}],
        "a sample id as a list": [{"sample_id": ["S1"]}],
        "a sample id as a dict": [{"sample_id": {"a": "b"}}],
        "a test version of four parts": [{"sample_id": "S1", "test_version": "1.2.3.4"}],
        "an empty worklist": [],
        "a row that is not a map": ["S1"],
        "two rows, one bad": [{"sample_id": "S1"}, {"test_id": "WGS"}],
    }

# What each paste gives today: ('read', rows, header_found, columns_used,
# columns_unused), or ('refused', the words).
PASTES = {
    'CRLF':
        ('read', (('S1', 'WGS', '', 'ATTACTCG', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test'), ('index', 'i7'), ('index2', 'i5')), ()),
    'a byte order mark':
        ('read', (('S1', 'WGS', '', 'ATTACTCG', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test'), ('index', 'i7'), ('index2', 'i5')), ()),
    'a column named barcode':
        ('refused', 'Column(s) "barcode": SeqSetup does not read these, so the whole paste was refused. The i7 is read from a column named index, index1, i7, index_i7, i7_index or index i7; the i5 from index2, i5, index_i5, i5_index or index i5. Index names are read from columns such as i7_name, i5_name and index_pair_name. Rename or remove the column(s), or keep one column for each index.'),
    'a column named lane':
        ('refused', 'Column(s) "lane": SeqSetup does not read these, so the whole paste was refused. The i7 is read from a column named index, index1, i7, index_i7, i7_index or index i7; the i5 from index2, i5, index_i5, i5_index or index i5. Index names are read from columns such as i7_name, i5_name and index_pair_name. Lanes come from the Lanes picker, not from the paste. Rename or remove the column(s), or keep one column for each index.'),
    'a column that looks like an index':
        ('refused', 'Column(s) "Index 3": SeqSetup does not read these, so the whole paste was refused. The i7 is read from a column named index, index1, i7, index_i7, i7_index or index i7; the i5 from index2, i5, index_i5, i5_index or index i5. Index names are read from columns such as i7_name, i5_name and index_pair_name. Rename or remove the column(s), or keep one column for each index.'),
    'a column with no header name':
        ('refused', 'Row(s) 2: column 2 has data but no header name, so SeqSetup cannot tell what it is. Give the column a header name, or remove its data.'),
    'a lower-case sequence':
        ('read', (('S1', '', '', 'ATTACTCG', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index', 'i7')), ()),
    'a lower-ranked sample column first':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ('name',)),
    'a multi-line cell':
        ('refused', 'Line 2: a cell runs over more than one line — a double quote (") that is not closed, or a line break inside a cell. Rows would be merged, so fix it and paste again.'),
    'a number as an id':
        ('read', (('12345', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    'a row with more cells than the header':
        ('refused', 'Row(s) 2: column 3 has data but no header name, so SeqSetup cannot tell what it is. Give the column a header name, or remove its data.'),
    'a row with no id':
        ('refused', 'Row(s) 2: sample_id is required. Either supply a sample_id or remove the row entirely.'),
    'a semicolon paste':
        ('read', (('sample_id;test_id', '', '', '', '', '', '', '', 1), ('S1;WGS', '', '', '', '', '', '', '', 2)), False, (('column 1', 'Sample ID'),), ()),
    'a sequence that is not DNA':
        ('refused', "Invalid characters in index1 for sample 'S1': {'X'}. Only A, C, G, T, N are allowed."),
    'a test of 257 characters':
        ('refused', 'Row(s) 2: the test is longer than 256 characters. SeqSetup does not shorten it; shorten it in the source.'),
    'a test version of four parts':
        ('refused', 'Row(s) 2: the test version is not right. A test version is 1, 2 or 3 whole numbers joined by dots, each at most 9 digits, like 1, 1.2 or 1.2.3.'),
    'a test version that is text':
        ('refused', 'Row(s) 2: the test version is not right. A test version is 1, 2 or 3 whole numbers joined by dots, each at most 9 digits, like 1, 1.2 or 1.2.3.'),
    'a third column with no header at all':
        ('refused', 'Row(s) 1: this paste has no header row, and these rows have more than two columns. Without a header row SeqSetup reads only the sample ID (first column) and the test (second column); it does not guess which column holds which index. Add a header row naming the columns, for example: sample_id, test_id, index_i7, index_i5. The header row must be the first line.'),
    'an empty paste':
        ('read', (), False, (), ()),
    'an id of 256 characters':
        ('read', (('SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    'an id of 257 characters':
        ('refused', 'Row(s) 2: the sample_id is longer than 256 characters. SeqSetup does not shorten it; shorten it in the source.'),
    'an id of zeros':
        ('refused', 'Row(s) 2: A sample ID made only of zeros is not a sample ID — a LIMS may use 0 for an empty well. Give the sample its real ID or remove the row entirely.'),
    'columns reordered':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('test_id', 'Test'), ('sample_id', 'Sample ID')), ()),
    'every column':
        ('read', (('S1', 'WGS', '1.2', 'ATTACTCG', 'TATAGCCT', 'Kit A', 'D701', 'D501', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test'), ('test_version', 'Test version'), ('index', 'i7'), ('index2', 'i5'), ('i7_name', 'i7 name'), ('i5_name', 'i5 name'), ('index_kit', 'Index name')), ()),
    'four columns, commas':
        ('read', (('S1', 'WGS', '', 'ATTACTCG', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test'), ('index', 'i7'), ('index2', 'i5')), ()),
    'header in capitals':
        ('read', (('S1', 'WGS', '', 'ATTACTCG', 'TATAGCCT', '', '', '', 2),), True, (('Sample_ID', 'Sample ID'), ('Test', 'Test'), ('index', 'i7'), ('index2', 'i5')), ()),
    'header with spaces':
        ('read', (('S1', 'WGS', '', 'ATTACTCG', 'TATAGCCT', '', '', '', 2),), True, (('Sample ID', 'Sample ID'), ('Test ID', 'Test'), ('index', 'i7'), ('index2', 'i5')), ()),
    'mixed tabs and commas':
        ('read', (('S1,WGS', '', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    'no header row':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 1), ('S2', 'PANEL', '', '', '', '', '', '', 2)), False, (('column 1', 'Sample ID'), ('column 2', 'Test')), ()),
    'one cell':
        ('read', (('S1', '', '', '', '', '', '', '', 1),), False, (('column 1', 'Sample ID'),), ()),
    'only a name column':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('name', 'Sample ID'), ('test_id', 'Test')), ()),
    'quoted cells':
        ('read', (('S1', 'WGS, extra', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    'spaces only':
        ('read', (), False, (), ()),
    'trailing blank rows':
        ('read', (('S1', 'WGS', '', 'ATTACTCG', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test'), ('index', 'i7'), ('index2', 'i5')), ()),
    'two columns, tabs':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2), ('S2', 'WGS', '', '', '', '', '', '', 3)), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    'two sample columns':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ('name',)),
}


# What each worklist gives today.
WORKLISTS = {
    'a field named barcode':
        ('refused', 'LIMS row(s) 1: the field(s) "barcode" look like an index or a lane, but SeqSetup does not read them, so the whole worklist was refused. It reads the i7 from index_i7, index1, i7, index_i7_sequence or i7_sequence, and the i5 from index_i5, index2, i5, index_i5_sequence or i5_sequence. Rename or remove the field(s) in the LIMS.'),
    'a field named lane':
        ('refused', 'LIMS row(s) 1: the field(s) "lane" look like an index or a lane, but SeqSetup does not read them, so the whole worklist was refused. It reads the i7 from index_i7, index1, i7, index_i7_sequence or i7_sequence, and the i5 from index_i5, index2, i5, index_i5_sequence or i5_sequence. Lanes come from the Lanes picker on the import, not from the LIMS. Rename or remove the field(s) in the LIMS.'),
    'a field that looks like an index':
        ('refused', 'LIMS row(s) 1: the field(s) "Index 3" look like an index or a lane, but SeqSetup does not read them, so the whole worklist was refused. It reads the i7 from index_i7, index1, i7, index_i7_sequence or i7_sequence, and the i5 from index_i5, index2, i5, index_i5_sequence or i5_sequence. Rename or remove the field(s) in the LIMS.'),
    'a lower-case sequence':
        ('read', ((('index1_sequence', 'ATTACTCG'), ('sample_id', 'S1'), ('test_version', '')),)),
    'a row that is not a map':
        ('refused', 'LIMS row(s) 1: sample_id is missing or empty. Fix the upstream record(s) before retrying.'),
    'a sample id as a dict':
        ('refused', 'LIMS row 1 has a sample ID that is not text or a whole number ({"a": "b"}).'),
    'a sample id as a list':
        ('refused', 'LIMS row 1 has a sample ID that is not text or a whole number (["S1"]).'),
    'a sample id as a number':
        ('read', ((('sample_id', '12345'), ('test_id', 'WGS'), ('test_version', '')),)),
    'a sample id as the number 0':
        ('refused', 'LIMS row(s) 1: A sample ID made only of zeros is not a sample ID — a LIMS may use 0 for an empty well. Fix the upstream record(s) before retrying.'),
    'a sample id of 256 characters':
        ('read', ((('sample_id', 'SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS'), ('test_version', '')),)),
    'a sample id of 257 characters':
        ('refused', 'LIMS row(s) 1: the sample_id is longer than 256 characters. SeqSetup does not shorten it. Fix the upstream record(s) before retrying.'),
    'a sample id of zeros':
        ('refused', 'LIMS row(s) 1: A sample ID made only of zeros is not a sample ID — a LIMS may use 0 for an empty well. Fix the upstream record(s) before retrying.'),
    'a sequence that is not DNA':
        ('refused', "Sample 'S1' has an invalid index1_sequence ('ATTAXTCG'): only A, C, G, T, N are allowed (offending: X)."),
    'a test of 257 characters':
        ('refused', 'LIMS row(s) 1: the test is longer than 256 characters. SeqSetup does not shorten it. Fix the upstream record(s) before retrying.'),
    'a test version of four parts':
        ('refused', "Sample 'S1' has a test version that is not right ('1.2.3.4'). A test version is 1, 2 or 3 whole numbers joined by dots, each at most 9 digits, like 1, 1.2 or 1.2.3."),
    'an empty sample id':
        ('refused', 'LIMS row(s) 1: sample_id is missing or empty. Fix the upstream record(s) before retrying.'),
    'an empty worklist':
        ('read', ()),
    'every field':
        ('read', ((('index1_name', 'D701'), ('index1_sequence', 'ATTACTCG'), ('index2_name', 'D501'), ('index2_sequence', 'TATAGCCT'), ('index_pair_name', 'Kit A'), ('sample_id', 'S1'), ('test_id', 'WGS'), ('test_version', '1.2'), ('worksheet_id', 'W1')),)),
    'no sample id':
        ('refused', 'LIMS row(s) 1: sample_id is missing or empty. Fix the upstream record(s) before retrying.'),
    'the field is called id':
        ('read', ((('sample_id', 'S1'), ('test_id', 'WGS'), ('test_version', '')),)),
    'the field is called id and holds a number':
        ('read', ((('sample_id', '12345'), ('test_version', '')),)),
    'the field is called name':
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
    'the field is called sample':
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
    'two fields':
        ('read', ((('sample_id', 'S1'), ('test_id', 'WGS'), ('test_version', '')),)),
    'two names for one index':
        ('refused', 'LIMS row 1 has more than one name for an i7 sequence ("index_i7", "i7"), so the whole worklist was refused: SeqSetup would read only one of them. Send only one.'),
    'two rows, one bad':
        ('refused', 'LIMS row(s) 2: sample_id is missing or empty. Fix the upstream record(s) before retrying.'),
    'unrelated metadata':
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
}


def _read_paste(text):
    try:
        read = read_pasted_samples(text)
    except Exception as e:
        return ("refused", str(e))
    return ("read",
            tuple(tuple(asdict(s).get(f, "") for f in FIELDS) for s in read.samples),
            read.header_found,
            tuple(tuple(pair) for pair in read.columns_used),
            tuple(read.columns_unused))


def _read_worklist(data):
    try:
        samples = parse_api_samples(data)
    except Exception as e:
        return ("refused", str(e))
    return ("read", tuple(tuple(sorted(s.items())) for s in samples))


class TestEveryPasteGivesWhatItGaveBefore:

    def test_the_corpus_and_the_record_name_the_same_cases(self):
        assert sorted(paste_corpus()) == sorted(PASTES)

    @pytest.mark.parametrize("label", sorted(PASTES))
    def test_the_paste(self, label):
        assert _read_paste(paste_corpus()[label]) == PASTES[label]


class TestEveryWorklistGivesWhatItGaveBefore:

    def test_the_corpus_and_the_record_name_the_same_cases(self):
        assert sorted(worklist_corpus()) == sorted(WORKLISTS)

    @pytest.mark.parametrize("label", sorted(WORKLISTS))
    def test_the_worklist(self, label):
        assert _read_worklist(worklist_corpus()[label]) == WORKLISTS[label]


class TestTheCorpusIsWideEnoughToSeeAChange:
    """A guard that says nothing is no guard: the corpus must hold cases of
    both kinds, and enough of them."""

    def test_it_holds_pastes_that_are_read_and_pastes_that_are_refused(self):
        kinds = [value[0] for value in PASTES.values()]

        assert kinds.count("read") >= 15 and kinds.count("refused") >= 10

    def test_it_holds_worklists_of_both_kinds(self):
        kinds = [value[0] for value in WORKLISTS.values()]

        assert kinds.count("read") >= 5 and kinds.count("refused") >= 10
