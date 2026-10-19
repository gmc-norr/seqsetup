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

A fresh review of the first version of this file wrote 24 real mutations and
found 20 of them passed it: it held **one** sample per index-carrying case,
so an index exchanged between two rows -- the one failure the index-mixup
audit exists for -- went unseen, and so did a paste's i5 DNA rule, the test
and kit column aliases, the refusal order, a new field on ``ParsedSample``, a
refusal's exception type, ``_MAX_FIELD_LEN``, ``MAX_SAMPLES_PER_RUN`` and the
LIMS field mapping. Every one of those is a case or an assertion below.

Recorded on 2026-10-19 from ``services/sample_parser.read_pasted_samples``
and ``services/sample_api.parse_api_samples``.
"""

from dataclasses import asdict, fields

import pytest

from seqsetup.models.sample_api_config import SampleApiConfig
from seqsetup.services.sample_api import parse_api_samples
from seqsetup.services.sample_parser import ParsedSample, read_pasted_samples

# Every field a read sample carries, in order. Taken from the dataclass, not
# written out: a field the move adds is then compared too, or this file says
# so (fresh review of f99478f, P2-7).
FIELDS = tuple(f.name for f in fields(ParsedSample))

def paste_corpus():
    base_tab = "sample_id\ttest_id\nS1\tWGS\nS2\tWGS\n"
    base_csv = "sample_id,test_id,index,index2\nS1,WGS,ATTACTCG,TATAGCCT\n"
    headerless = "S1\tWGS\nS2\tPANEL\n"
    full = ("sample_id,test_id,test_version,index,index2,i7_name,i5_name,index_kit\n"
            "S1,WGS,1.2,ATTACTCG,TATAGCCT,D701,D501,Kit A\n")
    # Three samples, each with its own i7 and i5: an index exchanged between
    # two rows is the one failure the whole index-mixup audit exists for, and
    # a corpus of one-sample cases cannot see it (fresh review of f99478f,
    # P1-1).
    three = ("sample_id,test_id,index,index2,i7_name,i5_name\n"
             "S1,WGS,ATTACTCG,TATAGCCT,D701,D501\n"
             "S2,WGS,TCCGGAGA,ATAGAGGC,D702,D502\n"
             "S3,PANEL,CGCTCATT,CCTATCCT,D703,D503\n")
    out = {
        "two columns, tabs": base_tab,
        "four columns, commas": base_csv,
        "no header row": headerless,
        "every column": full,
        "three samples, each with its own i7 and i5": three,
        "three samples, the i5 column first": (
            "sample_id,index2,index\nS1,TATAGCCT,ATTACTCG\nS2,ATAGAGGC,TCCGGAGA\n"
            "S3,CCTATCCT,CGCTCATT\n"),
        "three samples, no header row": "S1\tWGS\nS2\tPANEL\nS3\tWGS\n",
        "header in capitals": base_csv.replace("sample_id,test_id", "Sample_ID,Test"),
        "header with spaces": base_csv.replace("sample_id,test_id", "Sample ID,Test ID"),
        "columns reordered": "test_id,sample_id\nWGS,S1\n",
        "CRLF": base_csv.replace("\n", "\r\n"),
        "a byte order mark": "﻿" + base_csv,
        "trailing blank rows": base_csv + "\n\n\n",
        "quoted cells": 'sample_id,test_id\n"S1","WGS, extra"\n',
        "a number as an id": "sample_id,test_id\n12345,WGS\n",
        "an id of zeros": "sample_id,test_id\n000,WGS\n",
        "ids of zeros in several rows": (
            "sample_id,test_id\n000,WGS\nS1,WGS\n0,WGS\n00000,WGS\n"),
        "a row with no id": "sample_id,test_id\n,WGS\n",
        "an id of 256 characters": f"sample_id,test_id\n{'S' * 256},WGS\n",
        "an id of 257 characters": f"sample_id,test_id\n{'S' * 257},WGS\n",
        "a test of 257 characters": f"sample_id,test_id\nS1,{'T' * 257}\n",
        "a test of 257 characters with no header row": f"S1\t{'T' * 257}\n",
        "a kit name of 300 characters": f"sample_id,index_kit\nS1,{'K' * 300}\n",
        "an i7 name of 300 characters": f"sample_id,i7_name\nS1,{'N' * 300}\n",
        "a column that looks like an index": "sample_id,Index 3\nS1,ATTACTCG\n",
        "a column named barcode": "sample_id,barcode\nS1,ATTACTCG\n",
        "a column named lane": "sample_id,lane\nS1,1\n",
        "a column with no header name": "sample_id,\nS1,x\n",
        "a third column with no header at all": "S1\tWGS\tEXTRA\n",
        "a sequence that is not DNA": "sample_id,index\nS1,ATTAXTCG\n",
        "an i5 that is not DNA": "sample_id,index,index2\nS1,ATTACTCG,TATAXCCT\n",
        "a lower-case sequence": "sample_id,index\nS1,attactcg\n",
        "a lower-case i5": "sample_id,index,index2\nS1,ATTACTCG,tatagcct\n",
        "a test version of four parts": "sample_id,test_id,test_version\nS1,WGS,1.2.3.4\n",
        "a test version that is text": "sample_id,test_id,test_version\nS1,WGS,one\n",
        "a test version but no test": "sample_id,test_version\nS1,1.2\n",
        "two sample columns": "sample_id,name,test_id\nS1,Other,WGS\n",
        "a lower-ranked sample column first": "name,sample_id,test_id\nOther,S1,WGS\n",
        "only a name column": "name,test_id\nS1,WGS\n",
        "two test columns": "sample_id,test_id,assay\nS1,FIRST,SECOND\n",
        "one sample id twice": "sample_id,test_id\nS1,WGS\nS1,PANEL\n",
        "two rows, two different faults": (
            "sample_id,test_id,test_version\n,WGS,1\nS2,WGS,one\n"),
        "the same two faults, the rows the other way round": (
            "sample_id,test_id,test_version\nS2,WGS,one\n,WGS,1\n"),
        "one row with two faults": "sample_id,test_id,test_version\n000,WGS,one\n",
        "an empty paste": "",
        "spaces only": "   \n  \n",
        "one cell": "S1\n",
        "a multi-line cell": 'sample_id,test_id\n"S1\nS2",WGS\n',
        "a row with more cells than the header": "sample_id,test_id\nS1,WGS,EXTRA\n",
        "a semicolon paste (the header becomes a sample: a poor read, recorded as it is)":
            "sample_id;test_id\nS1;WGS\n",
        "mixed tabs and commas (two cells become one id: a poor read, recorded as it is)":
            "sample_id\ttest_id\nS1,WGS\n",
        "a well column and a test column": "sample_id,well,test_id\nS1,A01,WGS\n",
        "a double quote that is not closed": 'sample_id,test_id\n"S1,WGS\n',
        "a cell too long for the reader": 'sample_id\n"' + "x" * 200_000 + "\n",
    }
    # One case per alias of every column the paste reads, so dropping an
    # alias is seen (fresh review of f99478f, P2-4).
    from seqsetup.services.sample_parser import (
        INDEX1_HEADERS, INDEX1_NAME_HEADERS, INDEX2_HEADERS, INDEX2_NAME_HEADERS,
        INDEX_PAIR_NAME_HEADERS, SAMPLE_HEADERS, TEST_HEADERS, TEST_VERSION_HEADERS,
    )
    for group, value in ((SAMPLE_HEADERS, "S1"), (TEST_HEADERS, "WGS"),
                         (TEST_VERSION_HEADERS, "1.2"), (INDEX1_HEADERS, "ATTACTCG"),
                         (INDEX2_HEADERS, "TATAGCCT"), (INDEX_PAIR_NAME_HEADERS, "Kit A"),
                         (INDEX1_NAME_HEADERS, "D701"), (INDEX2_NAME_HEADERS, "D501")):
        for name in sorted(group):
            if name in SAMPLE_HEADERS:
                out[f"a column named {name!r}"] = f"{name}\n{value}\n"
            else:
                out[f"a column named {name!r}"] = f"sample_id,{name}\nS1,{value}\n"
    # More samples than a run may hold.
    out["one sample over the cap"] = "sample_id\n" + "".join(
        f"S{n}\n" for n in range(5001))
    return out

def worklist_corpus():
    out = {
        "two fields": [{"sample_id": "S1", "test_id": "WGS"}],
        "every field": [{"sample_id": "S1", "test_id": "WGS", "test_version": "1.2",
                         "worksheet_id": "W1", "index_i7": "ATTACTCG",
                         "index_i5": "TATAGCCT", "i7_name": "D701", "i5_name": "D501",
                         "index_kit": "Kit A"}],
        "three samples, each with its own i7 and i5": [
            {"sample_id": "S1", "test_id": "WGS", "index_i7": "ATTACTCG",
             "index_i5": "TATAGCCT", "i7_name": "D701", "i5_name": "D501"},
            {"sample_id": "S2", "test_id": "WGS", "index_i7": "TCCGGAGA",
             "index_i5": "ATAGAGGC", "i7_name": "D702", "i5_name": "D502"},
            {"sample_id": "S3", "test_id": "PANEL", "index_i7": "CGCTCATT",
             "index_i5": "CCTATCCT", "i7_name": "D703", "i5_name": "D503"}],
        "three samples, the fields in another order": [
            {"index_i5": "TATAGCCT", "index_i7": "ATTACTCG", "sample_id": "S1"},
            {"index_i5": "ATAGAGGC", "index_i7": "TCCGGAGA", "sample_id": "S2"},
            {"index_i5": "CCTATCCT", "index_i7": "CGCTCATT", "sample_id": "S3"}],
        "a sample id as a number": [{"sample_id": 12345, "test_id": "WGS"}],
        "the field is called id": [{"id": "S1", "test_id": "WGS"}],
        "the field is called id and holds a number": [{"id": 12345}],
        "the field is called sample": [{"sample": "S1"}],
        "the field is called name": [{"name": "S1"}],
        "a sample id of zeros": [{"sample_id": "000", "test_id": "WGS"}],
        "a sample id as the number 0": [{"sample_id": 0, "test_id": "WGS"}],
        "ids of zeros in several rows": [{"sample_id": "000"}, {"sample_id": "S1"},
                                        {"sample_id": 0}, {"sample_id": "00000"}],
        "no sample id": [{"test_id": "WGS"}],
        "an empty sample id": [{"sample_id": "", "test_id": "WGS"}],
        "unrelated metadata": [{"sample_id": "S1", "patient": "x", "ordered": "2026-01-01"}],
        "a field that looks like an index": [{"sample_id": "S1", "Index 3": "ATTACTCG"}],
        "a field named barcode": [{"sample_id": "S1", "barcode": "ATTACTCG"}],
        "a field named lane": [{"sample_id": "S1", "lane": 1}],
        "two names for one index": [{"sample_id": "S1", "index_i7": "ATTACTCG",
                                     "i7": "TATAGCCT"}],
        "two field names differing only in case": [{"sample_id": "S1", "Test_ID": "A",
                                                    "test_id": "B"}],
        "a sample id of 256 characters": [{"sample_id": "S" * 256}],
        "a sample id of 257 characters": [{"sample_id": "S" * 257}],
        "a test of 257 characters": [{"sample_id": "S1", "test_id": "T" * 257}],
        "a kit name of 300 characters": [{"sample_id": "S1", "index_kit": "K" * 300}],
        "an i7 name of 300 characters": [{"sample_id": "S1", "i7_name": "N" * 300}],
        "a sequence that is not DNA": [{"sample_id": "S1", "index_i7": "ATTAXTCG"}],
        "an i5 that is not DNA": [{"sample_id": "S1", "index_i7": "ATTACTCG",
                                   "index_i5": "TATAXCCT"}],
        "a lower-case sequence": [{"sample_id": "S1", "index_i7": "attactcg"}],
        "a sample id as a list": [{"sample_id": ["S1"]}],
        "a sample id as a dict": [{"sample_id": {"a": "b"}}],
        "a sample id as a float": [{"sample_id": 1.5}],
        "a sample id as true": [{"sample_id": True}],
        "a sample id as null": [{"sample_id": None}],
        "a test version of four parts": [{"sample_id": "S1", "test_version": "1.2.3.4"}],
        "a test version but no test": [{"sample_id": "S1", "test_version": "1.2"}],
        "an empty worklist": [],
        "a row that is not a map": ["S1"],
        "two rows, one bad": [{"sample_id": "S1"}, {"test_id": "WGS"}],
        "one sample id twice": [{"sample_id": "S1"}, {"sample_id": "S1"}],
        "one sample over the cap": [{"sample_id": f"S{n}"} for n in range(5001)],
    }
    # One case per field name the LIMS import reads, so dropping an alias is
    # seen (fresh review of f99478f, P2-4).
    from seqsetup.services.sample_api import ALIAS_NAMES
    for field, names in sorted(ALIAS_NAMES.items()):
        value = {"index1_sequence": "ATTACTCG", "index2_sequence": "TATAGCCT",
                 "test_version": "1.2"}.get(field, "V1")
        for name in names:
            row = {"sample_id": "S1"} if field != "sample_id" else {}
            row[name] = value if field != "sample_id" else "S1"
            out[f"a field named {name!r}"] = [row]
    return out

def mapped_corpus():
    """Worklists read with a config whose field_mappings rename the fields:
    the LIMS adapter the corpus otherwise never runs (fresh review of
    f99478f, P3-12)."""
    return {
        "a mapping for every field": (
            {"sample_id": "LimsId", "test_id": "LimsTest",
             "index1_sequence": "LimsI7", "index2_sequence": "LimsI5"},
            [{"LimsId": "S1", "LimsTest": "WGS", "LimsI7": "ATTACTCG",
              "LimsI5": "TATAGCCT"},
             {"LimsId": "S2", "LimsTest": "WGS", "LimsI7": "TCCGGAGA",
              "LimsI5": "ATAGAGGC"},
             {"LimsId": "S3", "LimsTest": "PANEL", "LimsI7": "CGCTCATT",
              "LimsI5": "CCTATCCT"}]),
        "a mapping for the worksheet only": (
            {"worksheet_id": "AL"}, [{"sample_id": "S1", "AL": "W1"}]),
        "a mapping whose field the row does not have": (
            {"sample_id": "LimsId"}, [{"sample_id": "S1"}]),
    }

# What each paste gives today: ('read', rows, header_found, columns_used,
# columns_unused), or ('refused', the exception's type, the words).
PASTES = {
    'CRLF':
        ('read', (('S1', 'WGS', '', 'ATTACTCG', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test'), ('index', 'i7'), ('index2', 'i5')), ()),
    'a byte order mark':
        ('read', (('S1', 'WGS', '', 'ATTACTCG', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test'), ('index', 'i7'), ('index2', 'i5')), ()),
    'a cell too long for the reader':
        ('refused', 'ValueError', 'Line 2: this line could not be read — check it for a double quote (") that is not closed correctly, then paste again.'),
    "a column named 'application'":
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('application', 'Test')), ()),
    "a column named 'assay'":
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('assay', 'Test')), ()),
    "a column named 'i5 name'":
        ('read', (('S1', '', '', '', '', '', '', 'D501', 2),), True, (('sample_id', 'Sample ID'), ('i5 name', 'i5 name')), ()),
    "a column named 'i5'":
        ('read', (('S1', '', '', '', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('i5', 'i5')), ()),
    "a column named 'i5_index'":
        ('read', (('S1', '', '', '', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('i5_index', 'i5')), ()),
    "a column named 'i5_name'":
        ('read', (('S1', '', '', '', '', '', '', 'D501', 2),), True, (('sample_id', 'Sample ID'), ('i5_name', 'i5 name')), ()),
    "a column named 'i7 name'":
        ('read', (('S1', '', '', '', '', '', 'D701', '', 2),), True, (('sample_id', 'Sample ID'), ('i7 name', 'i7 name')), ()),
    "a column named 'i7'":
        ('read', (('S1', '', '', 'ATTACTCG', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('i7', 'i7')), ()),
    "a column named 'i7_index'":
        ('read', (('S1', '', '', 'ATTACTCG', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('i7_index', 'i7')), ()),
    "a column named 'i7_name'":
        ('read', (('S1', '', '', '', '', '', 'D701', '', 2),), True, (('sample_id', 'Sample ID'), ('i7_name', 'i7 name')), ()),
    "a column named 'id'":
        ('read', (('S1', '', '', '', '', '', '', '', 2),), True, (('id', 'Sample ID'),), ()),
    "a column named 'index i5'":
        ('read', (('S1', '', '', '', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index i5', 'i5')), ()),
    "a column named 'index i7'":
        ('read', (('S1', '', '', 'ATTACTCG', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index i7', 'i7')), ()),
    "a column named 'index kit'":
        ('read', (('S1', '', '', '', '', 'Kit A', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index kit', 'Index name')), ()),
    "a column named 'index name'":
        ('read', (('S1', '', '', '', '', '', 'D701', '', 2),), True, (('sample_id', 'Sample ID'), ('index name', 'i7 name')), ()),
    "a column named 'index pair'":
        ('read', (('S1', '', '', '', '', 'Kit A', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index pair', 'Index name')), ()),
    "a column named 'index'":
        ('read', (('S1', '', '', 'ATTACTCG', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index', 'i7')), ()),
    "a column named 'index1'":
        ('read', (('S1', '', '', 'ATTACTCG', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index1', 'i7')), ()),
    "a column named 'index1_name'":
        ('read', (('S1', '', '', '', '', '', 'D701', '', 2),), True, (('sample_id', 'Sample ID'), ('index1_name', 'i7 name')), ()),
    "a column named 'index2'":
        ('read', (('S1', '', '', '', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index2', 'i5')), ()),
    "a column named 'index2_name'":
        ('read', (('S1', '', '', '', '', '', '', 'D501', 2),), True, (('sample_id', 'Sample ID'), ('index2_name', 'i5 name')), ()),
    "a column named 'index_i5'":
        ('read', (('S1', '', '', '', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index_i5', 'i5')), ()),
    "a column named 'index_i5_name'":
        ('read', (('S1', '', '', '', '', '', '', 'D501', 2),), True, (('sample_id', 'Sample ID'), ('index_i5_name', 'i5 name')), ()),
    "a column named 'index_i7'":
        ('read', (('S1', '', '', 'ATTACTCG', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index_i7', 'i7')), ()),
    "a column named 'index_i7_name'":
        ('read', (('S1', '', '', '', '', '', 'D701', '', 2),), True, (('sample_id', 'Sample ID'), ('index_i7_name', 'i7 name')), ()),
    "a column named 'index_kit'":
        ('read', (('S1', '', '', '', '', 'Kit A', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index_kit', 'Index name')), ()),
    "a column named 'index_name'":
        ('read', (('S1', '', '', '', '', '', 'D701', '', 2),), True, (('sample_id', 'Sample ID'), ('index_name', 'i7 name')), ()),
    "a column named 'index_pair'":
        ('read', (('S1', '', '', '', '', 'Kit A', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index_pair', 'Index name')), ()),
    "a column named 'index_pair_name'":
        ('read', (('S1', '', '', '', '', 'Kit A', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index_pair_name', 'Index name')), ()),
    "a column named 'kit name'":
        ('read', (('S1', '', '', '', '', 'Kit A', '', '', 2),), True, (('sample_id', 'Sample ID'), ('kit name', 'Index name')), ()),
    "a column named 'kit_name'":
        ('read', (('S1', '', '', '', '', 'Kit A', '', '', 2),), True, (('sample_id', 'Sample ID'), ('kit_name', 'Index name')), ()),
    "a column named 'name'":
        ('read', (('S1', '', '', '', '', '', '', '', 2),), True, (('name', 'Sample ID'),), ()),
    "a column named 'pair_name'":
        ('read', (('S1', '', '', '', '', 'Kit A', '', '', 2),), True, (('sample_id', 'Sample ID'), ('pair_name', 'Index name')), ()),
    "a column named 'sample id'":
        ('read', (('S1', '', '', '', '', '', '', '', 2),), True, (('sample id', 'Sample ID'),), ()),
    "a column named 'sample'":
        ('read', (('S1', '', '', '', '', '', '', '', 2),), True, (('sample', 'Sample ID'),), ()),
    "a column named 'sample-id'":
        ('read', (('S1', '', '', '', '', '', '', '', 2),), True, (('sample-id', 'Sample ID'),), ()),
    "a column named 'sample_id'":
        ('read', (('S1', '', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'),), ()),
    "a column named 'sample_name'":
        ('read', (('S1', '', '', '', '', '', '', '', 2),), True, (('sample_name', 'Sample ID'),), ()),
    "a column named 'sampleid'":
        ('read', (('S1', '', '', '', '', '', '', '', 2),), True, (('sampleid', 'Sample ID'),), ()),
    "a column named 'samplename'":
        ('read', (('S1', '', '', '', '', '', '', '', 2),), True, (('samplename', 'Sample ID'),), ()),
    "a column named 'test id'":
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test id', 'Test')), ()),
    "a column named 'test type'":
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test type', 'Test')), ()),
    "a column named 'test version'":
        ('read', (('S1', '', '1.2', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test version', 'Test version')), ()),
    "a column named 'test'":
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test', 'Test')), ()),
    "a column named 'test-id'":
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test-id', 'Test')), ()),
    "a column named 'test-version'":
        ('read', (('S1', '', '1.2', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test-version', 'Test version')), ()),
    "a column named 'test_id'":
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    "a column named 'test_type'":
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_type', 'Test')), ()),
    "a column named 'test_version'":
        ('read', (('S1', '', '1.2', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_version', 'Test version')), ()),
    "a column named 'testid'":
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('testid', 'Test')), ()),
    "a column named 'testtype'":
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('testtype', 'Test')), ()),
    "a column named 'testversion'":
        ('read', (('S1', '', '1.2', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('testversion', 'Test version')), ()),
    'a column named barcode':
        ('refused', 'ValueError', 'Column(s) "barcode": SeqSetup does not read these, so the whole paste was refused. The i7 is read from a column named index, index1, i7, index_i7, i7_index or index i7; the i5 from index2, i5, index_i5, i5_index or index i5. Index names are read from columns such as i7_name, i5_name and index_pair_name. Rename or remove the column(s), or keep one column for each index.'),
    'a column named lane':
        ('refused', 'ValueError', 'Column(s) "lane": SeqSetup does not read these, so the whole paste was refused. The i7 is read from a column named index, index1, i7, index_i7, i7_index or index i7; the i5 from index2, i5, index_i5, i5_index or index i5. Index names are read from columns such as i7_name, i5_name and index_pair_name. Lanes come from the Lanes picker, not from the paste. Rename or remove the column(s), or keep one column for each index.'),
    'a column that looks like an index':
        ('refused', 'ValueError', 'Column(s) "Index 3": SeqSetup does not read these, so the whole paste was refused. The i7 is read from a column named index, index1, i7, index_i7, i7_index or index i7; the i5 from index2, i5, index_i5, i5_index or index i5. Index names are read from columns such as i7_name, i5_name and index_pair_name. Rename or remove the column(s), or keep one column for each index.'),
    'a column with no header name':
        ('refused', 'ValueError', 'Row(s) 2: column 2 has data but no header name, so SeqSetup cannot tell what it is. Give the column a header name, or remove its data.'),
    'a double quote that is not closed':
        ('refused', 'ValueError', 'Line 2: this line could not be read — check it for a double quote (") that is not closed correctly, then paste again.'),
    'a kit name of 300 characters':
        ('read', (('S1', '', '', '', '', 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index_kit', 'Index name')), ()),
    'a lower-case i5':
        ('read', (('S1', '', '', 'ATTACTCG', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index', 'i7'), ('index2', 'i5')), ()),
    'a lower-case sequence':
        ('read', (('S1', '', '', 'ATTACTCG', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('index', 'i7')), ()),
    'a lower-ranked sample column first':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ('name',)),
    'a multi-line cell':
        ('refused', 'ValueError', 'Line 2: a cell runs over more than one line — a double quote (") that is not closed, or a line break inside a cell. Rows would be merged, so fix it and paste again.'),
    'a number as an id':
        ('read', (('12345', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    'a row with more cells than the header':
        ('refused', 'ValueError', 'Row(s) 2: column 3 has data but no header name, so SeqSetup cannot tell what it is. Give the column a header name, or remove its data.'),
    'a row with no id':
        ('refused', 'ValueError', 'Row(s) 2: sample_id is required. Either supply a sample_id or remove the row entirely.'),
    'a semicolon paste (the header becomes a sample: a poor read, recorded as it is)':
        ('read', (('sample_id;test_id', '', '', '', '', '', '', '', 1), ('S1;WGS', '', '', '', '', '', '', '', 2)), False, (('column 1', 'Sample ID'),), ()),
    'a sequence that is not DNA':
        ('refused', 'ValueError', "Invalid characters in index1 for sample 'S1': {'X'}. Only A, C, G, T, N are allowed."),
    'a test of 257 characters':
        ('refused', 'ValueError', 'Row(s) 2: the test is longer than 256 characters. SeqSetup does not shorten it; shorten it in the source.'),
    'a test of 257 characters with no header row':
        ('refused', 'ValueError', 'Row(s) 1: the test is longer than 256 characters. SeqSetup does not shorten it; shorten it in the source.'),
    'a test version but no test':
        ('read', (('S1', '', '1.2', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_version', 'Test version')), ()),
    'a test version of four parts':
        ('refused', 'ValueError', 'Row(s) 2: the test version is not right. A test version is 1, 2 or 3 whole numbers joined by dots, each at most 9 digits, like 1, 1.2 or 1.2.3.'),
    'a test version that is text':
        ('refused', 'ValueError', 'Row(s) 2: the test version is not right. A test version is 1, 2 or 3 whole numbers joined by dots, each at most 9 digits, like 1, 1.2 or 1.2.3.'),
    'a third column with no header at all':
        ('refused', 'ValueError', 'Row(s) 1: this paste has no header row, and these rows have more than two columns. Without a header row SeqSetup reads only the sample ID (first column) and the test (second column); it does not guess which column holds which index. Add a header row naming the columns, for example: sample_id, test_id, index_i7, index_i5. The header row must be the first line.'),
    'a well column and a test column':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ('well',)),
    'an empty paste':
        ('read', (), False, (), ()),
    'an i5 that is not DNA':
        ('refused', 'ValueError', "Invalid characters in index2 for sample 'S1': {'X'}. Only A, C, G, T, N are allowed."),
    'an i7 name of 300 characters':
        ('read', (('S1', '', '', '', '', '', 'NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN', '', 2),), True, (('sample_id', 'Sample ID'), ('i7_name', 'i7 name')), ()),
    'an id of 256 characters':
        ('read', (('SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    'an id of 257 characters':
        ('refused', 'ValueError', 'Row(s) 2: the sample_id is longer than 256 characters. SeqSetup does not shorten it; shorten it in the source.'),
    'an id of zeros':
        ('refused', 'ValueError', 'Row(s) 2: A sample ID made only of zeros is not a sample ID — a LIMS may use 0 for an empty well. Give the sample its real ID or remove the row entirely.'),
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
    'ids of zeros in several rows':
        ('refused', 'ValueError', 'Row(s) 2, 4, 5: A sample ID made only of zeros is not a sample ID — a LIMS may use 0 for an empty well. Give the sample its real ID or remove the row entirely.'),
    'mixed tabs and commas (two cells become one id: a poor read, recorded as it is)':
        ('read', (('S1,WGS', '', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    'no header row':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 1), ('S2', 'PANEL', '', '', '', '', '', '', 2)), False, (('column 1', 'Sample ID'), ('column 2', 'Test')), ()),
    'one cell':
        ('read', (('S1', '', '', '', '', '', '', '', 1),), False, (('column 1', 'Sample ID'),), ()),
    'one row with two faults':
        ('refused', 'ValueError', 'Row(s) 2: A sample ID made only of zeros is not a sample ID — a LIMS may use 0 for an empty well. Give the sample its real ID or remove the row entirely.'),
    'one sample id twice':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2), ('S1', 'PANEL', '', '', '', '', '', '', 3)), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    'one sample over the cap':
        ('refused', 'ValueError', 'Too many samples: a run accepts a maximum of 5000. Reduce the worklist or split it across runs.'),
    'only a name column':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('name', 'Sample ID'), ('test_id', 'Test')), ()),
    'quoted cells':
        ('read', (('S1', 'WGS, extra', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    'spaces only':
        ('read', (), False, (), ()),
    'the same two faults, the rows the other way round':
        ('refused', 'ValueError', 'Row(s) 3: sample_id is required. Either supply a sample_id or remove the row entirely.'),
    'three samples, each with its own i7 and i5':
        ('read', (('S1', 'WGS', '', 'ATTACTCG', 'TATAGCCT', '', 'D701', 'D501', 2), ('S2', 'WGS', '', 'TCCGGAGA', 'ATAGAGGC', '', 'D702', 'D502', 3), ('S3', 'PANEL', '', 'CGCTCATT', 'CCTATCCT', '', 'D703', 'D503', 4)), True, (('sample_id', 'Sample ID'), ('test_id', 'Test'), ('index', 'i7'), ('index2', 'i5'), ('i7_name', 'i7 name'), ('i5_name', 'i5 name')), ()),
    'three samples, no header row':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 1), ('S2', 'PANEL', '', '', '', '', '', '', 2), ('S3', 'WGS', '', '', '', '', '', '', 3)), False, (('column 1', 'Sample ID'), ('column 2', 'Test')), ()),
    'three samples, the i5 column first':
        ('read', (('S1', '', '', 'ATTACTCG', 'TATAGCCT', '', '', '', 2), ('S2', '', '', 'TCCGGAGA', 'ATAGAGGC', '', '', '', 3), ('S3', '', '', 'CGCTCATT', 'CCTATCCT', '', '', '', 4)), True, (('sample_id', 'Sample ID'), ('index2', 'i5'), ('index', 'i7')), ()),
    'trailing blank rows':
        ('read', (('S1', 'WGS', '', 'ATTACTCG', 'TATAGCCT', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test'), ('index', 'i7'), ('index2', 'i5')), ()),
    'two columns, tabs':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2), ('S2', 'WGS', '', '', '', '', '', '', 3)), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ()),
    'two rows, two different faults':
        ('refused', 'ValueError', 'Row(s) 2: sample_id is required. Either supply a sample_id or remove the row entirely.'),
    'two sample columns':
        ('read', (('S1', 'WGS', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ('name',)),
    'two test columns':
        ('read', (('S1', 'FIRST', '', '', '', '', '', '', 2),), True, (('sample_id', 'Sample ID'), ('test_id', 'Test')), ('assay',)),
}

# What each worklist gives today.
WORKLISTS = {
    "a field named 'al'":
        ('read', ((('sample_id', 'S1'), ('test_version', ''), ('worksheet_id', 'V1')),)),
    "a field named 'application'":
        ('read', ((('sample_id', 'S1'), ('test_id', 'V1'), ('test_version', '')),)),
    "a field named 'assay'":
        ('read', ((('sample_id', 'S1'), ('test_id', 'V1'), ('test_version', '')),)),
    "a field named 'i5'":
        ('read', ((('index2_sequence', 'TATAGCCT'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'i5_name'":
        ('read', ((('index2_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'i5_sequence'":
        ('read', ((('index2_sequence', 'TATAGCCT'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'i7'":
        ('read', ((('index1_sequence', 'ATTACTCG'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'i7_name'":
        ('read', ((('index1_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'i7_sequence'":
        ('read', ((('index1_sequence', 'ATTACTCG'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'id'":
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index1'":
        ('read', ((('index1_sequence', 'ATTACTCG'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index1_name'":
        ('read', ((('index1_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index2'":
        ('read', ((('index2_sequence', 'TATAGCCT'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index2_name'":
        ('read', ((('index2_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index_i5'":
        ('read', ((('index2_sequence', 'TATAGCCT'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index_i5_name'":
        ('read', ((('index2_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index_i5_sequence'":
        ('read', ((('index2_sequence', 'TATAGCCT'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index_i7'":
        ('read', ((('index1_sequence', 'ATTACTCG'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index_i7_name'":
        ('read', ((('index1_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index_i7_sequence'":
        ('read', ((('index1_sequence', 'ATTACTCG'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index_kit'":
        ('read', ((('index_pair_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index_name'":
        ('read', ((('index1_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index_pair'":
        ('read', ((('index_pair_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'index_pair_name'":
        ('read', ((('index_pair_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'kit_name'":
        ('read', ((('index_pair_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'name'":
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'pair_name'":
        ('read', ((('index_pair_name', 'V1'), ('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'sample'":
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'sample_id'":
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'sample_name'":
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'sampleid'":
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
    "a field named 'test'":
        ('read', ((('sample_id', 'S1'), ('test_id', 'V1'), ('test_version', '')),)),
    "a field named 'test_id'":
        ('read', ((('sample_id', 'S1'), ('test_id', 'V1'), ('test_version', '')),)),
    "a field named 'test_type'":
        ('read', ((('sample_id', 'S1'), ('test_id', 'V1'), ('test_version', '')),)),
    "a field named 'test_version'":
        ('refused', 'ValueError', "Sample 'S1' has a test version but no test."),
    "a field named 'testid'":
        ('read', ((('sample_id', 'S1'), ('test_id', 'V1'), ('test_version', '')),)),
    "a field named 'testversion'":
        ('refused', 'ValueError', "Sample 'S1' has a test version but no test."),
    "a field named 'worklist_id'":
        ('read', ((('sample_id', 'S1'), ('test_version', ''), ('worksheet_id', 'V1')),)),
    "a field named 'worksheet'":
        ('read', ((('sample_id', 'S1'), ('test_version', ''), ('worksheet_id', 'V1')),)),
    "a field named 'worksheet_id'":
        ('read', ((('sample_id', 'S1'), ('test_version', ''), ('worksheet_id', 'V1')),)),
    "a field named 'worksheetid'":
        ('read', ((('sample_id', 'S1'), ('test_version', ''), ('worksheet_id', 'V1')),)),
    'a field named barcode':
        ('refused', 'ValueError', 'LIMS row(s) 1: the field(s) "barcode" look like an index or a lane, but SeqSetup does not read them, so the whole worklist was refused. It reads the i7 from index_i7, index1, i7, index_i7_sequence or i7_sequence, and the i5 from index_i5, index2, i5, index_i5_sequence or i5_sequence. Rename or remove the field(s) in the LIMS.'),
    'a field named lane':
        ('refused', 'ValueError', 'LIMS row(s) 1: the field(s) "lane" look like an index or a lane, but SeqSetup does not read them, so the whole worklist was refused. It reads the i7 from index_i7, index1, i7, index_i7_sequence or i7_sequence, and the i5 from index_i5, index2, i5, index_i5_sequence or i5_sequence. Lanes come from the Lanes picker on the import, not from the LIMS. Rename or remove the field(s) in the LIMS.'),
    'a field that looks like an index':
        ('refused', 'ValueError', 'LIMS row(s) 1: the field(s) "Index 3" look like an index or a lane, but SeqSetup does not read them, so the whole worklist was refused. It reads the i7 from index_i7, index1, i7, index_i7_sequence or i7_sequence, and the i5 from index_i5, index2, i5, index_i5_sequence or i5_sequence. Rename or remove the field(s) in the LIMS.'),
    'a kit name of 300 characters':
        ('read', ((('index_pair_name', 'KKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKKK'), ('sample_id', 'S1'), ('test_version', '')),)),
    'a lower-case sequence':
        ('read', ((('index1_sequence', 'ATTACTCG'), ('sample_id', 'S1'), ('test_version', '')),)),
    'a row that is not a map':
        ('refused', 'ValueError', 'LIMS row(s) 1: sample_id is missing or empty. Fix the upstream record(s) before retrying.'),
    'a sample id as a dict':
        ('refused', 'ValueError', 'LIMS row 1 has a sample ID that is not text or a whole number ({"a": "b"}).'),
    'a sample id as a float':
        ('refused', 'ValueError', 'LIMS row 1 has a sample ID that is a number with a decimal point (1.5), which JSON may have changed (1.10 is read as 1.1). Send it as text, for example "1.10".'),
    'a sample id as a list':
        ('refused', 'ValueError', 'LIMS row 1 has a sample ID that is not text or a whole number (["S1"]).'),
    'a sample id as a number':
        ('read', ((('sample_id', '12345'), ('test_id', 'WGS'), ('test_version', '')),)),
    'a sample id as null':
        ('refused', 'ValueError', 'LIMS row(s) 1: sample_id is missing or empty. Fix the upstream record(s) before retrying.'),
    'a sample id as the number 0':
        ('refused', 'ValueError', 'LIMS row(s) 1: A sample ID made only of zeros is not a sample ID — a LIMS may use 0 for an empty well. Fix the upstream record(s) before retrying.'),
    'a sample id as true':
        ('refused', 'ValueError', 'LIMS row 1 has a sample ID that is not text or a whole number (true).'),
    'a sample id of 256 characters':
        ('read', ((('sample_id', 'SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS'), ('test_version', '')),)),
    'a sample id of 257 characters':
        ('refused', 'ValueError', 'LIMS row(s) 1: the sample_id is longer than 256 characters. SeqSetup does not shorten it. Fix the upstream record(s) before retrying.'),
    'a sample id of zeros':
        ('refused', 'ValueError', 'LIMS row(s) 1: A sample ID made only of zeros is not a sample ID — a LIMS may use 0 for an empty well. Fix the upstream record(s) before retrying.'),
    'a sequence that is not DNA':
        ('refused', 'ValueError', "Sample 'S1' has an invalid index1_sequence ('ATTAXTCG'): only A, C, G, T, N are allowed (offending: X)."),
    'a test of 257 characters':
        ('refused', 'ValueError', 'LIMS row(s) 1: the test is longer than 256 characters. SeqSetup does not shorten it. Fix the upstream record(s) before retrying.'),
    'a test version but no test':
        ('refused', 'ValueError', "Sample 'S1' has a test version but no test."),
    'a test version of four parts':
        ('refused', 'ValueError', "Sample 'S1' has a test version that is not right ('1.2.3.4'). A test version is 1, 2 or 3 whole numbers joined by dots, each at most 9 digits, like 1, 1.2 or 1.2.3."),
    'an empty sample id':
        ('refused', 'ValueError', 'LIMS row(s) 1: sample_id is missing or empty. Fix the upstream record(s) before retrying.'),
    'an empty worklist':
        ('read', ()),
    'an i5 that is not DNA':
        ('refused', 'ValueError', "Sample 'S1' has an invalid index2_sequence ('TATAXCCT'): only A, C, G, T, N are allowed (offending: X)."),
    'an i7 name of 300 characters':
        ('read', ((('index1_name', 'NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN'), ('sample_id', 'S1'), ('test_version', '')),)),
    'every field':
        ('read', ((('index1_name', 'D701'), ('index1_sequence', 'ATTACTCG'), ('index2_name', 'D501'), ('index2_sequence', 'TATAGCCT'), ('index_pair_name', 'Kit A'), ('sample_id', 'S1'), ('test_id', 'WGS'), ('test_version', '1.2'), ('worksheet_id', 'W1')),)),
    'ids of zeros in several rows':
        ('refused', 'ValueError', 'LIMS row(s) 1, 3, 4: A sample ID made only of zeros is not a sample ID — a LIMS may use 0 for an empty well. Fix the upstream record(s) before retrying.'),
    'no sample id':
        ('refused', 'ValueError', 'LIMS row(s) 1: sample_id is missing or empty. Fix the upstream record(s) before retrying.'),
    'one sample id twice':
        ('refused', 'ValueError', 'these sample IDs appear more than once in the worklist: S1. Nothing was added.'),
    'one sample over the cap':
        ('refused', 'ValueError', 'Too many samples: a run accepts a maximum of 5000. Reduce the worklist or split it across runs.'),
    'the field is called id':
        ('read', ((('sample_id', 'S1'), ('test_id', 'WGS'), ('test_version', '')),)),
    'the field is called id and holds a number':
        ('read', ((('sample_id', '12345'), ('test_version', '')),)),
    'the field is called name':
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
    'the field is called sample':
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
    'three samples, each with its own i7 and i5':
        ('read', ((('index1_name', 'D701'), ('index1_sequence', 'ATTACTCG'), ('index2_name', 'D501'), ('index2_sequence', 'TATAGCCT'), ('sample_id', 'S1'), ('test_id', 'WGS'), ('test_version', '')), (('index1_name', 'D702'), ('index1_sequence', 'TCCGGAGA'), ('index2_name', 'D502'), ('index2_sequence', 'ATAGAGGC'), ('sample_id', 'S2'), ('test_id', 'WGS'), ('test_version', '')), (('index1_name', 'D703'), ('index1_sequence', 'CGCTCATT'), ('index2_name', 'D503'), ('index2_sequence', 'CCTATCCT'), ('sample_id', 'S3'), ('test_id', 'PANEL'), ('test_version', '')))),
    'three samples, the fields in another order':
        ('read', ((('index1_sequence', 'ATTACTCG'), ('index2_sequence', 'TATAGCCT'), ('sample_id', 'S1'), ('test_version', '')), (('index1_sequence', 'TCCGGAGA'), ('index2_sequence', 'ATAGAGGC'), ('sample_id', 'S2'), ('test_version', '')), (('index1_sequence', 'CGCTCATT'), ('index2_sequence', 'CCTATCCT'), ('sample_id', 'S3'), ('test_version', '')))),
    'two field names differing only in case':
        ('refused', 'ValueError', "LIMS row 1 has the names 'Test_ID' and 'test_id', which SeqSetup reads as one name. Send only one of them."),
    'two fields':
        ('read', ((('sample_id', 'S1'), ('test_id', 'WGS'), ('test_version', '')),)),
    'two names for one index':
        ('refused', 'ValueError', 'LIMS row 1 has more than one name for an i7 sequence ("index_i7", "i7"), so the whole worklist was refused: SeqSetup would read only one of them. Send only one.'),
    'two rows, one bad':
        ('refused', 'ValueError', 'LIMS row(s) 2: sample_id is missing or empty. Fix the upstream record(s) before retrying.'),
    'unrelated metadata':
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
}

# ... and each one read with a field mapping.
MAPPED = {
    'a mapping for every field':
        ('read', ((('index1_sequence', 'ATTACTCG'), ('index2_sequence', 'TATAGCCT'), ('sample_id', 'S1'), ('test_id', 'WGS'), ('test_version', '')), (('index1_sequence', 'TCCGGAGA'), ('index2_sequence', 'ATAGAGGC'), ('sample_id', 'S2'), ('test_id', 'WGS'), ('test_version', '')), (('index1_sequence', 'CGCTCATT'), ('index2_sequence', 'CCTATCCT'), ('sample_id', 'S3'), ('test_id', 'PANEL'), ('test_version', '')))),
    'a mapping for the worksheet only':
        ('read', ((('sample_id', 'S1'), ('test_version', ''), ('worksheet_id', 'W1')),)),
    'a mapping whose field the row does not have':
        ('read', ((('sample_id', 'S1'), ('test_version', '')),)),
}


def _read_paste(text):
    try:
        read = read_pasted_samples(text)
    except Exception as e:
        return ("refused", type(e).__name__, str(e))
    return ("read",
            tuple(tuple(asdict(s)[name] for name in FIELDS) for s in read.samples),
            read.header_found,
            tuple(tuple(pair) for pair in read.columns_used),
            tuple(read.columns_unused))


def _read_worklist(data, config=None):
    try:
        samples = parse_api_samples(data, config)
    except Exception as e:
        return ("refused", type(e).__name__, str(e))
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


class TestAWorklistReadWithAFieldMapping:
    """``config.field_mappings`` renames every field a LIMS sends; the whole
    adapter was run by nothing (fresh review of f99478f, P3-12)."""

    def test_the_corpus_and_the_record_name_the_same_cases(self):
        assert sorted(mapped_corpus()) == sorted(MAPPED)

    @pytest.mark.parametrize("label", sorted(MAPPED))
    def test_the_worklist(self, label):
        mapping, data = mapped_corpus()[label]
        assert _read_worklist(data, SampleApiConfig(field_mappings=mapping)) == MAPPED[label]


class TestTheCorpusCanSeeTheThingsThatMatter:
    """A guard that says nothing is no guard. Not a count of cases -- the
    index-carrying cases could all be deleted and a count still pass (fresh
    review of f99478f, P1-2) -- but what the corpus can actually see."""

    def _read_samples(self, record):
        return record[1] if record[0] == "read" else ()

    def test_every_field_of_a_read_sample_is_compared(self):
        assert FIELDS == tuple(f.name for f in fields(ParsedSample))
        assert len(FIELDS) >= 9

    def test_a_refusal_s_own_type_is_recorded(self):
        """The routes catch ValueError; a move that raised another type
        would keep every word and turn a banner into a 500."""
        refused = [r for r in list(PASTES.values()) + list(WORKLISTS.values())
                   if r[0] == "refused"]

        assert refused, "no refusal in the corpus"
        assert {r[1] for r in refused} == {"ValueError"}, {r[1] for r in refused}

    def test_a_paste_holds_three_samples_with_three_different_i7_and_i5(self):
        """An index exchanged between two rows is the failure the whole
        index-mixup audit exists for, and a corpus of one-sample cases
        cannot see it."""
        i7, i5 = FIELDS.index("index1_sequence"), FIELDS.index("index2_sequence")
        wide = [rows for rows in map(self._read_samples, PASTES.values())
                if len(rows) >= 3 and len({r[i7] for r in rows}) == len(rows)
                and len({r[i5] for r in rows}) == len(rows)
                and all(r[i7] and r[i5] for r in rows)]

        assert wide, "no paste case pins which row gets which index"

    def test_a_worklist_holds_three_samples_with_three_different_i7_and_i5(self):
        wide = []
        for record in list(WORKLISTS.values()) + list(MAPPED.values()):
            if record[0] != "read" or len(record[1]) < 3:
                continue
            rows = [dict(r) for r in record[1]]
            i7 = {r.get("index1_sequence") for r in rows}
            i5 = {r.get("index2_sequence") for r in rows}
            if len(i7) == len(rows) and len(i5) == len(rows) and all(i7) and all(i5):
                wide.append(rows)

        assert wide, "no worklist case pins which row gets which index"

    @pytest.mark.parametrize("field", ["test_id", "test_version", "index1_sequence",
                                       "index2_sequence", "index_pair_name",
                                       "index1_name", "index2_name"])
    def test_some_read_paste_fills_each_field(self, field):
        """A column alias that is dropped loses the field silently, so every
        field must be filled by some case."""
        at = FIELDS.index(field)

        assert any(row[at] for rows in map(self._read_samples, PASTES.values())
                   for row in rows), field

    @pytest.mark.parametrize("field", ["test_id", "test_version", "worksheet_id",
                                       "index1_sequence", "index2_sequence",
                                       "index_pair_name", "index1_name", "index2_name"])
    def test_some_read_worklist_fills_each_field(self, field):
        filled = [dict(row).get(field)
                  for record in list(WORKLISTS.values()) + list(MAPPED.values())
                  if record[0] == "read" for row in record[1]]

        assert any(filled), field

    def test_every_column_name_the_paste_reads_has_a_case(self):
        from seqsetup.services.sample_parser import (
            INDEX1_HEADERS, INDEX1_NAME_HEADERS, INDEX2_HEADERS, INDEX2_NAME_HEADERS,
            INDEX_PAIR_NAME_HEADERS, SAMPLE_HEADERS, TEST_HEADERS, TEST_VERSION_HEADERS,
        )

        every = (SAMPLE_HEADERS | TEST_HEADERS | TEST_VERSION_HEADERS | INDEX1_HEADERS
                 | INDEX2_HEADERS | INDEX_PAIR_NAME_HEADERS | INDEX1_NAME_HEADERS
                 | INDEX2_NAME_HEADERS)
        missing = [name for name in sorted(every) if f"a column named {name!r}" not in PASTES]

        assert missing == [], missing

    def test_every_field_name_the_lims_import_reads_has_a_case(self):
        from seqsetup.services.sample_api import ALIAS_NAMES

        missing = [name for names in ALIAS_NAMES.values() for name in names
                   if f"a field named {name!r}" not in WORKLISTS]

        assert missing == [], missing

    def test_both_readers_refuse_more_samples_than_a_run_holds(self):
        for record in (PASTES["one sample over the cap"],
                       WORKLISTS["one sample over the cap"]):
            assert record[0] == "refused" and "Too many samples" in record[2]
