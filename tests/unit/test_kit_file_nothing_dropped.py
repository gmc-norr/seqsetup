"""A kit file never loses data without a word.

``ec465fc``..``00ed519`` stopped an uploaded kit file's i7 and i5 from
pairing by a guess, and refused a name given twice or one YAML does not read
as text. The same rule -- refuse the whole file, naming what and where,
nothing saved -- was still missing for five more ways a file's content went
in and did not come out:

* a **Single** upload whose file carries i5 data: the i5 column, the
  ``i5Index2`` list, the ``IndexNumber 2`` lines, an ``[i5]`` section or a
  SeqSetup-format ``i5_indexes`` list went nowhere, or went into a kit whose
  panel never shows them;
* a CSV row with content but no name or no i7 sequence, dropped by
  ``if name and i7_seq``;
* a TSV ``[Indices]`` line with fewer than three cells, or a third cell that
  is not 1 or 2, dropped by ``if len(parts) >= 3`` and the ``elif``;
* an Illumina YAML that gives both ``i7Index1`` and ``Index1`` (or both
  ``i5Index2`` and ``Index2``): ``a or b`` read one and dropped the other;
* a SeqSetup-format YAML index name YAML does not read as text -- an
  unquoted ``012`` is the number 10.
"""

import pytest

from seqsetup.models.index import IndexMode
from seqsetup.services.index_parser import (I5DataInSingleKit, IncompleteIndexRows,
                                            IndexNamesNotText, IndexParser, KitFileRefused,
                                            PairsInSingleKit, TwoKeysForOneList)

I7 = {"A1": "ATTACTCG", "A2": "TCCGGAGA"}
I5 = {"A1": "TATAGCCT", "A2": "ATAGAGGC"}


def _sequences(kit) -> set[str]:
    """Every index sequence the kit holds, whatever shape it holds them in."""
    out = {i.sequence for i in kit.i7_indexes} | {i.sequence for i in kit.i5_indexes}
    for pair in kit.index_pairs:
        out.add(pair.index1.sequence)
        if pair.index2:
            out.add(pair.index2.sequence)
    return out


def _illumina_yaml(i7: dict, i5: dict) -> str:
    lines = ["Name: Old kit", 'Version: "1.0"', "IndexSequences:", "  i7Index1:"]
    lines += [f"    {name}: {seq}" for name, seq in i7.items()]
    if i5:
        lines += ["  i5Index2:"] + [f"    {name}: {seq}" for name, seq in i5.items()]
    return "\n".join(lines) + "\n"


def _illumina_tsv(i7: dict, i5: dict) -> str:
    lines = ["[IndexKit]", "Name\tOld kit", "Version\t1.0", "", "[Indices]",
             "Name\tSequence\tIndexNumber"]
    lines += [f"{name}\t{seq}\t1" for name, seq in i7.items()]
    lines += [f"{name}\t{seq}\t2" for name, seq in i5.items()]
    return "\n".join(lines) + "\n"


def _simple_csv(i7: dict, i5: dict) -> str:
    lines = ["name,index,index2"]
    lines += [f"{name},{seq},{i5.get(name, '')}" for name, seq in i7.items()]
    return "\n".join(lines) + "\n"


def _combinatorial_csv(i7: dict, i5: dict) -> str:
    lines = ["[i7]", "name,sequence"] + [f"{n},{s}" for n, s in i7.items()]
    if i5:
        lines += ["[i5]", "name,sequence"] + [f"{n},{s}" for n, s in i5.items()]
    return "\n".join(lines) + "\n"


def _sync_yaml_i5(i7: dict, i5: dict) -> str:
    lines = ["name: Old kit", 'version: "1.0"', "index_mode: combinatorial", "i7_indexes:"]
    lines += [f"  - name: {n}\n    sequence: {s}" for n, s in i7.items()]
    if i5:
        lines += ["i5_indexes:"] + [f"  - name: {n}\n    sequence: {s}" for n, s in i5.items()]
    return "\n".join(lines) + "\n"


ALL_FORMATS = [
    ("old.yaml", _illumina_yaml, "i5Index2"),
    ("old.tsv", _illumina_tsv, "IndexNumber"),
    ("old.csv", _simple_csv, "index2"),
    ("comb.csv", _combinatorial_csv, "[i5]"),
    ("sync.yaml", _sync_yaml_i5, "i5_indexes"),
]


class TestASingleUploadWithI5DataIsRefused:
    """Uploading a dual or combinatorial kit file as Single once threw its i5
    away -- the i7 indexes were saved and the admin was told nothing. The whole
    file is refused instead, naming where the i5 data is and what to do."""

    @pytest.mark.parametrize("filename, make, where", ALL_FORMATS)
    def test_the_file_is_refused_naming_where_the_i5_is(self, filename, make, where):
        with pytest.raises(I5DataInSingleKit) as refused:
            IndexParser.parse_from_content(make(I7, I5), filename, index_mode=IndexMode.SINGLE)

        message = str(refused.value)
        assert where in message, message
        assert "Unique Dual" in message and "Combinatorial" in message, message
        assert refused.value.reason == "i5_data_in_single_kit"

    @pytest.mark.parametrize("filename, make, _where", ALL_FORMATS)
    def test_the_same_file_with_no_i5_is_saved_as_single(self, filename, make, _where):
        kit = IndexParser.parse_from_content(make(I7, {}), filename,
                                             index_mode=IndexMode.SINGLE)

        assert kit.index_mode == IndexMode.SINGLE
        assert [i.name for i in kit.i7_indexes] == list(I7)
        assert kit.i5_indexes == [] and kit.index_pairs == []

    def test_an_i5_column_with_no_values_in_it_is_not_i5_data(self):
        kit = IndexParser.parse_from_content("name,index,index2\nA1,ATTACTCG,\n", "k.csv",
                                             index_mode=IndexMode.SINGLE)

        assert [i.name for i in kit.i7_indexes] == ["A1"]

    @pytest.mark.parametrize("filename, make, _where", ALL_FORMATS)
    def test_the_same_file_as_combinatorial_keeps_every_index(self, filename, make, _where):
        # A simple CSV read as Combinatorial still becomes pairs -- _parse_csv
        # only tells Single from the rest -- so this asks for the sequences,
        # not the shape: none of them may go missing.
        kit = IndexParser.parse_from_content(make(I7, I5), filename,
                                             index_mode=IndexMode.COMBINATORIAL)

        assert _sequences(kit) == set(I7.values()) | set(I5.values())

    def test_a_sync_yaml_with_pairs_is_refused_as_single(self):
        content = ("name: Old kit\nindex_pairs:\n  - name: P1\n    index1:\n"
                   "      name: A1\n      sequence: ATTACTCG\n    index2:\n"
                   "      name: A1\n      sequence: TATAGCCT\n")

        with pytest.raises(PairsInSingleKit) as refused:
            IndexParser.parse_from_content(content, "sync.yaml", index_mode=IndexMode.SINGLE)

        assert "index_pairs" in str(refused.value)
        assert refused.value.reason == "pairs_in_single_kit"


class TestARowWithNoNameOrNoSequenceIsRefused:
    """``if name and i7_seq`` dropped such a row without a word, so a kit
    file with a stray line saved fewer indexes than it listed. The whole file
    is refused, naming the lines, as a pasted worklist is."""

    @pytest.mark.parametrize("row, line", [
        (",CCCCGGGG,TTTTAAAA", 3),
        ("B1,,TTTTAAAA", 3),
        ("B1", 3),
    ])
    def test_a_simple_csv_row_is_named_by_its_line(self, row, line):
        content = f"name,index,index2\nA1,ATTACTCG,TATAGCCT\n{row}\n"

        with pytest.raises(IncompleteIndexRows) as refused:
            IndexParser.parse_from_content(content, "k.csv", index_mode=IndexMode.UNIQUE_DUAL)

        assert f"line {line}" in str(refused.value)
        assert refused.value.reason == "incomplete_index_rows"

    def test_every_bad_line_is_named(self):
        content = "name,index,index2\n,CCCCGGGG,\nA1,ATTACTCG,TATAGCCT\nB1,,\n"

        with pytest.raises(IncompleteIndexRows) as refused:
            IndexParser.parse_from_content(content, "k.csv", index_mode=IndexMode.UNIQUE_DUAL)

        message = str(refused.value)
        assert "line 2" in message and "line 4" in message

    def test_the_line_number_is_the_files_own_after_leading_blank_lines(self):
        # The CSV reader strips the content so DictReader can find the header;
        # the lines it strips are counted back on, or the refusal would name
        # line 3 for a row on line 5.
        content = "\n\nname,index,index2\nA1,ATTACTCG,TATAGCCT\n,CCCCGGGG,\n"

        with pytest.raises(IncompleteIndexRows) as refused:
            IndexParser.parse_from_content(content, "k.csv", index_mode=IndexMode.UNIQUE_DUAL)

        assert "line 5" in str(refused.value), str(refused.value)

    def test_a_row_of_only_separators_is_not_a_row(self):
        content = "name,index,index2\nA1,ATTACTCG,TATAGCCT\n,,\nA2,TCCGGAGA,ATAGAGGC\n"

        kit = IndexParser.parse_from_content(content, "k.csv", index_mode=IndexMode.UNIQUE_DUAL)

        assert [p.name for p in kit.index_pairs] == ["A1", "A2"]

    def test_a_combinatorial_row_of_only_separators_is_not_a_row(self):
        content = "[i7]\nname,sequence\nA1,ATTACTCG\n,\n[i5]\nname,sequence\nB1,TATAGCCT\n"

        kit = IndexParser.parse_from_content(content, "k.csv",
                                             index_mode=IndexMode.COMBINATORIAL)

        assert ([i.name for i in kit.i7_indexes], [i.name for i in kit.i5_indexes]) == (
            ["A1"], ["B1"])

    def test_a_blank_line_is_not_a_row(self):
        content = "name,index,index2\nA1,ATTACTCG,TATAGCCT\n\n\nA2,TCCGGAGA,ATAGAGGC\n"

        kit = IndexParser.parse_from_content(content, "k.csv", index_mode=IndexMode.UNIQUE_DUAL)

        assert [p.name for p in kit.index_pairs] == ["A1", "A2"]

    @pytest.mark.parametrize("section, row, line", [
        ("i7", ",CCCCGGGG", 4),
        ("i5", "B1,", 7),
    ])
    def test_a_combinatorial_csv_row_is_named_by_its_line(self, section, row, line):
        lines = ["[i7]", "name,sequence", "A1,ATTACTCG"]
        if section == "i7":
            lines.insert(3, row)
        lines += ["[i5]", "name,sequence", "A1,TATAGCCT"]
        if section == "i5":
            lines.append(row)

        with pytest.raises(IncompleteIndexRows) as refused:
            IndexParser.parse_from_content("\n".join(lines) + "\n", "k.csv",
                                           index_mode=IndexMode.COMBINATORIAL)

        assert f"line {line}" in str(refused.value), str(refused.value)


class TestATsvLineThatIsNotAnIndexIsRefused:
    """``if len(parts) >= 3`` and ``elif index_num == "2"`` dropped a short
    line and a line whose index number is neither 1 nor 2."""

    # _illumina_tsv(I7, I5) is ten lines: [IndexKit], Name, Version, blank,
    # [Indices], the header, two i7 lines, two i5 lines. The row goes on 11.
    @pytest.mark.parametrize("row, line", [
        ("B1\tCCCCGGGG", 11),
        ("B1\tCCCCGGGG\t3", 11),
        ("B1\tCCCCGGGG\ti7", 11),
        ("B1\tCCCCGGGG\t", 11),
    ])
    def test_the_line_is_named(self, row, line):
        content = _illumina_tsv(I7, I5).rstrip("\n") + f"\n{row}\n"

        with pytest.raises(IncompleteIndexRows) as refused:
            IndexParser.parse_from_content(content, "k.tsv", index_mode=IndexMode.UNIQUE_DUAL)

        message = str(refused.value)
        assert f"line {line}" in message, message
        assert refused.value.reason == "incomplete_index_rows"

    def test_the_line_number_is_the_files_own_after_leading_blank_lines(self):
        # The TSV reader counts the file's own lines, blanks included: it does
        # not strip the content first, or a line on 9 would be named as 7.
        content = ("\n\n[IndexKit]\nName\tOld kit\n\n[Indices]\n"
                   "Name\tSequence\tIndexNumber\nA1\tATTACTCG\t1\nB1\tCCCCGGGG\t3\n")

        with pytest.raises(IncompleteIndexRows) as refused:
            IndexParser.parse_from_content(content, "k.tsv", index_mode=IndexMode.SINGLE)

        assert "line 9" in str(refused.value), str(refused.value)

    def test_the_header_line_is_not_refused(self):
        kit = IndexParser.parse_from_content(_illumina_tsv(I7, I5), "k.tsv",
                                             index_mode=IndexMode.UNIQUE_DUAL)

        assert [p.name for p in kit.index_pairs] == list(I7)

    def test_a_file_with_no_header_line_still_reads_its_indexes(self):
        content = ("[IndexKit]\nName\tOld kit\n\n[Indices]\n"
                   "A1\tATTACTCG\t1\nA1\tTATAGCCT\t2\n")

        kit = IndexParser.parse_from_content(content, "k.tsv",
                                             index_mode=IndexMode.UNIQUE_DUAL)

        assert [p.name for p in kit.index_pairs] == ["A1"]


class TestTwoKeysForOneListAreRefused:
    """``index_seqs.get("i7Index1", {}) or index_seqs.get("Index1", {})``
    read one list and dropped the other without a word."""

    @pytest.mark.parametrize("keys, other", [
        (("i7Index1", "Index1"), "i5Index2"),
        (("i5Index2", "Index2"), "i7Index1"),
    ])
    def test_both_keys_are_named(self, keys, other):
        first, second = keys
        content = (f"Name: Old kit\nIndexSequences:\n  {first}:\n    A1: ATTACTCG\n"
                   f"  {second}:\n    A2: TCCGGAGA\n  {other}:\n    A1: TATAGCCT\n")

        with pytest.raises(TwoKeysForOneList) as refused:
            IndexParser.parse_from_content(content, "old.yaml",
                                           index_mode=IndexMode.COMBINATORIAL)

        message = str(refused.value)
        assert first in message and second in message, message
        assert refused.value.reason == "two_keys_for_one_list"

    def test_an_empty_first_key_is_still_two_keys(self):
        content = ("Name: Old kit\nIndexSequences:\n  i7Index1:\n  Index1:\n"
                   "    A2: TCCGGAGA\n")

        with pytest.raises(TwoKeysForOneList):
            IndexParser.parse_from_content(content, "old.yaml", index_mode=IndexMode.SINGLE)

    def test_one_key_alone_is_read(self):
        content = "Name: Old kit\nIndexSequences:\n  Index1:\n    A1: ATTACTCG\n"

        kit = IndexParser.parse_from_content(content, "old.yaml", index_mode=IndexMode.SINGLE)

        assert [i.name for i in kit.i7_indexes] == ["A1"]


class TestASyncYamlNameMustBeText:
    """``012`` unquoted is the number 10 to YAML, so two names written
    differently can be read as one -- the same refusal the Illumina format
    already had."""

    @pytest.mark.parametrize("where", ["i7_indexes", "index_pairs"])
    def test_a_name_that_is_not_text_is_refused(self, where):
        if where == "i7_indexes":
            content = ("name: Old kit\nindex_mode: single\ni7_indexes:\n"
                       "  - name: 012\n    sequence: ATTACTCG\n")
            mode = IndexMode.SINGLE
        else:
            content = ("name: Old kit\nindex_pairs:\n  - name: 012\n    index1:\n"
                       "      name: 012\n      sequence: ATTACTCG\n")
            mode = IndexMode.UNIQUE_DUAL

        with pytest.raises(IndexNamesNotText) as refused:
            IndexParser.parse_from_content(content, "sync.yaml", index_mode=mode)

        assert "quote" in str(refused.value)
        assert refused.value.reason == "index_names_not_text"

    def test_a_quoted_name_is_read(self):
        content = ("name: Old kit\nindex_mode: single\ni7_indexes:\n"
                   "  - name: '012'\n    sequence: ATTACTCG\n")

        kit = IndexParser.parse_from_content(content, "sync.yaml", index_mode=IndexMode.SINGLE)

        assert [i.name for i in kit.i7_indexes] == ["012"]

    def test_a_sequence_that_is_not_text_is_refused(self):
        content = ("name: Old kit\nindex_mode: single\ni7_indexes:\n"
                   "  - name: A1\n    sequence: 1234\n")

        with pytest.raises(IndexNamesNotText) as refused:
            IndexParser.parse_from_content(content, "sync.yaml", index_mode=IndexMode.SINGLE)

        assert "A1" in str(refused.value)


class TestEveryRefusalIsAKitFileRefusal:
    """The upload route shows a KitFileRefused in full and audits its
    ``reason``; anything else becomes "Failed to parse file"."""

    @pytest.mark.parametrize("cls", [I5DataInSingleKit, PairsInSingleKit,
                                     IncompleteIndexRows, TwoKeysForOneList])
    def test_it_is_a_kit_file_refused_with_its_own_reason(self, cls):
        assert issubclass(cls, KitFileRefused)
        assert cls.reason != KitFileRefused.reason


class TestAColumnTheParserDoesNotReadIsRefused:
    """A CSV header that looks like an index or a lane but is not a column the
    kit parser reads was ignored, so a Single upload of a file whose i5 column
    is called ``Index 2`` dropped the i5 and said nothing -- the refusal the
    ``index2`` spelling gets. The sample paste has refused such a column by
    name since ``32ae40e``; the kit parser now does too."""

    # "Index 2", "I5" and "index_2" are the i5 column spelled differently and
    # are read as it (see TestAColumnIsReadHoweverItIsSpelled), so in a Single
    # upload they are refused as i5 data -- never ignored. These are the names
    # the format cannot place at all.
    @pytest.mark.parametrize("column", ["Lane", "Barcode", "I7_Index_ID", "Index_Plate"])
    def test_a_column_that_looks_like_an_index_or_a_lane_is_refused(self, column):
        content = f"name,index,{column}\nA1,ATTACTCG,TATAGCCT\n"

        with pytest.raises(KitFileRefused) as refused:
            IndexParser.parse_from_content(content, "k.csv", index_mode=IndexMode.SINGLE)

        assert column in str(refused.value), str(refused.value)

    @pytest.mark.parametrize("column", ["Index 2", "I5", "index_2"])
    def test_an_i5_column_spelled_differently_is_read_not_ignored(self, column):
        content = f"name,index,{column}\nA1,ATTACTCG,TATAGCCT\n"

        kit = IndexParser.parse_from_content(content, "k.csv",
                                             index_mode=IndexMode.UNIQUE_DUAL)

        assert [(p.index1.sequence, p.index2.sequence) for p in kit.index_pairs] == [
            ("ATTACTCG", "TATAGCCT")]

    @pytest.mark.parametrize("column", ["plate", "Description", "Owner"])
    def test_a_column_that_looks_like_neither_is_still_ignored(self, column):
        content = f"name,index,{column}\nA1,ATTACTCG,anything\n"

        kit = IndexParser.parse_from_content(content, "k.csv", index_mode=IndexMode.SINGLE)

        assert [i.name for i in kit.i7_indexes] == ["A1"]

    def test_a_column_in_a_combinatorial_section_is_refused(self):
        content = "[i7]\nname,sequence,Index 2\nA1,ATTACTCG,TATAGCCT\n"

        with pytest.raises(KitFileRefused) as refused:
            IndexParser.parse_from_content(content, "k.csv",
                                           index_mode=IndexMode.COMBINATORIAL)

        assert "Index 2" in str(refused.value), str(refused.value)

    def test_a_row_with_more_cells_than_the_header_is_refused_by_line(self):
        content = "name,index\nA1,ATTACTCG\nA2,TCCGGAGA,TATAGCCT\n"

        with pytest.raises(KitFileRefused) as refused:
            IndexParser.parse_from_content(content, "k.csv", index_mode=IndexMode.SINGLE)

        assert "line 3" in str(refused.value), str(refused.value)

    def test_a_row_with_more_empty_cells_than_the_header_is_not_a_row(self):
        content = "name,index\nA1,ATTACTCG\n,,\nA2,TCCGGAGA\n"

        kit = IndexParser.parse_from_content(content, "k.csv", index_mode=IndexMode.SINGLE)

        assert [i.name for i in kit.i7_indexes] == ["A1", "A2"]


class TestALineOutsideASectionIsRefused:
    """``process_section`` kept the lines before the first ``[i7]`` and read
    them as part of it, so an ``[IndexKit]`` preamble became the i7 section's
    header and the refusal named a good index instead of the culprit."""

    def test_a_line_before_the_first_section_is_named(self):
        content = "stray,line\n[i7]\nname,sequence\nA1,ATTACTCG\n"

        with pytest.raises(KitFileRefused) as refused:
            IndexParser.parse_from_content(content, "k.csv",
                                           index_mode=IndexMode.COMBINATORIAL)

        assert "line 1" in str(refused.value), str(refused.value)

    def test_an_index_kit_preamble_names_the_preamble_not_the_header(self):
        content = ("[IndexKit]\nName,Old kit\n[i7]\nname,sequence\nA1,ATTACTCG\n"
                   "[i5]\nname,sequence\nB1,TATAGCCT\n")

        with pytest.raises(KitFileRefused) as refused:
            IndexParser.parse_from_content(content, "k.csv",
                                           index_mode=IndexMode.COMBINATORIAL)

        message = str(refused.value)
        assert "line 2" in message and "line 5" not in message, message


class TestTheTsvHeaderLineIsReadHoweverItIsSpelled:
    """Skipping only a third cell spelled exactly ``IndexNumber`` refused a
    file whose header says ``Index Number`` -- and called the admin's own
    header "not an index"."""

    @pytest.mark.parametrize("header", [
        "Name\tSequence\tIndexNumber",
        "Name\tSequence\tIndex Number",
        "name\tsequence\tindex_number",
        "Name\tSequence",
        "Index Name\tSeq\tNum",
    ])
    def test_a_header_with_no_sequence_in_it_is_the_header(self, header):
        content = (f"[IndexKit]\nName\tOld kit\n\n[Indices]\n{header}\n"
                   "A1\tATTACTCG\t1\n")

        kit = IndexParser.parse_from_content(content, "k.tsv", index_mode=IndexMode.SINGLE)

        assert [i.name for i in kit.i7_indexes] == ["A1"]

    def test_only_the_sections_first_line_can_be_its_header(self):
        # A line with no sequence in it later in the section is not a second
        # header: it is a line that carries something and is not an index.
        content = ("[IndexKit]\nName\tOld kit\n\n[Indices]\n"
                   "Name\tSequence\tIndexNumber\nA1\tATTACTCG\t1\nNotes\tsee below\n")

        with pytest.raises(IncompleteIndexRows) as refused:
            IndexParser.parse_from_content(content, "k.tsv", index_mode=IndexMode.SINGLE)

        assert "line 7" in str(refused.value), str(refused.value)

    def test_a_first_line_that_carries_a_sequence_is_not_a_header(self):
        content = "[IndexKit]\nName\tOld kit\n\n[Indices]\nA1\tATTACTCG\n"

        with pytest.raises(IncompleteIndexRows) as refused:
            IndexParser.parse_from_content(content, "k.tsv", index_mode=IndexMode.SINGLE)

        assert "line 5" in str(refused.value), str(refused.value)


class TestAColumnIsReadHoweverItIsSpelled:
    """``row.get("index")`` matched the header text exactly, so a file whose
    column is called ``INDEX`` or ``Index_2`` in the other letter case was
    read as having no such column -- ignored, and then refused as an unread
    index-looking column. The sample paste matches a header on
    ``col.lower().strip()``; the kit reader now does too, so the file is read
    rather than turned away."""

    @pytest.mark.parametrize("i7_column", ["index", "INDEX", "Index", " index ", "SEQUENCE"])
    @pytest.mark.parametrize("i5_column", ["index2", "INDEX2", "Index_2", "index_2", "i5"])
    def test_the_columns_are_read_in_any_case_or_spacing(self, i7_column, i5_column):
        content = f"name,{i7_column},{i5_column}\nA1,ATTACTCG,TATAGCCT\n"

        kit = IndexParser.parse_from_content(content, "k.csv",
                                             index_mode=IndexMode.UNIQUE_DUAL)

        assert [(p.index1.sequence, p.index2.sequence) for p in kit.index_pairs] == [
            ("ATTACTCG", "TATAGCCT")]

    def test_two_columns_for_one_slot_are_refused_naming_both(self):
        content = "name,index,INDEX\nA1,ATTACTCG,TCCGGAGA\n"

        with pytest.raises(KitFileRefused) as refused:
            IndexParser.parse_from_content(content, "k.csv", index_mode=IndexMode.SINGLE)

        message = str(refused.value)
        assert "index" in message and "INDEX" in message, message

    def test_a_byte_order_mark_does_not_hide_the_first_column(self):
        content = "﻿name,index\nA1,ATTACTCG\n"

        kit = IndexParser.parse_from_content(content, "k.csv", index_mode=IndexMode.SINGLE)

        assert [i.name for i in kit.i7_indexes] == ["A1"]


class TestASectionHeaderIsReadWithAStraySeparator:
    """A spreadsheet writes ``[i7]`` as ``[i7],`` or ``"[i7]"`` when the sheet
    has more than one column, and ``line.lower() == "[i7]"`` then read the
    header as a line of the section."""

    @pytest.mark.parametrize("marker", ["[i7]", "[i7],", '"[i7]"', "[i7] ,,"])
    def test_the_section_is_still_a_section(self, marker):
        content = (f"{marker}\nname,sequence\nA1,ATTACTCG\n"
                   f"{marker.replace('i7', 'i5')}\nname,sequence\nB1,TATAGCCT\n")

        kit = IndexParser.parse_from_content(content, "k.csv",
                                             index_mode=IndexMode.COMBINATORIAL)

        assert ([i.name for i in kit.i7_indexes], [i.name for i in kit.i5_indexes]) == (
            ["A1"], ["B1"])

    def test_a_section_row_with_a_cell_under_no_column_is_refused(self):
        content = "[i7]\nname,sequence\nA1,ATTACTCG,TATAGCCT\n"

        with pytest.raises(KitFileRefused) as refused:
            IndexParser.parse_from_content(content, "k.csv",
                                           index_mode=IndexMode.COMBINATORIAL)

        assert "line 3" in str(refused.value), str(refused.value)


class TestATsvLineInNoSectionOrAnUnreadSectionIsRefused:
    """``_parse_tsv`` had no branch for any section but [IndexKit] and
    [Indices], so a line before the first section, between the two, or under a
    section header spelled [Indexes] vanished while the file's other lines kept
    the kit valid -- indexes gone, nothing said."""

    def test_a_line_before_the_first_section_is_named(self):
        content = "Old kit\tnotes\n[IndexKit]\nName\tOld kit\n\n[Indices]\nA1\tATTACTCG\t1\n"

        with pytest.raises(KitFileRefused) as refused:
            IndexParser.parse_from_content(content, "k.tsv", index_mode=IndexMode.SINGLE)

        assert "line 1" in str(refused.value), str(refused.value)

    def test_a_misspelled_indices_section_is_named_with_its_lines(self):
        content = ("[IndexKit]\nName\tOld kit\n\n[Indexes]\n"
                   "Name\tSequence\tIndexNumber\nA1\tATTACTCG\t1\n\n[Indices]\n"
                   "Name\tSequence\tIndexNumber\nB1\tTCCGGAGA\t1\n")

        with pytest.raises(KitFileRefused) as refused:
            IndexParser.parse_from_content(content, "k.tsv", index_mode=IndexMode.SINGLE)

        message = str(refused.value)
        assert "Indexes" in message and "line 5" in message, message

    def test_a_file_with_only_the_two_sections_it_reads_is_read(self):
        kit = IndexParser.parse_from_content(_illumina_tsv(I7, I5), "k.tsv",
                                             index_mode=IndexMode.UNIQUE_DUAL)

        assert [p.name for p in kit.index_pairs] == list(I7)


class TestASyncFormatListTheModeDoesNotReadIsRefused:
    """The upload path refused a list a Single kit does not read but kept the
    pairs of a Combinatorial upload and the i7 list of a Unique Dual one, both
    of which the panel never shows. The sync refuses every such list; the
    upload now does the same."""

    @pytest.mark.parametrize("mode, extra, unread", [
        (IndexMode.COMBINATORIAL, "index_pairs:\n  - name: P1\n    index1:\n"
                                  "      name: A1\n      sequence: ATTACTCG\n", "index_pairs"),
        (IndexMode.UNIQUE_DUAL, "i7_indexes:\n  - name: Z9\n    sequence: CGCTCATT\n",
         "i7_indexes"),
    ])
    def test_the_unread_list_is_named(self, mode, extra, unread):
        base = ("name: Old kit\ni7_indexes:\n  - name: A1\n    sequence: ATTACTCG\n"
                "i5_indexes:\n  - name: B1\n    sequence: TATAGCCT\n"
                if mode == IndexMode.COMBINATORIAL else
                "name: Old kit\nindex_pairs:\n  - name: P1\n    index1:\n"
                "      name: A1\n      sequence: ATTACTCG\n    index2:\n"
                "      name: A1\n      sequence: TATAGCCT\n")

        with pytest.raises(KitFileRefused) as refused:
            IndexParser.parse_from_content(base + extra, "sync.yaml", index_mode=mode)

        assert unread in str(refused.value), str(refused.value)

    @pytest.mark.parametrize("mode, content", [
        (IndexMode.COMBINATORIAL, "name: K\ni7_indexes:\n  - name: A1\n    sequence: ATTACTCG\n"
                                  "i5_indexes:\n  - name: B1\n    sequence: TATAGCCT\n"),
        (IndexMode.UNIQUE_DUAL, "name: K\nindex_pairs:\n  - name: P1\n    index1:\n"
                                "      name: A1\n      sequence: ATTACTCG\n    index2:\n"
                                "      name: A1\n      sequence: TATAGCCT\n"),
        (IndexMode.SINGLE, "name: K\ni7_indexes:\n  - name: A1\n    sequence: ATTACTCG\n"),
    ])
    def test_a_file_whose_lists_match_its_mode_is_read(self, mode, content):
        kit = IndexParser.parse_from_content(content, "sync.yaml", index_mode=mode)

        assert _sequences(kit) >= {"ATTACTCG"}
