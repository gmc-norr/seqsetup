"""safe_load_unique_keys refuses a key given twice in one mapping, which
PyYAML would keep the last of without a word (utils/yaml_safety.py)."""

import pytest

from seqsetup.utils.yaml_safety import DuplicateKeyError, UnsafeYAMLError, safe_load_unique_keys


class TestSafeLoadUniqueKeys:

    def test_a_key_given_twice_is_refused_with_its_line(self):
        with pytest.raises(DuplicateKeyError) as refused:
            safe_load_unique_keys("a: 1\nb: 2\na: 3\n")

        assert (refused.value.key, refused.value.line) == ("a", 3)

    @pytest.mark.parametrize("text", [
        "top:\n  inner:\n    a: 1\n    a: 2\n",
        "- a: 1\n  a: 2\n",
        "{a: 1, a: 2}\n",
        "a: 1\n'a': 2\n",
        "x: {<<: {a: 1, a: 2}}\n",
        "x: {<<: [{a: 1}, {a: 2}]}\n",
        "x: {<<: {a: 1}, a: 2}\n",
    ])
    def test_everywhere(self, text):
        with pytest.raises(DuplicateKeyError):
            safe_load_unique_keys(text)

    def test_the_same_key_in_two_mappings_is_fine(self):
        assert safe_load_unique_keys("x:\n  a: 1\ny:\n  a: 2\n") == {"x": {"a": 1}, "y": {"a": 2}}

    def test_anchors_are_still_refused(self):
        with pytest.raises(UnsafeYAMLError):
            safe_load_unique_keys("a: &x 1\nb: *x\n")
