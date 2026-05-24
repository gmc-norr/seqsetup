"""Shared Pydantic ``BeforeValidator`` builders for SeqSetup form models.

CLAUDE.md hard rules require:
  - Strings: strip + length-limit (CLAMP, not reject)
  - Numbers: clamp to valid range (CLAMP, not reject)
  - DNA sequences: uppercase + validate against ``^[ACGTN]*$`` (REJECT bad regex)

Pydantic's built-in constraints (``max_length``, ``ge``, ``le``,
``pattern``) all REJECT. These validators implement the reject-vs-clamp
semantics CLAUDE.md requires.

Per-form models pick which validator each field gets; switching a field
from clamp->reject is a deliberate semantic change documented in the
commit message that introduces it.
"""

import json
import re
from typing import Callable


_DNA_RE = re.compile(r"[ACGTN]*")


def strip_and_truncate(max_len: int) -> Callable[[object], str]:
    """Strip whitespace and truncate to ``max_len`` chars. NEVER rejects.

    Replaces the existing ``sanitize_string(value, max_len)`` helper.
    Same semantics: empty input -> empty string; oversized input ->
    truncated to ``max_len``.
    """
    def _v(value: object) -> str:
        if value is None:
            return ""
        return str(value).strip()[:max_len]
    return _v


def clamp(lo: int, hi: int) -> Callable[[object], int]:
    """Clamp an int to [lo, hi]. NEVER rejects valid-int input.

    Non-int or unparseable input raises ``ValueError`` (Pydantic surfaces
    it as a 422). Use ``BeforeValidator`` so this runs before Pydantic's
    int coercion.
    """
    def _v(value: object) -> int:
        try:
            n = int(value)
        except (TypeError, ValueError) as e:
            raise ValueError(f"expected integer, got {value!r}") from e
        return max(lo, min(hi, n))
    return _v


def dna_upper_or_reject(value: object) -> str:
    """Uppercase and validate as ``[ACGTN]*``. REJECTS invalid sequences.

    This is the only place in the form layer that rejects on bad
    content: a sample with non-ACGTN bases is clinically wrong and the
    user should see an error, not silently accept a sanitised version.
    """
    if value is None:
        return ""
    s = str(value).strip().upper()
    if not _DNA_RE.fullmatch(s):
        raise ValueError("DNA sequence must contain only A, C, G, T, N")
    return s


def json_list(item_type: type = str) -> Callable[[object], list]:
    """Decode a JSON-string form field into a list.

    Used by the Alpine multi-select pattern (Section 4 of the design
    spec) -- bulk-action HTMX forms send the selected IDs as
    ``JSON.stringify([...])`` inside ``hx-vals`` because form-encoding
    is text, not structured. Pydantic won't parse the JSON
    automatically.
    """
    def _v(value: object) -> list:
        if isinstance(value, list):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError as e:
                raise ValueError("expected a JSON array") from e
            if not isinstance(parsed, list):
                raise ValueError("expected a JSON array")
            return parsed
        raise ValueError("expected a JSON array or list")
    return _v
