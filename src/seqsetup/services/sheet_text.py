"""What text may be written into a Sample Sheet.

One source for the rules that the config sync, Mark Ready and both Sample
Sheet writers apply.
"""

import re
import unicodedata

# A name written into the sheet's structure — a section header such as
# ``[BCLConvert_Settings]`` or the ``InstrumentPlatform`` line — as is.
# Same alphabet as a Sample ID.
PLAIN_NAME_RE = re.compile(r"[A-Za-z0-9_-]+")

# A software version written as is, e.g. ``4.3.6``.
PLAIN_VERSION_RE = re.compile(r"[A-Za-z0-9._-]+")

_SEPARATORS = frozenset("\u2028\u2029")
_NAMES = {"\t": "tab"}


def hidden_characters(text: str | None) -> list[str]:
    """The distinct hidden characters in ``text``, in order of first
    appearance: control characters (Unicode category Cc), format characters
    (Cf: the zero-width space, byte-order mark, soft hyphen, and the
    direction marks and overrides, which can change the order a name is
    shown in) and the Unicode line and paragraph separators."""
    return [
        c for c in dict.fromkeys(text or "")
        if unicodedata.category(c) in ("Cc", "Cf") or c in _SEPARATORS
    ]


def refuse_hidden_characters(value: str, allow: str = "") -> None:
    """Raise ``ValueError`` if ``value`` holds a hidden character that is not
    in ``allow``. The message names the character codes only — the text can
    be patient data, and the error is logged."""
    bad = [c for c in hidden_characters(value) if c not in allow]
    if bad:
        raise ValueError(
            f"Hidden character ({describe(bad)}) cannot be written to the Sample Sheet"
        )


def starts_a_section(text: str) -> bool:
    """True if ``text`` begins with ``[`` (after any spaces). Written first on
    a line, it would start a new section of the Sample Sheet."""
    return text.lstrip().startswith("[")


def describe(chars: list[str]) -> str:
    """Character codes for a message: ``'U+0000, U+0009 (tab)'``."""
    parts = []
    for c in chars:
        code = f"U+{ord(c):04X}"
        parts.append(f"{code} ({_NAMES[c]})" if c in _NAMES else code)
    return ", ".join(parts)
