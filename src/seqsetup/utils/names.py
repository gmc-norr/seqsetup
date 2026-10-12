"""The rule for a stored name that a URL path segment has to carry.

A name made only of dots can be created but never removed: ``.`` and ``..``
are dot segments, so the browser rewrites the URL the app would need
(``/admin/users/..`` becomes ``/admin/``, ``/indexes/kits/../1.0`` becomes
``/indexes/1.0``) and a percent-encoded one is refused with 400 by the
dot-segment guard in ``middleware.py`` before the route runs. ``...`` is not
itself a dot segment, but one rule an operator can state beats three special
cases, and no real name is only dots.

The models enforce it, on construction and on later assignment, so no
ingest path has to remember to.
"""

import re

# ``\Z``, not ``$``: in Python ``$`` also matches just before a trailing
# newline, so "..\n" would pass (project convention).
_DOT_ONLY_RE = re.compile(r"\.+\Z")


def is_dot_only(value) -> bool:
    """True when ``value`` is a string of nothing but dots, of any length."""
    return isinstance(value, str) and bool(_DOT_ONLY_RE.match(value))
