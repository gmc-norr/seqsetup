"""Test versions (spec 2026-10-07 group A4): the rule for a test profile's
Version."""

import re

# A test profile's Version: three whole numbers joined by dots, each 0 or
# without a leading zero and at most 9 digits, so it always turns into numbers.
PROFILE_VERSION_RE = re.compile(r"(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z")
PROFILE_VERSION_RULE = (
    "must be three whole numbers joined by dots, each at most 9 digits, like 1.0.0"
)
