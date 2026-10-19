"""The rulebook for the database settings file, ``config/mongodb.yaml``
(docs/design/2026-10-18-input-rules-design.md, "Step 4: the database settings
file").

It is the one **sensitive** input: the file holds the connection string,
password and all, so no value of it and no name of a key the rulebook does not
define may reach a message, a log line, a status or an audit row. A misspelt
``mongodb:`` key meant ``mongodb://localhost:27017`` -- a different server --
without a word.

This module imports nothing of ``services/database.py``, which pulls in
pymongo: the settings command must run with no database and no app.
"""

from typing import Annotated

from pydantic import AfterValidator, StringConstraints

from ..services.sheet_text import describe, hidden_characters
from .base import StrictRules
from .check import CheckResult, check_data, check_yaml
from .reader import Locations

# The longest connection string the file may hold. Nothing in SeqSetup bounds
# it; 4,096 is the cap the app gives a description.
MOST_URI_CHARACTERS = 4096
# MongoDB's own limit on a database name, in BYTES: "é" * 63 is 63 characters
# and 126 bytes, and both a character bound and pymongo let it through
# (measured 2026-10-19).
MOST_DATABASE_BYTES = 63
# The characters pymongo refuses in a database name with InvalidName
# (measured on pymongo 4.18.2). The name reached ``_client[name]``, which is
# outside ``init_db``'s try, so it was an unhandled error with no log line.
DATABASE_CHARACTERS_REFUSED = ' ./\\"$\x00'
# pymongo reads a value with no scheme as a HOST list, so a hand edit to
# ``localhost:27017`` connected to another server with no authentication
# (measured with connect=False). dnspython, which "+srv" needs, is in the
# default pixi environment, not only dev.
URI_SCHEMES = ("mongodb://", "mongodb+srv://")


def _no_hidden(value: str) -> str:
    """No line break, tab or invisible character: such a value reaches every
    log line, the Admin > Logs page and every audit row. The message names
    the character's code point, never the value."""
    chars = hidden_characters(value)
    if chars:
        raise ValueError(f"holds a hidden character: {describe(chars)}")
    return value


def _a_connection_string(value: str) -> str:
    _no_hidden(value)
    if not value.lower().startswith(URI_SCHEMES):
        raise ValueError(
            "is not a connection string: it must begin mongodb:// or mongodb+srv://. "
            "Without a scheme the driver reads the value as a host name and connects "
            "to it with no authentication."
        )
    return value


def _a_database_name(value: str) -> str:
    _no_hidden(value)
    wrong = sorted(set(value) & set(DATABASE_CHARACTERS_REFUSED))
    if wrong:
        raise ValueError(
            "may not hold " + ", ".join(repr(c) for c in wrong)
            + ": MongoDB refuses a database name with any of "
            + ", ".join(repr(c) for c in DATABASE_CHARACTERS_REFUSED)
        )
    if len(value.encode("utf-8")) > MOST_DATABASE_BYTES:
        raise ValueError(f"must be at most {MOST_DATABASE_BYTES} bytes long "
                         "(MongoDB's own limit, counted in bytes, not characters)")
    return value


DatabaseUri = Annotated[str, StringConstraints(min_length=1, max_length=MOST_URI_CHARACTERS),
                        AfterValidator(_a_connection_string)]
# No max_length: the bound is on the UTF-8 byte length, so the message says
# bytes rather than characters.
DatabaseName = Annotated[str, StringConstraints(min_length=1),
                         AfterValidator(_a_database_name)]


class MongodbSettingsRules(StrictRules):
    """The two settings SeqSetup reads. Both are written out: falling back to
    another server is the one thing this step exists to stop."""

    uri: DatabaseUri
    database: DatabaseName


class DatabaseFileRules(StrictRules):
    """``config/mongodb.yaml``. ``mongodb`` is its only key; the file has held
    exactly these two settings since the initial commit, so no older spelling
    needs its own message."""

    mongodb: MongodbSettingsRules


def check_database_file(text: str, file: str) -> CheckResult:
    """Check one database settings file. Sensitive: no value is quoted, and a
    key the rulebook does not define is shown only as "an unknown key"."""
    return check_yaml(text, file, DatabaseFileRules, sensitive=True)


class _UriOnly(StrictRules):
    uri: DatabaseUri


class _DatabaseOnly(StrictRules):
    database: DatabaseName


# The environment variables, and the one-setting rulebook each one is checked
# by.
SETTINGS = {"MONGODB_URI": (_UriOnly, "uri"),
            "MONGODB_DATABASE": (_DatabaseOnly, "database")}


def check_setting(variable: str, value: str) -> list[str]:
    """One sentence per problem with an environment variable's value, naming
    the variable where a file's problem would name a line.

    ``docker-compose.yml`` sets both variables, so a lab takes that path and
    never reads the file; a ``MONGODB_DATABASE`` holding a '.' was an
    unhandled ``InvalidName`` from outside ``init_db``'s try. What the
    variables *mean* is unchanged: they win over the file, as before.
    """
    rulebook, key = SETTINGS[variable]
    result = check_data({key: value}, Locations(), variable, rulebook, sensitive=True)
    return [f"{variable}: {problem.message}"
            for problem in result.problems if problem.level == "error"]
