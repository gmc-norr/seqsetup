"""A failed database connection never logs the connection string.

``init_db`` logged ``%s`` of whatever it caught. pymongo itself is careful --
probed across ``InvalidURI``, ``ConfigurationError``,
``ServerSelectionTimeoutError`` and ``OperationFailure``, none of its own
messages echoes the URI or the password (evidence in the run's DECISIONS) --
but two things can still put credentials in front of that ``%s``:

* the **server's** own ``errmsg``. MongoDB's AuthenticationFailed has read
  "Authentication failed on database 'admin' with user '<user>'", so the
  name SeqSetup connects as reached the log.
* any **other** exception from the driver stack or a wrapper, which may
  carry the connection string it was given.

And a malformed ``config/mongodb.yaml`` makes PyYAML quote the line it
stumbled on -- which is the line holding the URI, password included -- and
``_load_config`` let that out of ``init_db`` entirely.

So: log the exception's type and a message with credentials taken out, and
never the raw text.
"""

import logging

import pytest
import yaml
from pymongo.errors import ConnectionFailure, OperationFailure

from seqsetup.services import database

USER = "seqsetup_app"
PASSWORD = "sUp3r-s3cr3t-pw"
URI = f"mongodb://{USER}:{PASSWORD}@mongodb:27017/seqsetup?authSource=seqsetup"


class _Raises:
    """A MongoClient whose ping raises ``error``."""

    def __init__(self, error):
        self.error = error

    def __call__(self, *args, **kwargs):
        return self

    @property
    def admin(self):
        return self

    def command(self, _name):
        raise self.error


@pytest.fixture
def connecting(monkeypatch):
    monkeypatch.setattr(database, "_client", None)
    monkeypatch.setattr(database, "_db", None)
    monkeypatch.setenv("MONGODB_URI", URI)

    def connect(error, caplog) -> str:
        monkeypatch.setattr(database, "MongoClient", _Raises(error))
        with caplog.at_level(logging.DEBUG, logger=database.logger.name):
            with pytest.raises(type(error)):
                database.init_db()
        return caplog.text

    return connect


ERRORS = {
    "the server names the user": OperationFailure(
        f"Authentication failed on database 'admin' with user '{USER}'", 18,
        {"ok": 0.0, "code": 18, "codeName": "AuthenticationFailed"}),
    "another refusal names the user": OperationFailure(
        f"not authorized: user '{USER}' on seqsetup", 13, {"ok": 0.0, "code": 13}),
    "something echoes the whole uri": RuntimeError(f"could not connect using {URI}"),
    "a connection failure echoes the uri": ConnectionFailure(f"no server for {URI}"),
    "an error echoes only the credentials": RuntimeError(
        f"handshake failed for {USER}:{PASSWORD}@mongodb:27017"),
    # Not the configured URI at all -- a replica-set member, a redirect, a
    # wrapper repeating a string from elsewhere. Scrubbing by the configured
    # user and password alone would leave this one whole.
    "an error echoes another connection string": RuntimeError(
        "no server for mongodb://other_user:0th3r-s3cr3t@member2:27017/x"),
}

OTHER_PASSWORD = "0th3r-s3cr3t"


class TestTheLogNeverHoldsTheCredentials:

    @pytest.mark.parametrize("label", list(ERRORS))
    def test_the_password_is_not_in_the_log(self, connecting, caplog, label):
        log = connecting(ERRORS[label], caplog)

        assert PASSWORD not in log, log

    @pytest.mark.parametrize("label", list(ERRORS))
    def test_the_user_name_is_not_in_the_log(self, connecting, caplog, label):
        log = connecting(ERRORS[label], caplog)

        assert USER not in log, log

    @pytest.mark.parametrize("label", list(ERRORS))
    def test_the_log_still_says_what_went_wrong(self, connecting, caplog, label):
        """Scrubbing must not leave the operator with nothing: the exception's
        own type is always named."""
        log = connecting(ERRORS[label], caplog)

        assert type(ERRORS[label]).__name__ in log, log

    def test_a_refused_password_still_says_where_to_look(self, connecting, caplog):
        log = connecting(ERRORS["the server names the user"], caplog)

        assert "MONGO_APP_PASSWORD" in log
        assert "openssl rand -hex 24" in log

    def test_another_connection_strings_credentials_go_too(self, connecting, caplog):
        """Scrubbing by the configured user and password alone would leave a
        URI from somewhere else whole (break row B5)."""
        log = connecting(ERRORS["an error echoes another connection string"], caplog)

        assert OTHER_PASSWORD not in log, log
        assert "other_user" not in log, log
        assert "member2:27017" in log, log

    def test_a_percent_escaped_password_goes_in_either_form(self, monkeypatch, caplog):
        """A URI escapes a password; a server or a wrapper may echo it
        unescaped. Both forms are scrubbed (break row B11)."""
        escaped, plain = "s3cret%41word", "s3cretAword"
        monkeypatch.setattr(database, "_client", None)
        monkeypatch.setattr(database, "_db", None)
        monkeypatch.setenv("MONGODB_URI", f"mongodb://{USER}:{escaped}@mongodb:27017/s")
        monkeypatch.setattr(database, "MongoClient",
                            _Raises(ConnectionFailure(f"refused for {plain} and {escaped}")))
        with caplog.at_level(logging.DEBUG, logger=database.logger.name):
            with pytest.raises(ConnectionFailure):
                database.init_db()

        assert escaped not in caplog.text and plain not in caplog.text, caplog.text

    def test_what_is_left_of_a_message_is_still_useful(self, connecting, caplog):
        log = connecting(ConnectionFailure("connection refused by mongodb:27017"), caplog)

        assert "connection refused" in log and "mongodb:27017" in log


class TestAMalformedConfigFileKeepsItsSecret:
    """PyYAML quotes the line it stumbled on. When that is the URI line, the
    password is in the exception's message -- and ``_load_config`` ran outside
    ``init_db``'s try, so it left the app with nothing but a traceback."""

    BROKEN = f'mongodb:\n  uri: mongodb://{USER}:{PASSWORD}@db:27017\t[\n'

    def _config(self, monkeypatch, tmp_path, text):
        monkeypatch.delenv("MONGODB_URI", raising=False)
        path = tmp_path / "mongodb.yaml"
        path.write_text(text)
        monkeypatch.setattr(database, "CONFIG_PATH", path)
        return path

    def test_pyyaml_does_quote_the_password(self):
        """The premise, so this test file fails if PyYAML stops doing it."""
        with pytest.raises(yaml.YAMLError) as broken:
            yaml.safe_load(self.BROKEN)

        assert PASSWORD in str(broken.value)

    def test_the_refusal_repeats_nothing_of_a_message_that_quotes_the_line(self):
        """``_load_config`` reads the file as a stream, and PyYAML then names
        the file and the place without quoting it -- so this is a guard, not a
        live leak. It is tested against the error that *does* carry the line
        (string input), so the rule holds whichever way the file is loaded
        (break row B10)."""
        with pytest.raises(yaml.YAMLError) as broken:
            yaml.safe_load(self.BROKEN)
        assert PASSWORD in str(broken.value), "the premise"

        refusal = str(database._yaml_refusal(broken.value))

        assert PASSWORD not in refusal and USER not in refusal, refusal
        assert "line 2" in refusal and "YAML" in refusal, refusal

    def test_the_refusal_names_the_file_and_the_place_only(self, monkeypatch, tmp_path):
        path = self._config(monkeypatch, tmp_path, self.BROKEN)

        with pytest.raises(ValueError) as refused:
            database._load_config()

        message = str(refused.value)
        assert PASSWORD not in message and USER not in message, message
        assert str(path) in message and "line 2" in message, message

    def test_a_readable_config_file_still_reads(self, monkeypatch, tmp_path):
        self._config(monkeypatch, tmp_path,
                     f'mongodb:\n  uri: "{URI}"\n  database: seqsetup\n')

        assert database._load_config() == {"uri": URI, "database": "seqsetup"}
