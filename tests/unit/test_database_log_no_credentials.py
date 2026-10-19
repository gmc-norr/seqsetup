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

    @pytest.mark.parametrize("password, as_sent", [
        # A space in the credentials made the whole scrub give up: the
        # userinfo pattern refused \s, so nothing was parsed out of the URI
        # and the generic pass could not match that URI either. parse_uri
        # accepts such a URI, so it is a deployable setting
        # (review of 5aef69b, P2-2).
        ("pa ss word", "pa ss word"),
        ("pa%20ss", "pa ss"),
        # A URI "+" is sent to the server as a space, so the form the server
        # saw is a third one (review of 5aef69b, P2-3). The project's own
        # deployment notes call out this hazard twice.
        ("pa+ss", "pa ss"),
        ("s3cret%41word", "s3cretAword"),
    ])
    def test_every_form_of_an_awkward_password_goes(self, monkeypatch, caplog,
                                                    password, as_sent):
        monkeypatch.setattr(database, "_client", None)
        monkeypatch.setattr(database, "_db", None)
        monkeypatch.setenv("MONGODB_URI", f"mongodb://{USER}:{password}@mongodb:27017/s")
        monkeypatch.setattr(database, "MongoClient", _Raises(
            ConnectionFailure(f"refused: tried {password} then {as_sent}")))
        with caplog.at_level(logging.DEBUG, logger=database.logger.name):
            with pytest.raises(ConnectionFailure):
                database.init_db()

        assert password not in caplog.text, caplog.text
        assert as_sent not in caplog.text, caplog.text

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
        """``_load_config`` reads the file's text now, and PyYAML's own
        message for text input DOES quote the line -- so what was a guard is
        a live leak if anything repeats it. The input rules build every
        message themselves and scrub the file's own text out of it
        (``input_rules/check.py``, a sensitive input), which is what
        ``_yaml_refusal`` used to promise (break row B10)."""
        from seqsetup.input_rules.database import check_database_file

        with pytest.raises(yaml.YAMLError) as broken:
            yaml.safe_load(self.BROKEN)
        assert PASSWORD in str(broken.value), "the premise"

        result = check_database_file(self.BROKEN, "config/mongodb.yaml")

        said = " ".join(f"{p.line} {p.path} {p.message}" for p in result.problems)
        assert not result.ok, said
        assert PASSWORD not in said and USER not in said, said
        assert [p.line for p in result.problems] == [2], said

    def test_the_refusal_names_the_file_and_the_place_only(self, monkeypatch, tmp_path):
        path = self._config(monkeypatch, tmp_path, self.BROKEN)

        with pytest.raises(ValueError) as refused:
            database._load_config()

        message = str(refused.value)
        assert PASSWORD not in message and USER not in message, message
        # file:line:column:, as every other settings file is named since
        # step 2 of the input rules.
        assert str(path) in message and f"{path}:2:" in message, message

    def test_an_empty_config_file_still_stops_start_up(self, monkeypatch, tmp_path):
        """An empty file is a broken one: it must not quietly turn into the
        localhost default, which is what a file that does not exist means.
        It stopped start-up with an ``AttributeError`` and no words; it now
        says which file is empty."""
        path = self._config(monkeypatch, tmp_path, "")

        with pytest.raises(ValueError) as refused:
            database._load_config()

        assert str(path) in str(refused.value) and "is empty" in str(refused.value)

    def test_a_file_that_cannot_be_read_says_so(self, monkeypatch, tmp_path):
        import os

        path = self._config(monkeypatch, tmp_path, f'mongodb:\n  uri: "{URI}"\n')
        if os.geteuid() == 0:
            pytest.skip("root reads a file whatever its mode")
        path.chmod(0o000)
        try:
            with pytest.raises(ValueError) as refused:
                database._load_config()
        finally:
            path.chmod(0o600)

        assert "cannot be read" in str(refused.value)
        assert PASSWORD not in str(refused.value)

    @pytest.mark.parametrize("make", ["dangling link", "a folder"])
    def test_a_file_that_is_there_but_cannot_be_opened_stops_start_up(
            self, monkeypatch, tmp_path, make):
        """``Path.exists()`` says no for a dangling link, a link loop and an
        unreadable parent as well as for a file that is not there, so a
        mongodb.yaml the operator DID configure -- a secret mount is a link --
        quietly became mongodb://localhost:27017, with no line in the log
        (fresh review of 6164dd9, P1-1)."""
        monkeypatch.delenv("MONGODB_URI", raising=False)
        path = tmp_path / "mongodb.yaml"
        if make == "dangling link":
            path.symlink_to(tmp_path / "gone.yaml")
        else:
            path.mkdir()
        monkeypatch.setattr(database, "CONFIG_PATH", path)

        with pytest.raises(ValueError) as refused:
            database._load_config()

        assert "cannot be read" in str(refused.value), str(refused.value)
        assert str(path) in str(refused.value)

    def test_the_source_of_the_settings_is_logged(self, monkeypatch, tmp_path, caplog):
        """"falls back to localhost without a word" stops being true: one
        line names where the settings came from, with no value in it."""
        path = self._config(monkeypatch, tmp_path,
                            f'mongodb:\n  uri: "{URI}"\n  database: seqsetup\n')

        with caplog.at_level(logging.INFO, logger=database.logger.name):
            database._load_config()

        assert str(path) in caplog.text
        assert PASSWORD not in caplog.text and USER not in caplog.text

    def test_the_local_default_says_it_is_the_local_default(
            self, monkeypatch, tmp_path, caplog):
        monkeypatch.delenv("MONGODB_URI", raising=False)
        monkeypatch.setattr(database, "CONFIG_PATH", tmp_path / "not-there.yaml")

        with caplog.at_level(logging.INFO, logger=database.logger.name):
            config = database._load_config()

        assert config["uri"] == "mongodb://localhost:27017"
        assert "no database settings file" in caplog.text, caplog.text

    def test_a_file_that_is_not_utf_8_says_so_and_names_no_byte_of_it(
            self, monkeypatch, tmp_path):
        """The decode error names a byte of the file and its offset, and for
        a latin-1 password that byte is part of the password."""
        monkeypatch.delenv("MONGODB_URI", raising=False)
        path = tmp_path / "mongodb.yaml"
        path.write_bytes(f'mongodb:\n  uri: "mongodb://u:p\xe4ss@db"\n'.encode("latin-1"))
        monkeypatch.setattr(database, "CONFIG_PATH", path)

        with pytest.raises(ValueError) as refused:
            database._load_config()

        message = str(refused.value)
        assert "is not UTF-8 text" in message
        assert "0xe4" not in message and "position" not in message, message

    def test_a_readable_config_file_still_reads(self, monkeypatch, tmp_path):
        self._config(monkeypatch, tmp_path,
                     f'mongodb:\n  uri: "{URI}"\n  database: seqsetup\n')

        assert database._load_config() == {"uri": URI, "database": "seqsetup"}
