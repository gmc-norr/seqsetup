"""The database settings file (docs/design/2026-10-18-input-rules-design.md,
"Step 4: the database settings file").

``config/mongodb.yaml`` holds the connection string, password and all, so it
is the one **sensitive** input: no value of it, and no name of a key the
rulebook does not define, may reach any message. A misspelt key meant
``mongodb://localhost:27017`` -- a different server -- without a word.
"""

import pytest

from seqsetup.input_rules.database import (
    MOST_DATABASE_BYTES,
    DatabaseFileRules,
    check_database_file,
    check_setting,
)

SECRET = "sUp3r-s3cr3t-pw"
URI = f"mongodb://seqsetup_app:{SECRET}@mongodb:27017/seqsetup?authSource=seqsetup"
GOOD = f'mongodb:\n  uri: "{URI}"\n  database: "seqsetup"\n'


def problems(text, file="config/mongodb.yaml"):
    return [(p.line, tuple(p.path), p.message) for p in check_database_file(text, file).problems]


def checked(text):
    result = check_database_file(text, "config/mongodb.yaml")
    assert result.ok, result.problems
    return result.value


class TestAFileThatWritesItsSettingsOut:

    def test_the_shipped_shape_is_accepted(self):
        value = checked(GOOD)

        assert (value.mongodb.uri, value.mongodb.database) == (URI, "seqsetup")

    def test_an_empty_file_is_refused_by_name(self):
        assert problems("") == [(1, (), "is empty")]

    @pytest.mark.parametrize("key", ["uri", "database"])
    def test_a_missing_setting_is_refused(self, key):
        text = "\n".join(line for line in GOOD.splitlines()
                         if not line.strip().startswith(key + ":"))

        (problem,) = problems(text + "\n")

        assert problem[1] == ("mongodb", key)
        assert problem[2] == "is required"

    def test_a_misspelt_top_key_is_refused_and_the_real_one_named(self):
        found = problems(GOOD.replace("mongodb:", "mongdb:"))

        assert (1, ("mongodb",), "is required") in found
        assert any(p[1] == ("an unknown key",) for p in found), found

    def test_a_misspelt_setting_is_refused(self):
        found = problems(GOOD.replace("  uri:", "  url:"))

        assert (2, ("mongodb", "uri"), "is required") in found
        assert any("an unknown key" in str(p[1]) for p in found), found


class TestAConnectionStringIsAConnectionString:
    """pymongo reads a value with no scheme as a HOST list, so a hand edit to
    ``localhost:27017`` connected to another server with no authentication."""

    @pytest.mark.parametrize("uri", [
        "mongodb://db:27017/x",
        "mongodb+srv://cluster.example.com/x",
        "MONGODB://db:27017/x",
    ])
    def test_a_real_scheme_is_accepted(self, uri):
        assert checked(f'mongodb:\n  uri: "{uri}"\n  database: db\n').mongodb.uri == uri

    @pytest.mark.parametrize("uri", ["localhost:27017", "mongodb.example.invalid",
                                     "see .env", "http://db:27017", "mongodb:/db"])
    def test_anything_else_is_refused(self, uri):
        (problem,) = problems(f'mongodb:\n  uri: "{uri}"\n  database: db\n')

        assert problem[1] == ("mongodb", "uri")
        assert "mongodb://" in problem[2]

    def test_a_uri_over_4096_characters_is_refused(self):
        long = "mongodb://" + "h" * 4096
        (problem,) = problems(f'mongodb:\n  uri: "{long}"\n  database: db\n')

        assert problem[1] == ("mongodb", "uri")
        assert problem[2] == "must be at most 4096 characters"

    def test_a_uri_with_a_hidden_character_is_refused(self):
        (problem,) = problems('mongodb:\n  uri: "mongodb://db​:27017"\n  database: db\n')

        assert problem[1] == ("mongodb", "uri")
        assert "hidden character" in problem[2]


class TestADatabaseNameMongodbCanHold:
    """pymongo refuses exactly these seven characters with InvalidName, and
    bounds the length not at all; MongoDB's own limit is 63 bytes. The name
    reached ``_client[name]``, which is outside init_db's try."""

    @pytest.mark.parametrize("bad", [" ", ".", "$", "/", "\\", '"'])
    def test_a_character_mongodb_refuses_is_refused_here(self, bad):
        (problem,) = problems(f"mongodb:\n  uri: '{URI}'\n  database: 'a{bad}b'\n")

        assert problem[1] == ("mongodb", "database")

    def test_a_nul_byte_is_refused_as_a_character_no_yaml_file_may_hold(self):
        found = problems(f"mongodb:\n  uri: '{URI}'\n  database: 'a\x00b'\n")

        assert any("control character" in p[2] for p in found), found

    def test_a_name_of_63_bytes_is_accepted(self):
        name = "a" * MOST_DATABASE_BYTES

        assert checked(f'mongodb:\n  uri: "{URI}"\n  database: "{name}"\n').mongodb.database == name

    def test_a_name_of_64_bytes_is_refused(self):
        name = "a" * (MOST_DATABASE_BYTES + 1)

        (problem,) = problems(f'mongodb:\n  uri: "{URI}"\n  database: "{name}"\n')

        assert problem[1] == ("mongodb", "database")
        assert "63 bytes" in problem[2]

    def test_a_name_of_63_characters_but_126_bytes_is_refused(self):
        """A character bound let it through, and so does pymongo; only the
        server refuses it."""
        name = "é" * 63

        (problem,) = problems(f'mongodb:\n  uri: "{URI}"\n  database: "{name}"\n')

        assert problem[1] == ("mongodb", "database")
        assert "63 bytes" in problem[2]

    @pytest.mark.parametrize("hidden", ["\t", "​", "\n"])
    def test_a_hidden_character_is_refused(self, hidden):
        (problem,) = problems(f'mongodb:\n  uri: "{URI}"\n  database: "a{hidden}b"\n')

        assert problem[1] == ("mongodb", "database")


class TestEachValueHasOneSpelling:

    @pytest.mark.parametrize("written", ["7", "true", "[a]", "{a: b}", "~"])
    def test_a_setting_of_another_kind_is_refused(self, written):
        (problem,) = problems(f'mongodb:\n  uri: {written}\n  database: db\n')

        assert problem[1] == ("mongodb", "uri")

    def test_a_key_given_twice_is_refused(self):
        found = problems(GOOD + "mongodb:\n  uri: x\n  database: y\n")

        assert any("given twice" in p[2] for p in found), found

    def test_the_whole_file_must_be_a_map(self):
        (problem,) = problems("- a\n- b\n")

        assert problem[1] == ()


class TestNoMessageQuotesAnything:
    """PyYAML's message quotes the line it stumbled on, and that line holds
    the password; a validator's own message can quote its input; and an
    unknown key's NAME can be a connection string."""

    def _all_text(self, result):
        return " ".join(f"{p.path} {p.message}" for p in result.problems)

    @pytest.mark.parametrize("text", [
        'mongodb:\n  uri: "{uri}"\n  database: "db/{secret}"\n',
        'mongodb:\n  uri: "{uri}"\n  database: "{secret}"\n  extra: 1\n',
        'mongodb:\n  uri: "{uri}"\n  database: db\n  "{uri}": 1\n',
        'mongodb:\n  uri: "{uri}"\n  database: db\n  nested:\n    deep: "{secret}"\n',
        'mongodb:\n  uri: "{uri}"\n  database: db\n\t[\n',
        'mongodb:\n  uri: "{uri}"\n  database: "{secret}{secret}{secret}{secret}{secret}"\n',
    ], ids=["value", "unknown key beside", "a uri AS a key", "nested", "not YAML", "long"])
    def test_the_password_is_in_no_message_and_no_path(self, text):
        result = check_database_file(
            text.format(uri=URI, secret=SECRET), "config/mongodb.yaml")

        said = self._all_text(result)
        assert not result.ok, said
        assert SECRET not in said, said
        assert "seqsetup_app" not in said, said

    def test_an_unknown_key_is_shown_as_one(self):
        found = problems(GOOD.replace("  database:", f'  "{URI}": 1\n  database:'))

        assert any(p[1] == ("mongodb", "an unknown key") for p in found), found

    def test_a_key_the_rulebook_defines_is_not_scrubbed_from_a_message(self):
        """The file's own strings are taken out of every message, but a name
        the rulebook defines is public: "must begin mongodb://" must not
        become "must begin ***://"."""
        (problem,) = problems(f'mongodb:\n  uri: "localhost:27017"\n  database: db\n')

        assert "mongodb://" in problem[2], problem

    def test_a_good_file_says_nothing_at_all(self):
        assert check_database_file(GOOD, "config/mongodb.yaml").problems == []


class TestTheEnvironmentSValuesFollowTheSameRules:
    """docker-compose.yml sets both variables, so the lab takes that path and
    never reads the file; a MONGODB_DATABASE holding a '.' was an unhandled
    InvalidName from outside init_db's try."""

    def test_a_good_pair_passes(self):
        assert check_setting("MONGODB_URI", URI) == []
        assert check_setting("MONGODB_DATABASE", "seqsetup") == []

    def test_a_uri_with_no_scheme_is_refused_naming_the_variable(self):
        (problem,) = check_setting("MONGODB_URI", "localhost:27017")

        assert problem.startswith("MONGODB_URI:")
        assert "mongodb://" in problem

    def test_a_database_with_a_dot_is_refused_naming_the_variable(self):
        (problem,) = check_setting("MONGODB_DATABASE", "seq.setup")

        assert problem.startswith("MONGODB_DATABASE:")

    def test_the_message_quotes_no_value(self):
        (problem,) = check_setting("MONGODB_URI", f"see-the-env-file-{SECRET}")

        assert SECRET not in problem

    def test_an_unknown_variable_name_is_a_mistake_in_the_code(self):
        with pytest.raises(KeyError):
            check_setting("MONGODB_WHATEVER", "x")


class TestTheRulebookIsTheOnlyDocument:

    def test_it_names_exactly_the_two_settings(self):
        assert set(DatabaseFileRules.model_fields) == {"mongodb"}
