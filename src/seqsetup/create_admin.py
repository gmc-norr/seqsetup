"""``pixi run create-admin``: make a local admin from the server
(spec 2026-09-28 group 2b, N-20).

The same password rules as Admin → Users. It never changes an existing
account, and never prints or logs the password. Every read happens before
the one write, so "Nothing was changed" is only said when it is known
(plan review 1, P3).
"""

import getpass
import re
import sys

from .models.local_user import USERNAME_PATTERN, LocalUser, WeakPasswordError
from .models.user import UserRole

_NOT_YET = ("Directory sign-in is on and local fallback is off, so this admin cannot sign "
            "in yet. Run 'pixi run use-local-sign-in' first, or turn on local fallback.")


def main(ask=input, ask_secret=getpass.getpass, get_db=None, say=print) -> int:
    """Ask for the account, save it as an admin, and return the exit code."""
    from pymongo.errors import PyMongoError

    from .repositories.audit_event_repo import AuditEventRepository
    from .repositories.auth_config_repo import AuthConfigRepository
    from .repositories.local_user_repo import LocalUserRepository
    from .services.audit_log import audit, set_audit_sink
    from .services.database import init_db

    try:
        db = (get_db or init_db)()
    except Exception:
        say("Could not reach the database. Nothing was changed.")
        return 1
    users = LocalUserRepository(db)

    username = ask("Username: ").strip()
    if not re.match(USERNAME_PATTERN, username):
        say("A username is 1-64 letters, digits, '.', '_', '@' or '-'. Nothing was changed.")
        return 1
    try:
        taken = users.exists(username)
        config = AuthConfigRepository(db).get()
    except PyMongoError as e:
        say(f"The database failed while reading ({type(e).__name__}). Nothing was changed.")
        return 1
    if taken:
        say(f"An account named '{username}' already exists. Nothing was changed.")
        return 1
    display_name = ask("Display name: ").strip()[:256]
    if not display_name:
        say("A display name is required. Nothing was changed.")
        return 1
    email = ask("Email (optional): ").strip()[:256]
    password = ask_secret("Password: ")
    if password != ask_secret("Password again: "):
        say("The two passwords differ. Nothing was changed.")
        return 1

    admin = LocalUser(username=username, display_name=display_name, email=email,
                      role=UserRole.ADMIN)
    try:
        admin.set_password(password)
    except WeakPasswordError as e:
        say(f"{e} Nothing was changed.")
        return 1
    try:
        created = users.create(admin)
    except PyMongoError as e:
        # The database may have saved the account before the answer was lost.
        say(f"The database failed while saving ({type(e).__name__}), so it is not known "
            f"whether '{username}' was created. Run 'pixi run create-admin' again with the "
            "same name: if it says the account already exists, it was created.")
        return 1
    if not created:
        say(f"An account named '{username}' already exists. Nothing was changed.")
        return 1

    set_audit_sink(AuditEventRepository(db))
    audit("user.created", actor="create-admin", target=username, role="admin",
          via="server command")
    say(f"Admin '{username}' created. Sign in on the web page.")
    if config.is_ldap_enabled and not config.allow_local_fallback:
        say(_NOT_YET)
    return 0


if __name__ == "__main__":
    sys.exit(main())
