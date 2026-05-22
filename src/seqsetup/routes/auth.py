"""Authentication routes for login/logout."""

from fasthtml.common import *
from starlette.responses import RedirectResponse

from ..components.login import LoginPage
from ..services.audit_log import audit
from ..services.auth import AuthenticationError


def _login_user(sess, user) -> None:
    """Apply the authenticated user to the session.

    Clears any prior session contents first to defeat session fixation: an
    attacker who plants a known session ID on a shared workstation must not
    retain that session after a legitimate user logs in.
    """
    sess.clear()
    sess["user"] = user.to_dict()


def register(app, rt, auth_service):
    """Register authentication routes."""

    @rt("/login")
    def login_page(req, sess):
        """Display login page."""
        # If already logged in, redirect to main
        if sess.get("user"):
            return RedirectResponse("/", status_code=303)
        return LoginPage()

    @rt("/login/submit")
    def post(req, sess, username: str, password: str):
        """Process login form submission."""
        # Truncate username for audit logging — protect against multi-MB
        # values landing in the audit stream from an automated probe.
        actor = (username or "")[:128]
        try:
            user = auth_service.authenticate(username, password)
            _login_user(sess, user)
            audit("login.success", actor=actor)
            return RedirectResponse("/", status_code=303)
        except AuthenticationError as e:
            # Log the reason category but not the raw error text — it can
            # echo back the supplied username and would inflate the log.
            audit("login.failure", actor=actor, outcome="failure")
            return LoginPage(error_message=str(e))

    @rt("/logout")
    def logout(sess):
        """Log out user and redirect to login."""
        # Best-effort capture of who is logging out; sess may already be empty.
        user_data = sess.get("user") or {}
        actor = (user_data.get("username") or "")[:128]
        sess.clear()
        audit("logout", actor=actor)
        return RedirectResponse("/login", status_code=303)
