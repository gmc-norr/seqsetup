"""Authentication routes for login/logout."""

from fasthtml.common import *
from starlette.responses import RedirectResponse

from ..components.login import LoginPage
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
        try:
            user = auth_service.authenticate(username, password)

            _login_user(sess, user)

            # Redirect to main application
            return RedirectResponse("/", status_code=303)

        except AuthenticationError as e:
            return LoginPage(error_message=str(e))

    @rt("/logout")
    def logout(sess):
        """Log out user and redirect to login."""
        sess.clear()
        return RedirectResponse("/login", status_code=303)
