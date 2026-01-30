"""Authentication routes for login/logout."""

from fasthtml.common import *
from starlette.responses import RedirectResponse

from ..components.login import LoginPage
from ..services.auth import AuthenticationError


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

            # Store user in session
            sess["user"] = user.to_dict()

            # Redirect to main application
            return RedirectResponse("/", status_code=303)

        except AuthenticationError as e:
            return LoginPage(error_message=str(e))

    @rt("/logout")
    def logout(sess):
        """Log out user and redirect to login."""
        sess.clear()
        return RedirectResponse("/login", status_code=303)
