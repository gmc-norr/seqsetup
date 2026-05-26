"""Authentication routes for login/logout.

Migrated to APIRouter via the make_router(auth_service) factory.
auth_service is closed over because it's an app-singleton built at
startup, not per-request DI. No AppContext dependency — auth routes
only touch auth_service and request.session.

Handlers are intentionally synchronous (def, not async def) because
they call into bcrypt (a blocking C extension). Starlette runs sync
handlers in a threadpool, isolating the blocking call from the event
loop.
"""

from typing import Annotated

from fastapi import APIRouter, Form, Request
from pydantic import BaseModel, Field
from pydantic.functional_validators import BeforeValidator
from starlette.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response

from ..forms.validators import strip_and_truncate
from ..rate_limit import client_identity, get_login_limiter
from ..services.audit_log import audit
from ..services.auth import AuthenticationError
from ..templating import render


class LoginForm(BaseModel):
    """Login credentials form.

    username: CLAMP (strip + truncate to 64). Defensive length cap;
        auth_service does the actual existence check.
    password: PASS-THROUGH, REJECT if oversize. NOT stripped (whitespace
        in a password may be intentional; silent strip would cause
        lockouts), NOT truncated (silently chopping a password is wrong
        — a 600-char password should fail, not log in with the first
        256 chars). max_length=512 is a DoS guard; oversize → 422 not a
        silent corruption. min_length=1 rejects empty submissions
        (browser-side `required` already blocks the common case; this
        handles scripted/bypassed posts).
    """
    username: Annotated[str, BeforeValidator(strip_and_truncate(64))]
    password: str = Field(min_length=1, max_length=512)


def _login_user(sess, user) -> None:
    """Apply the authenticated user to the session.

    Clears any prior session contents first to defeat session fixation:
    an attacker who plants a known session ID on a shared workstation
    must not retain that session after a legitimate user logs in.
    """
    sess.clear()
    sess["user"] = user.to_dict()


def make_router(auth_service) -> APIRouter:
    """Build the auth router. auth_service is closed over because it's
    an app-singleton built at startup, not per-request DI."""
    router = APIRouter(tags=["auth"])

    @router.get("/login", response_class=HTMLResponse)
    def login_page(request: Request) -> Response:
        """GET /login — render the login page, OR redirect to / if
        already authenticated.

        The redirect is load-bearing for session-fixation defence: a
        user who hits /login after authenticating shouldn't get a
        fresh form (which would invite re-submission with browser
        autofill on a new session id).
        """
        if request.session.get("user"):
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", {"error_message": ""})

    @router.post("/login/submit")
    def login_submit(
        request: Request,
        form: Annotated[LoginForm, Form()],
    ) -> Response:
        """POST /login/submit — validate, rate-limit, authenticate.

        Sync def (not async) because bcrypt blocks; Starlette runs
        sync handlers in a threadpool, isolating the blocking step.
        FastAPI parses the Form into LoginForm before the body runs —
        request.form() does NOT need to be awaited here.
        """
        username = form.username
        password = form.password
        sess = request.session

        # Truncate username for audit logging — protect against multi-MB
        # values landing in the audit stream from an automated probe.
        # (Pydantic already clamped to 64, but be defensive.)
        actor = (username or "")[:128]

        # Rate-limit per IP and per username independently. A credential-
        # stuffing attacker rotating usernames is caught by the per-IP
        # cap; a low-and-slow distributed attacker still trips the
        # per-username cap.
        limiter = get_login_limiter()
        ip = client_identity(request)
        ok_ip, retry_ip = limiter.allow(f"login-ip:{ip}")
        ok_user, retry_user = limiter.allow(f"login-user:{actor.lower()}")
        if not (ok_ip and ok_user):
            retry = max(retry_ip, retry_user)
            audit(
                "login.rate_limited",
                actor=actor,
                outcome="denied",
                ip=ip,
                retry_after=retry,
            )
            return PlainTextResponse(
                "Too many login attempts. Try again later.",
                status_code=429,
                headers={"Retry-After": str(retry)},
            )

        try:
            user = auth_service.authenticate(username, password)
            _login_user(sess, user)
            audit("login.success", actor=actor)
            return RedirectResponse("/", status_code=303)
        except AuthenticationError as e:
            # Log the reason category but not the raw error text — it
            # can echo back the supplied username and would inflate
            # the log.
            audit("login.failure", actor=actor, outcome="failure")
            return render(
                request,
                "login.html",
                {"error_message": str(e)},
                status_code=200,
            )

    @router.post("/logout")
    def logout(request: Request) -> Response:
        """POST /logout — clear the session and redirect to /login.

        Method intentionally restricted to POST so the
        ``OriginCheckMiddleware`` (which only inspects state-changing
        methods) can defend against cross-site logout triggers. A GET
        endpoint would be CSRF-actuatable by any same-site context
        despite the SameSite=Strict cookie.
        """
        sess = request.session
        # Best-effort capture of who is logging out; sess may be empty.
        user_data = sess.get("user") or {}
        actor = (user_data.get("username") or "")[:128]
        sess.clear()
        audit("logout", actor=actor)
        return RedirectResponse("/login", status_code=303)

    return router
