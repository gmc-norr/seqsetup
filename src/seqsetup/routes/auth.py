"""Authentication routes for login/logout.

Migrated off FastHTML to plain Starlette + Jinja2. No FT components, no
@rt decorator — the ``register(app, auth_service)`` function appends
Starlette Route objects directly. The middleware stack (security headers,
CSRF, session) lives on the parent app and applies unchanged.
"""

from starlette.requests import Request
from starlette.responses import PlainTextResponse, RedirectResponse, Response
from starlette.routing import Route

from ..rate_limit import client_identity, get_login_limiter
from ..services.audit_log import audit
from ..services.auth import AuthenticationError
from ..templating import render


def _login_user(sess, user) -> None:
    """Apply the authenticated user to the session.

    Clears any prior session contents first to defeat session fixation: an
    attacker who plants a known session ID on a shared workstation must not
    retain that session after a legitimate user logs in.
    """
    sess.clear()
    sess["user"] = user.to_dict()


def register(app, auth_service) -> None:
    """Register authentication routes on the parent Starlette app.

    Note the signature change: no ``rt`` parameter — Starlette routes
    aren't registered via a decorator factory.

    Handlers are intentionally synchronous (``def``, not ``async def``)
    because they call into bcrypt (a blocking C extension) via
    ``auth_service.authenticate``. Starlette runs sync handlers in a
    threadpool, which is what we want; an ``async def`` handler that
    calls bcrypt blocks the event loop and serialises every other
    request behind it. Login traffic is low but rate-limited probes can
    still saturate one thread per request without affecting the rest.

    Requires ``app`` to have a mutable ``.routes`` list (Starlette/
    FastHTML do — anything else does not).
    """
    if not hasattr(app, "routes") or not isinstance(app.routes, list):
        raise TypeError(
            f"auth.register requires a Starlette-style app with a mutable "
            f"routes list, got {type(app).__name__}"
        )

    def login_page(request: Request) -> Response:
        """GET /login — render the login page."""
        sess = request.session
        if sess.get("user"):
            return RedirectResponse("/", status_code=303)
        return render(request, "login.html", {"error_message": ""})

    async def login_submit(request: Request) -> Response:
        """POST /login/submit — process the login form.

        ``async def`` here only because we need ``await request.form()``
        (Starlette's form parser is async). The auth call itself runs
        bcrypt — for the same reason as ``login_page``, we keep the work
        small here; the blocking step is unavoidable.
        """
        form = await request.form()
        username = form.get("username", "")
        password = form.get("password", "")
        sess = request.session

        # Truncate username for audit logging — protect against multi-MB
        # values landing in the audit stream from an automated probe.
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
            # Log the reason category but not the raw error text — it can
            # echo back the supplied username and would inflate the log.
            audit("login.failure", actor=actor, outcome="failure")
            return render(
                request,
                "login.html",
                {"error_message": str(e)},
                status_code=200,
            )

    def logout(request: Request) -> Response:
        """GET /logout — clear the session and redirect to /login."""
        sess = request.session
        # Best-effort capture of who is logging out; sess may already be empty.
        user_data = sess.get("user") or {}
        actor = (user_data.get("username") or "")[:128]
        sess.clear()
        audit("logout", actor=actor)
        return RedirectResponse("/login", status_code=303)

    app.routes.append(Route("/login", login_page, methods=["GET"]))
    app.routes.append(Route("/login/submit", login_submit, methods=["POST"]))
    app.routes.append(Route("/logout", logout, methods=["GET"]))
