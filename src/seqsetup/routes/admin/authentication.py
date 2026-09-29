"""Admin authentication settings (Local / Active Directory / LDAP).

Five endpoints:
  GET  /admin/authentication           — full page
  POST /admin/settings/auth-method     — change auth method radio
                                          (HTMX fragment swap into
                                          #ldap-config-form)
  POST /admin/settings/ldap            — save LDAP connection config
                                          (HTMX fragment swap into
                                          #ldap-config-form)
  POST /admin/settings/ldap/test       — connection test; returns
                                          LDAPTestResult into
                                          #ldap-test-result
  POST /admin/settings/ldap/test-auth  — authentication test; rate-
                                          limited per IP + per username
                                          (same policy as /login/submit);
                                          returns LDAPTestResult into
                                          #ldap-auth-test-result

Admin-only via router-level require_admin_dep.

Clinical/security invariants preserved:
  - No service account: SeqSetup binds as the person signing in, so no
    bind DN or password is taken or stored (spec 2026-09-28 group 2b)
  - user_dn_pattern and the group attribute are validated; a bad value is
    REJECTED (400)
  - Auth-method clamp: unknown value falls back to LOCAL (matches
    the previous handler — defensive)
  - Saving config resets ldap_tested to False; whether directory sign-in
    is on is computed from the saved settings (AuthConfig.is_ldap_enabled)
  - test_ldap_auth is rate-limited identically to /login/submit and
    never starts a session
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from pydantic import BaseModel, Field
from pydantic.functional_validators import BeforeValidator
from starlette.responses import HTMLResponse, Response

from ...context import AppContext
from ...forms.validators import clamp, strip_and_truncate
from ...models.auth_config import AuthMethod, LDAPConfig, validate_attribute_name, validate_user_dn_pattern
from ...rate_limit import client_identity, get_login_limiter
from ...services.audit_log import audit
from ...services.ldap import LDAPError, LDAPService, SignInRefused
from ...templating import render
from ..dependencies import get_ctx, require_admin_dep
from ..utils import get_username


logger = logging.getLogger("seqsetup")


router = APIRouter(
    tags=["admin-authentication"],
    dependencies=[Depends(require_admin_dep)],
)


# ---------------------------------------------------------------------
# Pydantic forms
# ---------------------------------------------------------------------


class AuthMethodForm(BaseModel):
    """Auth-method radio change.

    auth_method: clamp-to-LOCAL on unknown — matches the original
        handler's defensive "if not in enum: AuthMethod.LOCAL" branch.
        Done in the handler (not Pydantic) because Pydantic 422 would
        be wrong UX for a radio change that's likely a developer typo.
    allow_local_fallback: checkbox; default False (unchecked).
    """
    auth_method: Annotated[str, BeforeValidator(strip_and_truncate(64))] = ""
    allow_local_fallback: bool = False


class LDAPConfigFormModel(BaseModel):
    """Directory connection settings (spec 2026-09-28 group 2b).

    Every text field CLAMP. There is no service account: SeqSetup binds as
    the person signing in, so no bind DN or password is taken. Numeric
    timeouts CLAMP via clamp(1, 300) to keep them sane.
    """
    server_url: Annotated[str, BeforeValidator(strip_and_truncate(1024))] = ""
    use_ssl: bool = False
    verify_ssl_cert: bool = True
    base_dn: Annotated[str, BeforeValidator(strip_and_truncate(512))] = ""
    user_dn_pattern: Annotated[str, BeforeValidator(strip_and_truncate(512))] = ""
    display_name_attribute: Annotated[str, BeforeValidator(strip_and_truncate(128))] = "displayName"
    email_attribute: Annotated[str, BeforeValidator(strip_and_truncate(128))] = "mail"
    admin_group_dn: Annotated[str, BeforeValidator(strip_and_truncate(512))] = ""
    user_group_dn: Annotated[str, BeforeValidator(strip_and_truncate(512))] = ""
    group_membership_attribute: Annotated[str, BeforeValidator(strip_and_truncate(128))] = "memberOf"
    connect_timeout: Annotated[int, BeforeValidator(clamp(1, 300))] = 10
    receive_timeout: Annotated[int, BeforeValidator(clamp(1, 300))] = 10


class LDAPTestAuthForm(BaseModel):
    """LDAP auth test (admin verifies a real user's credentials).

    test_username is stripped and clamped. test_password is NOT stripped
    or truncated beyond the DoS guard max_length 512 — silent changes
    would alter what the user typed.
    """
    test_username: Annotated[str, BeforeValidator(strip_and_truncate(256))] = ""
    test_password: str = Field(default="", max_length=512)


# ---------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------


@router.get("/admin/authentication", response_class=HTMLResponse)
def admin_authentication(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """GET /admin/authentication — full page."""
    return render(
        request,
        "admin/authentication.html",
        {"config": ctx.auth_config_repo.get(), "message": ""},
    )


@router.post("/admin/settings/auth-method", response_class=HTMLResponse)
def update_auth_method(
    request: Request,
    form: Annotated[AuthMethodForm, Form()],
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/settings/auth-method — radio change; fragment swap."""
    config = ctx.auth_config_repo.get()
    try:
        config.auth_method = AuthMethod(form.auth_method)
    except ValueError:
        config.auth_method = AuthMethod.LOCAL
    config.allow_local_fallback = form.allow_local_fallback
    ctx.auth_config_repo.save(config)
    audit(
        "auth.method.changed",
        actor=get_username(request),
        target="auth_config",
        method=config.auth_method.value,
        allow_local_fallback=config.allow_local_fallback,
    )
    return render(
        request,
        "admin/authentication.html",
        {"config": config, "message": "Authentication method updated"},
        block_name="ldap_config_form",
    )


@router.post("/admin/settings/ldap", response_class=HTMLResponse)
def update_ldap_config(
    request: Request,
    form: Annotated[LDAPConfigFormModel, Form()],
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/settings/ldap — save LDAP config; fragment swap.

    user_dn_pattern and the group attribute are validated and REJECTED (400) when unsafe. No bind DN or password is taken.
    """
    try:
        validate_user_dn_pattern(form.user_dn_pattern)
        validate_attribute_name(form.group_membership_attribute)
    except ValueError as e:
        return Response(str(e), status_code=400)

    config = ctx.auth_config_repo.get()
    config.ldap_config = LDAPConfig(
        server_url=form.server_url,
        use_ssl=form.use_ssl,
        verify_ssl_cert=form.verify_ssl_cert,
        base_dn=form.base_dn,
        user_dn_pattern=form.user_dn_pattern,
        display_name_attribute=form.display_name_attribute,
        email_attribute=form.email_attribute,
        admin_group_dn=form.admin_group_dn,
        user_group_dn=form.user_group_dn,
        group_membership_attribute=form.group_membership_attribute,
        connect_timeout=form.connect_timeout,
        receive_timeout=form.receive_timeout,
    )
    config.ldap_tested = False
    ctx.auth_config_repo.save(config)
    audit(
        "auth.ldap_config.updated",
        actor=get_username(request),
        target="ldap_config",
        server_url=config.ldap_config.server_url,
        base_dn=config.ldap_config.base_dn,
        user_dn_pattern=config.ldap_config.user_dn_pattern,
        admin_group_dn=config.ldap_config.admin_group_dn,
        user_group_dn=config.ldap_config.user_group_dn,
    )
    return render(
        request,
        "admin/authentication.html",
        {"config": config, "message": "LDAP configuration saved"},
        block_name="ldap_config_form",
    )


@router.post("/admin/settings/ldap/test", response_class=HTMLResponse)
def test_ldap_connection(
    request: Request,
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/settings/ldap/test — connection-test ping.

    Returns the ldap_test_result fragment into #ldap-test-result.
    """
    config = ctx.auth_config_repo.get()
    if not config.ldap_config.server_url:
        return _test_result(request, False, "LDAP server URL is not configured")
    try:
        ldap_service = LDAPService(
            config.ldap_config,
            active_directory=config.auth_method is AuthMethod.ACTIVE_DIRECTORY)
        success, message = ldap_service.test_connection()
        if success:
            config.ldap_tested = True
            ctx.auth_config_repo.save(config)
        return _test_result(request, success, message)
    except LDAPError as e:
        return _test_result(request, False, str(e))
    except Exception:
        logger.exception("LDAP connection test failed unexpectedly")
        return _test_result(request, False, "Connection test failed unexpectedly")


@router.post("/admin/settings/ldap/test-auth", response_class=HTMLResponse)
def test_ldap_auth(
    request: Request,
    form: Annotated[LDAPTestAuthForm, Form()],
    ctx: AppContext = Depends(get_ctx),
) -> Response:
    """POST /admin/settings/ldap/test-auth — auth test (real bind).

    Rate-limited per IP + per username on the same limiter as
    /login/submit — this endpoint triggers a real LDAP bind from
    admin-supplied credentials.
    """
    if not form.test_username or not form.test_password:
        return _test_result(request, False, "Please provide both username and password")

    limiter = get_login_limiter()
    ip = client_identity(request)
    actor_user = form.test_username.lower()[:128]
    ok_ip, retry_ip = limiter.allow(f"ldap-test-ip:{ip}")
    ok_user, retry_user = limiter.allow(f"ldap-test-user:{actor_user}")
    if not (ok_ip and ok_user):
        retry = max(retry_ip, retry_user)
        audit(
            "ldap.test_auth.rate_limited",
            actor=get_username(request),
            outcome="denied",
            ip=ip,
            target_user=actor_user,
            retry_after=retry,
        )
        return _test_result(request, False, f"Too many test attempts. Retry after {retry}s.")

    config = ctx.auth_config_repo.get()
    if config.auth_method not in (AuthMethod.LDAP, AuthMethod.ACTIVE_DIRECTORY):
        return _test_result(request, False, "Choose Active Directory or LDAP above first.")
    missing = config.missing_settings()
    if missing:
        return _test_result(
            request, False,
            f"Directory sign-in is not fully set up. Missing: {', '.join(missing)}.")
    try:
        result = LDAPService(
            config.ldap_config,
            active_directory=config.auth_method is AuthMethod.ACTIVE_DIRECTORY,
        ).sign_in(form.test_username, form.test_password)
    except SignInRefused as e:
        return _test_result(request, False, e.message)
    except Exception:
        logger.exception("LDAP authentication test failed")
        return _test_result(request, False, "Authentication test failed")
    user = result.user
    return _test_result(
        request, True,
        f"Signed in as {user.display_name} ({user.email or 'no email'}). "
        f"Role: {user.role.value}. "
        f"Admins group: {'yes' if result.in_admins else 'no'}. "
        f"Users group: {'yes' if result.in_users else 'no'}.",
    )


# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------


def _test_result(request: Request, success: bool, message: str) -> Response:
    """Render the small ldap_test_result fragment."""
    return render(
        request,
        "admin/authentication.html",
        {"test_success": success, "test_message": message},
        block_name="ldap_test_result",
    )
