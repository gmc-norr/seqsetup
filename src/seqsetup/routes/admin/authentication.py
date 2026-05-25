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
  - user_dn_pattern validation REJECTS injection attempts (400)
  - bind_password empty = keep existing (no silent clearing)
  - Auth-method clamp: unknown value falls back to LOCAL (matches
    the previous handler — defensive)
  - Saving config flips ldap_configured (derived) AND resets
    ldap_tested to False
  - test_ldap_auth is rate-limited identically to /login/submit
"""

import logging
from typing import Annotated

from fastapi import APIRouter, Depends, Form, Request
from pydantic import BaseModel, Field
from pydantic.functional_validators import BeforeValidator
from starlette.responses import HTMLResponse, Response

from ...context import AppContext
from ...forms.validators import clamp, strip_and_truncate
from ...models.auth_config import AuthMethod, LDAPConfig, validate_user_dn_pattern
from ...rate_limit import client_identity, get_login_limiter
from ...services.audit_log import audit
from ...services.ldap import LDAPError, LDAPService
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
    """LDAP connection configuration.

    Every text field CLAMP. bind_password is special: empty means
    "keep existing" (preserved verbatim from the original handler).
    Numeric timeouts CLAMP via clamp(1, 300) to keep them sane.
    """
    server_url: Annotated[str, BeforeValidator(strip_and_truncate(1024))] = ""
    use_ssl: bool = False
    verify_ssl_cert: bool = True
    base_dn: Annotated[str, BeforeValidator(strip_and_truncate(512))] = ""
    bind_dn: Annotated[str, BeforeValidator(strip_and_truncate(512))] = ""
    bind_password: Annotated[str, BeforeValidator(strip_and_truncate(512))] = ""
    user_search_base: Annotated[str, BeforeValidator(strip_and_truncate(512))] = ""
    user_search_filter: Annotated[str, BeforeValidator(strip_and_truncate(512))] = "(sAMAccountName={username})"
    user_dn_pattern: Annotated[str, BeforeValidator(strip_and_truncate(512))] = ""
    username_attribute: Annotated[str, BeforeValidator(strip_and_truncate(128))] = "sAMAccountName"
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

    user_dn_pattern is validated by validate_user_dn_pattern which
    REJECTS injection attempts (returns 400 — strict reject).
    """
    try:
        validate_user_dn_pattern(form.user_dn_pattern)
    except ValueError as e:
        return Response(str(e), status_code=400)

    config = ctx.auth_config_repo.get()
    config.ldap_config = LDAPConfig(
        server_url=form.server_url,
        use_ssl=form.use_ssl,
        verify_ssl_cert=form.verify_ssl_cert,
        base_dn=form.base_dn,
        bind_dn=form.bind_dn,
        bind_password=form.bind_password if form.bind_password else config.ldap_config.bind_password,
        user_search_base=form.user_search_base,
        user_search_filter=form.user_search_filter,
        user_dn_pattern=form.user_dn_pattern,
        username_attribute=form.username_attribute,
        display_name_attribute=form.display_name_attribute,
        email_attribute=form.email_attribute,
        admin_group_dn=form.admin_group_dn,
        user_group_dn=form.user_group_dn,
        group_membership_attribute=form.group_membership_attribute,
        connect_timeout=form.connect_timeout,
        receive_timeout=form.receive_timeout,
    )
    config.ldap_configured = bool(config.ldap_config.server_url and config.ldap_config.base_dn)
    config.ldap_tested = False
    ctx.auth_config_repo.save(config)
    audit(
        "auth.ldap_config.updated",
        actor=get_username(request),
        target="ldap_config",
        server_url=config.ldap_config.server_url,
        base_dn=config.ldap_config.base_dn,
        bind_dn=config.ldap_config.bind_dn,
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
        ldap_service = LDAPService(config.ldap_config)
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
    if not config.ldap_config.server_url:
        return _test_result(request, False, "LDAP server URL is not configured")
    try:
        ldap_service = LDAPService(config.ldap_config)
        user = ldap_service.authenticate(form.test_username, form.test_password)
        return _test_result(
            request, True,
            f"Authentication successful! User: {user.display_name}, Role: {user.role.value}",
        )
    except LDAPError as e:
        return _test_result(request, False, str(e))
    except Exception:
        logger.exception("LDAP authentication test failed")
        return _test_result(request, False, "Authentication test failed")


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
