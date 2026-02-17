"""Authentication settings components."""

from typing import Optional

from fasthtml.common import *

from ...models.auth_config import AuthConfig, AuthMethod


def AuthenticationPage(auth_config: AuthConfig):
    """Authentication settings page."""
    return Div(
        H2("Authentication"),
        LDAPConfigForm(auth_config),
        cls="admin-settings-page",
    )


def LDAPConfigForm(auth_config: AuthConfig, message: Optional[str] = None):
    """LDAP/Active Directory configuration form."""
    config = auth_config.ldap_config
    is_ldap = auth_config.auth_method in (AuthMethod.LDAP, AuthMethod.ACTIVE_DIRECTORY)

    return Div(
        # Success/info message
        Div(message, cls="settings-message success") if message else None,

        # Auth method selection
        Form(
            Fieldset(
                Legend("Authentication Method"),
                Div(
                    Label(
                        Input(
                            type="radio",
                            name="auth_method",
                            value="local",
                            checked=auth_config.auth_method == AuthMethod.LOCAL,
                            hx_post="/admin/settings/auth-method",
                            hx_trigger="change",
                            hx_target="#ldap-config-section",
                            hx_include="[name='allow_local_fallback']",
                        ),
                        " Local Authentication",
                        cls="radio-label",
                    ),
                    P("Users are managed in users.yaml configuration file.", cls="auth-method-desc"),
                    cls="auth-method-option",
                ),
                Div(
                    Label(
                        Input(
                            type="radio",
                            name="auth_method",
                            value="active_directory",
                            checked=auth_config.auth_method == AuthMethod.ACTIVE_DIRECTORY,
                            hx_post="/admin/settings/auth-method",
                            hx_trigger="change",
                            hx_target="#ldap-config-section",
                            hx_include="[name='allow_local_fallback']",
                        ),
                        " Active Directory",
                        cls="radio-label",
                    ),
                    P("Authenticate users against Microsoft Active Directory.", cls="auth-method-desc"),
                    cls="auth-method-option",
                ),
                Div(
                    Label(
                        Input(
                            type="radio",
                            name="auth_method",
                            value="ldap",
                            checked=auth_config.auth_method == AuthMethod.LDAP,
                            hx_post="/admin/settings/auth-method",
                            hx_trigger="change",
                            hx_target="#ldap-config-section",
                            hx_include="[name='allow_local_fallback']",
                        ),
                        " LDAP",
                        cls="radio-label",
                    ),
                    P("Authenticate users against generic LDAP server.", cls="auth-method-desc"),
                    cls="auth-method-option",
                ),
                Div(
                    Label(
                        Input(
                            type="checkbox",
                            name="allow_local_fallback",
                            checked=auth_config.allow_local_fallback,
                        ),
                        " Allow local user fallback",
                        cls="checkbox-label",
                    ),
                    P("If LDAP authentication fails, try local authentication.", cls="fallback-desc"),
                    cls="fallback-option",
                ),
            ),
        ),

        # LDAP Configuration section
        Div(
            LDAPSettingsForm(auth_config) if is_ldap else None,
            id="ldap-config-section",
        ),

        id="ldap-config-form",
        cls="ldap-config-form",
    )


def LDAPSettingsForm(auth_config: AuthConfig):
    """LDAP connection and user settings form."""
    config = auth_config.ldap_config

    return Form(
        H4("LDAP/AD Connection Settings"),

        # Connection settings
        Fieldset(
            Legend("Server Connection"),
            Div(
                Label("Server URL:", fr="server_url"),
                Input(
                    type="text",
                    name="server_url",
                    id="server_url",
                    value=config.server_url,
                    placeholder="ldap://dc.example.com or ldaps://dc.example.com:636",
                    cls="settings-input",
                ),
                P("Example: ldaps://ad.company.com:636", cls="field-hint"),
                cls="form-row",
            ),
            Div(
                Label(
                    Input(
                        type="checkbox",
                        name="use_ssl",
                        checked=config.use_ssl,
                    ),
                    " Use SSL/TLS",
                    cls="checkbox-label",
                ),
                cls="form-row",
            ),
            Div(
                Label("Base DN:", fr="base_dn"),
                Input(
                    type="text",
                    name="base_dn",
                    id="base_dn",
                    value=config.base_dn,
                    placeholder="DC=example,DC=com",
                    cls="settings-input",
                ),
                cls="form-row",
            ),
        ),

        # Bind credentials
        Fieldset(
            Legend("Service Account (for searching users)"),
            Div(
                Label("Bind DN:", fr="bind_dn"),
                Input(
                    type="text",
                    name="bind_dn",
                    id="bind_dn",
                    value=config.bind_dn,
                    placeholder="CN=ServiceAccount,OU=Services,DC=example,DC=com",
                    cls="settings-input",
                ),
                cls="form-row",
            ),
            Div(
                Label("Bind Password:", fr="bind_password"),
                Input(
                    type="password",
                    name="bind_password",
                    id="bind_password",
                    placeholder="Leave blank to keep existing password",
                    cls="settings-input",
                ),
                P("Password is stored encrypted." if config.bind_password else "", cls="field-hint"),
                cls="form-row",
            ),
        ),

        # User search settings
        Fieldset(
            Legend("User Search Settings"),
            Div(
                Label("User Search Base:", fr="user_search_base"),
                Input(
                    type="text",
                    name="user_search_base",
                    id="user_search_base",
                    value=config.user_search_base,
                    placeholder="OU=Users,DC=example,DC=com (optional, defaults to Base DN)",
                    cls="settings-input",
                ),
                cls="form-row",
            ),
            Div(
                Label("User Search Filter:", fr="user_search_filter"),
                Input(
                    type="text",
                    name="user_search_filter",
                    id="user_search_filter",
                    value=config.user_search_filter,
                    placeholder="(sAMAccountName={username})",
                    cls="settings-input",
                ),
                P("Use {username} as placeholder for the login username.", cls="field-hint"),
                cls="form-row",
            ),
            Div(
                Label("Direct User DN Pattern (optional):", fr="user_dn_pattern"),
                Input(
                    type="text",
                    name="user_dn_pattern",
                    id="user_dn_pattern",
                    value=config.user_dn_pattern,
                    placeholder="CN={username},OU=Users,DC=example,DC=com",
                    cls="settings-input",
                ),
                P("If set, skips user search and binds directly.", cls="field-hint"),
                cls="form-row",
            ),
        ),

        # Attribute mappings
        Fieldset(
            Legend("Attribute Mappings"),
            Div(
                Label("Username Attribute:", fr="username_attribute"),
                Input(
                    type="text",
                    name="username_attribute",
                    id="username_attribute",
                    value=config.username_attribute,
                    placeholder="sAMAccountName",
                    cls="settings-input settings-input-small",
                ),
                cls="form-row",
            ),
            Div(
                Label("Display Name Attribute:", fr="display_name_attribute"),
                Input(
                    type="text",
                    name="display_name_attribute",
                    id="display_name_attribute",
                    value=config.display_name_attribute,
                    placeholder="displayName",
                    cls="settings-input settings-input-small",
                ),
                cls="form-row",
            ),
            Div(
                Label("Email Attribute:", fr="email_attribute"),
                Input(
                    type="text",
                    name="email_attribute",
                    id="email_attribute",
                    value=config.email_attribute,
                    placeholder="mail",
                    cls="settings-input settings-input-small",
                ),
                cls="form-row",
            ),
        ),

        # Group settings for role mapping
        Fieldset(
            Legend("Role Mapping (via AD Groups)"),
            Div(
                Label("Admin Group DN:", fr="admin_group_dn"),
                Input(
                    type="text",
                    name="admin_group_dn",
                    id="admin_group_dn",
                    value=config.admin_group_dn,
                    placeholder="CN=SeqSetup-Admins,OU=Groups,DC=example,DC=com",
                    cls="settings-input",
                ),
                P("Users in this group will be granted admin role.", cls="field-hint"),
                cls="form-row",
            ),
            Div(
                Label("User Group DN (optional):", fr="user_group_dn"),
                Input(
                    type="text",
                    name="user_group_dn",
                    id="user_group_dn",
                    value=config.user_group_dn,
                    placeholder="CN=SeqSetup-Users,OU=Groups,DC=example,DC=com",
                    cls="settings-input",
                ),
                P("If set, only members of this group can log in.", cls="field-hint"),
                cls="form-row",
            ),
            Div(
                Label("Group Membership Attribute:", fr="group_membership_attribute"),
                Input(
                    type="text",
                    name="group_membership_attribute",
                    id="group_membership_attribute",
                    value=config.group_membership_attribute,
                    placeholder="memberOf",
                    cls="settings-input settings-input-small",
                ),
                cls="form-row",
            ),
        ),

        # Connection timeouts
        Fieldset(
            Legend("Timeouts"),
            Div(
                Label("Connect Timeout (seconds):", fr="connect_timeout"),
                Input(
                    type="number",
                    name="connect_timeout",
                    id="connect_timeout",
                    value=config.connect_timeout,
                    min=1,
                    max=60,
                    cls="settings-input settings-input-small",
                ),
                cls="form-row inline",
            ),
            Div(
                Label("Receive Timeout (seconds):", fr="receive_timeout"),
                Input(
                    type="number",
                    name="receive_timeout",
                    id="receive_timeout",
                    value=config.receive_timeout,
                    min=1,
                    max=60,
                    cls="settings-input settings-input-small",
                ),
                cls="form-row inline",
            ),
        ),

        # Action buttons
        Div(
            Button("Save Configuration", type="submit", cls="btn-primary"),
            Button(
                "Test Connection",
                type="button",
                hx_post="/admin/settings/ldap/test",
                hx_target="#ldap-test-result",
                cls="btn-secondary",
            ),
            cls="form-actions",
        ),

        # Test result area
        Div(id="ldap-test-result", cls="test-result-area"),

        # Test authentication section
        Fieldset(
            Legend("Test User Authentication"),
            Div(
                Label("Test Username:", fr="test_username"),
                Input(
                    type="text",
                    name="test_username",
                    id="test_username",
                    placeholder="testuser",
                    cls="settings-input settings-input-small",
                ),
                cls="form-row inline",
            ),
            Div(
                Label("Test Password:", fr="test_password"),
                Input(
                    type="password",
                    name="test_password",
                    id="test_password",
                    placeholder="password",
                    cls="settings-input settings-input-small",
                ),
                cls="form-row inline",
            ),
            Button(
                "Test Authentication",
                type="button",
                hx_post="/admin/settings/ldap/test-auth",
                hx_target="#ldap-auth-test-result",
                hx_include="[name='test_username'],[name='test_password']",
                cls="btn-secondary",
            ),
            Div(id="ldap-auth-test-result", cls="test-result-area"),
            cls="test-auth-section",
        ),

        hx_post="/admin/settings/ldap",
        hx_target="#ldap-config-form",
        hx_swap="outerHTML",
        cls="ldap-settings-form",
    )


def LDAPTestResult(success: bool, message: str):
    """Display LDAP test result."""
    status_class = "success" if success else "error"
    icon = "\u2713" if success else "\u2717"

    return Div(
        Span(icon, cls=f"test-icon {status_class}"),
        Span(message, cls="test-message"),
        cls=f"test-result {status_class}",
    )
