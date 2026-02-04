"""Admin settings page components."""

from typing import Optional

from fasthtml.common import *

from ..models.auth_config import AuthConfig, AuthMethod
from ..models.profile_sync_config import ProfileSyncConfig
from ..models.sample_api_config import SampleApiConfig
from ..models.application_profile import ApplicationProfile
from ..models.test_profile import TestProfile
from ..models.instrument_definition import InstrumentDefinition


def AuthenticationPage(auth_config: AuthConfig):
    """Authentication settings page."""
    return Div(
        H2("Authentication"),
        LDAPConfigForm(auth_config),
        cls="admin-settings-page",
    )


def InstrumentsPage(
    synced_instruments: list[InstrumentDefinition] = None,
    message: Optional[str] = None,
):
    """Instrument visibility settings page."""
    synced_instruments = synced_instruments or []

    # Show message if using local config fallback
    fallback_notice = None
    if not synced_instruments:
        fallback_notice = Div(
            Strong("Note: "),
            "No instruments have been synced from GitHub. ",
            "Using local configuration file (config/instruments.yaml) as fallback. ",
            A("Configure sync", href="/admin/config-sync"),
            " to enable instrument management.",
            cls="settings-message info",
            style="background: var(--bg-info, #e0f2fe); border-color: var(--border-info, #0ea5e9); margin-bottom: 1rem;",
        )

    return Div(
        H2("Instruments"),
        P(
            "Configure which instruments are available when setting up a new run.",
            cls="page-description",
        ),
        Div(message, cls="settings-message success") if message else None,
        fallback_notice,
        SyncedInstrumentsSection(synced_instruments) if synced_instruments else None,
        cls="admin-settings-page",
        id="instruments-page",
    )


def SyncedInstrumentsSection(instruments: list[InstrumentDefinition], message: Optional[str] = None):
    """Section showing synced instruments with enable/disable toggles."""
    if not instruments:
        return None

    # Group by chemistry type
    two_color = [i for i in instruments if i.chemistry_type == "2-color"]
    four_color = [i for i in instruments if i.chemistry_type == "4-color"]

    def instrument_row(inst: InstrumentDefinition):
        flowcell_names = ", ".join(fc.name for fc in inst.flowcells) if inst.flowcells else "None"
        return Tr(
            Td(
                Label(
                    Input(
                        type="checkbox",
                        name="enabled_instruments",
                        value=inst.id,
                        checked=inst.enabled,
                        hx_post="/admin/instruments/synced/toggle",
                        hx_vals=f'{{"instrument_id": "{inst.id}", "enabled": "{str(not inst.enabled).lower()}"}}',
                        hx_target="#synced-instruments-section",
                        hx_swap="outerHTML",
                    ),
                    cls="checkbox-label",
                ),
            ),
            Td(inst.name),
            Td(inst.version or "-"),
            Td(inst.chemistry_type),
            Td(flowcell_names),
            Td("Yes" if inst.has_dragen_onboard else "No"),
            Td(inst.source_file),
        )

    def instrument_table(instruments_list: list[InstrumentDefinition], title: str):
        if not instruments_list:
            return None
        return Div(
            H4(title),
            Table(
                Thead(
                    Tr(
                        Th("Enabled", style="width: 60px;"),
                        Th("Name"),
                        Th("Version"),
                        Th("Chemistry"),
                        Th("Flowcells"),
                        Th("DRAGEN"),
                        Th("Source"),
                    )
                ),
                Tbody(*[instrument_row(inst) for inst in instruments_list]),
                cls="sample-table",
            ),
            style="margin-bottom: 1rem;",
        )

    return Div(
        H3("Synced Instruments"),
        Div(message, cls="settings-message success", style="margin: 0.5rem 0;") if message else None,
        P(
            "Instruments synced from GitHub. Enable or disable which ones are available for new runs.",
            cls="field-hint",
            style="margin-bottom: 0.75rem;",
        ),
        instrument_table(two_color, "Two-Color SBS Instruments"),
        instrument_table(four_color, "Four-Color SBS Instruments"),
        Div(
            Button(
                "Enable All",
                type="button",
                hx_post="/admin/instruments/synced/enable-all",
                hx_target="#synced-instruments-section",
                hx_swap="outerHTML",
                cls="btn-secondary btn-small",
            ),
            Button(
                "Disable All",
                type="button",
                hx_post="/admin/instruments/synced/disable-all",
                hx_target="#synced-instruments-section",
                hx_swap="outerHTML",
                cls="btn-secondary btn-small",
                style="margin-left: 0.5rem;",
            ),
            style="margin-top: 0.5rem;",
        ),
        cls="synced-instruments-section",
        style="margin-bottom: 2rem; padding-bottom: 1.5rem; border-bottom: 1px solid var(--border);",
        id="synced-instruments-section",
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
    icon = "✓" if success else "✗"

    return Div(
        Span(icon, cls=f"test-icon {status_class}"),
        Span(message, cls="test-message"),
        cls=f"test-result {status_class}",
    )


# Config Sync Components

def ConfigSyncPage(
    config: ProfileSyncConfig,
    app_profiles: list[ApplicationProfile] = None,
    test_profiles: list[TestProfile] = None,
    message: Optional[str] = None,
):
    """Configuration sync page for profiles and instruments."""
    app_profiles = app_profiles or []
    test_profiles = test_profiles or []

    return Div(
        H2("Config Sync"),
        P(
            "Configure synchronization of profiles and instruments from a GitHub repository.",
            cls="page-description",
        ),

        # Success message
        Div(message, cls="settings-message success") if message else None,

        # Sync status panel
        ConfigSyncStatus(config),

        # Configuration form
        ConfigSyncConfigForm(config),

        # Manual sync button
        Div(
            Button(
                "Sync Now",
                hx_post="/admin/config-sync/sync",
                hx_target="#config-sync-page",
                hx_swap="outerHTML",
                cls="btn-primary",
            ),
            cls="sync-actions",
            style="margin: 1rem 0;",
        ),

        # Profile lists
        ProfileListSection("Application Profiles", app_profiles),
        ProfileListSection("Test Profiles", test_profiles),

        cls="admin-config-sync-page",
        id="config-sync-page",
    )


def ConfigSyncStatus(config: ProfileSyncConfig):
    """Display sync status."""
    status_class = ""
    if config.last_sync_status == "success":
        status_class = "status-ok"
    elif config.last_sync_status == "error":
        status_class = "status-error"

    last_sync_str = (
        config.last_sync_at.strftime("%Y-%m-%d %H:%M:%S")
        if config.last_sync_at
        else "Never"
    )

    return Div(
        H3("Sync Status"),
        Dl(
            Dt("Last Sync:"),
            Dd(last_sync_str),
            Dt("Status:"),
            Dd(
                config.last_sync_status.capitalize() if config.last_sync_status else "Not synced",
                cls=status_class,
            ),
            Dt("Profiles Synced:"),
            Dd(str(config.last_sync_count)),
            Dt("Instruments Synced:"),
            Dd(str(config.last_instruments_sync_count)),
            Dt("Index Kits Synced:"),
            Dd(str(config.last_index_kits_sync_count)),
            Dt("Message:"),
            Dd(config.last_sync_message or "-"),
            cls="summary-list",
        ),
        cls="sync-status-panel",
        style="background: var(--bg); padding: 1rem; border-radius: 8px; margin-bottom: 1rem;",
    )


def ConfigSyncConfigForm(config: ProfileSyncConfig):
    """Form for config sync configuration."""
    return Form(
        Fieldset(
            Legend("GitHub Repository"),
            Div(
                Label("Repository URL:", fr="github_repo_url"),
                Input(
                    type="text",
                    name="github_repo_url",
                    id="github_repo_url",
                    value=config.github_repo_url,
                    placeholder="https://github.com/org/profiles",
                    cls="settings-input",
                ),
                P("Public GitHub repository containing profile and instrument YAML files.", cls="field-hint"),
                cls="form-row",
            ),
            Div(
                Label("Branch:", fr="github_branch"),
                Input(
                    type="text",
                    name="github_branch",
                    id="github_branch",
                    value=config.github_branch,
                    placeholder="main",
                    cls="settings-input settings-input-small",
                ),
                cls="form-row",
            ),
            Div(
                Label("Test Profiles Path:", fr="test_profiles_path"),
                Input(
                    type="text",
                    name="test_profiles_path",
                    id="test_profiles_path",
                    value=config.test_profiles_path,
                    placeholder="profiles/test_profiles/",
                    cls="settings-input settings-input-small",
                ),
                P("Directory path within repo for test profiles.", cls="field-hint"),
                cls="form-row",
            ),
            Div(
                Label("Application Profiles Path:", fr="application_profiles_path"),
                Input(
                    type="text",
                    name="application_profiles_path",
                    id="application_profiles_path",
                    value=config.application_profiles_path,
                    placeholder="profiles/application_profiles/",
                    cls="settings-input settings-input-small",
                ),
                P("Directory path within repo for application profiles.", cls="field-hint"),
                cls="form-row",
            ),
            Div(
                Label("Instruments Path:", fr="instruments_path"),
                Input(
                    type="text",
                    name="instruments_path",
                    id="instruments_path",
                    value=config.instruments_path,
                    placeholder="instruments/",
                    cls="settings-input settings-input-small",
                ),
                P("Directory path within repo for instrument definitions.", cls="field-hint"),
                cls="form-row",
            ),
            Div(
                Label("Index Kits Path:", fr="index_kits_path"),
                Input(
                    type="text",
                    name="index_kits_path",
                    id="index_kits_path",
                    value=config.index_kits_path,
                    placeholder="index_kits/",
                    cls="settings-input settings-input-small",
                ),
                P("Directory path within repo for index kit definitions.", cls="field-hint"),
                cls="form-row",
            ),
        ),
        Fieldset(
            Legend("Sync Settings"),
            Div(
                Label(
                    Input(
                        type="checkbox",
                        name="sync_enabled",
                        checked=config.sync_enabled,
                    ),
                    " Enable automatic sync",
                    cls="checkbox-label",
                ),
                cls="form-row",
            ),
            Div(
                Label(
                    Input(
                        type="checkbox",
                        name="sync_instruments_enabled",
                        checked=config.sync_instruments_enabled,
                    ),
                    " Sync instrument definitions",
                    cls="checkbox-label",
                ),
                P("When enabled, instrument definitions are synced from the GitHub repository.", cls="field-hint"),
                cls="form-row",
            ),
            Div(
                Label(
                    Input(
                        type="checkbox",
                        name="sync_index_kits_enabled",
                        checked=config.sync_index_kits_enabled,
                    ),
                    " Sync index kit definitions",
                    cls="checkbox-label",
                ),
                P("When enabled, index kits are synced from the GitHub repository. User-uploaded kits are preserved.", cls="field-hint"),
                cls="form-row",
            ),
            Div(
                Label("Sync Interval (minutes):", fr="sync_interval_minutes"),
                Input(
                    type="number",
                    name="sync_interval_minutes",
                    id="sync_interval_minutes",
                    value=config.sync_interval_minutes,
                    min=5,
                    max=1440,
                    cls="settings-input settings-input-small",
                ),
                cls="form-row",
            ),
        ),
        Div(
            Button("Save Configuration", type="submit", cls="btn-primary"),
            cls="form-actions",
        ),
        hx_post="/admin/config-sync/config",
        hx_target="#config-sync-page",
        hx_swap="outerHTML",
        cls="config-sync-config-form",
    )


def ProfileSyncResult(success: bool, message: str, count: int):
    """Display sync result."""
    status_class = "success" if success else "error"
    icon = "✓" if success else "✗"

    return Div(
        Span(icon, cls=f"test-icon {status_class}"),
        Span(message, cls="test-message"),
        cls=f"test-result {status_class}",
    )


def ProfileListSection(title: str, profiles: list):
    """Display a list of profiles."""
    if not profiles:
        return Div(
            H3(title),
            P("No profiles synced yet.", cls="empty-message"),
            cls="profile-list-section",
            style="margin-top: 1.5rem;",
        )

    # Determine profile type and create rows
    rows = []
    for profile in profiles:
        if isinstance(profile, ApplicationProfile):
            rows.append(
                Tr(
                    Td(profile.name),
                    Td(profile.version),
                    Td(profile.application_name),
                    Td(profile.source_file),
                )
            )
        elif isinstance(profile, TestProfile):
            app_refs = ", ".join(
                f"{ap.profile_name} v{ap.profile_version}"
                for ap in profile.application_profiles
            )
            rows.append(
                Tr(
                    Td(profile.test_type),
                    Td(profile.test_name),
                    Td(profile.version),
                    Td(app_refs or "-"),
                )
            )

    # Create appropriate headers
    if profiles and isinstance(profiles[0], ApplicationProfile):
        headers = Tr(
            Th("Name"),
            Th("Version"),
            Th("Application"),
            Th("Source File"),
        )
    else:
        headers = Tr(
            Th("Test Type"),
            Th("Test Name"),
            Th("Version"),
            Th("Application Profiles"),
        )

    return Div(
        H3(f"{title} ({len(profiles)})"),
        Table(
            Thead(headers),
            Tbody(*rows),
            cls="sample-table",
        ),
        cls="profile-list-section",
        style="margin-top: 1.5rem;",
    )


# Sample API Components

def SampleApiPage(config: SampleApiConfig, message: Optional[str] = None):
    """Sample API configuration page."""
    return Div(
        H2("LIMS Integration"),
        P(
            "Configure a connection to an external LIMS for fetching worklists and sample data.",
            cls="page-description",
        ),
        Div(message, cls="settings-message success") if message else None,
        SampleApiConfigForm(config),
        cls="admin-settings-page",
        id="sample-api-page",
    )


def SampleApiConfigForm(config: SampleApiConfig, message: Optional[str] = None, error: Optional[str] = None):
    """Form for sample API configuration."""
    return Div(
        Div(message, cls="settings-message success") if message else None,
        Div(
            error,
            style="background: rgba(220, 38, 38, 0.1); color: #dc2626; border: 1px solid #dc2626; padding: 0.75rem; border-radius: 4px; margin-bottom: 1rem; font-size: 0.875rem;",
        ) if error else None,
        Form(
            Fieldset(
                Legend("API Endpoint"),
                Div(
                    Label("Base URL:", fr="base_url"),
                    Input(
                        type="text",
                        name="base_url",
                        id="base_url",
                        value=config.base_url,
                        placeholder="https://lims.example.com/api",
                        cls="settings-input",
                    ),
                    P("Base URL for the worksheet API. Endpoints used:", cls="field-hint"),
                    P(
                        Code("{base_url}/worksheets?detail=true"),
                        " — list available worksheets",
                        cls="field-hint",
                        style="margin-top:0.1rem;",
                    ),
                    P(
                        Code("{base_url}/worksheets/{id}"),
                        " — get samples for a worksheet",
                        cls="field-hint",
                        style="margin-top:0.1rem;",
                    ),
                    cls="form-row",
                ),
                Div(
                    Label("API Key:", fr="api_key"),
                    Input(
                        type="password",
                        name="api_key",
                        id="api_key",
                        placeholder="Leave blank to keep existing key",
                        cls="settings-input",
                    ),
                    P(
                        "Sent as 'api-key' header."
                        + (" Key is configured." if config.api_key else ""),
                        cls="field-hint",
                    ),
                    cls="form-row",
                ),
            ),
            Fieldset(
                Legend("Settings"),
                Div(
                    Label(
                        Input(
                            type="checkbox",
                            name="enabled",
                            checked=config.enabled,
                        ),
                        " Enable LIMS Integration",
                        cls="checkbox-label",
                    ),
                    P("When enabled, a 'Fetch Worklist' option appears in sample forms.", cls="field-hint"),
                    cls="form-row",
                ),
            ),
            Fieldset(
                Legend("Field Mappings"),
                P(
                    "Map API field names to SeqSetup fields. Leave blank to use defaults.",
                    cls="field-hint",
                    style="margin-bottom: 0.75rem;",
                ),
                Div(
                    Label("Worksheet ID field:", fr="field_worksheet_id"),
                    Input(
                        type="text",
                        name="field_worksheet_id",
                        id="field_worksheet_id",
                        value=config.field_mappings.get("worksheet_id", ""),
                        placeholder="e.g., AL",
                        cls="settings-input",
                    ),
                    P("API field name for worksheet ID (default: 'id').", cls="field-hint"),
                    cls="form-row",
                ),
                Div(
                    Label("Investigator field:", fr="field_investigator"),
                    Input(
                        type="text",
                        name="field_investigator",
                        id="field_investigator",
                        value=config.field_mappings.get("investigator", ""),
                        placeholder="e.g., Investigator",
                        cls="settings-input",
                    ),
                    P("API field name for investigator.", cls="field-hint"),
                    cls="form-row",
                ),
                Div(
                    Label("Updated timestamp field:", fr="field_updated_at"),
                    Input(
                        type="text",
                        name="field_updated_at",
                        id="field_updated_at",
                        value=config.field_mappings.get("updated_at", ""),
                        placeholder="e.g., updatedAt",
                        cls="settings-input",
                    ),
                    P("API field name for last updated timestamp.", cls="field-hint"),
                    cls="form-row",
                ),
                Div(
                    Label("Samples field:", fr="field_samples"),
                    Input(
                        type="text",
                        name="field_samples",
                        id="field_samples",
                        value=config.field_mappings.get("samples", ""),
                        placeholder="e.g., samples",
                        cls="settings-input",
                    ),
                    P("API field name for embedded samples data.", cls="field-hint"),
                    cls="form-row",
                ),
            ),
            Div(
                Button("Save Configuration", type="submit", cls="btn-primary"),
                cls="form-actions",
            ),
            hx_post="/admin/settings/sample-api",
            hx_target="#sample-api-config-form",
            hx_swap="outerHTML",
        ),
        id="sample-api-config-form",
    )


# Log Viewer Components

def LogsPage(
    entries: list,
    stats: dict,
    level_filter: str = "",
    search_filter: str = "",
    message: Optional[str] = None,
):
    """Admin logs viewer page."""
    return Div(
        H2("Application Logs"),
        P(
            "View recent application logs including sync operations and validation errors.",
            cls="page-description",
        ),

        # Success message
        Div(message, cls="settings-message success") if message else None,

        # Stats summary
        LogStats(stats),

        # Filters
        LogFilters(level_filter, search_filter),

        # Log entries
        LogEntriesTable(entries),

        cls="admin-logs-page",
        id="logs-page",
    )


def LogStats(stats: dict):
    """Display log statistics."""
    by_level = stats.get("by_level", {})

    level_badges = []
    for level in ["ERROR", "WARNING", "INFO", "DEBUG"]:
        count = by_level.get(level, 0)
        if count > 0:
            badge_cls = f"log-badge log-badge-{level.lower()}"
            level_badges.append(
                Span(f"{level}: {count}", cls=badge_cls)
            )

    return Div(
        Div(
            Span(f"Total: {stats.get('total', 0)} / {stats.get('max_entries', 0)} max"),
            *level_badges,
            cls="log-stats-row",
        ),
        Button(
            "Clear Logs",
            hx_post="/admin/logs/clear",
            hx_target="#logs-page",
            hx_swap="outerHTML",
            hx_confirm="Clear all captured logs?",
            cls="btn-secondary btn-small",
        ),
        cls="log-stats-panel",
        style="display: flex; justify-content: space-between; align-items: center; background: var(--bg); padding: 0.75rem 1rem; border-radius: 8px; margin-bottom: 1rem;",
    )


def LogFilters(level_filter: str = "", search_filter: str = ""):
    """Log filtering controls."""
    return Form(
        Div(
            Label("Level:", fr="level"),
            Select(
                Option("All Levels", value="", selected=not level_filter),
                Option("ERROR", value="ERROR", selected=level_filter == "ERROR"),
                Option("WARNING", value="WARNING", selected=level_filter == "WARNING"),
                Option("INFO", value="INFO", selected=level_filter == "INFO"),
                Option("DEBUG", value="DEBUG", selected=level_filter == "DEBUG"),
                name="level",
                id="level",
                cls="settings-input settings-input-small",
            ),
            cls="filter-field",
        ),
        Div(
            Label("Search:", fr="search"),
            Input(
                type="text",
                name="search",
                id="search",
                value=search_filter,
                placeholder="Search in messages...",
                cls="settings-input",
            ),
            cls="filter-field",
        ),
        Button("Filter", type="submit", cls="btn-primary btn-small"),
        Button(
            "Refresh",
            type="button",
            hx_get="/admin/logs",
            hx_target="#logs-page",
            hx_swap="outerHTML",
            cls="btn-secondary btn-small",
        ),
        hx_get="/admin/logs",
        hx_target="#logs-page",
        hx_swap="outerHTML",
        cls="log-filters",
        style="display: flex; gap: 1rem; align-items: end; margin-bottom: 1rem; flex-wrap: wrap;",
    )


def LogEntriesTable(entries: list):
    """Table of log entries."""
    if not entries:
        return Div(
            P("No log entries found.", cls="empty-message"),
            cls="log-entries-empty",
            style="padding: 2rem; text-align: center; color: var(--text-muted);",
        )

    rows = []
    for entry in entries:
        level_cls = f"log-level log-level-{entry.level.lower()}"
        timestamp_str = entry.timestamp.strftime("%Y-%m-%d %H:%M:%S")

        rows.append(
            Tr(
                Td(timestamp_str, cls="log-col-time"),
                Td(Span(entry.level, cls=level_cls), cls="log-col-level"),
                Td(entry.logger_name, cls="log-col-logger"),
                Td(
                    Pre(entry.message, cls="log-message"),
                    cls="log-col-message",
                ),
            )
        )

    return Div(
        Table(
            Thead(
                Tr(
                    Th("Time", cls="log-col-time"),
                    Th("Level", cls="log-col-level"),
                    Th("Logger", cls="log-col-logger"),
                    Th("Message", cls="log-col-message"),
                )
            ),
            Tbody(*rows),
            cls="log-table",
        ),
        cls="log-entries-container",
        style="overflow-x: auto;",
    )
