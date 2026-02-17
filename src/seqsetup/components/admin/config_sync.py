"""Configuration sync components for profiles and instruments."""

from typing import Optional

from fasthtml.common import *

from ...models.profile_sync_config import ProfileSyncConfig
from ...models.application_profile import ApplicationProfile
from ...models.test_profile import TestProfile


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
    icon = "\u2713" if success else "\u2717"

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
