"""Profiles page components."""

from typing import Optional

from fasthtml.common import *

from ..models.application_profile import ApplicationProfile
from ..models.test_profile import TestProfile
from ..services.version_resolver import resolve_application_profiles


def ProfilesPage(
    test_profiles: list[TestProfile],
    app_profiles: list[ApplicationProfile],
    resolved_map: Optional[dict] = None,
):
    """
    Profiles overview page showing test profiles and application profiles.

    Args:
        test_profiles: List of test profiles
        app_profiles: List of application profiles
        resolved_map: Pre-computed resolved application profile map. If None,
                     computes it internally as fallback.
    """
    # Use pre-computed map or compute as fallback
    if resolved_map is None:
        # Collect all references across all test profiles
        all_refs = []
        for tp in test_profiles:
            all_refs.extend(tp.application_profiles)
        # Resolve version constraints to concrete application profiles
        resolved_map = resolve_application_profiles(all_refs, app_profiles)

    return Div(
        H2("Profiles"),
        P(
            "Test profiles define sequencing test types and their associated application profiles. "
            "Application profiles configure DRAGEN pipeline settings for samplesheet export.",
            cls="page-description",
        ),
        TestProfilesSection(test_profiles, resolved_map),
        ApplicationProfilesSection(app_profiles),
        cls="profiles-page",
    )


def TestProfilesSection(
    test_profiles: list[TestProfile],
    resolved_map: dict,
):
    """Section showing all test profiles with their resolved application profiles."""
    if not test_profiles:
        return Div(
            H3("Test Profiles"),
            P("No test profiles available. Sync profiles from Admin > Profiles.", cls="empty-message"),
            cls="profiles-section",
        )

    cards = []
    for tp in sorted(test_profiles, key=lambda t: t.test_type):
        # Build application profile reference list
        app_refs = []
        for ref in tp.application_profiles:
            ap = resolved_map.get((ref.profile_name, ref.profile_version))
            if ap:
                sw_version = ap.settings.get("SoftwareVersion", "") if ap.settings else ""
                app_refs.append(
                    Tr(
                        Td(ref.profile_name),
                        Td(ref.profile_version),
                        Td(f"v{ap.version}"),
                        Td(ap.application_name),
                        Td(ap.application_type),
                        Td(sw_version or "—"),
                    )
                )
            else:
                app_refs.append(
                    Tr(
                        Td(ref.profile_name),
                        Td(ref.profile_version),
                        Td("—", style="color: var(--text-muted);"),
                        Td("—", colspan="3", style="color: var(--text-muted);"),
                    )
                )

        app_table = Table(
            Thead(
                Tr(
                    Th("Profile Name"),
                    Th("Constraint"),
                    Th("Resolved"),
                    Th("Application"),
                    Th("Type"),
                    Th("Software Version"),
                )
            ),
            Tbody(*app_refs),
            cls="sample-table",
        ) if app_refs else P("No application profiles assigned.", style="color: var(--text-muted);")

        cards.append(
            Div(
                Fieldset(
                    Legend(f"{tp.test_name} (v{tp.version})"),
                    Dl(
                        Dt("Test Type:"),
                        Dd(tp.test_type),
                        Dt("Description:"),
                        Dd(tp.description or "—"),
                        cls="summary-list",
                        style="margin-bottom: 0.75rem;",
                    ),
                    H4("Application Profiles", style="margin: 0.5rem 0 0.25rem;"),
                    app_table,
                ),
                cls="profile-card",
                style="margin-bottom: 1rem;",
            )
        )

    return Div(
        H3(f"Test Profiles ({len(test_profiles)})"),
        *cards,
        cls="profiles-section",
    )


def ApplicationProfilesSection(app_profiles: list[ApplicationProfile]):
    """Section showing all application profiles."""
    if not app_profiles:
        return Div(
            H3("Application Profiles"),
            P("No application profiles available. Sync profiles from Admin > Profiles.", cls="empty-message"),
            cls="profiles-section",
            style="margin-top: 1.5rem;",
        )

    rows = []
    for ap in sorted(app_profiles, key=lambda a: (a.application_name, a.name)):
        sw_version = ap.settings.get("SoftwareVersion", "")

        # Summarize remaining settings (exclude SoftwareVersion since it has its own column)
        other_settings = {k: v for k, v in ap.settings.items() if k != "SoftwareVersion"}
        settings_summary = ", ".join(
            f"{k}: {v}" for k, v in list(other_settings.items())[:3]
        )
        if len(other_settings) > 3:
            settings_summary += ", ..."

        rows.append(
            Tr(
                Td(ap.name),
                Td(f"v{ap.version}"),
                Td(ap.application_name),
                Td(ap.application_type),
                Td(sw_version or "—"),
                Td(settings_summary or "—", style="font-size: 0.85em;"),
            )
        )

    return Div(
        H3(f"Application Profiles ({len(app_profiles)})"),
        Table(
            Thead(
                Tr(
                    Th("Profile Name"),
                    Th("Version"),
                    Th("Application"),
                    Th("Type"),
                    Th("Software Version"),
                    Th("Settings"),
                )
            ),
            Tbody(*rows),
            cls="sample-table",
        ),
        cls="profiles-section",
        style="margin-top: 1.5rem;",
    )
