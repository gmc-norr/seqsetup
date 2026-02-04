"""Layout components for the application shell."""

from fasthtml.common import *

from ..models.user import User


def AppShell(user: User, active_route: str, content, title: str = "SeqSetup"):
    """
    Main application shell with header and sidebar navigation.

    Args:
        user: The authenticated user
        active_route: Current active route for highlighting nav items
        content: The main content to display
        title: Page title
    """
    return (
        Title(f"{title} - SeqSetup"),
        Main(
            AppHeader(user),
            Div(
                Sidebar(user, active_route),
                Div(content, cls="main-content"),
                cls="app-shell",
            ),
            cls="app-container",
        ),
    )


def AppHeader(user: User):
    """Application header with logo and user info."""
    return Header(
        Div(
            Img(src="/img/favicon.svg", alt="SeqSetup", width="32", height="32", cls="app-logo"),
            Span("SeqSetup", cls="app-brand-text"),
            cls="app-brand",
        ),
        Div(
            Span(f"Logged in as: {user.display_name}", cls="username"),
            A("Logout", href="/logout"),
            cls="user-info",
        ) if user else None,
        cls="app-header",
    )


def Sidebar(user: User, active: str):
    """
    Left sidebar navigation.

    Args:
        user: The authenticated user
        active: Current active route path
    """
    is_admin = user is not None and user.is_admin

    return Nav(
        NavItem("Dashboard", "/", active=(active == "/")),
        A(
            "+ New Run",
            href="/runs/new",
            cls="btn btn-primary sidebar-btn",
        ),
        Hr(cls="sidebar-divider"),
        SettingsSection(active),
        AdminSection(active) if is_admin else None,
        cls="sidebar",
    )


def SettingsSection(active_route: str):
    """
    Collapsible settings section with Index Kits and Tests sub-items.

    Args:
        active_route: Current active route path for auto-expanding
    """
    is_open = active_route in ["/indexes", "/profiles"]
    return Details(
        Summary("Settings"),
        Nav(
            NavItem("Index Kits", "/indexes", active=(active_route == "/indexes")),
            NavItem("Profiles", "/profiles", active=(active_route == "/profiles")),
            cls="settings-subnav",
        ),
        open=is_open,
        cls="settings-section",
    )


def AdminSection(active_route: str):
    """
    Collapsible admin section (only shown to admins).

    Args:
        active_route: Current active route path for auto-expanding
    """
    is_open = active_route is not None and active_route.startswith("/admin")
    return Details(
        Summary("Admin"),
        Nav(
            NavItem("Users", "/admin/users", active=(active_route == "/admin/users")),
            NavItem("Authentication", "/admin/authentication", active=(active_route == "/admin/authentication")),
            NavItem("Instruments", "/admin/instruments", active=(active_route == "/admin/instruments")),
            NavItem("Config Sync", "/admin/config-sync", active=(active_route == "/admin/config-sync")),
            NavItem("API Tokens", "/admin/api-tokens", active=(active_route == "/admin/api-tokens")),
            NavItem("LIMS Integration", "/admin/sample-api", active=(active_route == "/admin/sample-api")),
            NavItem("Logs", "/admin/logs", active=(active_route == "/admin/logs")),
            cls="settings-subnav",
        ),
        open=is_open,
        cls="settings-section admin-section",
    )


def NavItem(label: str, href: str, active: bool = False):
    """
    Navigation item for the sidebar.

    Args:
        label: Display text
        href: Link destination
        active: Whether this item is currently active
    """
    cls = "nav-item active" if active else "nav-item"
    return A(label, href=href, cls=cls)
