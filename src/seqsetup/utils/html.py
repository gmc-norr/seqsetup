"""HTML and JavaScript escaping utilities."""

import html as html_module


def escape_js_string(value: str) -> str:
    """
    Escape a string for safe use in JavaScript string literals within HTML attributes.

    This prevents XSS attacks when embedding user data in onclick handlers.

    Args:
        value: The string to escape

    Returns:
        Escaped string safe for JavaScript string literals
    """
    if not value:
        return ""
    # Escape backslashes first, then single quotes (for JS strings)
    # Also escape newlines and other control characters
    value = value.replace("\\", "\\\\")
    value = value.replace("'", "\\'")
    value = value.replace('"', '\\"')
    value = value.replace("\n", "\\n")
    value = value.replace("\r", "\\r")
    value = value.replace("<", "\\x3c")  # Prevent breaking out of script context
    value = value.replace(">", "\\x3e")
    return value


def escape_html_attr(value: str) -> str:
    """
    Escape a string for safe use in HTML attributes.

    Args:
        value: The string to escape

    Returns:
        Escaped string safe for HTML attributes
    """
    return html_module.escape(value, quote=True) if value else ""
