# Configuration file for the Sphinx documentation builder.

project = "SeqSetup"
copyright = "2025, Pär Larsson"
author = "Pär Larsson"
release = "0.1.0"

extensions = []

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "furo"
html_static_path = ["_static"]

html_logo = "_static/logo.svg"
html_favicon = "_static/logo.svg"

html_theme_options = {
    "source_repository": "https://github.com/parlar/seqsetup",
    "source_branch": "main",
    "source_directory": "docs/",
    "light_css_variables": {
        "color-brand-primary": "#2563eb",
        "color-brand-content": "#1d4ed8",
    },
    "dark_css_variables": {
        "color-brand-primary": "#60a5fa",
        "color-brand-content": "#3b82f6",
    },
    "sidebar_hide_name": False,
    "navigation_with_keys": True,
}
