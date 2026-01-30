# Configuration file for the Sphinx documentation builder.

project = "SeqSetup"
copyright = "2025, Pär Larsson"
author = "Pär Larsson"
release = "0.1.0"

extensions = []

templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]

html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]

html_logo = "_static/logo.svg"
html_favicon = "_static/logo.svg"

html_theme_options = {
    "navigation_depth": 3,
    "collapse_navigation": False,
    "logo_only": False,
}
