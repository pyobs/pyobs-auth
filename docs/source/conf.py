# Configuration file for the Sphinx documentation builder.
#
# This file does only contain a selection of the most common options. For a
# full list see the documentation:
# http://www.sphinx-doc.org/en/stable/config

# -- Path setup --------------------------------------------------------------

import os
import sys

sys.path.insert(0, os.path.abspath("../../"))

# -- Django --------------------
# pyobs_auth has no models of its own, so a full settings module isn't needed - just enough
# to satisfy django.setup() for autodoc to import views.py/authentication.py.
import django
from django.conf import settings

settings.configure(
    INSTALLED_APPS=[
        "django.contrib.auth",
        "django.contrib.contenttypes",
        "django.contrib.sessions",
        "pyobs_auth",
    ]
)
django.setup()

# -- Project information -----------------------------------------------------

project = "pyobs-auth"
copyright = "2026, Tim-Oliver Husser"
author = "Tim-Oliver Husser"

# -- General configuration ---------------------------------------------------

add_module_names = False

extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.githubpages",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.autosectionlabel",
]

# napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_use_param = False
napoleon_use_ivar = True

# show c'tor parameters in class only
autoclass_content = "both"

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

source_suffix = ".rst"
master_doc = "index"
language = "en"
exclude_patterns = []
pygments_style = "sphinx"

# Be a little nitpicky
nitpicky = True
nitpick_ignore = [
    # base/parameter classes from third-party packages we don't have intersphinx inventories for
    ("py:class", "requests.sessions.Session"),
    ("py:class", "rest_framework.authentication.BaseAuthentication"),
    ("py:class", "django.views.generic.base.View"),
    # autodoc mis-renders KeycloakSettings.scopes' `tuple[str, ...]` annotation as a broken xref
    ("py:class", "'tuple[str"),
]

# -- Options for HTML output -------------------------------------------------

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "collapse_navigation": False,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "display_version": False,
    "logo_only": False,
    "prev_next_buttons_location": "bottom",
    "titles_only": False,
    "style_nav_header_background": "#cccccc",
}
html_logo = "_static/pyobs.gif"
