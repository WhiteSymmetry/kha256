# -*- coding: utf-8 -*-
"""Sphinx configuration for KHA-256."""

import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.abspath('../..'))

project = 'KHA-256'
author = 'Mehmet Keçeci'
copyright = f"{datetime.now().year}, {author}"
release = '0.3.1'
version = '0.3.1'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    'sphinx.ext.todo',
    'sphinx.ext.mathjax',
]

autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
    'undoc-members': True,
    'show-inheritance': True,
}
autodoc_typehints = 'description'
autosummary_generate = True

napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True

templates_path = ['_templates']
source_suffix = {'.rst': 'restructuredtext'}
master_doc = 'index'
language = 'en'
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
pygments_style = 'sphinx'

# HTML Output - RTD Theme
html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'navigation_depth': 4,
    'collapse_navigation': False,
    'sticky_navigation': True,
    'includehidden': True,
    'titles_only': False,
    # 'display_version': True,  ← RTD v2+ artık desteklemiyor, kaldırıldı
    'prev_next_buttons_location': 'bottom',
}
html_static_path = ['_static']
html_logo = None  # Logo yoksa None bırakın
html_show_sourcelink = True
html_show_sphinx = False

# Suppress specific warnings
suppress_warnings = [
    'ref.ref',           # Referans uyarıları
    'ref.numref',        # Numaralı referanslar
    'toc.not_readable',  # TOC uyarıları
    'app.add_directive', # Direktif çakışmaları
    'autodoc',           # Autodoc duplicate uyarıları ← EKLENDİ
]

# Autodoc duplicate uyarılarını özel olarak yönet
autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
    'undoc-members': True,
    'show-inheritance': True,
    'no-index': False,  # Duplicate'lar için index oluştur
    'ignore-module-all': True,  # __all__ listesini yoksay
}

intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
}
