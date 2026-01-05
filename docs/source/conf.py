# Configuration file for Sphinx documentation builder
import os
import sys
from datetime import datetime

# Add KHA-256 to Python path
sys.path.insert(0, os.path.abspath('../..'))

# Project information
project = 'KHA-256'
copyright = f'{datetime.now().year}, Mehmet Keçeci'
author = 'Mehmet Keçeci'

# The full version, including alpha/beta/rc tags
try:
    import kha256
    release = kha256.__version__
except ImportError:
    release = '0.1.2'

# Sphinx extensions
extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
    'sphinx.ext.viewcode',
    'sphinx.ext.intersphinx',
    'sphinx.ext.mathjax',
    'sphinx.ext.todo',
    'sphinx.ext.coverage',
    'sphinx.ext.githubpages',
    'sphinx.ext.autosectionlabel',
    'sphinx_rtd_theme',
    'myst_parser',
    'sphinx_copybutton',
    'sphinx.ext.autosummary',
    'sphinx.ext.graphviz',
    'sphinx.ext.inheritance_diagram',
]

# MyST extensions
myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "dollarmath",
    "amsmath",
    "fieldlist",
    "html_admonition",
    "html_image",
    "replacements",
    "smartquotes",
    "substitution",
    "tasklist",
]

# Templates
templates_path = ['_templates']

# Exclude patterns
exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']

# The suffix of source filenames
source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown',
}

# The master toctree document
master_doc = 'index'

# Language
language = 'en'

# HTML theme options
html_theme = 'sphinx_rtd_theme'
html_theme_options = {
    'logo_only': True,
    'display_version': True,
    'prev_next_buttons_location': 'bottom',
    'style_external_links': True,
    'style_nav_header_background': '#343131',
    # Toc options
    'collapse_navigation': False,
    'sticky_navigation': True,
    'navigation_depth': 4,
    'includehidden': True,
    'titles_only': False,
}

# Logo
html_logo = '_static/logo.png'
html_favicon = '_static/favicon.ico'

# Static files
html_static_path = ['_static']
html_css_files = ['custom.css']

# Extra options for HTML output
html_show_sourcelink = True
html_show_sphinx = True
html_show_copyright = True

# Latex options
latex_elements = {
    'papersize': 'a4paper',
    'pointsize': '11pt',
    'figure_align': 'htbp',
    'sphinxsetup': '''
        hmargin={1in,1in},
        vmargin={1in,1in},
        verbatimwithframe=false,
        VerbatimColor={HTML}{F5F5F5},
        TitleColor={HTML}{2C3E50},
        InnerLinkColor={HTML}{2980B9},
        OuterLinkColor={HTML}{2980B9},
    ''',
    'preamble': r'''
        \usepackage{fontspec}
        \setmainfont{DejaVu Serif}
        \setsansfont{DejaVu Sans}
        \setmonofont{DejaVu Sans Mono}
        \usepackage{xcolor}
        \usepackage{amsmath}
        \usepackage{amssymb}
        \usepackage{unicode-math}
        \usepackage{microtype}
        \usepackage{bookmark}
        \usepackage{hyperref}
        \hypersetup{
            colorlinks=true,
            linkcolor=blue,
            filecolor=magenta,
            urlcolor=cyan,
            pdftitle={KHA-256 Documentation},
            pdfauthor={Mehmet Keçeci},
        }
    ''',
    'maketitle': r'''
        \begin{titlepage}
            \centering
            \vspace*{2cm}
            {\Huge\textbf{KHA-256 Documentation}\par}
            \vspace{1cm}
            {\Large Keçeci Hash Algorithm (256-bit)\par}
            \vspace{2cm}
            {\Large Version ''' + release + r'''\par}
            \vspace{2cm}
            {\Large Mehmet Keçeci\par}
            \vspace{1cm}
            {\large \today\par}
            \vfill
            \includegraphics[width=0.3\textwidth]{logo.png}
        \end{titlepage}
    ''',
}

# Latex document structure
latex_documents = [
    (master_doc, 'kha256.tex', 'KHA-256 Documentation',
     'Mehmet Keçeci', 'manual'),
]

# EPUB options
epub_title = project
epub_author = author
epub_publisher = author
epub_copyright = copyright
epub_exclude_files = ['search.html']

# Intersphinx mapping
intersphinx_mapping = {
    'python': ('https://docs.python.org/3', None),
    'numpy': ('https://numpy.org/doc/stable/', None),
}

# AutoDoc options
autodoc_default_options = {
    'members': True,
    'member-order': 'bysource',
    'special-members': '__init__',
    'undoc-members': True,
    'exclude-members': '__weakref__',
    'show-inheritance': True,
    'inherited-members': True,
}

autodoc_typehints = 'description'
autodoc_class_signature = 'separated'
autodoc_member_order = 'bysource'

# Napoleon settings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = True
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = True
napoleon_use_admonition_for_notes = True
napoleon_use_admonition_for_references = True
napoleon_use_ivar = True
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_use_keyword = True
napoleon_preprocess_types = True
napoleon_type_aliases = None
napoleon_attr_annotations = True

# Todo settings
todo_include_todos = True

# Copybutton settings
copybutton_prompt_text = r">>> |\.\.\. |\$ |In \[\d*\]: | {2,5}\.\.\.: | {5,8}: "
copybutton_prompt_is_regexp = True
copybutton_line_continuation_character = "\\"
copybutton_here_doc_delimiter = "EOF"
copybutton_copy_empty_lines = False
copybutton_remove_prompts = True

# Add custom CSS
def setup(app):
    app.add_css_file('custom.css')
