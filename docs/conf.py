from os import path
import sys
sys.path.insert(0, path.abspath('ext'))

# -- Project information -----------------------------------------------------

repository = 'linux-security-vulns'
project = 'Linux Security Vulns'
copyright = '2026, Analog Devices, Inc.'
author = 'Analog Devices, Inc.'

locale_dirs = ['locales/']  # path is relative to the source directory
language = 'en'

# -- General configuration ---------------------------------------------------

extensions = [
    'adi_doctools',
    'sphinx.ext.intersphinx',
    'sphinx.ext.todo',
    'ext_stats',
]

needs_extensions = {
    'adi_doctools': '0.4.40'
}

exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
source_suffix = '.rst'

# -- External docs configuration ----------------------------------------------

interref_repos = [
]

intersphinx_mapping = {
    'upstream': ('https://docs.kernel.org', None),
}

# -- Options for HTML output --------------------------------------------------

html_theme = 'harmonic'

html_theme_options = {}

html_static_path = ["sources"]
html_favicon = path.join("sources", "icon.svg")
