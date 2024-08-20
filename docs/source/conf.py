# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'siotls'
copyright = '2024, Julien Castiaux'
author = 'Julien Castiaux'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    "sphinx.ext.autodoc",
]

templates_path = ['_templates']
exclude_patterns = []



# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'furo'
html_static_path = ['_static']


# custom
autodoc_type_aliases = {
    "PrivateKeyTypes": "cryptography.hazmat.primitives.asymmetric.types.PrivateKeyTypes",
    "PublicKeyTypes": "cryptography.hazmat.primitives.asymmetric.types.PublicKeyTypes",
}
autodoc_class_signature = "separated"
autodoc_typehints = "description"
python_maximum_signature_line_length = 80
python_display_short_literal_types = True
