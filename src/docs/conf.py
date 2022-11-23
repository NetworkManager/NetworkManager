#
# Sphinx Documentation Configuration
#

import re
import os
import sys

import capidocs.kerneldoc
import hawkmoth

# Global Setup

project = 'c-rbtree'

author = 'C-Util Community'
copyright = '2015-2022, C-Util Community'

# Hawkmoth C-Audodoc Setup

capidocs.kerneldoc.hawkmoth_conf()

# Extensions

exclude_patterns = []

extensions = [
    'hawkmoth',
]

# Hawkmoth Options

cautodoc_clang = capidocs.kerneldoc.hawkmoth_include_args()
cautodoc_clang += ["-I" + os.path.abspath("..")]
cautodoc_clang += capidocs.kerneldoc.hawkmoth_glob_includes("../../subprojects", "libc*/src")

cautodoc_root = os.path.abspath('..')

cautodoc_transformations = {
    'kerneldoc': capidocs.kerneldoc.hawkmoth_converter,
}

# HTML Options

html_theme = 'sphinx_rtd_theme'
