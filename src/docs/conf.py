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
    'capidocs.kerneldoc',
    'hawkmoth',
]

# Hawkmoth Options

hawkmoth_clang = capidocs.kerneldoc.hawkmoth_include_args()
hawkmoth_clang += ["-I" + os.path.abspath("..")]
hawkmoth_clang += capidocs.kerneldoc.hawkmoth_glob_includes("../../subprojects", "libc*/src")

hawkmoth_root = os.path.abspath('..')

# HTML Options

html_theme = 'sphinx_rtd_theme'
