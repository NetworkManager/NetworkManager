#!/bin/sh

# Extract NM_DEPRECATED_IN_* and NM_AVAILABLE_IN_* macros from a
# header file and output them in a way suitable to be passed to
# 'gtkdoc-scan --ignore-decorators'

grep -o "NM_DEPRECATED_IN_[0-9]_[0-9]\+$\|NM_AVAILABLE_IN_[0-9]_[0-9]\+$" "$1" | sed ':a;N;$!ba;s/\n/|/g'
