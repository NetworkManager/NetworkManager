#!/bin/bash

set -e

die() {
    printf '%s\n' "$@" >&2
    exit 1
}

word_regex() {
    tr '\n|<>\\' ' ' \
    | sed -e 's, *$,\\>,' \
          -e 's,^ *,\\<,' \
          -e 's, \+,\\>\\|\\<,g'
}

same_lines() {
    diff <(printf "%s\n" "$1"          | sed '/^$/d' | sort) \
         <(printf "%s\n%s\n" "$2" "$3" | sed '/^$/d' | sort) >&2
}

SOURCEDIR="$1"
[ -n "$SOURCEDIR" ] && SOURCEDIR="$SOURCEDIR/"

# Check that the D-Bus API docs contain all known interfaces
F1="$(sed -n 's,^      <xi:include href="dbus-\([^"]*\.xml\)"/>$,\1,p' "$SOURCEDIR"docs/api/network-manager-docs.xml)"
F2="$(cd "$SOURCEDIR"introspection; ls -1 *.xml)"
if ! same_lines "$F1" "$F2" ; then
    die "*** Error: D-Bus interfaces not included in docs/api/network-manager-docs.xml ***"
fi

# Check that files that define types that are in public libnm API are included in libnm documentation.
F1="$(sed -n 's/.*<xi:include href="xml\/\([^"]*\)\.xml".*/\1/p' "$SOURCEDIR"docs/libnm/libnm-docs.xml)"
F2="$(grep -l "$(sed -n 's/^[\t ]*\(.*_get_type\);/\1/p' "$SOURCEDIR"libnm/libnm.ver | word_regex)" \
           "$SOURCEDIR"libnm/*.h \
           "$SOURCEDIR"libnm-core/*.h \
      | sed 's,.*/\([^/]\+\)\.h$,\1,')"
F2_EXTRA="
annotation-glossary
api-index-full
nm-dbus-interface
nm-errors
nm-utils
nm-version
"
if ! same_lines "$F1" "$F2" "$F2_EXTRA"; then
    die "*** Error: libnm classes not included in docs/libnm/libnm-docs.xml ***"
fi
