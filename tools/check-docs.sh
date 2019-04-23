#!/bin/bash

set -e

export LANG=C

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
    diff <(printf "%s\n" "$1" | sed '/^$/d' | sort) \
         <(printf "%s\n" "$2" | sed '/^$/d' | sort) >&2
}

libnm_headers() {
    (
        ls -1 "$1/libnm"/*.h "$1/libnm-core"/*.h | \
        if [ -n "$2" ]; then
            grep -v -F "$1/libnm-core/nm-core-enum-types.h" | \
            grep -v -F "$1/libnm/nm-enum-types.h"
        else
            cat
        fi
        if [ -n "$2" ]; then
            ls -1 "$2/libnm"/*.h "$2/libnm-core"/*.h
        fi
    ) | sort | uniq
}


SOURCEDIR="$1"
BUILDDIR="$2"
if test "$SOURCEDIR" == "$BUILDDIR"; then
    BUILDDIR=
fi
[ -z "$SOURCEDIR" ] && SOURCEDIR='.'


# Check that the D-Bus API docs contain all known interfaces
F1="$(sed -n 's,^      <xi:include href="dbus-\([^"]*\.xml\)"/>$,\1,p' "$SOURCEDIR/docs/api/network-manager-docs.xml")"
F1_EXTRA="
org.freedesktop.NetworkManager.Device.WiMax.xml
org.freedesktop.NetworkManager.WiMax.Nsp.xml
"
F2="$(cd "$SOURCEDIR/introspection"; ls -1 *.xml)"
if ! same_lines "$F1"$'\n'"$F1_EXTRA" "$F2" ; then
    die "*** Error: D-Bus interfaces not included in docs/api/network-manager-docs.xml ***"
fi


# Check that files that define types that are in public libnm API are included in libnm documentation.
F1="$(sed -n 's/.*<xi:include href="xml\/\([^"]*\)\.xml".*/\1/p' "$SOURCEDIR/docs/libnm/libnm-docs.xml")"
F1_EXTRA="
nm-core-enum-types
nm-enum-types
"
F2="$(grep -l "$(sed -n 's/^[\t ]*\(.*_get_type\);/\1/p' "$SOURCEDIR/libnm/libnm.ver" | word_regex)" \
           $(libnm_headers "$SOURCEDIR" "$BUILDDIR") \
      | sed 's,.*/\([^/]\+\)\.h$,\1,')"
F2_EXTRA="
annotation-glossary
api-index-full
nm-dbus-interface
nm-errors
nm-utils
nm-version
"
if ! same_lines "$F1"$'\n'"$F1_EXTRA" "$F2"$'\n'"$F2_EXTRA"; then
    die "*** Error: libnm classes not included in docs/libnm/libnm-docs.xml ***"
fi
