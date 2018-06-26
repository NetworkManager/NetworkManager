#!/bin/sh

SOURCEDIR=$1
[ -n "$SOURCEDIR" ] && SOURCEDIR="$SOURCEDIR/"

# Check that the D-Bus API docs contain all known interfaces
if (sed -n 's/.*<xi:include href="dbus-\(.*\.xml\)".*/\1\n\1/p' $SOURCEDIR''docs/api/network-manager-docs.xml;
    cd $SOURCEDIR''introspection; ls *.xml) |sort |uniq -u| grep . >&2; then
	echo "*** Error: D-Bus interfaces not included in docs/api/network-manager-docs.xml ***" >&2
	exit 1
fi

# Check that files that define types that are in public libnm API are included in libnm documentation.
# Don't complain about readability or I'll rewrite this in Perl.
if (sed -n 's/.*<xi:include href="\(xml\/.*\.xml\)".*/\1\n\1/p' $SOURCEDIR''docs/libnm/libnm-docs.xml;
    grep -lE "$(sed -n 's/^[\t ]*\(.*_get_type\);/\1/p' $SOURCEDIR''libnm/libnm.ver |xargs echo |sed 's/ /|/g')" $SOURCEDIR''libnm{,-core}/*.h |
    sed 's,.*/,xml/,;s/\.h$/.xml/') |sort |uniq -u| grep . >&2; then
	echo "*** Error: libnm classes not included in docs/libnm/libnm-docs.xml ***" >&2
	exit 1
fi

exit 0
