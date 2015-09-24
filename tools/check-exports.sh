#!/bin/sh

LC_ALL=C
export LC_ALL

stat=0
so="$1"
def="$2"
PATTERN="_ANCHOR_"

TMPFILE="$(mktemp .nm-check-exports.XXXXXX)"


get_syms() {
    ${NM:-nm} "$1" |
    sed -n 's/^[[:xdigit:]]\+ [DT] //p' |
    sort
}

get_syms_from_def() {
    sed -n 's/^\t\(\([_a-zA-Z0-9]\+\)\|#\s*\([_a-zA-Z0-9]\+@@\?[_a-zA-Z0-9]\+\)\);$/\2\3/p' "$1" |
    sort
}

anchor() {
    sed "s/.*/$PATTERN\0$PATTERN/"
}

unanchor() {
    sed "s/^$PATTERN\(.*\)$PATTERN\$/\1/"
}


get_syms "$so" | anchor > "$TMPFILE"
WRONG="$(get_syms_from_def "$def" | anchor | grep -F -f - "$TMPFILE" -v)"
RESULT=$?
if [ $RESULT -eq 0 ]; then
    stat=1
    echo ">>library \"$so\" exports symbols that are not in linker script \"$def\":"
    echo "$WRONG" | unanchor | nl
fi

get_syms_from_def "$def" | anchor > "$TMPFILE"
WRONG="$(get_syms "$so" | anchor | grep -F -f - "$TMPFILE" -v)"
RESULT=$?
if [ $RESULT -eq 0 ]; then
    stat=1
    echo ">>linker script \"$def\" contains symbols that are not exported by library \"$so\":"
    echo "$WRONG" | unanchor | nl
fi

rm -rf "$TMPFILE"
exit $stat

