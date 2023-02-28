#!/bin/bash

set -e

die() {
    printf "%s\n" "$*" >&2
    exit 1
}

cd "$(dirname "$(readlink -f "$0")")/.." || die "cannot change to srcdir"

VAPI=./vapi/NM-1.0.metadata

for s in $(grep -r -h '#define \+\<NM_SETTING_.*SETTING_NAME\>' -- ./src/libnm-core-public/ \
           | sed -n 's/^#define \+NM_\(SETTING_[A-Z0-9_]\+\)_SETTING_NAME\> \+.*/\1/p') ; do
    grep -q "^$s" -- "$VAPI" || die "didn't see '$s' in \"$VAPI\""
done

for f in ./src/libnm-client-public/nm-device-*.h ; do
    D=( $(sed -n 's/^#define \+NM_IS_DEVICE_\([A-Z0-9_]\+\)_CLASS\>(.*/\1/p' "$f") )
    test ${#D[@]} = 1 || die "did not detect device in \"$f\""
    s="${D[0]}"
    c="$(grep -c "^DEVICE_${s}_\* *parent=" -- "$VAPI")"
    test "$c" = 1 || die "didn't see device '$s' in \"$VAPI\""
done
