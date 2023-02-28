#!/bin/bash

set -e

die() {
    printf "%s\n" "$*" >&2
    exit 1
}

cd "$(dirname "$(readlink -f "$0")")/.." || die "cannot change to srcdir"

AUTOPTR_H=./src/libnm-client-public/nm-autoptr.h

for s in $( sed -n 's/^ *typedef \+struct \+.*[A-Za-z0-9_]\+ \+\(NMSetting[A-Za-z0-9_]\+\)\> *;$/\1/p' ./src/libnm-core-public/nm-core-types.h ) ; do
    grep -q "^ *G_DEFINE_AUTOPTR_CLEANUP_FUNC *( *\\<$s\\> *, *g_object_unref *)" -- "$AUTOPTR_H" || die "didn't see setting '$s' in \"$AUTOPTR_H\""
done

for s in $( grep -h -o '\<NMDevice[A-Za-z0-9_]\+\>' ./src/libnm-client-public/nm-device-*.h | sort -u | grep -v 'Class$') ; do
    case "$s" in
        NMDeviceModemCapabilities| \
        NMDeviceWifiCapabilities)
            continue
            ;;
    esac
    grep -q "^ *G_DEFINE_AUTOPTR_CLEANUP_FUNC *( *\\<$s\\> *, *g_object_unref *)" -- "$AUTOPTR_H" || die "didn't see device '$s' in \"$AUTOPTR_H\""
done
