#!/bin/bash

set -e

TOP_DIR="$(dirname "$0")/.."

die() {
    printf 'FAIL: %s\n' "$*" >&2
    exit 1
}

check_cmp() {
    local a="$1"
    local b="$2"

    cmp "$TOP_DIR/$a" "$TOP_DIR/$b" && return 0

    diff "$TOP_DIR/$a" "$TOP_DIR/$b" || :
    die "files \"$a\" and \"$b\" differ!"
}

check_cmp src/libnm-base/nm-ethtool-utils-base.h src/libnm-client-public/nm-ethtool-utils.h
check_cmp src/libnm-core-intern/nm-meta-setting-base-impl.h src/libnmc-setting/nm-meta-setting-base-impl.h
check_cmp src/libnm-core-impl/nm-meta-setting-base-impl.c src/libnmc-setting/nm-meta-setting-base-impl.c
