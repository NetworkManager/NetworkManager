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

check_cmp shared/nm-base/nm-ethtool-utils-base.h libnm/nm-ethtool-utils.h
