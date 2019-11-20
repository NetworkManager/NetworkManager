#!/bin/bash

set -e

die() {
    echo "$@"
    exit 1
}

if [[ "x$(LANG=C git clean -ndx)" != x ]]; then
    die "The working directory is not clean. Refuse to run. Try \`git clean -dx -n\`"
fi
if [[ "x$(git status --porcelain)" != x ]]; then
    die "The working directory has local changes. Refuse to run. Try \`git reset --hard\`"
fi

build_out_of_tree() {
  local TARGET="$1"
  local C="$2"
  local M="$3"
  (
    git clean -fdx || return 1
    NOCONFIGURE=x ./autogen.sh || return 1
    mkdir -p x/y || return 1
    cd x/y || return 1
    ../../configure $C $NMTST_CONFIGURE || return 1
     make $TARGET $M $NMTST_MAKE || return 1
  )
}

TARGETS=("$@")
if [ "${#TARGETS}" -lt 1 ]; then
    TARGETS=(
        src/NetworkManager
        src/nm-iface-helper
        src/dhcp/nm-dhcp-helper
        dispatcher/nm-dispatcher
        clients/nm-online
        clients/cli/nmcli
        clients/tui/nmtui
        src/platform/tests/monitor
        src/ndisc/tests/test-ndisc-linux
        $(git grep -h '\.l\?a\>' Makefile.am | sed 's/[a-zA-Z.0-9_-/]\+/\n\0\n/g' | sort -u | grep '\.l\?a$')
    )
fi

set -x

cd "$(dirname "$(readlink -f "$0")")/.."

IDX=($(seq 0 $((${#TARGETS[@]} - 1))))
IDX=($(printf '%s\n' "${IDX[@]}" | sort -R))
for idx in "${IDX[@]}"; do
    TARGET="${TARGETS[$idx]}"
    echo "### $idx: TARGET=$TARGET"
    build_out_of_tree "$TARGET" "--enable-gtk-doc" "-j 5"
done
