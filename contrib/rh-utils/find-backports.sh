#!/bin/bash

die() {
    echo "$@" >&2
    exit 1
}

print_usage() {
    echo "$0 [REF_BASE REF_STABLE REF_UPSTREAM ...]"
    echo "   for example $0 1.1.0-dev~ nm-1-0 master"
}

ref_exists() {
    git rev-parse --verify "$1" &> /dev/null
}

get_cherry_picked_from() {
    local H="$1"
    local B

    for B in $(git log -n1 "$H" 2>&1 | sed -n -e 's/.*cherry.picked.*\<\([0-9a-f]\{6,40\}\)\>.*/\1/p'); do
        if ref_exists "$B"; then
            echo $B

            # if the original patch was cherry-picked too, continue
            # recursively.
            get_cherry_picked_from "$B"
        fi
    done
}

get_backported_all() {
    local RANGE="$1"
    local H

    for H in $(git log --pretty="%H" "$RANGE"); do
        get_cherry_picked_from "$H"
    done |
    sort | uniq
}

get_fixes() {
    local RANGE="$1"
    local BACKPORTED="$2"
    local H B

    for H in $BACKPORTED; do
        for B in $(git log --format="%H" --no-walk --grep '[Ff]ixes: *'"${H:0:7}" "$RANGE"); do
            echo "$B"

            # if commit $B fixes $H, and commit $B was itself backported (cherry-picked),
            # then also all original versions of $B fix $H.
            get_cherry_picked_from "$B"
        done
    done |
    sort | uniq
}

if [ "$#" -lt 3 -a "$#" -ne 0 ]; then
    print_usage
    die "Wrong arguments"
fi

if [ "$#" -ge 3 ]; then
    REF_BASE="$1"
    REF_STABLE="$2"
    shift
    shift
    REFS_UPSTREAM=( "$@" )
else
    REF_BASE=1.1.0-dev~
    REF_STABLE=nm-1-0
    REFS_UPSTREAM=( master )
fi

ref_exists "$REF_BASE" || die "Invalid REF_BASE=\"$REF_BASE\""
for R in "${REFS_UPSTREAM[@]}"; do
    ref_exists "$R"  || die "Invalid REF_UPSTREAM=\"$R\""
done
ref_exists "$REF_STABLE"  || die "Invalid REF_STABLE=\"$REF_STABLE\""

BACKPORTED="$(get_backported_all "$REF_BASE..$REF_STABLE")"

FIXES="$(
    for R in "${REFS_UPSTREAM[@]}"; do
        get_fixes "$REF_BASE..$R" "$BACKPORTED"
    done | sort | uniq)"

MISSING_BACKPORTS="$(printf '%s' "$FIXES" | grep $(printf '%s' "$BACKPORTED" | sed 's/^/-e /') - -v)"
if [ -n "$MISSING_BACKPORTS" ]; then
    git log -p --no-walk $(echo "$MISSING_BACKPORTS")
    printf "%s\n" "$MISSING_BACKPORTS"
fi
