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
    git rev-parse --verify "$1" &> /dev/null && return 0
    [[ -n "$2" ]] && ref_exists "$2/$1"
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

REF_BASE=
if ( ! ref_exists "$1" ) && [[ "$1" =~ ^[1-9][0-9]*\.[1-9][0-9]*$ ]]; then
    V_MAJ="$(echo "$1" | sed 's/\..*//')"
    V_MIN="$(echo "$1" | sed 's/.*\.//')"
    if ref_exists "refs/tags/$V_MAJ.$V_MIN.0"; then
        REF_BASE="refs/tags/$V_MAJ.$V_MIN.0"
        REF_STABLE="nm-$V_MAJ-$V_MIN"
        if ! ref_exists "$REF_STABLE" && ref_exists "refs/remotes/origin/$REF_STABLE"; then
            REF_STABLE="refs/remotes/origin/$REF_STABLE"
        fi
        shift
        if [ "$#" -eq 0 ]; then
            REFS_UPSTREAM=()
            V_MIN=$((V_MIN + 2))
            NEXT="nm-$V_MAJ-$V_MIN"
            while ref_exists "$NEXT" "refs/remotes/origin"; do
                if ! ref_exists "$NEXT" ; then
                    NEXT="refs/remotes/origin/$NEXT"
                fi
                REFS_UPSTREAM=( "${REFS_UPSTREAM[@]}" "$NEXT" )
                V_MIN=$((V_MIN + 2))
                NEXT="nm-$V_MAJ-$V_MIN"
            done
            for NEXT in master refs/remotes/origin/master; do
                if ref_exists "$NEXT"; then
                    REFS_UPSTREAM=( "${REFS_UPSTREAM[@]}" "$NEXT" )
                    break;
                fi
            done
        else
            REFS_UPSTREAM=( "$@")
        fi
    fi
fi
if [ -n "$REF_BASE" ]; then
    echo "### $0 $REF_BASE $REF_STABLE ${REFS_UPSTREAM[@]}"
elif [ "$#" -ge 3 ]; then
    REF_BASE="$1"
    REF_STABLE="$2"
    shift
    shift
    REFS_UPSTREAM=( "$@" )
elif [ "$#" -eq 0 ]; then
    REF_BASE=1.1.0-dev~
    REF_STABLE=nm-1-0
    REFS_UPSTREAM=( master )
else
    print_usage
    die "Wrong arguments"
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
