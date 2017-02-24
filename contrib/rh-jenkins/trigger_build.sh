#!/bin/bash

die() {
    echo "$@" >&2
    exit 1
}

url_encode() {
    perl -MURI::Escape -e 'print uri_escape($ARGV[0]);' "$*"
}

http_request() {
    if [[ "$DRY_RUN" == "no" ]]; then
        wget -q -O /dev/null "$1"
    fi
}

eval_bool() {
    case "$1" in
        no|No|NO|n|0|false|False|FALSE)
            return 1
            ;;
        yes|Yes|YES|y|1|true|True|TRUE)
            return 0
            ;;
        *)
            if [[ "$2" == 1 ]]; then
                return 0
            else
                return 1
            fi
            ;;
    esac
}

_USER="${_USER-$( git config user.email 2>/dev/null || echo 'unknown' )}"

_TOKEN=nm-build-token-f4bd8bb7eaae

ARGV=("$@")
REFS=()
for i in ${!ARGV[@]}; do
    if [[ "$REMAINING" == 1 ]]; then
        REFS=("${REFS[@]}" "${ARGV[i]}")
    else
        case "${ARGV[i]}" in
            -r|--rpm)
                RPM=true
                ;;
            -R|--no-rpm)
                RPM=false
                ;;
            -d|--distcheck)
                DISTCHECK=true
                ;;
            -D|--no-distcheck)
                DISTCHECK=false
                ;;
            --dist)
                DIST=true
                ;;
            --no-dist)
                DIST=false
                ;;
            -n|--dry-run|--test)
                DRY_RUN=yes
                ;;
            -N|-f|--no-test|--no-dry-run|--force)
                DRY_RUN=no
                ;;
            -c|--check-upstream)
                NO_CHECK_UPSTREAM=no
                ;;
            -C|--no-check-upstream)
                NO_CHECK_UPSTREAM=yes
                ;;
            -u|--check)
                NO_CHECK=no
                ;;
            -U|--no-check)
                NO_CHECK=yes
                ;;
            -o|--out-of-tree)
                OUT_OF_TREE_BUILD=yes
                ;;
            -O|--no-out-of-tree)
                OUT_OF_TREE_BUILD=no
                ;;
            -h|--help|'-?')
                echo "$0 [ -h | -r|--rpm|-R|--no-rpm | -n|--dry-run|--test|-N|-f|--no-test|--force | -u|--check|-U|--no-check -c|--check-upstream|-C|--no-check-upstream | -o|--out-of-tree|-O|--no-out-of-tree | -d|--distcheck|-D|--no-distcheck | --dist|--no-dist ] [--] REFS"
                exit 1
                ;;
            --)
                REMAINING=1
                ;;
            *)
                REFS=("${REFS[@]}" "${ARGV[i]}")
                ;;
        esac
    fi
done

if eval_bool "$NO_CHECK_UPSTREAM" 0; then
    NO_CHECK_UPSTREAM=yes
else
    NO_CHECK_UPSTREAM=no
fi

if eval_bool "$NO_CHECK" 0; then
    NO_CHECK=yes
    _NO_CHECK=true
else
    NO_CHECK=no
    _NO_CHECK=false
fi

if eval_bool "$OUT_OF_TREE_BUILD" 0; then
    OUT_OF_TREE_BUILD=yes
    _OUT_OF_TREE_BUILD=true
else
    OUT_OF_TREE_BUILD=no
    _OUT_OF_TREE_BUILD=false
fi

if eval_bool "$DRY_RUN" 1; then
    DRY_RUN=yes
else
    DRY_RUN=no
fi

if eval_bool "$RPM" 0; then
    RPM=yes
    _RPM=true
else
    RPM=no
    _RPM=false
fi

if eval_bool "$DISTCHECK" 0; then
    DISTCHECK=yes
    _DISTCHECK=true
else
    DISTCHECK=no
    _DISTCHECK=false
fi
__DISTCHECK=$DISTCHECK

if eval_bool "$DIST" 0; then
    DIST=yes
    _DIST=true
else
    DIST=no
    _DIST=false
fi
__DIST=$DIST

if [[ "$RPM" == yes ]]; then
    DISTCHECK=yes
    _DISTCHECK=true
fi
if [[ "$DISTCHECK" == yes ]]; then
    DIST=no
    _DIST=false
fi

if [[ "${#REFS[@]}" -eq 0 ]]; then
    REFS=("$(git symbolic-ref --short HEAD 2>/dev/null || git rev-parse HEAD)")
fi

echo "USER                  : \"$_USER\""
echo "TOKEN                 : \"$_TOKEN\""
echo "NO_CHECK_UPSTREAM     : $NO_CHECK_UPSTREAM"
echo "DRY_RUN               : $DRY_RUN"
echo
echo "OUT_OF_TREE_BUILD     : $OUT_OF_TREE_BUILD"
echo "NO_CHECK              : $NO_CHECK"
if [[ $__DIST != $DIST ]]; then
echo "DIST                  : $DIST (conflicts with DISTCHECK)"
else
echo "DIST                  : $DIST"
fi
if [[ $__DISTCHECK != $DISTCHECK ]]; then
echo "DISTCHECK             : $DISTCHECK (implied by RPM)"
else
echo "DISTCHECK             : $DISTCHECK"
fi
echo "RPM                   : $RPM"

for _BRANCH in "${REFS[@]}"; do
    _B="$(git rev-parse -q --verify "$_BRANCH")" || die "Error parsing revision \"$_BRANCH\""
    if [[ "$NO_CHECK_UPSTREAM" == "no" ]]; then
        if [[ "$FOUND" = "" ]]; then
            echo
            echo "checking that the commits are pushed upstream... disable with NO_CHECK_UPSTREAM..."
        fi
        FOUND=0
        for H in `git for-each-ref --format='%(objectname)' 'refs/remotes/origin/'`; do
            if [[ "$(git merge-base "$H" "$_B")" = "$_B" ]]; then
                FOUND=1
                break
            fi
        done
        [[ "$FOUND" = 1 ]] || die "error: $_BRANCH ($_B) does not seem to be reachable from upstream refs/remotes/origin/*. Did you push it? Set NO_CHECK_UPSTREAM to bypass this check"
    fi
done

i=0
for _BRANCH in "${REFS[@]}"; do
    i=$((i+1))
    i0="`printf '%03d' "$i"`"
    _B="$(git rev-parse "$_BRANCH")"
    CAUSE=${_CAUSE-"build invoked by ${_USER-"unknown"} for rev $_BRANCH"}
    if [[ -n "$CAUSE" ]]; then
        URL_CAUSE="&cause=`url_encode "$CAUSE"`"
    fi
    _URL="http://10.34.130.105:8080/job/NetworkManager/buildWithParameters?token=`url_encode "$_TOKEN"`$URL_CAUSE&BRANCH=`url_encode "$_B"`&RPM=$_RPM&NO_CHECK=$_NO_CHECK&OUT_OF_TREE_BUILD=$_OUT_OF_TREE_BUILD&DIST=$_DIST&DISTCHECK=$_DISTCHECK"
    echo
    echo "BRANCH[$i0]  : \"$_BRANCH\" ($_B)"
    echo "CAUSE[$i0]   : \"$CAUSE\""
    echo "URL[$i0]     : '$_URL'"
    if ! http_request "$_URL"; then
        echo "ERROR making HTTP request"
    fi
done

echo
echo "http://10.34.130.105:8080/job/NetworkManager"
