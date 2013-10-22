#!/bin/bash

die() {
    echo "$@" >&2
    exit 1
}

url_encode() {
    perl -MURI::Escape -e 'print uri_escape($ARGV[0]);' "$*"
}

http_request() {
    if [[ "$DRY_RUN" = "" ]]; then
        wget -q -O /dev/null "$1"
    fi
}

_USER="${_USER-$( git config user.email 2>/dev/null || echo 'unknown' )}"

_TOKEN=nm-build-token-f4bd8bb7eaae


if [[ "$DRY_RUN" != "" ]]; then
    DRY_RUN=yes
fi

echo "USER         : \"$_USER\""
echo "TOKEN        : \"$_TOKEN\""
echo "DRY_RUN      : ${DRY_RUN:-no}"

for _BRANCH; do
    git rev-parse --verify -q "$_BRANCH" >/dev/null || die "Error parsing revision \"$_BRANCH\""
done

i=0
for _BRANCH; do
    i=$((i+1))
    i0="`printf '%03d' "$i"`"
    _B="$(git rev-parse "$_BRANCH")"
    CAUSE=${_CAUSE-"build invoked by ${_USER-"unknown"} for rev $_BRANCH"}
    if [[ -n "$CAUSE" ]]; then
        URL_CAUSE="&cause=`url_encode "$CAUSE"`"
    fi
    _URL="http://10.34.131.51:8080/job/NetworkManager/buildWithParameters?token=`url_encode "$_TOKEN"`$URL_CAUSE&BRANCH=`url_encode "$_B"`"
    echo
    echo "BRANCH[$i0]  : \"$_BRANCH\" ($_B)"
    echo "CAUSE[$i0]   : \"$CAUSE\""
    echo "URL[$i0]     : '$_URL'"
    if ! http_request "$_URL"; then
        echo "ERROR making HTTP request"
    fi
done

echo
echo "http://10.34.131.51:8080/job/NetworkManager"
