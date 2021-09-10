#!/bin/bash

set -e

die() {
    printf '%s\n' "$*"
    exit 1
}

cleanup() {
    local IDX="$1"

    pkill -F "/tmp/nm-dnsmasq-d_$IDX.pid" dnsmasq &>/dev/null || :
    : > "/tmp/nm-dnsmasq-d_$IDX.pid"

    ip link del "d_$IDX" &>/dev/null || :
}

setup() {
    local IDX="$1"

    cleanup "$IDX"

    ip link add "net$IDX" type veth peer "d_$IDX"
    ip link set "d_$IDX" up

    ip addr add "192.168.$((120 + $IDX)).1/23" dev "d_$IDX"

    dnsmasq \
        --conf-file=/dev/null \
        --pid-file="/tmp/nm-dnsmasq-d_$IDX.pid" \
        --no-hosts \
        --keep-in-foreground \
        --bind-interfaces \
        --except-interface=lo \
        --clear-on-reload \
        --listen-address="192.168.$((120 + $IDX)).1" \
        --dhcp-range="192.168.$((120 + $IDX)).100,192.168.$((120 + $IDX)).150" \
        --no-ping \
        &
}

IDX=1
CMD=
for (( i=1 ; i<="$#" ; )) ; do
    c="${@:$i:1}"
    i=$((i+1))
    case "$c" in
        setup|cleanup)
            CMD="$c"
            ;;
        --idx|-i)
            test $i -le "$#" || die "missing argument to --idx"
            IDX="${@:$i:1}"
            i=$((i+1))
            ;;
        *)
            die "invalid argument"
            ;;
    esac
done

test "$CMD" != "" || die "missing command (setup|cleanup)"

$CMD "$IDX"
