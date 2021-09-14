#!/bin/bash

set -e

die() {
    printf '%s\n' "$*"
    exit 1
}

do_cleanup() {
    local IDX="$1"

    pkill -F "/tmp/nm-dnsmasq-d_$IDX.pid" dnsmasq &>/dev/null || :
    rm -rf "/tmp/nm-dnsmasq-d_$IDX.pid"

    pkill -F "/tmp/nm-radvd-d_$IDX.pid" radvd &>/dev/null || :
    rm -rf "/tmp/nm-radvd-d_$IDX.pid"

    rm -rf "/tmp/nm-radvd-d_$IDX.conf"

    ip link del "d_$IDX" &>/dev/null || :
}

do_setup() {
    local IDX="$1"

    do_cleanup "$IDX"

    ip link add "net$IDX" type veth peer "d_$IDX"
    ip link set "d_$IDX" up

    ip addr add "192.168.$((120 + $IDX)).1/23" dev "d_$IDX"
    ip addr add "192:168:$((120 + IDX))::1/64" dev "d_$IDX"

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

    cat <<EOF > "/tmp/nm-radvd-d_$IDX.conf"
interface d_$IDX
{
        AdvSendAdvert on;
        prefix 192:168:$((120 + IDX))::/64
        {
                AdvOnLink on;
        };

};
EOF
    radvd \
        --config "/tmp/nm-radvd-d_$IDX.conf" \
        --pidfile "/tmp/nm-radvd-d_$IDX.pid" \
        &
}

do_redo() {
    do_cleanup "$1"
    do_setup "$1"
}

###############################################################################

IDX=1
CMD=redo
for (( i=1 ; i<="$#" ; )) ; do
    c="${@:$i:1}"
    i=$((i+1))
    case "$c" in
        redo|setup|cleanup)
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

do_$CMD "$IDX"
