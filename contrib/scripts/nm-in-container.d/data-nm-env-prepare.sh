#!/bin/bash

set -e

die() {
    printf '%s\n' "$*"
    exit 1
}

do_cleanup() {
    local IDX="$1"
    local NAME_PREFIX="${2:-net}"
    local PEER_PREFIX="${3:-d_}"

    pkill -F "/tmp/nm-dnsmasq-$PEER_PREFIX$IDX.pid" dnsmasq &>/dev/null || :
    rm -rf "/tmp/nm-dnsmasq-$PEER_PREFIX$IDX.pid"

    pkill -F "/tmp/nm-radvd-$PEER_PREFIX$IDX.pid" radvd &>/dev/null || :
    rm -rf "/tmp/nm-radvd-$PEER_PREFIX$IDX.pid"

    rm -rf "/tmp/nm-radvd-$PEER_PREFIX$IDX.conf"

    ip link del "$PEER_PREFIX$IDX" &>/dev/null || :
}

do_setup() {
    local IDX="$1"
    local NAME_PREFIX="${2:-net}"
    local PEER_PREFIX="${3:-d_}"

    do_cleanup "$IDX"

    ip link add "$NAME_PREFIX$IDX" type veth peer "$PEER_PREFIX$IDX"
    ip link set "$PEER_PREFIX$IDX" up

    ip addr add "192.168.$((120 + $IDX)).1/23" dev "$PEER_PREFIX$IDX"
    ip addr add "192:168:$((120 + IDX))::1/64" dev "$PEER_PREFIX$IDX"

    dnsmasq \
        --conf-file=/dev/null \
        --pid-file="/tmp/nm-dnsmasq-$PEER_PREFIX$IDX.pid" \
        --no-hosts \
        --keep-in-foreground \
        --bind-interfaces \
        --except-interface=lo \
        --clear-on-reload \
        --listen-address="192.168.$((120 + $IDX)).1" \
        --dhcp-range="192.168.$((120 + $IDX)).100,192.168.$((120 + $IDX)).150" \
        --no-ping \
        &

    cat <<EOF > "/tmp/nm-radvd-$PEER_PREFIX$IDX.conf"
interface $PEER_PREFIX$IDX
{
        AdvSendAdvert on;
        prefix 192:168:$((120 + IDX))::/64
        {
                AdvOnLink on;
        };

};
EOF
    radvd \
        --config "/tmp/nm-radvd-$PEER_PREFIX$IDX.conf" \
        --pidfile "/tmp/nm-radvd-$PEER_PREFIX$IDX.pid" \
        &
}

do_redo() {
    do_cleanup "$@"
    do_setup "$@"
}

###############################################################################

IDX=1
NAME_PREFIX=net
PEER_PREFIX=
CMD=redo
for (( i=1 ; i<="$#" ; )) ; do
    c="${@:$i:1}"
    i=$((i+1))
    case "$c" in
        redo|setup|cleanup)
            CMD="$c"
            ;;
        --prefix|-p)
            NAME_PREFIX="${@:$i:1}"
            test -n "$NAME_PREFIX" || die "missing argument to --prefix"
            i=$((i+1))
            ;;
        --peer-prefix)
            PEER_PREFIX="${@:$i:1}"
            test -n "$PEER_PREFIX" || die "missing argument to --peer-prefix"
            i=$((i+1))
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

if [ -z "$PEER_PREFIX" ]; then
    if [ "$NAME_PREFIX" = net ]; then
        PEER_PREFIX=d_
    else
        PEER_PREFIX="d_${NAME_PREFIX}_"
    fi
fi

do_$CMD "$IDX" "$NAME_PREFIX" "$PEER_PREFIX"
