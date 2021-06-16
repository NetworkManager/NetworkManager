#!/bin/bash

set -x

die() {
    printf '%s\n' "$*" >&1
    exit 1
}

ARG_OP="$1"
shift
test -n "$ARG_OP" || die "specify the operation (setup, cleanup)"

test "$USER" = root || die "must run as root"

NUM_DEVS="${NUM_DEVS:-50}"


DNSMASQ_PIDFILE="/tmp/nm-test-create-many-device-setup.dnsmasq.pid"
NM_TEST_CONF="/etc/NetworkManager/conf.d/99-my-test.conf"
TEST_NETNS="T"


_dnsmasq_kill() {
    pkill -F "$DNSMASQ_PIDFILE"
    rm -rf "$DNSMASQ_PIDFILE"
}

_link_delete_all() {
    ip link | sed -n 's/^[0-9]\+:.*\(t-[^@:]\+\)@.*/\1/p' | xargs -n 1 ip link delete
}

cleanup_base() {
    ip netns delete "$TEST_NETNS"
    _dnsmasq_kill
    _link_delete_all
    rm -rf "$NM_TEST_CONF"
    rm -rf /run/NetworkManager/system-connections/c-*.nmconnection
}

cmd_cleanup() {
    systemctl stop NetworkManager
    cleanup_base
    systemctl unmask NetworkManager-dispatcher
    systemctl enable NetworkManager-dispatcher
    systemctl start NetworkManager
}

cmd_setup() {

    systemctl stop NetworkManager
    systemctl mask NetworkManager-dispatcher
    systemctl stop NetworkManager-dispatcher

    cleanup_base

    ip netns add "$TEST_NETNS"
    ip --netns "$TEST_NETNS" link add t-br0 type bridge
    ip --netns "$TEST_NETNS" link set t-br0 type bridge stp_state 0
    ip --netns "$TEST_NETNS" link set t-br0 up
    ip --netns "$TEST_NETNS" addr add 172.16.0.1/16 dev t-br0
    ip netns exec "$TEST_NETNS" \
        dnsmasq \
            --conf-file=/dev/null \
            --pid-file="$DNSMASQ_PIDFILE" \
            --no-hosts \
            --keep-in-foreground \
            --bind-interfaces \
            --except-interface=lo \
            --clear-on-reload \
            --listen-address=172.16.0.1 \
            --dhcp-range=172.16.1.1,172.16.20.1,60 \
            --no-ping \
            &
    disown
    for i in `seq "$NUM_DEVS"`; do
        ip --netns "$TEST_NETNS" link add t-a$i type veth peer t-b$i
        ip --netns "$TEST_NETNS" link set t-a$i up
        ip --netns "$TEST_NETNS" link set t-b$i up master t-br0
    done

    cat <<EOF > "$NM_TEST_CONF"
[main]
dhcp=internal
no-auto-default=interface-name:t-a*
[device-99-my-test]
match-device=interface-name:t-a*
managed=1
[logging]
level=INFO
[connectivity]
enabled=0
EOF

    systemctl start NetworkManager

    for i in `seq "$NUM_DEVS"`; do
      ip --netns "$TEST_NETNS" link set t-a$i netns $$
    done

    for i in `seq "$NUM_DEVS"`; do
        nmcli connection add save no type ethernet con-name c-a$i ifname t-a$i autoconnect no ipv4.method auto ipv6.method auto
    done
}


case "$ARG_OP" in
    "setup")
        cmd_setup
        ;;
    "cleanup")
        cmd_cleanup
        ;;
    *)
        die "Unknown command \"$ARG_OP\""
        ;;
esac
