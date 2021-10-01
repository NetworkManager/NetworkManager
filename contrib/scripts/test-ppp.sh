#!/bin/bash

# test-ppp.sh:
#
# Test script that creates an netns and connect it with
# veth pairs. On the other end, it runs pppoe-server.
# It also creates a NetworkManager profile that can be activated.
#
# Usage:
#
# ./test-ppp.sh [setup]: create the setup. This implies a "cleanup"
#   first.
# ./test-ppp.sh cleanup: cleanup the things that the script created.
set -e

export IFACE=net1
export IFACE_PEER=net1-x
export CON_NAME="ppp-$IFACE"
export NETNS=nm-ppp
export PPP_SERVICE=isp
export PPP_AUTH=pap
export PPP_USER=test-user
export PPP_PASSWD=test-passwd
export IP_PEER="192.168.133.6"
export IP_RANGE="192.168.133.100-130"

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

do_cleanup() {
    pkill -F "/tmp/nm-test-ppp-$IFACE.pid" pppoe-server &>/dev/null || :
    rm -rf \
        "/tmp/nm-test-ppp-$IFACE.pid" \
        "/tmp/nm-test-ppp-allip-$IFACE" \
        "/tmp/nm-test-ppp-pppoe-server-options-$IFACE" \
        "/tmp/nm-test-ppp-$IFACE-$PPP_AUTH-secrets"
    ip --netns "$NETNS" link delete "$IFACE_PEER" &>/dev/null || :
    ip netns delete "$NETNS" &>/dev/null || :

    nmcli connection delete id ppp-net1 || :
}

do_setup() {
    do_cleanup

    ip netns add "$NETNS"
    ip --netns "$NETNS" link add "$IFACE" type veth peer "$IFACE_PEER"
    ip --netns "$NETNS" link set "$IFACE_PEER" up

    ip --netns "$NETNS" addr add "$IP_PEER/24" dev "$IFACE_PEER"

    echo "$IP_RANGE" > "/tmp/nm-test-ppp-allip-$IFACE"

    cat <<EOF > "/tmp/nm-test-ppp-pppoe-server-options-$IFACE"
require-$PPP_AUTH
lcp-echo-interval 10
lcp-echo-failure 2
ms-dns 8.8.8.8
ms-dns 8.8.4.4
netmask 255.255.255.0
defaultroute
noipdefault
usepeerdns
EOF

    echo "$PPP_USER * $PPP_PASSWD $IP_PEER" > "/tmp/nm-test-ppp-$IFACE-$PPP_AUTH-secrets"
    chmod 600 "/tmp/nm-test-ppp-$IFACE-$PPP_AUTH-secrets"
    mkdir -p /etc/ppp
    touch "/etc/ppp/$PPP_AUTH-secrets"
    ip netns exec "$NETNS" bash -ex <(
        cat <<'EOF'
        mount -o bind  "/tmp/nm-test-ppp-$IFACE-$PPP_AUTH-secrets" "/etc/ppp/$PPP_AUTH-secrets" &&
        exec pppoe-server \
            -X "/tmp/nm-test-ppp-$IFACE.pid" \
            -S "$PPP_SERVICE" \
            -C "$PPP_SERVICE" \
            -L "$IP_PEER" \
            -p "/tmp/nm-test-ppp-allip-$IFACE" \
            -I "$IFACE_PEER" \
            -O "/tmp/nm-test-ppp-pppoe-server-options-$IFACE"
EOF
) &

    ip --netns "$NETNS" link set "$IFACE" netns $$

    nmcli connection add \
        type pppoe \
        con-name "$CON_NAME" \
        ifname "ppp-$IFACE" \
        pppoe.parent "$IFACE" \
        service "$PPP_SERVICE" \
        username "$PPP_USER" \
        password "$PPP_PASSWD" \
        autoconnect no
}

CMD="${1-setup}"
case "$CMD" in
    setup| \
    cleanup)
        "do_$CMD"
        ;;
    *)
        die "invalid command $1"
        ;;
esac
