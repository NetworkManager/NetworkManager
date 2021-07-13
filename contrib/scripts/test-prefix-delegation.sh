#!/bin/sh

# Usage: ./test-prefix-delegation {ll|slaac|dhcp-stateful|dhcp-stateless}

MODE=${1:-dhcp-stateful}

cleanup()
{
    pkill -F dhcpd.pid
    pkill -F radvd.pid
    rm -f radvd.conf
    rm -f dhcpd.conf
    rm -f leases.conf
    nmcli connection delete v1+ v2+
    ip netns del ns1
    ip netns del ns2
    ip link del v1
    ip link del v2
}

require()
{
    if ! command -v "$1" > /dev/null ; then
        echo " *** Error: command '$1' not found"
        exit 1
    fi
}

exit_hook()
{
    cleanup > /dev/null 2>&1
}

require nmcli
require ip
require jq
require radvd
require dhcpd

unalias ip 2> /dev/null

cleanup
trap exit_hook EXIT

# ns1 is the 'upstream' namespace that provides IPv6 connectivity
# through RA and DHCPv6. The DHCP server also acts as a delegating
# router for /60 prefixes.

# ns2 is the 'downstream' namespace where a client obtains IPv6
# connectivity through RA from NM.

# NM is in the default namespace and has a connection to ns1 with
# ipv6.method=auto and to ns2 with ipv6.method=shared.

ip netns add ns1
ip netns add ns2

ip link add v1 type veth peer name v1p
ip link add v2 type veth peer name v2p

ip link set v1p netns ns1
ip link set v2p netns ns2

ip link set v1 up
ip link set v2 up

ip -n ns1 link set v1p up
ip -n ns1 addr add dev v1p fc01::1/64

ip -n ns2 link set v2p up

if [ "$MODE" = ll ]; then
    adv_managed=off
    adv_other=off
elif [ "$MODE" = slaac ]; then
    adv_managed=off
    adv_other=off
    adv_prefix="prefix fc01::/64 {AdvOnLink on; AdvAutonomous on; AdvRouterAddr off; };"
elif [ "$MODE" = dhcp-stateless ]; then
    adv_managed=off
    adv_other=on
    adv_prefix="prefix fc01::/64 {AdvOnLink on; AdvAutonomous on; AdvRouterAddr off; };"
elif [ "$MODE" = dhcp-stateful ]; then
    adv_managed=on
    adv_other=off
    dhcp_range="range6  fc01::1000 fc01::ffff;"
else
    echo "Unknown mode '$MODE'"
    exit 1
fi

echo "Starting in $MODE mode..."

cat > radvd.conf <<EOF
interface v1p {
        AdvSendAdvert on;
        AdvManagedFlag ${adv_managed};
        AdvOtherConfigFlag ${adv_other};
        MinRtrAdvInterval 3;
        MaxRtrAdvInterval 60;
        ${adv_prefix}
};
EOF

cat > dhcpd.conf <<EOF
subnet6 fc01::/64 {
        ${dhcp_range}
        prefix6 fc01:bbbb:1:: fc01:bbbb:2:: / 60;
        option dhcp6.name-servers fc01::8888;
}
EOF

echo > leases.conf
ip netns exec ns1 radvd -n -C radvd.conf -p radvd.pid &
ip netns exec ns1 dhcpd -6 -d -cf dhcpd.conf -lf leases.conf -pf dhcpd.pid &

nmcli connection add type ethernet ifname v1 con-name v1+ ipv4.method disabled ipv6.method auto autoconnect no
nmcli connection add type ethernet ifname v2 con-name v2+ ipv4.method disabled ipv6.method shared autoconnect no

nmcli connection up v1+

sleep 5

nmcli connection up v2+

sleep 5

ip a show dev v1
ip a show dev v2

addr=$(ip -j addr show dev v1 | jq -r '.[0].addr_info[] | select(.scope=="link")'.local)
prefix="fc01:bbbb:1::/32"
ip netns exec ns1 ip route add $prefix via $addr dev v1p

# kernel does IPv6 autoconf in ns2 ...

sleep 10

# check connectivity to ns1
if ! ip -n ns2 a show dev v2p | grep 'fc01:bbbb:[a-f0-9\:]\+/64'; then
    ip -n ns2 a show dev v2p
    echo "ERROR: no address"
    exit 1
fi

if ! ip netns exec ns2 ping -c2 fc01::1; then
    echo "ERROR: ping failed"
    exit 1
fi

echo "OK"
