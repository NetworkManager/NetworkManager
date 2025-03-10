#!/bin/sh

#
# Test wireguard with NetworkManager, using IPv6 endpoint and mixed
# IPv4 and IPv6 connectivity.
#

#  +----------------+      +----------------+      +----------------+
#  |    fd01::1     <------>    fd01::2     |      |                |
#  |                |      |                |      |                |
#  |  default ns    |      |       ns2      |      |       ns3      |
#  |                |      |                |      |                |
#  |                |      |    fd03::2     <------>    fd03::1     |
#  +----------------+      +----------------+      +----------------+
#
#          wg1 <-----------------------------------------> wg1
#
#       172.16.1.1/24                                 172.16.3.1/24
#         2600::1/64                                    2800::1/64

set -ex

(
    ip link del v1
    ip netns del ns2
    ip netns del ns3
    rm /etc/NetworkManager/system-connections/wg1.nmconnection
    nmcli connection reload
) 2>/dev/null || true

ip netns add ns2
ip netns add ns3

ip link add v1 type veth peer name v21 netns ns2
ip -n ns3 link add v3 type veth peer name v23 netns ns2

ip -n ns2 link set v21 up
ip -n ns2 addr add dev v21 fd01::2/64
ip -n ns2 link set v23 up
ip -n ns2 addr add dev v23 fd03::2/64
ip netns exec ns2 sh -c "echo 1 > /proc/sys/net/ipv6/conf/all/forwarding"

ip link set v1 up
ip addr add dev v1 fd01::1/64
ip route add ::/0 via fd01::2 dev v1

ip -n ns3 link set v3 up
ip -n ns3 addr add dev v3 fd03::1/64
ip -n ns3 route add ::/0 via fd03::2 dev v3

# wait DAD
sleep 3

# check connectivity
ping -c2 fd03::1
ip netns exec ns3 ping -c2 fd01::1

# configure wireguard
cat <<EOF > /etc/NetworkManager/system-connections/wg1.nmconnection
[connection]
id=wg1-ipv6
uuid=2556676d-0d6e-4384-bfb5-cdf1b0ee4ee7
type=wireguard
autoconnect=false
interface-name=wg1

[wireguard]
private-key=YN9294QREKCU6pUP4YyAZPcnet/ngEq8Ng+bN3db4HA=

[wireguard-peer.f9yYk+WPyLXccrgAqvRLNCpqlnsj29iXM58YUnCk/U4=]
endpoint=[fd03::1]:1337
preshared-key-flags=4
allowed-ips=0.0.0.0/0;::/0;

[ipv4]
method=manual
address1=172.16.1.1/24

[ipv6]
addr-gen-mode=stable-privacy
address1=2600::1/64
ip6-privacy=0
method=manual

[proxy]
EOF

chmod 600 /etc/NetworkManager/system-connections/wg1.nmconnection
nmcli connection reload
nmcli connection up wg1-ipv6

cat <<EOF > /etc/wireguard/wg1.conf
[Interface]
Address = 2800::1/64, 172.16.3.1/24
ListenPort = 1337
PrivateKey = MKhVoW+LMi1WMB8NhbdzQBcyGpWnb0BzVsUA9hNHQVQ=
MTU = 1280

[Peer]
PublicKey = 7bSnIvE+cUrEIEeV7GTill5Z8x7CEeYCAuzQLxqKXWQ=
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 20
EOF

ip netns exec ns3 wg-quick up wg1

# check connectivity over the tunnel
ping -c1 172.16.3.1
ping -c1 2800::1
ip netns exec ns3 ping -c1 172.16.1.1
ip netns exec ns3 ping -c1 2600::1
