#!/bin/bash

set -e

PROFILE="${1-t-wg0}"
IFNAME="${2-i-wg0}"
IP4ADDR=192.168.144.5/24
IP4GW=192.168.144.1

umask 077
PRIVFILE=$(mktemp -t nm-wireguard-priv-key.XXXXXXXXXX)
trap "rm -f \"$PRIVFILE\"" EXIT
wg genkey > "$PRIVFILE"
PUBKEY=$(wg pubkey < "$PRIVFILE")

eval "$(ipcalc -n -p $IP4ADDR)"
IP4NET="$NETWORK/$PREFIX"

ANSWER="$(LANG=C nmcli connection add \
    type wireguard \
    con-name "$PROFILE" \
    ifname "$IFNAME" \
    connection.stable-id "t-wg0-$PUBKEY" \
    ipv4.method manual \
    ipv4.addresses "$IP4ADDR" \
    ipv4.gateway "$IP4GW" \
    ipv4.never-default yes \
    ipv6.method link-local \
    wireguard.listen-port 0 \
    wireguard.fwmark 0)"

UUID="$(echo "$ANSWER" | sed 's/.*(\(.*\))[^)]\+$/\1/')"

# currently nmcli is not very convenint about injecting secrets aside as command
# line options. So, don't do that, instead activate the profile for the first time,
# and provide the secrets during the activation.
nmcli connection up \
    uuid "$UUID" \
    passwd-file <(echo "wireguard.private-key:$(cat "$PRIVFILE")")

echo "new profile \"$PROFILE\" (uuid $UUID) with pubkey $PUBKEY"

nmcli -o connection show uuid "$UUID" | sed 's/^/    /'
