#!/bin/bash

# This script applies policy-based routing rules defined for the
# connection in the /etc/sysconfig/network-scripts/ directory.
#
# This should be installed in both dispatcher.d/ and
# dispatcher.d/pre-up.d/
#
# pre-up scripts delay activation of the device. To reduce the delay,
# it is advised to install the script as symlink to no-wait.d directory.
#
# This file is derived from scripts 'if{up,down}-routes' from
# Fedora/RHEL initscripts.

MATCH='^[[:space:]]*(\#.*)?$'

handle_file () {
    . $1
    routenum=0
    while [ "x$(eval echo '$'ADDRESS$routenum)x" != "xx" ]; do
        eval $(ipcalc -p $(eval echo '$'ADDRESS$routenum) $(eval echo '$'NETMASK$routenum))
        line="$(eval echo '$'ADDRESS$routenum)/$PREFIX"
        if [ "x$(eval echo '$'GATEWAY$routenum)x" != "xx" ]; then
            line="$line via $(eval echo '$'GATEWAY$routenum)"
        fi
        line="$line dev $2"
        /sbin/ip route add $line
        routenum=$(($routenum+1))
    done
}

handle_ip_file() {
    local f t type= file=$1 proto="-4"
    f=${file##*/}
    t=${f%%-*}
    type=${t%%6}
    if [ "$type" != "$t" ]; then
        proto="-6"
    fi
    { cat "$file" ; echo ; } | while read line; do
        if [[ ! "$line" =~ $MATCH ]]; then
            /sbin/ip $proto $type add $line
        fi
    done
}


if [ "$2" != "pre-up" ] && [ "$2" != "down" ]; then
    exit 0
fi

dir=$(dirname "$CONNECTION_FILENAME")
if [ "$dir" != "/etc/sysconfig/network-scripts" ]; then
    exit 0
fi

profile=$(basename "$CONNECTION_FILENAME" | sed -ne 's/^ifcfg-//p')
if [ -z "$profile" ]; then
    exit 0
fi

if [ ! -f "$dir/rule-$profile" ] && [ ! -f "$dir/rule6-$profile" ]; then
    exit 0
fi

case "$2" in
    pre-up)
        # Routes
        FILES="/etc/sysconfig/network-scripts/route-$DEVICE_IP_IFACE"
        FILES="$FILES /etc/sysconfig/network-scripts/route6-$DEVICE_IP_IFACE"
        if [ "$profile" != "$DEVICE_IP_IFACE" ]; then
            FILES="$FILES /etc/sysconfig/network-scripts/route-$profile"
            FILES="$FILES /etc/sysconfig/network-scripts/route6-$profile"
        fi

        for file in $FILES; do
            if [ -f "$file" ]; then
                if grep -Eq '^[[:space:]]*ADDRESS[0-9]+=' $file ; then
                    # new format
                    handle_file $file ${1%:*}
                else
                    # older format
                    handle_ip_file $file
                fi
            fi
        done

        # Rules
        FILES="/etc/sysconfig/network-scripts/rule-$DEVICE_IP_IFACE"
        FILES="$FILES /etc/sysconfig/network-scripts/rule6-$DEVICE_IP_IFACE"
        if [ "$profile" != "$DEVICE_IP_IFACE" ]; then
            FILES="$FILES /etc/sysconfig/network-scripts/rule-$profile"
            FILES="$FILES /etc/sysconfig/network-scripts/rule6-$profile"
        fi

        for file in $FILES; do
            if [ -f "$file" ]; then
                handle_ip_file $file
            fi
        done
        ;;
    down)
        # Routes are deleted by NetworkManager
        # Rules
        FILES="/etc/sysconfig/network-scripts/rule-$DEVICE_IP_IFACE"
        FILES="$FILES /etc/sysconfig/network-scripts/rule6-$DEVICE_IP_IFACE"
        if [ "$profile" != "$DEVICE_IP_IFACE" ]; then
            FILES="$FILES /etc/sysconfig/network-scripts/rule-$profile"
            FILES="$FILES /etc/sysconfig/network-scripts/rule6-$profile"
        fi
        for file in $FILES; do
            if [ -f "$file" ]; then
                proto=
                if [ "$file" != "${file##*/rule6-}" ]; then
                    proto="-6"
                fi
                { cat "$file" ; echo ; } | while read line; do
                    if [[ ! "$line" =~ $MATCH ]]; then
                        /sbin/ip $proto rule del $line
                    fi
                done
            fi
        done
        ;;
esac
