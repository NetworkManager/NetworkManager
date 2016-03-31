#!/bin/sh

# This ifcfg-rh-specific script runs
# /etc/sysconfig/network-scripts/ifup-routes when bringing up
# interfaces that have routing rules associated with them that can't
# be expressed by NMSettingIPConfig. (Eg, policy-based routing.)

# This should be installed in both dispatcher.d/ and
# dispatcher.d/pre-up.d/

# pre-up scripts delay activation of the device. To reduce the delay,
# it is advised to install the script as symlink to no-wait.d directory.

if [ "$2" != "pre-up" -a "$2" != "down" ]; then
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
if ! [ -f "$dir/rule-$profile" -o -f "$dir/rule6-$profile" ]; then
    exit 0
fi

case "$2" in
    pre-up)
        /etc/sysconfig/network-scripts/ifup-routes "$DEVICE_IP_IFACE" "$profile"
        ;;
    down)
        /etc/sysconfig/network-scripts/ifdown-routes "$DEVICE_IP_IFACE" "$profile"
        ;;
esac
