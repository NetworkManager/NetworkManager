#!/bin/sh

case "$2" in
    up|dhcp4-change)
        if systemctl -q is-enabled nm-cloud-setup.service ; then
            exec systemctl --no-block restart nm-cloud-setup.service
        fi
        ;;
esac
