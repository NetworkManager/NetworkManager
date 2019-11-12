#!/bin/sh

case "$2" in
    up|dhcp4-change)
        exec systemctl --no-block restart nm-cloud-setup.service
        ;;
esac
