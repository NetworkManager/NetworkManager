#!/bin/sh

case "$2" in
    pre-up)
	NO_BLOCK=
        ;;
    dhcp4-change)
	NO_BLOCK=--no-block
        ;;
    *)
	exit 0
	;;
esac

if systemctl -q is-enabled nm-cloud-setup.service ; then
    exec systemctl $NO_BLOCK restart nm-cloud-setup.service
fi
