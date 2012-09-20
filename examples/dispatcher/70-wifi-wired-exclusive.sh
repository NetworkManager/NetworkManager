#!/bin/bash
export LC_ALL=C

# This dispatcher script makes WiFi mutually exclusive with
# wired networking.  When a wired interface is connected,
# WiFi will be set to airplane mode (rfkilled).  When the wired
# interface is disconnected, WiFi will be turned back on.

enable_disable_wifi ()
{
	result=$(nmcli dev | grep "802-3-ethernet" | grep -w "connected")
	if [ -n "$result" ]; then
		nmcli nm wifi off
	else
		nmcli nm wifi on
	fi
}

if [ "$2" = "up" ]; then
	enable_disable_wifi
fi

if [ "$2" = "down" ]; then
	enable_disable_wifi
fi

