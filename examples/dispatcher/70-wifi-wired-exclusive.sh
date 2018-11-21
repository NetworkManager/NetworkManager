#!/bin/bash
# This dispatcher script makes Wi-Fi mutually exclusive with
# wired networking.  When a wired interface is connected,
# Wi-Fi will be set to airplane mode (rfkilled).  When the wired
# interface is disconnected, Wi-Fi will be turned back on.
#
# Copyright 2012 Johannes Buchner <buchner.johannes@gmx.at>
# Copyright 2012 - 2014 Red Hat, Inc.
#

export LC_ALL=C
if nmcli -t --fields type,state dev | grep -E "ethernet:connected" -q; then
	nmcli radio wifi off
else
	nmcli radio wifi on
fi

