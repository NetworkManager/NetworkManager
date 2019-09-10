#!/bin/sh
# SPDX-License-Identifier: GPL-2.0+
#
# Copyright (C) 2011 Red Hat, Inc.
#

#
# Sets NM logging level and/or domains (see description in 'man NetworkManager.conf')
# The level controls how verbose NM's log output will be (err,warn,info,debug).
# Domains control what parts of networking NM emits log messages for. Leaving
# either of the two arguments blank (i.e., an empty string) will leave that
# parameter unchanged.
#
# The normal logging level is 'info', for debugging use 'debug'.
#
# Examples:
#   nm-logging.sh debug   -  switches the debugging level on
#   nm-logging.sh info    -  turns debugging off (back to normal)
#   nm-logging.sh "" "WIFI"     -  changes domain to print only Wi-Fi related messages
#   nm-logging.sh err "HW,IP4"  -  will print only error messages related to hardware or IPv4
#

LOG_LEVEL=$1
LOG_DOMAINS=$2

dbus-send --system --print-reply \
--dest=org.freedesktop.NetworkManager \
/org/freedesktop/NetworkManager \
org.freedesktop.NetworkManager.SetLogging \
string:"$LOG_LEVEL" string:"$LOG_DOMAINS"

