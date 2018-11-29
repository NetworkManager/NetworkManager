#!/bin/sh
# vim: ft=sh ts=2 sts=2 sw=2 et ai
# -*- Mode: sh; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

