#!/usr/bin/env python
# coding=utf-8
# -*- Mode: Python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-
# vim: ft=python ts=4 sts=4 sw=4 et ai
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
# Copyright (C) 2013 Red Hat, Inc.
#

from gi.repository import NetworkManager, NMClient

#
# This example lists Wi-Fi access points NetworkManager scanned on Wi-Fi devices.
# It calls libnm-glib functions using GObject introspection.
#
# Note the second line of the file: coding=utf-8
# It is necessary because we use unicode characters and python would produce
# an error without it: http://www.python.org/dev/peps/pep-0263/
#

signal_bars = {
    0 : "____",
    1 : "▂___",
    2 : "▂▄__",
    3 : "▂▄▆_",
    4 : "▂▄▆█"
}

def clamp(value, minvalue, maxvalue):
    return max(minvalue, min(value, maxvalue))

def print_device_info(device):
    active_ap = dev.get_active_access_point()
    ssid = None
    if active_ap is not None:
        ssid = active_ap.get_ssid()
    info = "Device: %s | Driver: %s | Active AP: %s" % (dev.get_iface(), dev.get_driver(), ssid)
    print info
    print '=' * len(info)

def print_ap_info(ap):
    strength = ap.get_strength()
    frequency = ap.get_frequency()
    print "SSID:      %s"      % (ap.get_ssid())
    print "BSSID:     %s"      % (ap.get_bssid())
    print "Frequency: %s"      % (frequency)
    print "Channel:   %s"      % (NetworkManager.utils_wifi_freq_to_channel(frequency))
    print "Strength:  %s %s%%" % (signal_bars[(clamp(strength-5, 0, 99)+24)/25], strength)
    print

if __name__ == "__main__":
    nmc = NMClient.Client.new()
    devs = nmc.get_devices()

    for dev in devs:
        if dev.get_device_type() == NetworkManager.DeviceType.WIFI:
            print_device_info(dev)
            for ap in dev.get_access_points():
                print_ap_info(ap)

