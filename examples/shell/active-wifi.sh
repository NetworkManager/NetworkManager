#!/bin/sh
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
# Copyright (C) 2012 Red Hat, Inc.
#

#
# This example prints SSIDs of connected Wi-Fi networks.
# GetDevices() D-Bus call returns all devices. We go through them, find Wi-Fi
# ones and ask for ActiveAccessPoint property. If the access point path is not
# empty ("/"), we can read its properties, like SSID.
#

NM_SERVICE_NAME="org.freedesktop.NetworkManager"
NM_OBJECT_PATH="/org/freedesktop/NetworkManager"
DEVICE_IFACE="org.freedesktop.NetworkManager.Device"
DEVICE_WIFI_IFACE="org.freedesktop.NetworkManager.Device.Wireless"
ACCESS_POINT_IFACE="org.freedesktop.NetworkManager.AccessPoint"
NM_GET_DEVICES="org.freedesktop.NetworkManager.GetDevices"
DBUS_PROPERTIES_GET="org.freedesktop.DBus.Properties.Get"


get_devices()
{
  dbus-send --system --print-reply --dest=$NM_SERVICE_NAME $NM_OBJECT_PATH $NM_GET_DEVICES | \
    grep "object path" | cut -d '"' -f2
}

get_property()
{
  # first arg:  object path
  # second arg: interface
  # third arg:  property name
  # returns:    property value

  dbus-send --system --print-reply --dest=$NM_SERVICE_NAME "$1" $DBUS_PROPERTIES_GET string:"$2" string:"$3" | \
    grep "variant" | awk -F '"' '{ if (NF == 1) {FS=" "; n=split($0,a); print a[n];} else print $(NF-1); }'
}

is_wifi_device()
{
  DEV_TYPE=`get_property $device $DEVICE_IFACE "DeviceType"`

  if [ $DEV_TYPE -eq 2 ]; then
    return 0
  else
    return 1
  fi
}

show_active_ssids()
{
  for device in `get_devices`
  do
    INTERFACE=`get_property $device $DEVICE_IFACE "Interface"`

    if `is_wifi_device`; then
      ACTIVE_AP=`get_property $device $DEVICE_WIFI_IFACE "ActiveAccessPoint"`
      if [ "$ACTIVE_AP" != "/" ]; then
        SSID=`get_property $ACTIVE_AP $ACCESS_POINT_IFACE "Ssid"`
        BSSID=`get_property $ACTIVE_AP $ACCESS_POINT_IFACE "HwAddress"`
        echo "Device '$INTERFACE' is connected to '$SSID' (BSSID=$BSSID)"
      else
        echo "No active AP on device '$INTERFACE'" >&2
      fi
    fi
  done
}

# --- main program ---
# print currently connected SSID on all Wi-Fi devices
show_active_ssids

