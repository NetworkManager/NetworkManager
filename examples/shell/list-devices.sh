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
# Copyright (C) 2011 - 2012 Red Hat, Inc.
#

#
# This example lists basic information about network interfaces known to NM.
# It finds the devices via GetDevices() D-Bus call and then gets properties of
# each device.
#

NM_SERVICE_NAME="org.freedesktop.NetworkManager"
NM_OBJECT_PATH="/org/freedesktop/NetworkManager"
DEVICE_IFACE="org.freedesktop.NetworkManager.Device"
NM_GET_DEVICES="org.freedesktop.NetworkManager.GetDevices"
DBUS_PROPERTIES_GET="org.freedesktop.DBus.Properties.Get"

# For the types see include/NetworkManager.h
devtype_to_name()
{
  case $1 in
    1) echo "Ethernet" ;;
    2) echo "Wi-Fi" ;;
    5) echo "Bluetooth" ;;
    6) echo "OLPC" ;;
    7) echo "WiMAX" ;;
    8) echo "Modem" ;;
    9) echo "InfiniBand" ;;
   10) echo "Bond" ;;
   11) echo "VLAN" ;;
   12) echo "ADSL" ;;
   13) echo "Bridge" ;;
   14) echo "Generic" ;;
   15) echo "Team" ;;
    *) echo "Unknown" ;;
  esac
}

state_to_name()
{
  case $1 in
    10)  echo "Unmanaged" ;;
    20)  echo "Unavailable" ;;
    30)  echo "Disconnected" ;;
    40)  echo "Prepare" ;;
    50)  echo "Config" ;;
    60)  echo "Need Auth" ;;
    70)  echo "IP Config" ;;
    80)  echo "IP Check" ;;
    90)  echo "Secondaries" ;;
    100) echo "Activated" ;;
    110) echo "Deactivating" ;;
    120) echo "Failed" ;;
    *)   echo "Unknown" ;;
  esac
}

get_devices()
{
  dbus-send --system --print-reply --dest=$NM_SERVICE_NAME $NM_OBJECT_PATH $NM_GET_DEVICES | \
    grep "object path" | cut -d '"' -f2
}

get_device_property()
{
  # first arg:  device object path
  # second arg: property name
  # returns:    property value

  dbus-send --system --print-reply --dest=$NM_SERVICE_NAME "$1" $DBUS_PROPERTIES_GET string:$DEVICE_IFACE string:"$2" | \
    grep "variant" | awk '{print $3}' | sed 's/"//g'
}

list_devices_details()
{
  for device in `get_devices`
  do
    DEV_INTERFACE=`get_device_property "$device" "Interface"`
    DEV_TYPE=`get_device_property "$device" "DeviceType"`
    DEV_DRIVER=`get_device_property "$device" "Driver"`
    DEV_STATE=`get_device_property "$device" "State"`

    echo "============================"
    echo "Interface: $DEV_INTERFACE"
    echo "Type: `devtype_to_name $DEV_TYPE`"
    echo "Driver: $DEV_DRIVER"
    echo "State: `state_to_name $DEV_STATE`"
  done
}

# print devices details
list_devices_details

