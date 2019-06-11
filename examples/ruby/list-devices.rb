#!/usr/bin/env ruby
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

require 'dbus'

#
# This example lists basic information about network interfaces known to NM
#

# For the types see include/NetworkManager.h
devtypes = { 1 => "Ethernet",
             2 => "Wi-Fi",
             5 => "Bluetooth",
             6 => "OLPC",
             7 => "WiMAX",
             8 => "Modem",
             9 => "InfiniBand",
             10 => "Bond",
             11 => "VLAN",
             12 => "ADSL",
             13 => "Bridge",
             14 => "Generic",
             15 => "Team",
             16 => "TUN",
             17 => "IPTunnel",
             18 => "MACVLAN",
             19 => "VXLAN",
             20 => "Veth",
           }

states = { 0   => "Unknown",
           10  => "Unmanaged",
           20  => "Unavailable",
           30  => "Disconnected",
           40  => "Prepare",
           50  => "Config",
           60  => "Need Auth",
           70  => "IP Config",
           80  => "IP Check",
           90  => "Secondaries",
           100 => "Activated",
           110 => "Deactivating",
           120 => "Failed" }

# Get system bus
system_bus = DBus::SystemBus.instance

# Get the NetworkManager service
nm_service = system_bus.service("org.freedesktop.NetworkManager")

# Get the object from the service
nm_object = nm_service.object("/org/freedesktop/NetworkManager")

# Set default interface for the object
nm_object.default_iface = "org.freedesktop.NetworkManager"

# Introspect it
nm_object.introspect

# Get all devices known to NM
devices = nm_object.GetDevices.first

# and print their properties
devices.each do |d|
  dev_obj = system_bus.service("org.freedesktop.NetworkManager").object(d)
  dev_obj.introspect
  props = dev_obj["org.freedesktop.DBus.Properties"].GetAll("org.freedesktop.NetworkManager.Device")

  puts "============================"
  puts "Interface: #{props[0]['Interface']}"

  devtype = devtypes[props[0]['DeviceType']]
  devtype = "Unknown" if devtype.nil?
  puts "Type: #{devtype}"

  puts "Driver: #{props[0]['Driver']}"

  state = states[props[0]['State']]
  state = "Unknown" if state.nil?
  puts "State: #{state}"
end
