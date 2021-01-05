#!/usr/bin/env ruby
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (C) 2011 Red Hat, Inc.
#

require 'dbus'

#
# This example gets basic information about NetworkManager.
# Namely, it gets properties from /org/freedesktop/NetworkManager object.
#

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

properties = nm_object["org.freedesktop.DBus.Properties"].GetAll("org.freedesktop.NetworkManager")

puts "Basic NM properties:"
puts "===================="
properties[0].each do |prop,val|
  puts "#{prop} = #{val}"
end

