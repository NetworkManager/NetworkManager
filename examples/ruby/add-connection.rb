#!/usr/bin/env ruby
# vim: ft=ruby ts=2 sts=2 sw=2 et ai
# -*- Mode: ruby; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
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

require 'dbus'
require 'ipaddr'

#
# This example adds a new ethernet connection via Addconnection() D-Bus call.
# It also shows how to specify D-Bus signature for properties like "addresses"
# and "clone-mac-address".
#
# Configuration settings are described here:
# https://developer.gnome.org/NetworkManager/0.9/ref-settings.html
#

# Helper functions
def ip_to_int(ip_addr)
  return IPAddr.new(ip_addr).hton.unpack('L').first
end

def rand_hex_3(l)
  "%0#{l}x" % rand(1 << l*4)
end

def rand_uuid
  [8,4,4,4,12].map {|n| rand_hex_3(n)}.join('-')
end


# Create new connection settings
s_con = {
  "type" => "802-3-ethernet",
  "uuid"=> rand_uuid,
  "id" => "__MyConnection__"
}

s_wired = { "cloned-mac-address" => ["ay", [0x00, 0x22, 0x68, 0x01, 0x02, 0x03]]}

ip1 = ip_to_int("192.168.1.12")
ip2 = ip_to_int("192.168.1.13")
gw1 = ip_to_int("192.168.1.1")
ip3 = ip_to_int("10.0.2.5")
gw2 = ip_to_int("10.0.2.254")
dns1 = ip_to_int("8.8.8.8")
dns2 = ip_to_int("8.8.4.4")

s_ip4 = {
  "addresses"=> ["aau", [[ip1, 24, gw1], [ip2, 24, gw1], [ip3, 24, gw2]]],
  "method"=>["s", "manual"],
  "dns"=> ["au", [dns1, dns2]]
}
s_ip6 = {"method" => "ignore"}

con = {
  "802-3-ethernet" => s_wired,
  "connection" => s_con,
  "ipv4" => s_ip4,
  "ipv6" => s_ip6
}

system_bus = DBus::SystemBus.instance
nm = system_bus.service("org.freedesktop.NetworkManager").object("/org/freedesktop/NetworkManager/Settings")
nm.introspect
settings_iface = nm["org.freedesktop.NetworkManager.Settings"]

ret = settings_iface.AddConnection(con)
puts "New connection added: #{ret.first}"

