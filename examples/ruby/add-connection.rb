#!/usr/bin/env ruby
# SPDX-License-Identifier: GPL-2.0+
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
# This uses the old, backwards-compatible settings properties. The new 1.0
# properties (eg, 'address-data' rather than 'addresses') would make this simpler;
# see the python add-connection.py and add-connection-compat.py examples for
# details
#
# Configuration settings are described here:
# https://developer.gnome.org/NetworkManager/1.0/ref-settings.html
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

