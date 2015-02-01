#!/usr/bin/env lua
-- -*- Mode: Lua; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*-
-- vim: ft=lua ts=2 sts=2 sw=2 et ai
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License along
-- with this program; if not, write to the Free Software Foundation, Inc.,
-- 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
--
-- Copyright 2015 Red Hat, Inc.
--
--
-- This example shows how to get addresses, routes and DNS information from
-- NMIP4Config and NMIP6Config (got out of NMDevice)
-- The example uses libnm library using GObject introspection via Lua lgi module.
-- Most distribution ship the module as lua-lgi package.
-- libnm guide:   https://developer.gnome.org/libnm/1.0/
-- Lua-lgi guide: https://github.com/pavouk/lgi/blob/master/docs/guide.md
--

local lgi = require 'lgi'
local NM = lgi.NM

AF_INET = 2
AF_INET6 = 10

function to_str(table)
  local val = ""
  for i, str in ipairs(table) do
    local delim = i == #table and "" or ", "
    val = val .. str .. delim
  end
  return val
end

function show_addresses(dev, family)
  if (family == AF_INET) then ip_cfg = dev:get_ip4_config()
  else ip_cfg = dev:get_ip6_config() end

  if not ip_cfg then print("None") return end
  local nm_addresses = ip_cfg:get_addresses()
  if #nm_addresses == 0 then print("None") return end

  for _, nm_address in ipairs(nm_addresses) do
    addr = nm_address:get_address()
    prefix = nm_address:get_prefix()
    print(string.format("%s/%d", addr, prefix))
  end
end

function show_gateway(dev, family)
  if (family == AF_INET) then ip_cfg = dev:get_ip4_config()
  else ip_cfg = dev:get_ip6_config() end

  if not ip_cfg then print("None") return end
  gw = ip_cfg:get_gateway()
  print(gw)
end

function show_routes(dev, family)
  if (family == AF_INET) then ip_cfg = dev:get_ip4_config()
  else ip_cfg = dev:get_ip6_config() end

  if not ip_cfg then print("None") return end
  local nm_routes = ip_cfg:get_routes()
  if #nm_routes == 0 then print("None") return end

  for _, nm_route in ipairs(nm_routes) do
    dest = nm_route:get_dest()
    prefix = nm_route:get_prefix()
    next_hop = nm_route:get_next_hop()
    metric = nm_route:get_metric()
    print(string.format("%s/%d  %s  %d", dest, prefix, next_hop, metric))
  end
end

function show_dns(dev, family)
  if (family == AF_INET) then ip_cfg = dev:get_ip4_config()
  else ip_cfg = dev:get_ip6_config() end

  if not ip_cfg then print("None") return end

  print ("Nameservers:", to_str(ip_cfg:get_nameservers()))
  print ("Domains:    ", to_str(ip_cfg:get_domains()))
  print ("Searches:   ", to_str(ip_cfg:get_searches()))
  if (family == AF_INET) then
    print ("WINS:       ", to_str(ip_cfg:get_wins_servers()))
  end
end


---------------------------
-- Main code starts here --
---------------------------
if not arg[1] or arg[2] then
  io.stderr:write(string.format("Usage: %s <interface>\n", arg[0]))
  os.exit(1)
end
local dev_iface = arg[1]

local c = NM.Client.new()
local device = c:get_device_by_iface(dev_iface)
if not device then
  io.stderr:write(string.format("Device '%s' not found\n", dev_iface))
  os.exit(1)
end

local header = string.format("Device: %s - %s", dev_iface, device:get_device_type())
print(header)
print(string.rep("=", #header))

print("IPv4 addresses:")
print("---------------")
show_addresses(device, AF_INET)
print("")

print("IPv4 gateway:")
print("-------------")
show_gateway(device, AF_INET)
print("")

print("IPv4 routes:")
print("------------")
show_routes(device, AF_INET)
print("")

print "IPv6 addresses:"
print("---------------")
show_addresses(device, AF_INET6)
print("")

print("IPv6 gateway:")
print("-------------")
show_gateway(device, AF_INET6)
print("")

print "IPv6 routes:"
print("------------")
show_routes(device, AF_INET6)
print("")

print "IPv4 DNS:"
print("---------")
show_dns(device, AF_INET)
print("")

print "IPv6 DNS:"
print("---------")
show_dns(device, AF_INET6)
print("")

