#!/usr/bin/env lua
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
-- Deactivate all active connections (of certain type).
-- The example uses libnm library using GObject introspection via Lua lgi module.
-- Most distribution ship the module as lua-lgi package.
-- libnm guide:   https://developer.gnome.org/libnm/1.0/
-- Lua-lgi guide: https://github.com/pavouk/lgi/blob/master/docs/guide.md
--

local lgi = require 'lgi'
local NM = lgi.NM

-- supported connection types
connection_types = {
  NM.SETTING_VPN_SETTING_NAME,
  NM.SETTING_WIRELESS_SETTING_NAME,
  NM.SETTING_WIRED_SETTING_NAME,
  NM.SETTING_BOND_SETTING_NAME,
  NM.SETTING_BRIDGE_SETTING_NAME,
  NM.SETTING_TEAM_SETTING_NAME,
  NM.SETTING_INFINIBAND_SETTING_NAME,
  NM.SETTING_PPPOE_SETTING_NAME,
  NM.SETTING_ADSL_SETTING_NAME,
  NM.SETTING_BLUETOOTH_SETTING_NAME,
  NM.SETTING_WIMAX_SETTING_NAME,
  NM.SETTING_OLPC_MESH_SETTING_NAME,
  NM.SETTING_GENERIC_SETTING_NAME,
}

function known_ctype(ctype, types)
  for _,v in ipairs(types) do
    if v == ctype then return true end
  end
  return false
end

---------------------------
-- Main code starts here --
---------------------------
-- parse command-line arguments
local ctype = ...
if (ctype and not known_ctype(ctype, connection_types)) then
  print(string.format("Usage: %s [<type>]", arg[0]:gsub(".*/","")))
  print("Allowed types:", table.concat(connection_types, ", "))
  os.exit(1)
end

-- create Client object
local client = NM.Client.new()

-- get active connections
connections = client:get_active_connections()

-- deactivate the connections
for _, ac in pairs(connections) do
  if not ctype or ctype == ac:get_connection_type() then
    io.stdout:write(string.format("Deactivating %s (%s)", ac:get_id(), ac:get_uuid()))
    ok,err = client:deactivate_connection(ac, nil, nil)
    if ok then io.stdout:write("\27[32m  -> succeeded\27[0m\n")
    else io.stdout:write(string.format("\27[31m  -> failed\27[0m (%s)\n", err)) end
  end
end

