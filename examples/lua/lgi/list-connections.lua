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
-- Getting and printing all NetworkManager connection in Lua.
-- The example uses libnm library using GObject introspection via Lua lgi module.
-- Most distribution ship the module as lua-lgi package.
-- libnm guide:   https://developer.gnome.org/libnm/1.0/
-- Lua-lgi guide: https://github.com/pavouk/lgi/blob/master/docs/guide.md
--

local lgi = require 'lgi'
local GLib = lgi.GLib
local NM = lgi.NM

function print_values(setting, key, value, flags, data)
  print(string.format("  %s.%s: %s", setting:get_name(), key, value and tostring(value.value) or "nil"))
end


---------------------------
-- Main code starts here --
---------------------------
-- parse command-line arguments
local details = ...
if (details and not string.find("details", details, 1)) then
  print(string.format("Usage: %s [details]", arg[0]:gsub(".*/","")))
    os.exit(1)
end

-- create Client object
local client = NM.Client.new()

-- get connections
connections = client:get_connections()

-- print the connections' details
print(string.format("There are %s connection profiles.", #connections))
for i, c in pairs(connections) do
  print(string.format("=== %s | %25s | %s ", c:get_uuid(), c:get_id(), c:get_path()))
  if details then
    c:for_each_setting_value(print_values, nil)
    print("\n")
  end
end

