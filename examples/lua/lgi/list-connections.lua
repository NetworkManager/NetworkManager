#!/usr/bin/env lua
-- SPDX-License-Identifier: GPL-2.0+
--
-- Copyright (C) 2015 Red Hat, Inc.
--

-- Getting and printing all NetworkManager connection in Lua.
-- The example uses libnm library using GObject introspection via Lua lgi module.
-- Most distribution ship the module as lua-lgi package.
-- libnm guide:   https://developer.gnome.org/libnm/1.0/
-- Lua-lgi guide: https://github.com/pavouk/lgi/blob/master/docs/guide.md

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

