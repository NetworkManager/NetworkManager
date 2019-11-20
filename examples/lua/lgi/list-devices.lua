#!/usr/bin/env lua
-- SPDX-License-Identifier: GPL-2.0+
--
-- Copyright (C) 2015 Red Hat, Inc.
--

-- Getting basic information about network interfaces known to NetworkManager.
-- The example uses libnm library using GObject introspection via Lua lgi module.
-- Most distribution ship the module as lua-lgi package.
-- libnm guide:   https://developer.gnome.org/libnm/1.0/
-- Lua-lgi guide: https://github.com/pavouk/lgi/blob/master/docs/guide.md

local lgi = require 'lgi'
local GLib = lgi.GLib
local NM = lgi.NM

---------------------------
-- Main code starts here --
---------------------------
-- create Client object
local client = NM.Client.new()

-- get all devices
devices = client:get_devices()

-- print device details
for i, d in ipairs(devices) do
print("============================")
  print(string.format("Interface: %s", d[NM.DEVICE_INTERFACE]))
  print(string.format("MAC: %s",       d:get_hw_address()))
  print(string.format("Type: %s",      d:get_device_type()))
  print(string.format("Driver: %s",    d:get_driver()))
  print(string.format("State: %s",     d:get_state()))
end

