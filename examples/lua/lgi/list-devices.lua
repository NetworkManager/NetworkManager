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
-- Getting basic information about network interfaces known to NetworkManager.
-- The example uses libnm library using GObject introspection via Lua lgi module.
-- Most distribution ship the module as lua-lgi package.
-- libnm guide:   https://developer.gnome.org/libnm/1.0/
-- Lua-lgi guide: https://github.com/pavouk/lgi/blob/master/docs/guide.md
--

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

