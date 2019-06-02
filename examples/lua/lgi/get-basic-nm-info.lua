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
-- This example gets basic information about NetworkManager.
-- The example uses libnm library using GObject introspection via Lua lgi module.
-- Most distribution ship the module as lua-lgi package.
-- libnm guide:   https://developer.gnome.org/libnm/1.0/
-- Lua-lgi guide: https://github.com/pavouk/lgi/blob/master/docs/guide.md
--

local lgi = require 'lgi'
local NM = lgi.NM

---------------------------
-- Main code starts here --
---------------------------
-- get client object
client = NM.Client.new()

print("Basic NM properties:")
print("====================")
print("NM version:          ", client.version)
print("NM state:            ", client.state)
print("NM startup:          ", client.startup)
print("Networking enabled:  ", client.networking_enabled)
print("Wireless enabled:    ", client.wireless_enabled)
print("Wireless HW enabled: ", client.wireless_hardware_enabled)
print("WWAN enabled:        ", client.wwan_enabled)
print("WWAN HW enabled:     ", client.wwan_hardware_enabled)
print("# devices:           ", #client.devices)
print("# connections:       ", #client.connections)
print("# active connections:", #client.active_connections)

