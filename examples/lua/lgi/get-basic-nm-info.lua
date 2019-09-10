#!/usr/bin/env lua
-- SPDX-License-Identifier: GPL-2.0+
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

