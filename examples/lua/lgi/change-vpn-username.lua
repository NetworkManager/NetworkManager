#!/usr/bin/env lua
-- SPDX-License-Identifier: GPL-2.0+
--
-- Copyright (C) 2015 Red Hat, Inc.
--

-- This example changes username in a VPN profile.
-- The example uses libnm library using GObject introspection via Lua lgi module.
-- Most distribution ship the module as lua-lgi package.
-- libnm guide:   https://developer.gnome.org/libnm/1.0/
-- Lua-lgi guide: https://github.com/pavouk/lgi/blob/master/docs/guide.md

local lgi = require 'lgi'
local NM = lgi.NM

-- mapping from VPN type to username data item
vpn2username = {
  openvpn     = "username",
  vpnc        = "Xauth username",
  pptp        = "user",
  l2tp        = "user",
  openswan    = "leftxauthusername",
}

---------------------------
-- Main code starts here --
---------------------------
-- parse command-line arguments
local profile, username, extra = ...
if (not profile or not username or extra) then
  print(string.format("Usage: %s <vpn_profile> <username>", arg[0]:gsub(".*/","")))
  os.exit(1)
end

-- get client object
client = NM.Client.new()

-- find the connection profile
con = client:get_connection_by_id(profile)
if not con then con = client:get_connection_by_uuid(profile) end
if not con then con = client:get_connection_by_path(profile) end
if not con then io.stderr:write(string.format("Profile %s not found.\n", profile)) os.exit(1) end

if not con:is_type(NM.SETTING_VPN_SETTING_NAME) then
  io.stderr:write(string.format("Profile '%s' is not a VPN.\n", profile))
  os.exit(1)
end

-- get VPN setting
vpn = con:get_setting_vpn()
service_name = vpn:get_service_type()
vpn_type = service_name:match(".*%.(.*)")

if not vpn2username[vpn_type] then
  io.stderr:write(string.format("Unknown VPN type '%s'.\n", vpn_type))
  os.exit(1)
end

-- update the username
vpn:add_data_item(vpn2username[vpn_type], username)
-- save changes
ok, errmsg = con:commit_changes(true)
if not ok then
  io.stderr:write(string.format("Error in updating connection: %s.\n", errmsg))
  os.exit(1)
end

print(string.format("Username updated to '%s'.", username))

