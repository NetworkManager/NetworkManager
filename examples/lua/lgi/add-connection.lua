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
-- Adding an Ethernet connection to NetworkManager in Lua.
-- The example uses libnm library using GObject introspection via Lua lgi module.
-- Most distribution ship the module as lua-lgi package.
-- libnm guide:   https://developer.gnome.org/libnm/1.0/
-- Lua-lgi guide: https://github.com/pavouk/lgi/blob/master/docs/guide.md
--

local lgi = require 'lgi'
local GLib = lgi.GLib
local NM = lgi.NM

function uuid()
  math.randomseed(os.time())
  local template ='xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'
  local uuid = string.gsub(template, '[xy]', function (c)
    local v = (c == 'x') and math.random(0, 0xf) or math.random(8, 0xb)
    return string.format('%x', v)
  end)
  return uuid
end

-- function creating NMConnection
function create_profile(name)
  profile = NM.SimpleConnection.new()

  s_con = NM.SettingConnection.new()
  s_wired = NM.SettingWired.new()
  s_con[NM.SETTING_CONNECTION_ID] = name
  s_con[NM.SETTING_CONNECTION_UUID] = uuid()
  s_con[NM.SETTING_CONNECTION_TYPE] = "802-3-ethernet"

  profile:add_setting(s_con)
  profile:add_setting(s_wired)

  -- show the connection
  -- profile:dump()
  return profile
end

-- callback function for add_connection_async()
function added_cb(client, result, data)
  local con,err,code = client:add_connection_finish(result)
  if con then
    print("The connection profile has been succesfully added to NetworkManager:")
    print(con:get_id(), con:get_uuid())
  else
    print(string.format("Error: (%d) %s", code, err))
  end
  main_loop:quit() -- exit now
end


---------------------------
-- Main code starts here --
---------------------------
-- parse command-line arguments
local name, persist = ...
if (not name or (persist and not string.find("persistent", persist, 1))) then
  print(string.format("Usage: %s <connection name> [persistent]", arg[0]:gsub(".*/","")))
  os.exit(1)
end

-- create GLib main loop
main_loop = GLib.MainLoop(nil, false)

-- create Client object
local client = NM.Client.new()

-- create a connection profile
local con = create_profile(name)

-- send the connection to NetworkManager
client:add_connection_async(con, persist, nil, added_cb, nil)

-- run main loop so that the callback could be called
main_loop:run()

