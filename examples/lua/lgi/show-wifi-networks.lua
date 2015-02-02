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
-- This example lists Wi-Fi access points NetworkManager scanned on Wi-Fi devices.
-- The example uses libnm library using GObject introspection via Lua lgi module.
-- Most distribution ship the module as lua-lgi package.
-- libnm guide:   https://developer.gnome.org/libnm/1.0/
-- Lua-lgi guide: https://github.com/pavouk/lgi/blob/master/docs/guide.md
--

local lgi = require 'lgi'
local NM = lgi.NM

function ssid_to_utf8(ap)
  local ssid = ap:get_ssid()
  if not ssid then return "" end
  return NM.utils_ssid_to_utf8(ssid:get_data())
end

function print_device_info(device)
  local active_ap = device:get_active_access_point()
  if active_ap then ssid = ssid_to_utf8(active_ap) end
  local info = string.format("Device: %s | Driver: %s | Active AP: %s",
                             device:get_iface(), device:get_driver(), ssid)
  print(info)
  print(string.rep("=", info:len()))
end

function print_ap_info(ap)
  local strength = ap:get_strength()
  local frequency = ap:get_frequency()
  print("SSID:      ", ssid_to_utf8(ap))
  print("BSSID:     ", ap:get_bssid())
  print("Frequency: ", frequency)
  print("Channel:   ", NM.utils_wifi_freq_to_channel(frequency))
  print(string.format("Strength:  %s %s%%", NM.utils_wifi_strength_bars(strength), strength))
  print("")
end


---------------------------
-- Main code starts here --
---------------------------
-- Call setlocale() else NM.utils_wifi_strength_bars() will think the locale
-- is ASCII-only, and return the fallback characters rather than the unicode bars
os.setlocale('')

-- get all devices
client = NM.Client.new()
devs = client:get_devices()

-- print APs for all Wi-Fi devices
for _, dev in ipairs(devs) do
  if dev:get_device_type() == "WIFI" then
    print_device_info(dev)
    for _, ap in ipairs(dev:get_access_points()) do
      print_ap_info(ap)
    end
  end
end

