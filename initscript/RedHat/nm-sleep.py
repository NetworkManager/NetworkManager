#!/usr/bin/python

import dbus
service = "org.freedesktop.NetworkManager"
object_path = "/org/freedesktop/NetworkManager"
interface = "org.freedesktop.NetworkManager"
bus = dbus.Bus (dbus.Bus.TYPE_SYSTEM)
NWM_service = bus.get_service (service)
nm = NWM_service.get_object (object_path, interface)
nm.sleep()
