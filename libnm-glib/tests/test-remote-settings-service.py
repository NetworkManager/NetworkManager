#!/usr/bin/env python
# -*- Mode: python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-

from __future__ import print_function

from gi.repository import GLib, GObject
import sys
import dbus
import dbus.service
import dbus.mainloop.glib

IFACE_SETTINGS = 'org.freedesktop.NetworkManager.Settings'
IFACE_CONNECTION = 'org.freedesktop.NetworkManager.Settings.Connection'
IFACE_DBUS = 'org.freedesktop.DBus'

class UnknownInterfaceException(dbus.DBusException):
    _dbus_error_name = IFACE_DBUS + '.UnknownInterface'

class UnknownPropertyException(dbus.DBusException):
    _dbus_error_name = IFACE_DBUS + '.UnknownProperty'

class PermissionDeniedException(dbus.DBusException):
    _dbus_error_name = IFACE_SETTINGS + '.PermissionDenied'

mainloop = GObject.MainLoop()

class Connection(dbus.service.Object):
    def __init__(self, bus, object_path, settings, remove_func):
        dbus.service.Object.__init__(self, bus, object_path)
        self.path = object_path
        self.settings = settings
        self.remove_func = remove_func
        self.visible = True
        self.props = {}
        self.props['Unsaved'] = False

    # Properties interface
    @dbus.service.method(dbus_interface=dbus.PROPERTIES_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, iface):
        if iface != IFACE_CONNECTION:
            raise UnknownInterfaceException()
        return self.props

    @dbus.service.method(dbus_interface=dbus.PROPERTIES_IFACE, in_signature='ss', out_signature='v')
    def Get(self, iface, name):
        if iface != IFACE_CONNECTION:
            raise UnknownInterfaceException()
        if not name in self.props.keys():
            raise UnknownPropertyException()
        return self.props[name]

    # Connection methods
    @dbus.service.method(dbus_interface=IFACE_CONNECTION, in_signature='', out_signature='a{sa{sv}}')
    def GetSettings(self):
        if not self.visible:
            raise PermissionDeniedException()
        return self.settings

    @dbus.service.method(dbus_interface=IFACE_CONNECTION, in_signature='b', out_signature='')
    def SetVisible(self, vis):
        self.visible = vis
        self.Updated()

    @dbus.service.method(dbus_interface=IFACE_CONNECTION, in_signature='', out_signature='')
    def Delete(self):
        self.remove_func(self)
        self.Removed()

    @dbus.service.signal(IFACE_CONNECTION, signature='')
    def Removed(self):
        pass

    @dbus.service.signal(IFACE_CONNECTION, signature='')
    def Updated(self):
        pass

class Settings(dbus.service.Object):
    def __init__(self, bus, object_path):
        dbus.service.Object.__init__(self, bus, object_path)
        self.connections = {}
        self.bus = bus
        self.counter = 1
        self.props = {}
        self.props['Hostname'] = "foobar.baz"
        self.props['CanModify'] = True

    @dbus.service.method(dbus_interface=IFACE_SETTINGS, in_signature='', out_signature='ao')
    def ListConnections(self):
        connections = []
        return self.connections.keys()

    @dbus.service.method(dbus_interface=IFACE_SETTINGS, in_signature='a{sa{sv}}', out_signature='o')
    def AddConnection(self, settings):
        path = "/org/freedesktop/NetworkManager/Settings/Connection/{0}".format(self.counter)
        self.counter = self.counter + 1
        self.connections[path] = Connection(self.bus, path, settings, self.delete_connection)
        print("Added connection {0}".format(path))
        return path

    def delete_connection(self, connection):
        del self.connections[connection.path]

    @dbus.service.method(dbus_interface=dbus.PROPERTIES_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, iface):
        if iface != IFACE_SETTINGS:
            raise UnknownInterfaceException()
        return self.props

    @dbus.service.method(dbus_interface=dbus.PROPERTIES_IFACE, in_signature='ss', out_signature='v')
    def Get(self, iface, name):
        if iface != IFACE_SETTINGS:
            raise UnknownInterfaceException()
        if not name in self.props.keys():
            raise UnknownPropertyException()
        return self.props[name]

    @dbus.service.signal(IFACE_SETTINGS, signature='o')
    def NewConnection(self, path):
        pass

    @dbus.service.method(IFACE_SETTINGS, in_signature='', out_signature='')
    def Quit(self):
        mainloop.quit()

def quit_cb(user_data):
    mainloop.quit()

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    bus = dbus.SessionBus()
    obj = Settings(bus, "/org/freedesktop/NetworkManager/Settings")
    if not bus.request_name("org.freedesktop.NetworkManager"):
        sys.exit(1)

    print("Service started")

    GLib.timeout_add_seconds(20, quit_cb, None)

    try:
        mainloop.run()
    except Exception as e:
        pass

    print("Service stopped")
    sys.exit(0)

if __name__ == '__main__':
    main()

