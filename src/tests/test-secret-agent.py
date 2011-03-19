#!/usr/bin/env python
# -*- Mode: python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-

import glib
import gobject
import sys
import dbus
import dbus.service
import dbus.mainloop.glib

IFACE_SECRET_AGENT = 'org.freedesktop.NetworkManager.SecretAgent'
IFACE_AGENT_MANAGER = 'org.freedesktop.NetworkManager.AgentManager'

class NotAuthorizedException(dbus.DBusException):
    _dbus_error_name = IFACE_SECRET_AGENT + '.NotAuthorized'

class Agent(dbus.service.Object):
    def __init__(self, bus, object_path):
        self.agents = {}
        self.bus = bus
        dbus.service.Object.__init__(self, bus, object_path)

    @dbus.service.method(IFACE_SECRET_AGENT,
                         in_signature='a{sa{sv}}osasb',
                         out_signature='a{sa{sv}}',
                         sender_keyword='sender')
    def GetSecrets(self, connection_hash, connection_path, setting_name, hints, request_new, sender=None):
        if not sender:
            raise NotAuthorizedException("Internal error: couldn't get sender")
        uid = self.bus.get_unix_user(sender)
        if uid != 0:
            raise NotAuthorizedException("UID %d not authorized" % uid)

        print "Secrets requested path '%s' setting '%s' hints '%s' new %d" % (connection_path, setting_name, str(hints), request_new)

        # return some random GSM secrets
        s_gsm = dbus.Dictionary({'password': 'asdfadfasdfaf'})
        con = dbus.Dictionary({'gsm': s_gsm})
        return con

def register(proxy):
    proxy.Register("test.agent.id", dbus_interface=IFACE_AGENT_MANAGER)
    print "Registered!"
    return False

def unregister(proxy, loop):
    proxy.Unregister(dbus_interface=IFACE_AGENT_MANAGER)
    loop.quit()
    return False

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    bus = dbus.SystemBus()
    obj = Agent(bus, "/org/freedesktop/NetworkManager/SecretAgent")
    proxy = bus.get_object("org.freedesktop.NetworkManager",
                           "/org/freedesktop/NetworkManager/AgentManager")

    mainloop = gobject.MainLoop()

    gobject.idle_add(register, proxy)
    print "Running test secret agent" 

    try:
        mainloop.run()
    except KeyboardInterrupt, e:
        pass

    print "Unregistering..."
    unregister(proxy, mainloop);

if __name__ == '__main__':
    main()

