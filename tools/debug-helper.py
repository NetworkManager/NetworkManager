#!/usr/bin/python
# Copyright (C) 2011 Mathieu Trudel-Lapierre <mathieu.tl@gmail.com>

import dbus
import argparse

bus = dbus.SystemBus()

parser = argparse.ArgumentParser(description='Interface to easily control logging levels for NetworkManager, ModemManager, and wpasupplicant.')

# NM options
parser.add_argument('--nm', dest='do_set_nm_logging', action='store',
                   help='modify log level for NetworkManager (debug, info, etc.)')
parser.add_argument('--domains', dest='log_domains', action='store',
                   default=[], nargs='+',
                   help='log "domains" to use with NetworkManager (HW, CORE, etc.)')

# MM options
parser.add_argument('--mm', dest='do_set_mm_logging', action='store',
                   help='modify log level for ModemManager (debug, info, etc.)')

# wpasupplicant options
parser.add_argument('--wpa', dest='do_set_wpa_logging', action='store',
                   help='modify log level for wpasupplicant (debug, msgdump, info, etc.)')

args = parser.parse_args()

if args.do_set_nm_logging:
    #print args.log_domains
    dom_msg = ""
    if args.log_domains:
            dom_msg = " for domains: " + ','.join(args.log_domains)
    print("Setting NetworkManager log level to '" + args.do_set_nm_logging + "'" + dom_msg)

    nm_bus = bus.get_object('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager')
    nm = dbus.Interface(nm_bus, dbus_interface='org.freedesktop.NetworkManager')
    nm.SetLogging(args.do_set_nm_logging, ','.join(args.log_domains))

if args.do_set_mm_logging:
    print("Setting ModemManager log level to '" + args.do_set_mm_logging + "'")

    mm_bus = bus.get_object('org.freedesktop.ModemManager', '/org/freedesktop/ModemManager')
    mm = dbus.Interface(mm_bus, dbus_interface='org.freedesktop.ModemManager')
    mm.SetLogging(args.do_set_mm_logging)

if args.do_set_wpa_logging:
    print("Setting wpa_supplicant log level to '" + args.do_set_wpa_logging + "'")

    if 'debug' in args.do_set_wpa_logging or 'msgdump' in args.do_set_wpa_logging:
        print("Enabling timestamps for wpasupplicant debugging logs")
        use_timestamps = dbus.Boolean(True, variant_level=1)
    else:
        print("Disabling timestamps for wpasupplicant debugging logs")
        use_timestamps = dbus.Boolean(False, variant_level=1)

    wpa_bus = bus.get_object('fi.w1.wpa_supplicant1', '/fi/w1/wpa_supplicant1')
    wpa_properties = dbus.Interface(wpa_bus, dbus_interface='org.freedesktop.DBus.Properties')
    wpa_properties.Set('fi.w1.wpa_supplicant1', 'DebugTimestamp', use_timestamps)
    wpa_properties.Set('fi.w1.wpa_supplicant1', 'DebugLevel',
                           dbus.String(args.do_set_wpa_logging, variant_level=1))

