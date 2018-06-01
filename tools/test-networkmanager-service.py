#!/usr/bin/env python
# -*- Mode: python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-

from __future__ import print_function

import sys

import gi
from gi.repository import GLib

try:
    gi.require_version('NM', '1.0')
    from gi.repository import NM
except Exception as e:
    print("Cannot load gi.NM: %s" % (str(e)))
    sys.exit(77)

import dbus
import dbus.service
import dbus.mainloop.glib
import random
import collections
import uuid
import hashlib

###############################################################################

_DEFAULT_ARG = object()

###############################################################################

class Global:
    pass

gl = None

###############################################################################

class TestError(AssertionError):
    def __init__(self, message = 'Unspecified error', errors = None):
        AssertionError.__init__(self, message)
        self.errors = errors

###############################################################################

IFACE_DBUS = 'org.freedesktop.DBus'

class UnknownInterfaceException(dbus.DBusException):
    _dbus_error_name = IFACE_DBUS + '.UnknownInterface'

class UnknownPropertyException(dbus.DBusException):
    _dbus_error_name = IFACE_DBUS + '.UnknownProperty'

class Util:

    @staticmethod
    def pseudorandom_stream(seed, length = None):
        seed = str(seed)
        v = None
        i = 0
        while length is None or length > 0:
            if not v:
                s = seed + str(i)
                s = s.encode('utf8')
                v = hashlib.sha256(s).hexdigest()
                i += 1
            yield int(v[0:2], 16)
            v = v[2:]
            if length is not None:
                length -= 1

    @staticmethod
    def pseudorandom_num(seed, v_end, v_start = 0):
        n = 0
        span = v_end - v_start
        for r in Util.pseudorandom_stream(seed):
            n = n * 256 + r
            if n > span:
                break
        return v_start + (n % span)

    @staticmethod
    def random_mac(seed = None):
        if seed is None:
            r = tuple([random.randint(0, 255) for x in range(6)])
        else:
            r = tuple(Util.pseudorandom_stream(seed, 6))
        return '%02X:%02X:%02X:%02X:%02X:%02X' % r

###############################################################################

class ExportedObj(dbus.service.Object):

    DBusInterface = collections.namedtuple('DBusInterface', ['dbus_iface', 'props', 'legacy_prop_changed_func'])

    @staticmethod
    def create_path(klass, path_prefix = None):
        if path_prefix is None:
            path_prefix = klass.path_prefix
        path = path_prefix + str(klass.path_counter_next)
        klass.path_counter_next += 1
        return path

    @staticmethod
    def to_path_array(src):
        array = dbus.Array([], signature=dbus.Signature('o'))
        if src is not None:
            for o in src:
                array.append(ExportedObj.to_path(o))
        return array

    @staticmethod
    def to_path(src):
        if src:
            return dbus.ObjectPath(src.path)
        return dbus.ObjectPath("/")

    def __init__(self, object_path, ident = None):
        dbus.service.Object.__init__(self)

        self._dbus_ifaces = {}
        self.path = object_path

        # ident is an optional (unique) identifier for the instance.
        # The test driver may set it to reference to the object by
        # this identifier. For NetworkManager, the real ID of an
        # object on D-Bus is the object_path. But that is generated
        # by the stub server only after the test user created the
        # object. The ident parameter may be specified by the user
        # and thus can be hard-coded in the test.
        if ident is None:
            ident = object_path
        self.ident = ident

    def export(self):
        self.add_to_connection(gl.bus, self.path)
        gl.object_manager.add_object(self)

    def unexport(self):
        gl.object_manager.remove_object(self)
        self.remove_from_connection()

    def dbus_interface_add(self, dbus_iface, props, legacy_prop_changed_func = None):
        self._dbus_ifaces[dbus_iface] = ExportedObj.DBusInterface(dbus_iface, props, legacy_prop_changed_func)

    def _dbus_interface_get(self, dbus_iface):
        if dbus_iface not in self._dbus_ifaces:
            raise UnknownInterfaceException()
        return self._dbus_ifaces[dbus_iface]

    def _dbus_interface_get_property(self, dbus_interface, propname = None):
        props = dbus_interface.props
        if propname is None:
            return props
        if propname not in props:
            raise UnknownPropertyException()
        return props[propname]

    def _dbus_property_get(self, dbus_iface, propname = None):
        return self._dbus_interface_get_property(self._dbus_interface_get(dbus_iface),
                                                 propname)

    def _dbus_property_set(self, dbus_iface, propname, value, allow_detect_dbus_iface = False, dry_run = False):
        if allow_detect_dbus_iface and not dbus_iface:
            props = None
            for p, dbus_interface in self._dbus_ifaces.items():
                if propname in dbus_interface.props:
                    if props is not None:
                        raise TestError("Cannot uniquely find the property '%s' on object '%s'" % (propname, self.path))
                    props = dbus_interface.props
                    dbus_iface = p
            if props is None:
                raise TestError("Cannot find the property '%s' on object '%s'" % (propname, self.path))
        else:
            try:
                dbus_interface = self._dbus_interface_get(dbus_iface)
                props = self._dbus_interface_get_property(dbus_interface)
            except:
                if dry_run:
                    raise TestError("No interface '%s' on '%s'" % (dbus_iface, self.path))
                raise

        if dry_run:
            if propname not in props:
                raise TestError("No property '%s' on '%s' on '%s'" % (propname, dbus_iface, self.path))

            if     isinstance(self, ActiveConnection) \
               and dbus_iface == 'org.freedesktop.NetworkManager.Connection.Active' \
               and propname == 'State':
                return
            else:
                raise TestError("Cannot set property '%s' on '%s' on '%s' via D-Bus" % (propname, dbus_iface, self.path))

        assert propname in props

        props[propname] = value
        self._dbus_property_notify(dbus_iface, propname)

    def _dbus_property_notify(self, dbus_iface, propname):
        dbus_interface = self._dbus_interface_get(dbus_iface)
        prop = self._dbus_interface_get_property(dbus_interface, propname)
        if propname is not None:
            prop = { propname: prop }
        ExportedObj.PropertiesChanged(self, dbus_iface, prop, [])

        # the legacy_prop_changed_func signal is a legacy signal that got obsoleted by the standard
        # PropertiesChanged signal. NetworkManager (and this stub) still emit it for backward
        # compatibility reasons. Note that this stub server implementation gets this wrong,
        # for example, it emits PropertiesChanged signal on org.freedesktop.NetworkManager.Device,
        # which NetworkManager never did.
        # See https://cgit.freedesktop.org/NetworkManager/NetworkManager/tree/src/nm-dbus-manager.c?id=db80d5f62a1edf39c5970887ef7b9ec62dd4163f#n1274
        if dbus_interface.legacy_prop_changed_func is not None:
            dbus_interface.legacy_prop_changed_func(self, prop)

    @dbus.service.signal(dbus.PROPERTIES_IFACE, signature='sa{sv}as')
    def PropertiesChanged(self, iface, changed, invalidated):
        pass

    @dbus.service.method(dbus_interface=dbus.PROPERTIES_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, dbus_iface):
        return self._dbus_property_get(dbus_iface)

    @dbus.service.method(dbus_interface=dbus.PROPERTIES_IFACE, in_signature='ss', out_signature='v')
    def Get(self, dbus_iface, name):
        return self._dbus_property_get(dbus_iface, name)

    def get_managed_ifaces(self):
        my_ifaces = {}
        for iface in self._dbus_ifaces:
            my_ifaces[iface] = self._dbus_ifaces[iface].props
        return my_ifaces

###############################################################################

IFACE_DEVICE = 'org.freedesktop.NetworkManager.Device'

class NotSoftwareException(dbus.DBusException):
    _dbus_error_name = IFACE_DEVICE + '.NotSoftware'

PRP_DEVICE_UDI                   = "Udi"
PRP_DEVICE_IFACE                 = "Interface"
PRP_DEVICE_DRIVER                = "Driver"
PRP_DEVICE_STATE                 = "State"
PRP_DEVICE_ACTIVE_CONNECTION     = "ActiveConnection"
PRP_DEVICE_IP4_CONFIG            = "Ip4Config"
PRP_DEVICE_IP6_CONFIG            = "Ip6Config"
PRP_DEVICE_DHCP4_CONFIG          = "Dhcp4Config"
PRP_DEVICE_DHCP6_CONFIG          = "Dhcp6Config"
PRP_DEVICE_MANAGED               = "Managed"
PRP_DEVICE_AUTOCONNECT           = "Autoconnect"
PRP_DEVICE_DEVICE_TYPE           = "DeviceType"
PRP_DEVICE_AVAILABLE_CONNECTIONS = "AvailableConnections"

class Device(ExportedObj):

    path_counter_next = 1
    path_prefix = "/org/freedesktop/NetworkManager/Devices/"

    def __init__(self, iface, devtype, ident = None):

        if ident is None:
            ident = iface

        ExportedObj.__init__(self, ExportedObj.create_path(Device), ident)

        props = {
            PRP_DEVICE_UDI:                   "/sys/devices/virtual/%s" % (iface),
            PRP_DEVICE_IFACE:                 iface,
            PRP_DEVICE_DRIVER:                "virtual",
            PRP_DEVICE_STATE:                 dbus.UInt32(NM.DeviceState.UNAVAILABLE),
            PRP_DEVICE_ACTIVE_CONNECTION:     ExportedObj.to_path(None),
            PRP_DEVICE_IP4_CONFIG:            ExportedObj.to_path(None),
            PRP_DEVICE_IP6_CONFIG:            ExportedObj.to_path(None),
            PRP_DEVICE_DHCP4_CONFIG:          ExportedObj.to_path(None),
            PRP_DEVICE_DHCP6_CONFIG:          ExportedObj.to_path(None),
            PRP_DEVICE_MANAGED:               True,
            PRP_DEVICE_AUTOCONNECT:           True,
            PRP_DEVICE_DEVICE_TYPE:           dbus.UInt32(devtype),
            PRP_DEVICE_AVAILABLE_CONNECTIONS: ExportedObj.to_path_array([]),
        }

        self.dbus_interface_add(IFACE_DEVICE, props, Device.PropertiesChanged)

    @dbus.service.method(dbus_interface=IFACE_DEVICE, in_signature='', out_signature='')
    def Disconnect(self):
        pass

    @dbus.service.method(dbus_interface=IFACE_DEVICE, in_signature='', out_signature='')
    def Delete(self):
        # We don't currently support any software device types, so...
        raise NotSoftwareException()
        pass

    @dbus.service.signal(IFACE_DEVICE, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

    def set_active_connection(self, ac):
        self._dbus_property_set(IFACE_DEVICE, PRP_DEVICE_ACTIVE_CONNECTION, ac)

###############################################################################

IFACE_WIRED = 'org.freedesktop.NetworkManager.Device.Wired'

PRP_WIRED_HW_ADDRESS       = "HwAddress"
PRP_WIRED_PERM_HW_ADDRESS  = "PermHwAddress"
PRP_WIRED_SPEED            = "Speed"
PRP_WIRED_CARRIER          = "Carrier"
PRP_WIRED_S390_SUBCHANNELS = "S390Subchannels"

class WiredDevice(Device):
    def __init__(self, iface, mac = None, subchannels = None, ident = None):
        Device.__init__(self, iface, NM.DeviceType.ETHERNET, ident)

        if mac is None:
            mac = Util.random_mac(self.ident)
        if subchannels is None:
            subchannels = dbus.Array(signature = 's')

        props = {
            PRP_WIRED_HW_ADDRESS:       mac,
            PRP_WIRED_PERM_HW_ADDRESS:  mac,
            PRP_WIRED_SPEED:            dbus.UInt32(100),
            PRP_WIRED_CARRIER:          False,
            PRP_WIRED_S390_SUBCHANNELS: subchannels,
        }

        self.dbus_interface_add(IFACE_WIRED, props, WiredDevice.PropertiesChanged)

    @dbus.service.signal(IFACE_WIRED, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

###############################################################################

IFACE_VLAN = 'org.freedesktop.NetworkManager.Device.Vlan'

PRP_VLAN_HW_ADDRESS = "HwAddress"
PRP_VLAN_CARRIER    = "Carrier"
PRP_VLAN_VLAN_ID    = "VlanId"

class VlanDevice(Device):
    def __init__(self, iface, ident = None):
        Device.__init__(self, iface, NM.DeviceType.VLAN, ident)

        props = {
            PRP_VLAN_HW_ADDRESS: Util.random_mac(self.ident),
            PRP_VLAN_CARRIER:    False,
            PRP_VLAN_VLAN_ID:    dbus.UInt32(1),
        }

        self.dbus_interface_add(IFACE_VLAN, props, VlanDevice.PropertiesChanged)

    @dbus.service.signal(IFACE_VLAN, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

###############################################################################

IFACE_WIFI_AP = 'org.freedesktop.NetworkManager.AccessPoint'

PRP_WIFI_AP_FLAGS       = "Flags"
PRP_WIFI_AP_WPA_FLAGS   = "WpaFlags"
PRP_WIFI_AP_RSN_FLAGS   = "RsnFlags"
PRP_WIFI_AP_SSID        = "Ssid"
PRP_WIFI_AP_FREQUENCY   = "Frequency"
PRP_WIFI_AP_HW_ADDRESS  = "HwAddress"
PRP_WIFI_AP_MODE        = "Mode"
PRP_WIFI_AP_MAX_BITRATE = "MaxBitrate"
PRP_WIFI_AP_STRENGTH    = "Strength"

class WifiAp(ExportedObj):

    path_counter_next = 1
    path_prefix = "/org/freedesktop/NetworkManager/AccessPoint/"

    def __init__(self, ssid, bssid = None, flags = None, wpaf = None, rsnf = None, freq = None, strength = None, ident = None):

        ExportedObj.__init__(self, ExportedObj.create_path(WifiAp), ident)

        if flags is None:
            flags = 0x1
        if wpaf is None:
            wpaf = 0x1cc
        if rsnf is None:
            rsnf = 0x1cc
        if freq is None:
            freq = 2412
        if bssid is None:
            bssid = Util.random_mac(self.path)
        if strength is None:
            strength = Util.pseudorandom_num(self.path, 100)

        self.ssid = ssid
        self.strength_counter = 0
        self.strength_id = GLib.timeout_add_seconds(10, self.strength_cb, None)

        props = {
            PRP_WIFI_AP_FLAGS:       dbus.UInt32(flags),
            PRP_WIFI_AP_WPA_FLAGS:   dbus.UInt32(wpaf),
            PRP_WIFI_AP_RSN_FLAGS:   dbus.UInt32(rsnf),
            PRP_WIFI_AP_SSID:        dbus.ByteArray(self.ssid.encode('utf-8')),
            PRP_WIFI_AP_FREQUENCY:   dbus.UInt32(freq),
            PRP_WIFI_AP_HW_ADDRESS:  bssid,
            PRP_WIFI_AP_MODE:        dbus.UInt32(getattr(NM,'80211Mode').INFRA),
            PRP_WIFI_AP_MAX_BITRATE: dbus.UInt32(54000),
            PRP_WIFI_AP_STRENGTH:    dbus.Byte(strength),
        }

        self.dbus_interface_add(IFACE_WIFI_AP, props, WifiAp.PropertiesChanged)

    def __del__(self):
        if self.strength_id > 0:
            GLib.source_remove(self.strength_id)
        self.strength_id = 0

    def strength_cb(self, ignored):
        self.strength_counter += 1
        strength = Util.pseudorandom_num(self.path + str(self.strength_counter), 100)
        self._dbus_property_set(IFACE_WIFI_AP, PRP_WIFI_AP_STRENGTH, strength)
        return True

    @dbus.service.signal(IFACE_WIFI_AP, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

###############################################################################

IFACE_WIFI = 'org.freedesktop.NetworkManager.Device.Wireless'

class ApNotFoundException(dbus.DBusException):
    _dbus_error_name = IFACE_WIFI + '.AccessPointNotFound'

PRP_WIFI_HW_ADDRESS = "HwAddress"
PRP_WIFI_PERM_HW_ADDRESS = "PermHwAddress"
PRP_WIFI_MODE = "Mode"
PRP_WIFI_BITRATE = "Bitrate"
PRP_WIFI_ACCESS_POINTS = "AccessPoints"
PRP_WIFI_ACTIVE_ACCESS_POINT = "ActiveAccessPoint"
PRP_WIFI_WIRELESS_CAPABILITIES = "WirelessCapabilities"

class WifiDevice(Device):
    def __init__(self, iface, mac = None, ident = None):
        Device.__init__(self, iface, NM.DeviceType.WIFI, ident)

        if mac is None:
            mac = Util.random_mac(self.ident)

        self.aps = []

        props = {
            PRP_WIFI_HW_ADDRESS:            mac,
            PRP_WIFI_PERM_HW_ADDRESS:       mac,
            PRP_WIFI_MODE:                  dbus.UInt32(getattr(NM,'80211Mode').INFRA),
            PRP_WIFI_BITRATE:               dbus.UInt32(21000),
            PRP_WIFI_WIRELESS_CAPABILITIES: dbus.UInt32(0xFF),
            PRP_WIFI_ACCESS_POINTS:         ExportedObj.to_path_array(self.aps),
            PRP_WIFI_ACTIVE_ACCESS_POINT:   ExportedObj.to_path(None),
        }

        self.dbus_interface_add(IFACE_WIFI, props, WifiDevice.PropertiesChanged)

    @dbus.service.method(dbus_interface=IFACE_WIFI, in_signature='', out_signature='ao')
    def GetAccessPoints(self):
        # only include non-hidden APs
        return ExportedObj.to_path_array([a for a in self.aps if a.ssid])

    @dbus.service.method(dbus_interface=IFACE_WIFI, in_signature='', out_signature='ao')
    def GetAllAccessPoints(self):
        # include all APs including hidden ones
        return ExportedObj.to_path_array(self.aps)

    @dbus.service.method(dbus_interface=IFACE_WIFI, in_signature='a{sv}', out_signature='')
    def RequestScan(self, props):
        pass

    @dbus.service.signal(IFACE_WIFI, signature='o')
    def AccessPointAdded(self, ap_path):
        pass

    def add_ap(self, ap):
        ap.export()
        self.aps.append(ap)
        self._dbus_property_set(IFACE_WIFI, PRP_WIFI_ACCESS_POINTS, ExportedObj.to_path_array(self.aps))
        self.AccessPointAdded(ExportedObj.to_path(ap))
        return ap

    def remove_ap(self, ap):
        self.aps.remove(ap)
        self._dbus_property_set(IFACE_WIFI, PRP_WIFI_ACCESS_POINTS, ExportedObj.to_path_array(self.aps))
        self.AccessPointRemoved(ExportedObj.to_path(ap))
        ap.unexport()

    @dbus.service.signal(IFACE_WIFI, signature='o')
    def AccessPointRemoved(self, ap_path):
        pass

    @dbus.service.signal(IFACE_WIFI, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

    def remove_ap_by_path(self, path):
        for ap in self.aps:
            if ap.path == path:
                self.remove_ap(ap)
                return
        raise ApNotFoundException("AP %s not found" % path)


###############################################################################

IFACE_WIMAX_NSP = 'org.freedesktop.NetworkManager.WiMax.Nsp'

PRP_WIMAX_NSP_NAME = "Name"
PRP_WIMAX_NSP_SIGNAL_QUALITY = "SignalQuality"
PRP_WIMAX_NSP_NETWORK_TYPE = "NetworkType"

class WimaxNsp(ExportedObj):

    path_counter_next = 1
    path_prefix = "/org/freedesktop/NetworkManager/Nsp/"

    def __init__(self, name):

        ExportedObj.__init__(self, ExportedObj.create_path(WimaxNsp))

        self.strength_id = GLib.timeout_add_seconds(10, self.strength_cb, None)

        props = {
            PRP_WIMAX_NSP_NAME:           name,
            PRP_WIMAX_NSP_SIGNAL_QUALITY: dbus.UInt32(random.randint(0, 100)),
            PRP_WIMAX_NSP_NETWORK_TYPE:   dbus.UInt32(NM.WimaxNspNetworkType.HOME),
        }

        self.dbus_interface_add(IFACE_WIMAX_NSP, props, WimaxNsp.PropertiesChanged)

    def __del__(self):
        if self.strength_id > 0:
            GLib.source_remove(self.strength_id)
        self.strength_id = 0

    def strength_cb(self, ignored):
        self._dbus_property_set(IFACE_WIMAX_NSP, PRP_WIMAX_NSP_SIGNAL_QUALITY, dbus.UInt32(random.randint(0, 100)))
        return True

    @dbus.service.signal(IFACE_WIMAX_NSP, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

###############################################################################

IFACE_WIMAX = 'org.freedesktop.NetworkManager.Device.WiMax'

class NspNotFoundException(dbus.DBusException):
    _dbus_error_name = IFACE_WIMAX + '.NspNotFound'

PRP_WIMAX_NSPS = "Nsps"
PRP_WIMAX_HW_ADDRESS = "HwAddress"
PRP_WIMAX_CENTER_FREQUENCY = "CenterFrequency"
PRP_WIMAX_RSSI = "Rssi"
PRP_WIMAX_CINR = "Cinr"
PRP_WIMAX_TX_POWER = "TxPower"
PRP_WIMAX_BSID = "Bsid"
PRP_WIMAX_ACTIVE_NSP = "ActiveNsp"

class WimaxDevice(Device):
    def __init__(self, iface, ident = None):
        Device.__init__(self, iface, NM.DeviceType.WIMAX, ident)

        mac = Util.random_mac(self.ident)
        bsid = Util.random_mac(self.ident + '.bsid')

        self.nsps = []

        props = {
            PRP_WIMAX_HW_ADDRESS:       mac,
            PRP_WIMAX_CENTER_FREQUENCY: dbus.UInt32(2525),
            PRP_WIMAX_RSSI:             dbus.Int32(-48),
            PRP_WIMAX_CINR:             dbus.Int32(24),
            PRP_WIMAX_TX_POWER:         dbus.Int32(9),
            PRP_WIMAX_BSID:             bsid,
            PRP_WIMAX_NSPS:             ExportedObj.to_path_array(self.nsps),
            PRP_WIMAX_ACTIVE_NSP:       ExportedObj.to_path(None),
        }

        self.dbus_interface_add(IFACE_WIMAX, props, WimaxDevice.PropertiesChanged)

    @dbus.service.method(dbus_interface=IFACE_WIMAX, in_signature='', out_signature='ao')
    def GetNspList(self):
        return ExportedObj.to_path_array(self.nsps)

    @dbus.service.signal(IFACE_WIMAX, signature='o')
    def NspAdded(self, nsp_path):
        pass

    def add_nsp(self, nsp):
        nsp.export()
        self.nsps.append(nsp)
        self._dbus_property_set(IFACE_WIMAX, PRP_WIMAX_NSPS, ExportedObj.to_path_array(self.nsps))
        self.NspAdded(ExportedObj.to_path(nsp))

    def remove_nsp(self, nsp):
        self.nsps.remove(nsp)
        self._dbus_property_set(IFACE_WIMAX, PRP_WIMAX_NSPS, ExportedObj.to_path_array(self.nsps))
        self.NspRemoved(ExportedObj.to_path(nsp))
        nsp.unexport()

    @dbus.service.signal(IFACE_WIMAX, signature='o')
    def NspRemoved(self, nsp_path):
        pass

    @dbus.service.signal(IFACE_WIMAX, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

    def add_test_nsp(self, name):
        nsp = WimaxNsp(name)
        self.add_nsp(nsp)
        return nsp

    def remove_nsp_by_path(self, path):
        for nsp in self.nsps:
            if nsp.path == path:
                self.remove_nsp(nsp)
                return
        raise NspNotFoundException("NSP %s not found" % path)

###############################################################################

IFACE_ACTIVE_CONNECTION = 'org.freedesktop.NetworkManager.Connection.Active'

PRP_ACTIVE_CONNECTION_CONNECTION = "Connection"
PRP_ACTIVE_CONNECTION_SPECIFIC_OBJECT = "SpecificObject"
PRP_ACTIVE_CONNECTION_ID = "Id"
PRP_ACTIVE_CONNECTION_UUID = "Uuid"
PRP_ACTIVE_CONNECTION_TYPE = "Type"
PRP_ACTIVE_CONNECTION_DEVICES = "Devices"
PRP_ACTIVE_CONNECTION_STATE = "State"
PRP_ACTIVE_CONNECTION_DEFAULT = "Default"
PRP_ACTIVE_CONNECTION_IP4CONFIG = "Ip4Config"
PRP_ACTIVE_CONNECTION_DHCP4CONFIG = "Dhcp4Config"
PRP_ACTIVE_CONNECTION_DEFAULT6 = "Default6"
PRP_ACTIVE_CONNECTION_IP6CONFIG = "Ip6Config"
PRP_ACTIVE_CONNECTION_DHCP6CONFIG = "Dhcp6Config"
PRP_ACTIVE_CONNECTION_VPN = "Vpn"
PRP_ACTIVE_CONNECTION_MASTER = "Master"

class ActiveConnection(ExportedObj):

    path_counter_next = 1
    path_prefix = "/org/freedesktop/NetworkManager/ActiveConnection/"

    def __init__(self, device, connection, specific_object):

        ExportedObj.__init__(self, ExportedObj.create_path(ActiveConnection))

        self.device = device
        self.conn = connection

        self._activation_id = None

        s_con = connection.con_hash['connection']

        props = {
            PRP_ACTIVE_CONNECTION_CONNECTION:      ExportedObj.to_path(connection),
            PRP_ACTIVE_CONNECTION_SPECIFIC_OBJECT: ExportedObj.to_path(specific_object),
            PRP_ACTIVE_CONNECTION_ID:              s_con['id'],
            PRP_ACTIVE_CONNECTION_UUID:            s_con['uuid'],
            PRP_ACTIVE_CONNECTION_TYPE:            s_con['type'],
            PRP_ACTIVE_CONNECTION_DEVICES:         ExportedObj.to_path_array([self.device]),
            PRP_ACTIVE_CONNECTION_STATE:           dbus.UInt32(NM.ActiveConnectionState.UNKNOWN),
            PRP_ACTIVE_CONNECTION_DEFAULT:         False,
            PRP_ACTIVE_CONNECTION_IP4CONFIG:       ExportedObj.to_path(None),
            PRP_ACTIVE_CONNECTION_DHCP4CONFIG:     ExportedObj.to_path(None),
            PRP_ACTIVE_CONNECTION_DEFAULT6:        False,
            PRP_ACTIVE_CONNECTION_IP6CONFIG:       ExportedObj.to_path(None),
            PRP_ACTIVE_CONNECTION_DHCP6CONFIG:     ExportedObj.to_path(None),
            PRP_ACTIVE_CONNECTION_VPN:             False,
            PRP_ACTIVE_CONNECTION_MASTER:          ExportedObj.to_path(None),
        }

        self.dbus_interface_add(IFACE_ACTIVE_CONNECTION, props, ActiveConnection.PropertiesChanged)

    def _set_state(self, state, reason):
        state = dbus.UInt32(state)
        self._dbus_property_set(IFACE_ACTIVE_CONNECTION, PRP_ACTIVE_CONNECTION_STATE, state)
        self.StateChanged(state, dbus.UInt32(reason))

    def activation_cancel(self):
        if self._activation_id is None:
            return False
        GLib.source_remove(self._activation_id)
        self._activation_id = None
        return True

    def _activation_step2(self):
        assert self._activation_id is not None
        self._activation_id = None
        self._set_state(NM.ActiveConnectionState.ACTIVATED, NM.ActiveConnectionStateReason.UNKNOWN)
        return False

    def _activation_step1(self):
        assert self._activation_id is not None
        self._activation_id = GLib.timeout_add(50, self._activation_step2)
        self.device.set_active_connection(self)
        self._set_state(NM.ActiveConnectionState.ACTIVATING, NM.ActiveConnectionStateReason.UNKNOWN)
        return False

    def start_activation(self):
        assert self._activation_id is None
        self._activation_id = GLib.timeout_add(50, self._activation_step1)

    @dbus.service.signal(IFACE_ACTIVE_CONNECTION, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

    @dbus.service.signal(IFACE_ACTIVE_CONNECTION, signature='uu')
    def StateChanged(self, state, reason):
        pass

###############################################################################

IFACE_TEST = 'org.freedesktop.NetworkManager.LibnmGlibTest'
IFACE_NM = 'org.freedesktop.NetworkManager'

class PermissionDeniedException(dbus.DBusException):
    _dbus_error_name = IFACE_NM + '.PermissionDenied'

class UnknownDeviceException(dbus.DBusException):
    _dbus_error_name = IFACE_NM + '.UnknownDevice'

class UnknownConnectionException(dbus.DBusException):
    _dbus_error_name = IFACE_NM + '.UnknownConnection'

PRP_NM_DEVICES                   = 'Devices'
PRP_NM_ALL_DEVICES               = 'AllDevices'
PRP_NM_NETWORKING_ENABLED        = 'NetworkingEnabled'
PRP_NM_WWAN_ENABLED              = 'WwanEnabled'
PRP_NM_WWAN_HARDWARE_ENABLED     = 'WwanHardwareEnabled'
PRP_NM_WIRELESS_ENABLED          = 'WirelessEnabled'
PRP_NM_WIRELESS_HARDWARE_ENABLED = 'WirelessHardwareEnabled'
PRP_NM_WIMAX_ENABLED             = 'WimaxEnabled'
PRP_NM_WIMAX_HARDWARE_ENABLED    = 'WimaxHardwareEnabled'
PRP_NM_ACTIVE_CONNECTIONS        = 'ActiveConnections'
PRP_NM_PRIMARY_CONNECTION        = 'PrimaryConnection'
PRP_NM_ACTIVATING_CONNECTION     = 'ActivatingConnection'
PRP_NM_STARTUP                   = 'Startup'
PRP_NM_STATE                     = 'State'
PRP_NM_VERSION                   = 'Version'
PRP_NM_CONNECTIVITY              = 'Connectivity'

class NetworkManager(ExportedObj):
    def __init__(self):
        ExportedObj.__init__(self, "/org/freedesktop/NetworkManager")
        self.devices = []
        self.active_connections = []

        props = {
            PRP_NM_DEVICES:                   ExportedObj.to_path_array(self.devices),
            PRP_NM_ALL_DEVICES:               ExportedObj.to_path_array(self.devices),
            PRP_NM_NETWORKING_ENABLED:        True,
            PRP_NM_WWAN_ENABLED:              True,
            PRP_NM_WWAN_HARDWARE_ENABLED:     True,
            PRP_NM_WIRELESS_ENABLED:          True,
            PRP_NM_WIRELESS_HARDWARE_ENABLED: True,
            PRP_NM_WIMAX_ENABLED:             True,
            PRP_NM_WIMAX_HARDWARE_ENABLED:    True,
            PRP_NM_ACTIVE_CONNECTIONS:        ExportedObj.to_path_array(self.active_connections),
            PRP_NM_PRIMARY_CONNECTION:        ExportedObj.to_path(None),
            PRP_NM_ACTIVATING_CONNECTION:     ExportedObj.to_path(None),
            PRP_NM_STARTUP:                   False,
            PRP_NM_STATE:                     dbus.UInt32(NM.State.DISCONNECTED),
            PRP_NM_VERSION:                   "0.9.9.0",
            PRP_NM_CONNECTIVITY:              dbus.UInt32(NM.ConnectivityState.NONE),
        }

        self.dbus_interface_add(IFACE_NM, props, NetworkManager.PropertiesChanged)
        self.export()

    @dbus.service.signal(IFACE_NM, signature='u')
    def StateChanged(self, new_state):
        pass

    def set_state(self, new_state):
        self._dbus_property_set(IFACE_NM, PRP_NM_STATE, state)
        self.StateChanged(dbus.UInt32(self.state))

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='', out_signature='ao')
    def GetDevices(self):
        return ExportedObj.to_path_array(self.devices)

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='', out_signature='ao')
    def GetAllDevices(self):
        return ExportedObj.to_path_array(self.devices)

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='s', out_signature='o')
    def GetDeviceByIpIface(self, ip_iface):
        d = self.find_device_first(ip_iface = ip_iface, require = UnknownDeviceException)
        return ExportedObj.to_path(d)

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='ooo', out_signature='o')
    def ActivateConnection(self, conpath, devpath, specific_object):
        try:
            connection = gl.settings.get_connection(conpath)
        except Exception as e:
            raise UnknownConnectionException("Connection not found")

        con_hash = connection.con_hash
        s_con = con_hash['connection']

        device = self.find_device_first(path = devpath)
        if not device and s_con['type'] == 'vlan':
            ifname = s_con['interface-name']
            device = VlanDevice(ifname)
            self.add_device(device)
        if not device:
            raise UnknownDeviceException("No device found for the requested iface.")

        # See if we need secrets. For the moment, we only support WPA
        if '802-11-wireless-security' in con_hash:
            s_wsec = con_hash['802-11-wireless-security']
            if (s_wsec['key-mgmt'] == 'wpa-psk' and 'psk' not in s_wsec):
                secrets = gl.agent_manager.get_secrets(con_hash, conpath, '802-11-wireless-security')
                if secrets is None:
                    raise NoSecretsException("No secret agent available")
                if '802-11-wireless-security' not in secrets:
                    raise NoSecretsException("No secrets provided")
                s_wsec = secrets['802-11-wireless-security']
                if 'psk' not in s_wsec:
                    raise NoSecretsException("No secrets provided")

        ac = ActiveConnection(device, connection, None)
        self.active_connection_add(ac)

        if s_con['id'] == 'object-creation-failed-test':
            # FIXME: this is not the right test, to delete the active-connection
            # before returning it. It's the wrong order of what NetworkManager
            # would do.
            self.active_connection_remove(ac)
            return ExportedObj.to_path(ac)

        return ExportedObj.to_path(ac)

    def active_connection_add(self, ac):
        ac.export()
        self.active_connections.append(ac)
        self._dbus_property_set(IFACE_NM, PRP_NM_ACTIVE_CONNECTIONS, ExportedObj.to_path_array(self.active_connections))
        ac.start_activation()

    def active_connection_remove(self, ac):
        ac.activation_cancel()
        self.active_connections.remove(ac)
        self._dbus_property_set(IFACE_NM, PRP_NM_ACTIVE_CONNECTIONS, ExportedObj.to_path_array(self.active_connections))
        ac.unexport()

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='a{sa{sv}}oo', out_signature='oo')
    def AddAndActivateConnection(self, connection, devpath, specific_object):
        device = self.find_device_first(path = devpath, require = UnknownDeviceException)
        conpath = gl.settings.AddConnection(connection)
        return (conpath, self.ActivateConnection(conpath, devpath, specific_object))

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='o', out_signature='')
    def DeactivateConnection(self, active_connection):
        pass

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='b', out_signature='')
    def Sleep(self, do_sleep):
        if do_sleep:
            state = NM.State.ASLEEP
        else:
            state = NM.State.DISCONNECTED
        self.set_state(state)

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='b', out_signature='')
    def Enable(self, do_enable):
        pass

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='', out_signature='a{ss}')
    def GetPermissions(self):
        return { "org.freedesktop.NetworkManager.enable-disable-network":   "yes",
                 "org.freedesktop.NetworkManager.sleep-wake":               "no",
                 "org.freedesktop.NetworkManager.enable-disable-wifi":      "yes",
                 "org.freedesktop.NetworkManager.enable-disable-wwan":      "yes",
                 "org.freedesktop.NetworkManager.enable-disable-wimax":     "yes",
                 "org.freedesktop.NetworkManager.network-control":          "yes",
                 "org.freedesktop.NetworkManager.wifi.share.protected":     "yes",
                 "org.freedesktop.NetworkManager.wifi.share.open":          "yes",
                 "org.freedesktop.NetworkManager.settings.modify.own":      "yes",
                 "org.freedesktop.NetworkManager.settings.modify.system":   "yes",
                 "org.freedesktop.NetworkManager.settings.modify.hostname": "yes",
                 "org.freedesktop.NetworkManager.settings.modify.global-dns": "no",
                 "org.freedesktop.NetworkManager.reload":                   "no",
                 }

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='ss', out_signature='')
    def SetLogging(self, level, domains):
        pass

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='', out_signature='ss')
    def GetLogging(self):
        return ("info", "HW,RFKILL,CORE,DEVICE,WIFI,ETHER")

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='', out_signature='u')
    def CheckConnectivity(self):
        raise PermissionDeniedException("You fail")

    @dbus.service.signal(IFACE_NM, signature='o')
    def DeviceAdded(self, devpath):
        pass

    def find_devices(self, ident = _DEFAULT_ARG, path = _DEFAULT_ARG, iface = _DEFAULT_ARG, ip_iface = _DEFAULT_ARG):
        r = None
        for d in self.devices:
            if ident is not _DEFAULT_ARG:
                if d.ident != ident:
                    continue
            if path is not _DEFAULT_ARG:
                if d.path != path:
                    continue
            if iface is not _DEFAULT_ARG:
                if d.iface != iface:
                    continue
            if ip_iface is not _DEFAULT_ARG:
                # ignore iface/ip_iface distinction for now
                if d.iface != ip_iface:
                    continue
            yield d

    def find_device_first(self, ident = _DEFAULT_ARG, path = _DEFAULT_ARG, iface = _DEFAULT_ARG, ip_iface = _DEFAULT_ARG, require = None):
        r = None
        for d in self.find_devices(ident = ident, path = path, iface = iface, ip_iface = ip_iface):
            r = d
            break
        if r is None and require:
            if require is TestError:
                raise TestError('Device not found')
            raise UnknownDeviceException('Device not found')
        return r

    def add_device(self, device):
        if self.find_device_first(ident = device.ident, path = device.path) is not None:
            raise TestError("Duplicate device ident=%s / path=%s" % (device.ident, device.path))
        device.export()
        self.devices.append(device)
        self._dbus_property_set(IFACE_NM, PRP_NM_DEVICES, ExportedObj.to_path_array(self.devices))
        self._dbus_property_set(IFACE_NM, PRP_NM_ALL_DEVICES, ExportedObj.to_path_array(self.devices))
        self.DeviceAdded(ExportedObj.to_path(device))
        return device

    def remove_device(self, device):
        self.devices.remove(device)
        self._dbus_property_set(IFACE_NM, PRP_NM_DEVICES, ExportedObj.to_path_array(self.devices))
        self._dbus_property_set(IFACE_NM, PRP_NM_ALL_DEVICES, ExportedObj.to_path_array(self.devices))
        self.DeviceRemoved(ExportedObj.to_path(device))
        device.unexport()

    @dbus.service.signal(IFACE_NM, signature='o')
    def DeviceRemoved(self, devpath):
        pass

    @dbus.service.signal(IFACE_NM, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

    @dbus.service.method(IFACE_TEST, in_signature='', out_signature='')
    def Quit(self):
        gl.mainloop.quit()

    @dbus.service.method(IFACE_TEST, in_signature='a{ss}', out_signature='a(sss)')
    def FindConnections(self, selector_args):
        return [(c.path, c.get_uuid(), c.get_id()) for c in gl.settings.find_connections(**selector_args)]

    @dbus.service.method(IFACE_TEST, in_signature='a(oa(sa(sv)))', out_signature='')
    def SetProperties(self, all_args):
        for i in [0, 1]:
            for path, iface_args in all_args:
                o = gl.object_manager.find_object(path)
                if o is None:
                    raise TestError("Object %s does not exist" % (path))
                for iface_name, args in iface_args:
                    for propname, value in args:
                        o._dbus_property_set(iface_name, propname, value,
                                             allow_detect_dbus_iface = True,
                                             dry_run = (i == 0))


    @dbus.service.method(IFACE_TEST, in_signature='sa{sv}', out_signature='o')
    def AddObj(self, class_name, args):
        if class_name in ['WiredDevice', 'WifiDevice']:
            py_class = globals()[class_name]
            d = py_class(**args)
            return ExportedObj.to_path(self.add_device(d))
        elif class_name in ['WifiAp']:
            if 'device' not in args:
                raise TestError('missing "device" paramter')
            d = self.find_device_first(ident = args['device'], require = TestError)
            del args['device']
            if 'ssid' not in args:
                args['ssid'] = d.ident + '-ap-' + str(WifiAp.path_counter_next)
            ap = WifiAp(**args)
            return ExportedObj.to_path(d.add_ap(ap))
        raise TestError("Invalid python type \"%s\"" % (class_name))

    @dbus.service.method(IFACE_TEST, in_signature='ssas', out_signature='o')
    def AddWiredDevice(self, ifname, mac, subchannels):
        dev = WiredDevice(ifname, mac, subchannels)
        return ExportedObj.to_path(self.add_device(dev))

    @dbus.service.method(IFACE_TEST, in_signature='s', out_signature='o')
    def AddWifiDevice(self, ifname):
        dev = WifiDevice(ifname)
        return ExportedObj.to_path(self.add_device(dev))

    @dbus.service.method(IFACE_TEST, in_signature='s', out_signature='o')
    def AddWimaxDevice(self, ifname):
        dev = WimaxDevice(ifname)
        return ExportedObj.to_path(self.add_device(dev))

    @dbus.service.method(IFACE_TEST, in_signature='o', out_signature='')
    def RemoveDevice(self, path):
        d = self.find_device_first(path = path, require = TestError)
        self.remove_device(d)

    @dbus.service.method(IFACE_TEST, in_signature='sss', out_signature='o')
    def AddWifiAp(self, ident, ssid, bssid):
        d = self.find_device_first(ident = ident, require = TestError)
        ap = WifiAp(ssid, bssid)
        return ExportedObj.to_path(d.add_ap(ap))

    @dbus.service.method(IFACE_TEST, in_signature='so', out_signature='')
    def RemoveWifiAp(self, ident, ap_path):
        d = self.find_device_first(ident = ident, require = TestError)
        d.remove_ap_by_path(ap_path)

    @dbus.service.method(IFACE_TEST, in_signature='ss', out_signature='o')
    def AddWimaxNsp(self, ident, name):
        d = self.find_device_first(ident = ident, require = TestError)
        return ExportedObj.to_path(d.add_test_nsp(name))

    @dbus.service.method(IFACE_TEST, in_signature='so', out_signature='')
    def RemoveWimaxNsp(self, ident, nsp_path):
        d = self.find_device_first(ident = ident, require = TestError)
        d.remove_nsp_by_path(nsp_path)

    @dbus.service.method(IFACE_TEST, in_signature='', out_signature='')
    def AutoRemoveNextConnection(self):
        gl.settings.auto_remove_next_connection()

    @dbus.service.method(dbus_interface=IFACE_TEST, in_signature='a{sa{sv}}b', out_signature='o')
    def AddConnection(self, connection, verify_connection):
        return gl.settings.add_connection(connection, verify_connection)

    @dbus.service.method(dbus_interface=IFACE_TEST, in_signature='sa{sa{sv}}b', out_signature='')
    def UpdateConnection(self, path, connection, verify_connection):
        return gl.settings.update_connection(connection, path, verify_connection)

    @dbus.service.method(dbus_interface=IFACE_TEST, in_signature='ba{ss}', out_signature='')
    def ConnectionSetVisible(self, vis, selector_args):
        cons = list(gl.settings.find_connections(**selector_args))
        assert(len(cons) == 1)
        cons[0].SetVisible(vis)

    @dbus.service.method(dbus_interface=IFACE_TEST, in_signature='', out_signature='')
    def Restart(self):
        gl.bus.release_name("org.freedesktop.NetworkManager")
        gl.bus.request_name("org.freedesktop.NetworkManager")


###############################################################################

IFACE_CONNECTION = 'org.freedesktop.NetworkManager.Settings.Connection'

class InvalidPropertyException(dbus.DBusException):
    _dbus_error_name = IFACE_CONNECTION + '.InvalidProperty'

class MissingPropertyException(dbus.DBusException):
    _dbus_error_name = IFACE_CONNECTION + '.MissingProperty'

class InvalidSettingException(dbus.DBusException):
    _dbus_error_name = IFACE_CONNECTION + '.InvalidSetting'

class MissingSettingException(dbus.DBusException):
    _dbus_error_name = IFACE_CONNECTION + '.MissingSetting'

PRP_CONNECTION_UNSAVED = 'Unsaved'

class Connection(ExportedObj):
    def __init__(self, path_counter, con_hash, verify_connection=True):

        path = "/org/freedesktop/NetworkManager/Settings/Connection/%s" % (path_counter)

        ExportedObj.__init__(self, path)

        if 'connection' not in con_hash:
            con_hash['connection'] = { }
        if self.get_id(con_hash) is None:
            con_hash['connection']['id'] = 'connection-%s' % (path_counter)
        if self.get_uuid(con_hash) is None:
            con_hash['connection']['uuid'] = str(uuid.uuid3(uuid.NAMESPACE_URL, path))

        self.verify(con_hash, verify_strict=verify_connection)

        self.path = path
        self.con_hash = con_hash
        self.visible = True

        props = {
            PRP_CONNECTION_UNSAVED: False,
        }

        self.dbus_interface_add(IFACE_CONNECTION, props)

    def get_id(self, con_hash=None):
        if con_hash is None:
            con_hash = self.con_hash
        if 'connection' in con_hash:
            s_con = con_hash['connection']
            if 'id' in s_con:
                return s_con['id']
        return None

    def get_uuid(self, con_hash=None):
        if con_hash is None:
            con_hash = self.con_hash
        if 'connection' in con_hash:
            s_con = con_hash['connection']
            if 'uuid' in s_con:
                return s_con['uuid']
        return None

    def verify(self, con_hash=None, verify_strict=True):
        if con_hash is None:
            con_hash = self.con_hash;
        if 'connection' not in con_hash:
            raise MissingSettingException('connection: setting is required')
        s_con = con_hash['connection']
        if 'type' not in s_con:
            raise MissingPropertyException('connection.type: property is required')
        if 'uuid' not in s_con:
            raise MissingPropertyException('connection.uuid: property is required')
        if 'id' not in s_con:
            raise MissingPropertyException('connection.id: property is required')

        if not verify_strict:
            return;
        t = s_con['type']
        if t not in ['802-3-ethernet', '802-11-wireless', 'vlan', 'wimax']:
            raise InvalidPropertyException('connection.type: unsupported connection type "%s"' % (t))

    def update_connection(self, con_hash, verify_connection):
        self.verify(con_hash, verify_strict=verify_connection)

        old_uuid = self.get_uuid()
        new_uuid = self.get_uuid(con_hash)
        if old_uuid != new_uuid:
            raise InvalidPropertyException('connection.uuid: cannot change the uuid from %s to %s' % (old_uuid, new_uuid))

        self.con_hash = con_hash;
        self.Updated()

    @dbus.service.method(dbus_interface=IFACE_CONNECTION, in_signature='', out_signature='a{sa{sv}}')
    def GetSettings(self):
        if not self.visible:
            raise PermissionDeniedException()
        return self.con_hash

    @dbus.service.method(dbus_interface=IFACE_CONNECTION, in_signature='b', out_signature='')
    def SetVisible(self, vis):
        self.visible = vis
        self.Updated()

    @dbus.service.method(dbus_interface=IFACE_CONNECTION, in_signature='', out_signature='')
    def Delete(self):
        gl.settings.delete_connection(self)

    @dbus.service.method(dbus_interface=IFACE_CONNECTION, in_signature='a{sa{sv}}', out_signature='')
    def Update(self, con_hash):
        self.update_connection(con_hash, True)

    @dbus.service.method(dbus_interface=IFACE_CONNECTION, in_signature='a{sa{sv}}ua{sv}', out_signature='a{sv}')
    def Update2(self, con_hash, flags, args):
        self.update_connection(con_hash, True)
        return []

    @dbus.service.signal(IFACE_CONNECTION, signature='')
    def Removed(self):
        pass

    @dbus.service.signal(IFACE_CONNECTION, signature='')
    def Updated(self):
        pass

###############################################################################

IFACE_SETTINGS = 'org.freedesktop.NetworkManager.Settings'

class InvalidHostnameException(dbus.DBusException):
    _dbus_error_name = IFACE_SETTINGS + '.InvalidHostname'

PRP_SETTINGS_HOSTNAME = 'Hostname'
PRP_SETTINGS_CAN_MODIFY = 'CanModify'
PRP_SETTINGS_CONNECTIONS = 'Connections'

class Settings(ExportedObj):
    def __init__(self):
        ExportedObj.__init__(self, "/org/freedesktop/NetworkManager/Settings")

        self.connections = {}
        self.c_counter = 0
        self.remove_next_connection = False

        props = {
            PRP_SETTINGS_HOSTNAME:    "foobar.baz",
            PRP_SETTINGS_CAN_MODIFY:  True,
            PRP_SETTINGS_CONNECTIONS: dbus.Array([], 'o'),
        }

        self.dbus_interface_add(IFACE_SETTINGS, props, Settings.PropertiesChanged)
        self.export()

    def auto_remove_next_connection(self):
        self.remove_next_connection = True;

    def get_connection(self, path):
        return self.connections[path]

    def find_connections(self, path = None, con_id = None, con_uuid = None):
        for c in self.connections.values():
            if path is not None:
                if c.path != path:
                    continue
            if con_id is not None:
                if c.get_id() != con_id:
                    continue
            if con_uuid is not None:
                if c.get_uuid() != con_uuid:
                    continue
            yield c

    @dbus.service.method(dbus_interface=IFACE_SETTINGS, in_signature='', out_signature='ao')
    def ListConnections(self):
        return self.connections.keys()

    @dbus.service.method(dbus_interface=IFACE_SETTINGS, in_signature='a{sa{sv}}', out_signature='o')
    def AddConnection(self, con_hash):
        return self.add_connection(con_hash)

    def add_connection(self, con_hash, verify_connection=True):
        self.c_counter += 1
        con = Connection(self.c_counter, con_hash, verify_connection)

        uuid = con.get_uuid()
        if uuid in [c.get_uuid() for c in self.connections.values()]:
            raise InvalidSettingException('cannot add duplicate connection with uuid %s' % (uuid))

        con.export()
        self.connections[con.path] = con
        self.NewConnection(con.path)
        self._dbus_property_set(IFACE_SETTINGS, PRP_SETTINGS_CONNECTIONS, dbus.Array(self.connections.keys(), 'o'))

        if self.remove_next_connection:
            self.remove_next_connection = False
            self.delete_connection(con)

        return con.path

    def update_connection(self, connection, path=None, verify_connection=True):
        if path is None:
            path = connection.path
        if path not in self.connections:
            raise UnknownConnectionException('Connection not found')
        con = self.connections[path]
        con.update_connection(connection, verify_connection)

    def delete_connection(self, connection):
        del self.connections[connection.path]
        self._dbus_property_set(IFACE_SETTINGS, PRP_SETTINGS_CONNECTIONS, dbus.Array(self.connections.keys(), 'o'))
        connection.Removed()
        connection.unexport()

    @dbus.service.method(dbus_interface=IFACE_SETTINGS, in_signature='s', out_signature='')
    def SaveHostname(self, hostname):
        # Arbitrary requirement to test error handling
        if hostname.find('.') == -1:
            raise InvalidHostnameException()
        self._dbus_property_set(IFACE_SETTINGS, PRP_SETTINGS_HOSTNAME, hostname)

    @dbus.service.signal(IFACE_SETTINGS, signature='o')
    def NewConnection(self, path):
        pass

    @dbus.service.signal(IFACE_SETTINGS, signature='a{sv}')
    def PropertiesChanged(self, path):
        pass

    @dbus.service.method(IFACE_SETTINGS, in_signature='', out_signature='')
    def Quit(self):
        gl.mainloop.quit()

###############################################################################

IFACE_DNS_MANAGER = 'org.freedesktop.NetworkManager.DnsManager'

PRP_DNS_MANAGER_MODE          = 'Mode'
PRP_DNS_MANAGER_RC_MANAGER    = 'RcManager'
PRP_DNS_MANAGER_CONFIGURATION = 'Configuration'

class DnsManager(ExportedObj):
    def __init__(self):
        ExportedObj.__init__(self, "/org/freedesktop/NetworkManager/DnsManager")

        props = {
            PRP_DNS_MANAGER_MODE:          "dnsmasq",
            PRP_DNS_MANAGER_RC_MANAGER:    "symlink",
            PRP_DNS_MANAGER_CONFIGURATION: dbus.Array(
                [
                    dbus.Dictionary(
                        {
                            'nameservers' : dbus.Array(['1.2.3.4', '5.6.7.8'], 's'),
                            'priority'    : dbus.Int32(100),
                        },
                        'sv')
                ],
                'a{sv}'),
        }

        self.dbus_interface_add(IFACE_DNS_MANAGER, props)
        self.export()

###############################################################################

IFACE_AGENT_MANAGER = 'org.freedesktop.NetworkManager.AgentManager'
IFACE_AGENT = 'org.freedesktop.NetworkManager.SecretAgent'

PATH_SECRET_AGENT = '/org/freedesktop/NetworkManager/SecretAgent'

FLAG_ALLOW_INTERACTION = 0x1
FLAG_REQUEST_NEW = 0x2
FLAG_USER_REQUESTED = 0x4

class NoSecretsException(dbus.DBusException):
    _dbus_error_name = IFACE_AGENT_MANAGER + '.NoSecrets'

class UserCanceledException(dbus.DBusException):
    _dbus_error_name = IFACE_AGENT_MANAGER + '.UserCanceled'

class AgentManager(dbus.service.Object):
    def __init__(self):
        dbus.service.Object.__init__(self, gl.bus, "/org/freedesktop/NetworkManager/AgentManager")
        self.agents = {}

    @dbus.service.method(dbus_interface=IFACE_AGENT_MANAGER,
                         in_signature='s', out_signature='',
                         sender_keyword='sender')
    def Register(self, name, sender=None):
        self.RegisterWithCapabilities(name, 0, sender)

    @dbus.service.method(dbus_interface=IFACE_AGENT_MANAGER,
                         in_signature='su', out_signature='',
                         sender_keyword='sender')
    def RegisterWithCapabilities(self, name, caps, sender=None):
        self.agents[sender] = gl.bus.get_object(sender, PATH_SECRET_AGENT)

    @dbus.service.method(dbus_interface=IFACE_AGENT_MANAGER,
                         in_signature='', out_signature='',
                         sender_keyword='sender')
    def Unregister(self, sender=None):
        del self.agents[sender]

    def get_secrets(self, con_hash, path, setting_name):
        if len(self.agents) == 0:
            return None

        secrets = {}
        for sender in self.agents:
            agent = self.agents[sender]
            try:
                secrets = agent.GetSecrets(con_hash, path, setting_name,
                                           dbus.Array([], 's'),
                                           FLAG_ALLOW_INTERACTION | FLAG_USER_REQUESTED,
                                           dbus_interface=IFACE_AGENT)
                break
            except dbus.DBusException as e:
                if e.get_dbus_name() == IFACE_AGENT + '.UserCanceled':
                    raise UserCanceledException('User canceled')
                continue
        return secrets

###############################################################################

IFACE_OBJECT_MANAGER = 'org.freedesktop.DBus.ObjectManager'

class ObjectManager(dbus.service.Object):
    def __init__(self, object_path):
        dbus.service.Object.__init__(self, gl.bus, object_path)
        self.objs = []

    def find_object(self, path):
        for o in self.objs:
            if path == o.path:
                return o
        return None

    def add_object(self, obj):
        self.objs.append(obj)
        self.InterfacesAdded(obj.path, obj.get_managed_ifaces())

    def remove_object(self, obj):
        self.objs.remove(obj)
        self.InterfacesRemoved(obj.path, obj.get_managed_ifaces().keys())

    @dbus.service.signal(IFACE_OBJECT_MANAGER, signature='oa{sa{sv}}')
    def InterfacesAdded(self, name, ifaces):
        pass

    @dbus.service.signal(IFACE_OBJECT_MANAGER, signature='oas')
    def InterfacesRemoved(self, name, ifaces):
        pass

    @dbus.service.method(dbus_interface=IFACE_OBJECT_MANAGER,
                         in_signature='', out_signature='a{oa{sa{sv}}}',
                         sender_keyword='sender')
    def GetManagedObjects(self, sender=None):
        managed_objects = {}
        for obj in self.objs:
            managed_objects[obj.path] = obj.get_managed_ifaces()
        return managed_objects

###############################################################################

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    random.seed()

    global gl
    gl = Global()

    gl.mainloop = GLib.MainLoop()
    gl.bus = dbus.SessionBus()

    gl.object_manager = ObjectManager('/org/freedesktop')
    gl.manager = NetworkManager()
    gl.settings = Settings()
    gl.dns_manager = DnsManager()
    gl.agent_manager = AgentManager()

    if not gl.bus.request_name("org.freedesktop.NetworkManager"):
        raise AssertionError("Failure to request D-Bus name org.freedesktop.NetworkManager")

    # Watch stdin; if it closes, assume our parent has crashed, and exit
    id1 = GLib.IOChannel(0).add_watch(GLib.IOCondition.HUP,
                                      lambda io, condition: gl.mainloop.quit() or True)

    # also quit after inactivity to ensure we don't stick around if the above fails somehow
    id2 = GLib.timeout_add_seconds(20,
                                   lambda: gl.mainloop.quit() or True)

    gl.mainloop.run()

    GLib.source_remove(id1)
    GLib.source_remove(id2)

    gl.agent_manager.remove_from_connection()
    gl.dns_manager.unexport()
    gl.settings.unexport()
    gl.manager.unexport()
    gl.object_manager.remove_from_connection()

    sys.exit(0)

if __name__ == '__main__':
    main()
