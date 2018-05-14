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

gl = Global()

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

    DBusInterface = collections.namedtuple('DBusInterface', ['dbus_iface', 'get_props_func', 'prop_changed_func'])

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

    def dbus_interface_add(self, dbus_iface, get_props_func, prop_changed_func):
        if not hasattr(self, '_dbus_ifaces'):
            self._dbus_ifaces = {}
        self._dbus_ifaces[dbus_iface] = ExportedObj.DBusInterface(dbus_iface, get_props_func, prop_changed_func)

    def _dbus_interface_get(self, dbus_iface):
        if dbus_iface not in self._dbus_ifaces:
            raise UnknownInterfaceException()
        return self._dbus_ifaces[dbus_iface]

    def _dbus_property_get(self, dbus_iface, propname = None):
        props = self._dbus_interface_get(dbus_iface).get_props_func()
        if propname is None:
            return props
        if propname not in props:
            raise UnknownPropertyException()
        return props[propname]

    def _dbus_property_notify(self, dbus_iface, propname):
        prop = self._dbus_property_get(dbus_iface, propname)
        if propname is not None:
            prop = { propname: prop }
        ExportedObj.PropertiesChanged(self, dbus_iface, prop, [])

        # the prop_changed_func signal is a legacy signal that got obsoleted by the standard
        # PropertiesChanged signal. NetworkManager (and this stub) still emit it for backward
        # compatibility reasons. Note that this stub server implementation gets this wrong,
        # for example, it emits PropertiesChanged signal on org.freedesktop.NetworkManager.Device,
        # which NetworkManager never did.
        # See https://cgit.freedesktop.org/NetworkManager/NetworkManager/tree/src/nm-dbus-manager.c?id=db80d5f62a1edf39c5970887ef7b9ec62dd4163f#n1274
        self._dbus_interface_get(dbus_iface).prop_changed_func(self, prop)

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
            my_ifaces[iface] = self._dbus_ifaces[iface].get_props_func()
        return self.path, my_ifaces

###############################################################################

IFACE_DEVICE = 'org.freedesktop.NetworkManager.Device'

class NotSoftwareException(dbus.DBusException):
    _dbus_error_name = IFACE_DEVICE + '.NotSoftware'

PD_UDI = "Udi"
PD_IFACE = "Interface"
PD_DRIVER = "Driver"
PD_STATE = "State"
PD_ACTIVE_CONNECTION = "ActiveConnection"
PD_IP4_CONFIG = "Ip4Config"
PD_IP6_CONFIG = "Ip6Config"
PD_DHCP4_CONFIG = "Dhcp4Config"
PD_DHCP6_CONFIG = "Dhcp6Config"
PD_MANAGED = "Managed"
PD_AUTOCONNECT = "Autoconnect"
PD_DEVICE_TYPE = "DeviceType"
PD_AVAILABLE_CONNECTIONS = "AvailableConnections"

class Device(ExportedObj):

    path_counter_next = 1
    path_prefix = "/org/freedesktop/NetworkManager/Devices/"

    def __init__(self, iface, devtype, ident = None):

        if ident is None:
            ident = iface

        object_path = ExportedObj.create_path(Device)

        ExportedObj.__init__(self, object_path, ident)

        self.iface = iface
        self.udi = "/sys/devices/virtual/%s" % (self.iface)
        self.devtype = devtype
        self.active_connection = None
        self.state = NM.DeviceState.UNAVAILABLE
        self.ip4_config = None
        self.ip6_config = None
        self.dhcp4_config = None
        self.dhcp6_config = None
        self.available_connections = []

        self.dbus_interface_add(IFACE_DEVICE, self.__get_props, Device.PropertiesChanged)

    def __get_props(self):
        props = {}
        props[PD_UDI] = self.udi
        props[PD_IFACE] = self.iface
        props[PD_DRIVER] = "virtual"
        props[PD_STATE] = dbus.UInt32(self.state)
        props[PD_ACTIVE_CONNECTION] = ExportedObj.to_path(self.active_connection)
        props[PD_IP4_CONFIG] = ExportedObj.to_path(self.ip4_config)
        props[PD_IP6_CONFIG] = ExportedObj.to_path(self.ip6_config)
        props[PD_DHCP4_CONFIG] = ExportedObj.to_path(self.dhcp4_config)
        props[PD_DHCP6_CONFIG] = ExportedObj.to_path(self.dhcp6_config)
        props[PD_MANAGED] = True
        props[PD_AUTOCONNECT] = True
        props[PD_DEVICE_TYPE] = dbus.UInt32(self.devtype)
        props[PD_AVAILABLE_CONNECTIONS] = ExportedObj.to_path_array(self.available_connections)
        return props

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
        self.active_connection = ac
        self._dbus_property_notify(IFACE_DEVICE, PD_ACTIVE_CONNECTION)

###############################################################################

IFACE_WIRED = 'org.freedesktop.NetworkManager.Device.Wired'

PE_HW_ADDRESS = "HwAddress"
PE_PERM_HW_ADDRESS = "PermHwAddress"
PE_SPEED = "Speed"
PE_CARRIER = "Carrier"
PE_S390_SUBCHANNELS = "S390Subchannels"

class WiredDevice(Device):
    def __init__(self, iface, mac = None, subchannels = None, ident = None):
        Device.__init__(self, iface, NM.DeviceType.ETHERNET, ident)
        if mac is None:
            mac = Util.random_mac(self.ident)
        if subchannels is None:
            subchannels = dbus.Array(signature = 's')
        self.mac = mac
        self.carrier = False
        self.s390_subchannels = subchannels

        self.dbus_interface_add(IFACE_WIRED, self.__get_props, WiredDevice.PropertiesChanged)
        self.export()

    def __get_props(self):
        props = {}
        props[PE_HW_ADDRESS] = self.mac
        props[PE_PERM_HW_ADDRESS] = self.mac
        props[PE_SPEED] = dbus.UInt32(100)
        props[PE_CARRIER] = self.carrier
        props[PE_S390_SUBCHANNELS] = self.s390_subchannels
        return props

    @dbus.service.signal(IFACE_WIRED, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

###############################################################################

IFACE_VLAN = 'org.freedesktop.NetworkManager.Device.Vlan'

PV_HW_ADDRESS = "HwAddress"
PV_CARRIER = "Carrier"
PV_VLAN_ID = "VlanId"

class VlanDevice(Device):
    def __init__(self, iface, ident = None):
        Device.__init__(self, iface, NM.DeviceType.VLAN, ident)
        self.mac = Util.random_mac(iface if ident is None else ident)
        self.carrier = False
        self.vlan_id = 1

        self.dbus_interface_add(IFACE_VLAN, self.__get_props, VlanDevice.PropertiesChanged)
        self.export()

    def __get_props(self):
        props = {}
        props[PV_HW_ADDRESS] = self.mac
        props[PV_CARRIER] = self.carrier
        props[PV_VLAN_ID] = dbus.UInt32(self.vlan_id)
        return props

    @dbus.service.signal(IFACE_VLAN, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

###############################################################################

IFACE_WIFI_AP = 'org.freedesktop.NetworkManager.AccessPoint'

PP_FLAGS = "Flags"
PP_WPA_FLAGS = "WpaFlags"
PP_RSN_FLAGS = "RsnFlags"
PP_SSID = "Ssid"
PP_FREQUENCY = "Frequency"
PP_HW_ADDRESS = "HwAddress"
PP_MODE = "Mode"
PP_MAX_BITRATE = "MaxBitrate"
PP_STRENGTH = "Strength"

class WifiAp(ExportedObj):

    path_counter_next = 1
    path_prefix = "/org/freedesktop/NetworkManager/AccessPoint/"

    def __init__(self, ssid, bssid = None, flags = None, wpaf = None, rsnf = None, freq = None, strength = None, ident = None):
        path = ExportedObj.create_path(WifiAp)

        ExportedObj.__init__(self, path, ident)

        if flags is None:
            flags = 0x1
        if wpaf is None:
            wpaf = 0x1cc
        if rsnf is None:
            rsnf = 0x1cc
        if freq is None:
            freq = 2412
        if bssid is None:
            bssid = Util.random_mac(path)
        if strength is None:
            strength = Util.pseudorandom_num(path, 100)

        self.ssid = ssid
        self.bssid = bssid
        self.flags = flags
        self.wpaf = wpaf
        self.rsnf = rsnf
        self.freq = freq
        self.strength = strength
        self.strength_counter = 0
        self.strength_id = GLib.timeout_add_seconds(10, self.strength_cb, None)

        self.dbus_interface_add(IFACE_WIFI_AP, self.__get_props, WifiAp.PropertiesChanged)
        self.export()

    def __del__(self):
        if self.strength_id > 0:
            GLib.source_remove(self.strength_id)
        self.strength_id = 0

    def strength_cb(self, ignored):
        self.strength_counter += 1
        self.strength = Util.pseudorandom_num(self.path + str(self.strength_counter), 100)
        self._dbus_property_notify(IFACE_WIFI_AP, PP_STRENGTH)
        return True

    def __get_props(self):
        props = {}
        props[PP_FLAGS] = dbus.UInt32(self.flags)
        props[PP_WPA_FLAGS] = dbus.UInt32(self.wpaf)
        props[PP_RSN_FLAGS] = dbus.UInt32(self.rsnf)
        props[PP_SSID] = dbus.ByteArray(self.ssid.encode('utf-8'))
        props[PP_FREQUENCY] = dbus.UInt32(self.freq)
        props[PP_HW_ADDRESS] = self.bssid
        props[PP_MODE] = dbus.UInt32(2)  # NM_802_11_MODE_INFRA
        props[PP_MAX_BITRATE] = dbus.UInt32(54000)
        props[PP_STRENGTH] = dbus.Byte(self.strength)
        return props

    @dbus.service.signal(IFACE_WIFI_AP, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

###############################################################################

IFACE_WIFI = 'org.freedesktop.NetworkManager.Device.Wireless'

class ApNotFoundException(dbus.DBusException):
    _dbus_error_name = IFACE_WIFI + '.AccessPointNotFound'

PW_HW_ADDRESS = "HwAddress"
PW_PERM_HW_ADDRESS = "PermHwAddress"
PW_MODE = "Mode"
PW_BITRATE = "Bitrate"
PW_ACCESS_POINTS = "AccessPoints"
PW_ACTIVE_ACCESS_POINT = "ActiveAccessPoint"
PW_WIRELESS_CAPABILITIES = "WirelessCapabilities"

class WifiDevice(Device):
    def __init__(self, iface, mac = None, ident = None):
        Device.__init__(self, iface, NM.DeviceType.WIFI, ident)
        if mac is None:
            mac = Util.random_mac(self.ident)
        self.mac = mac
        self.aps = []
        self.active_ap = None

        self.dbus_interface_add(IFACE_WIFI, self.__get_props, WifiDevice.PropertiesChanged)
        self.export()

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
        self.aps.append(ap)
        self._dbus_property_notify(IFACE_WIFI, PW_ACCESS_POINTS)
        self.AccessPointAdded(ExportedObj.to_path(ap))
        return ap

    @dbus.service.signal(IFACE_WIFI, signature='o')
    def AccessPointRemoved(self, ap_path):
        pass

    def remove_ap(self, ap):
        self.aps.remove(ap)
        self._dbus_property_notify(IFACE_WIFI, PW_ACCESS_POINTS)
        self.AccessPointRemoved(ExportedObj.to_path(ap))

    def __get_props(self):
        props = {}
        props[PW_HW_ADDRESS] = self.mac
        props[PW_PERM_HW_ADDRESS] = self.mac
        props[PW_MODE] = dbus.UInt32(3)  # NM_802_11_MODE_INFRA
        props[PW_BITRATE] = dbus.UInt32(21000)
        props[PW_WIRELESS_CAPABILITIES] = dbus.UInt32(0xFF)
        props[PW_ACCESS_POINTS] = ExportedObj.to_path_array(self.aps)
        props[PW_ACTIVE_ACCESS_POINT] = ExportedObj.to_path(self.active_ap)
        return props

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

PN_NAME = "Name"
PN_SIGNAL_QUALITY = "SignalQuality"
PN_NETWORK_TYPE = "NetworkType"

class WimaxNsp(ExportedObj):

    path_counter_next = 1
    path_prefix = "/org/freedesktop/NetworkManager/Nsp/"

    def __init__(self, name):
        path = ExportedObj.create_path(WimaxNsp)

        ExportedObj.__init__(self, path)

        self.name = name
        self.strength = random.randint(0, 100)
        self.strength_id = GLib.timeout_add_seconds(10, self.strength_cb, None)

        self.dbus_interface_add(IFACE_WIMAX_NSP, self.__get_props, WimaxNsp.PropertiesChanged)
        self.export()

    def __del__(self):
        if self.strength_id > 0:
            GLib.source_remove(self.strength_id)
        self.strength_id = 0

    def strength_cb(self, ignored):
        self.strength = random.randint(0, 100)
        self._dbus_property_notify(IFACE_WIMAX_NSP, PN_SIGNAL_QUALITY)
        return True

    def __get_props(self):
        props = {}
        props[PN_NAME] = self.name
        props[PN_SIGNAL_QUALITY] = dbus.UInt32(self.strength)
        props[PN_NETWORK_TYPE] = dbus.UInt32(0x1)  # NM_WIMAX_NSP_NETWORK_TYPE_HOME
        return props

    @dbus.service.signal(IFACE_WIMAX_NSP, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

###############################################################################

IFACE_WIMAX = 'org.freedesktop.NetworkManager.Device.WiMax'

class NspNotFoundException(dbus.DBusException):
    _dbus_error_name = IFACE_WIMAX + '.NspNotFound'

PX_NSPS = "Nsps"
PX_HW_ADDRESS = "HwAddress"
PX_CENTER_FREQUENCY = "CenterFrequency"
PX_RSSI = "Rssi"
PX_CINR = "Cinr"
PX_TX_POWER = "TxPower"
PX_BSID = "Bsid"
PX_ACTIVE_NSP = "ActiveNsp"

class WimaxDevice(Device):
    def __init__(self, iface, ident = None):
        Device.__init__(self, iface, NM.DeviceType.WIMAX, ident)
        self.mac = Util.random_mac(iface if ident is None else ident)
        self.bsid = Util.random_mac(iface if ident is None else ident)
        self.nsps = []
        self.active_nsp = None

        self.dbus_interface_add(IFACE_WIMAX, self.__get_props, WimaxDevice.PropertiesChanged)
        self.export()

    @dbus.service.method(dbus_interface=IFACE_WIMAX, in_signature='', out_signature='ao')
    def GetNspList(self):
        return ExportedObj.to_path_array(self.nsps)

    @dbus.service.signal(IFACE_WIMAX, signature='o')
    def NspAdded(self, nsp_path):
        pass

    def add_nsp(self, nsp):
        self.nsps.append(nsp)
        self._dbus_property_notify(IFACE_WIMAX, PX_NSPS)
        self.NspAdded(ExportedObj.to_path(nsp))

    @dbus.service.signal(IFACE_WIMAX, signature='o')
    def NspRemoved(self, nsp_path):
        pass

    def remove_nsp(self, nsp):
        self.nsps.remove(nsp)
        self._dbus_property_notify(IFACE_WIMAX, PX_NSPS)
        self.NspRemoved(ExportedObj.to_path(nsp))

    def __get_props(self):
        props = {}
        props[PX_HW_ADDRESS] = self.mac
        props[PX_CENTER_FREQUENCY] = dbus.UInt32(2525)
        props[PX_RSSI] = dbus.Int32(-48)
        props[PX_CINR] = dbus.Int32(24)
        props[PX_TX_POWER] = dbus.Int32(9)
        props[PX_BSID] = self.bsid
        props[PX_NSPS] = ExportedObj.to_path_array(self.nsps)
        props[PX_ACTIVE_NSP] = ExportedObj.to_path(self.active_nsp)
        return props

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

PAC_CONNECTION = "Connection"
PAC_SPECIFIC_OBJECT = "SpecificObject"
PAC_ID = "Id"
PAC_UUID = "Uuid"
PAC_TYPE = "Type"
PAC_DEVICES = "Devices"
PAC_STATE = "State"
PAC_DEFAULT = "Default"
PAC_IP4CONFIG = "Ip4Config"
PAC_DHCP4CONFIG = "Dhcp4Config"
PAC_DEFAULT6 = "Default6"
PAC_IP6CONFIG = "Ip6Config"
PAC_DHCP6CONFIG = "Dhcp6Config"
PAC_VPN = "Vpn"
PAC_MASTER = "Master"

class ActiveConnection(ExportedObj):

    path_counter_next = 1
    path_prefix = "/org/freedesktop/NetworkManager/ActiveConnection/"

    def __init__(self, device, connection, specific_object):
        object_path = ExportedObj.create_path(ActiveConnection)

        ExportedObj.__init__(self, object_path)

        self.device = device
        self.conn = connection
        self.specific_object = specific_object
        self.state = NM.ActiveConnectionState.UNKNOWN
        self.default = False
        self.ip4config = None
        self.dhcp4config = None
        self.default6 = False
        self.ip6config = None
        self.dhcp6config = None
        self.vpn = False
        self.master = None

        self.dbus_interface_add(IFACE_ACTIVE_CONNECTION, self.__get_props, ActiveConnection.PropertiesChanged)

    def __get_props(self):
        props = {}
        props[PAC_CONNECTION] = ExportedObj.to_path(self.conn)
        props[PAC_SPECIFIC_OBJECT] = ExportedObj.to_path(self.specific_object)
        conn_settings = self.conn.GetSettings()
        s_con = conn_settings['connection']
        props[PAC_ID] = s_con['id']
        props[PAC_UUID] = s_con['uuid']
        props[PAC_TYPE] = s_con['type']
        props[PAC_DEVICES] = ExportedObj.to_path_array([self.device])
        props[PAC_STATE] = dbus.UInt32(self.state)
        props[PAC_DEFAULT] = self.default
        props[PAC_IP4CONFIG] = ExportedObj.to_path(self.ip4config)
        props[PAC_DHCP4CONFIG] = ExportedObj.to_path(self.dhcp4config)
        props[PAC_DEFAULT6] = self.default6
        props[PAC_IP6CONFIG] = ExportedObj.to_path(self.ip6config)
        props[PAC_DHCP6CONFIG] = ExportedObj.to_path(self.dhcp6config)
        props[PAC_VPN] = self.vpn
        props[PAC_MASTER] = ExportedObj.to_path(self.master)
        return props

    @dbus.service.signal(IFACE_ACTIVE_CONNECTION, signature='a{sv}')
    def PropertiesChanged(self, changed):
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

PM_DEVICES = 'Devices'
PM_ALL_DEVICES = 'AllDevices'
PM_NETWORKING_ENABLED = 'NetworkingEnabled'
PM_WWAN_ENABLED = 'WwanEnabled'
PM_WWAN_HARDWARE_ENABLED = 'WwanHardwareEnabled'
PM_WIRELESS_ENABLED = 'WirelessEnabled'
PM_WIRELESS_HARDWARE_ENABLED = 'WirelessHardwareEnabled'
PM_WIMAX_ENABLED = 'WimaxEnabled'
PM_WIMAX_HARDWARE_ENABLED = 'WimaxHardwareEnabled'
PM_ACTIVE_CONNECTIONS = 'ActiveConnections'
PM_PRIMARY_CONNECTION = 'PrimaryConnection'
PM_ACTIVATING_CONNECTION = 'ActivatingConnection'
PM_STARTUP = 'Startup'
PM_STATE = 'State'
PM_VERSION = 'Version'
PM_CONNECTIVITY = 'Connectivity'

class NetworkManager(ExportedObj):
    def __init__(self, object_path):
        ExportedObj.__init__(self, object_path)
        self.devices = []
        self.active_connections = []
        self.primary_connection = None
        self.activating_connection = None
        self.state = NM.State.DISCONNECTED
        self.connectivity = 1

        self.dbus_interface_add(IFACE_NM, self.__get_props, NetworkManager.PropertiesChanged)
        self.export()

    @dbus.service.signal(IFACE_NM, signature='u')
    def StateChanged(self, new_state):
        pass

    def set_state(self, new_state):
        self.state = new_state
        self._dbus_property_notify(IFACE_NM, PM_STATE)
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

        hash = connection.GetSettings()
        s_con = hash['connection']

        device = self.find_device_first(path = devpath)
        if not device and s_con['type'] == 'vlan':
            ifname = s_con['interface-name']
            device = VlanDevice(ifname)
            self.add_device(device)
        if not device:
            raise UnknownDeviceException("No device found for the requested iface.")

        # See if we need secrets. For the moment, we only support WPA
        if '802-11-wireless-security' in hash:
            s_wsec = hash['802-11-wireless-security']
            if (s_wsec['key-mgmt'] == 'wpa-psk' and 'psk' not in s_wsec):
                secrets = gl.agent_manager.get_secrets(hash, conpath, '802-11-wireless-security')
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
        else:
            GLib.timeout_add(50,
                             lambda: device.set_active_connection(ac))

        return ExportedObj.to_path(ac)

    def active_connection_add(self, ac):
        ac.export()
        self.active_connections.append(ac)
        self._dbus_property_notify(IFACE_NM, PM_ACTIVE_CONNECTIONS)

    def active_connection_remove(self, ac):
        self.active_connections.remove(ac)
        self._dbus_property_notify(IFACE_NM, PM_ACTIVE_CONNECTIONS)
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
            self.state = NM.State.ASLEEP
        else:
            self.state = NM.State.DISCONNECTED
        self._dbus_property_notify(IFACE_NM, PM_STATE)

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
        self.devices.append(device)
        self._dbus_property_notify(IFACE_NM, PM_DEVICES)
        self._dbus_property_notify(IFACE_NM, PM_ALL_DEVICES)
        self.DeviceAdded(ExportedObj.to_path(device))
        return device

    @dbus.service.signal(IFACE_NM, signature='o')
    def DeviceRemoved(self, devpath):
        pass

    def remove_device(self, device):
        self.devices.remove(device)
        self._dbus_property_notify(IFACE_NM, PM_DEVICES)
        self._dbus_property_notify(IFACE_NM, PM_ALL_DEVICES)
        self.DeviceRemoved(ExportedObj.to_path(device))

    def __get_props(self):
        props = {}
        props[PM_DEVICES] = ExportedObj.to_path_array(self.devices)
        props[PM_ALL_DEVICES] = ExportedObj.to_path_array(self.devices)
        props[PM_NETWORKING_ENABLED] = True
        props[PM_WWAN_ENABLED] = True
        props[PM_WWAN_HARDWARE_ENABLED] = True
        props[PM_WIRELESS_ENABLED] = True
        props[PM_WIRELESS_HARDWARE_ENABLED] = True
        props[PM_WIMAX_ENABLED] = True
        props[PM_WIMAX_HARDWARE_ENABLED] = True
        props[PM_ACTIVE_CONNECTIONS] = ExportedObj.to_path_array(self.active_connections)
        props[PM_PRIMARY_CONNECTION] = ExportedObj.to_path(self.primary_connection)
        props[PM_ACTIVATING_CONNECTION] = ExportedObj.to_path(self.activating_connection)
        props[PM_STARTUP] = False
        props[PM_STATE] = dbus.UInt32(self.state)
        props[PM_VERSION] = "0.9.9.0"
        props[PM_CONNECTIVITY] = dbus.UInt32(self.connectivity)
        return props

    @dbus.service.signal(IFACE_NM, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

    @dbus.service.method(IFACE_TEST, in_signature='', out_signature='')
    def Quit(self):
        gl.mainloop.quit()

    @dbus.service.method(IFACE_TEST, in_signature='a{ss}', out_signature='a(sss)')
    def FindConnections(self, args):
        return [(c.path, c.get_uuid(), c.get_id()) for c in gl.settings.find_connections(**args)]

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

class Connection(ExportedObj):
    def __init__(self, path_counter, settings, verify_connection=True):

        path = "/org/freedesktop/NetworkManager/Settings/Connection/%s" % (path_counter)

        ExportedObj.__init__(self, path)

        if 'connection' not in settings:
            settings['connection'] = { }
        if self.get_id(settings) is None:
            settings['connection']['id'] = 'connection-%s' % (path_counter)
        if self.get_uuid(settings) is None:
            settings['connection']['uuid'] = str(uuid.uuid3(uuid.NAMESPACE_URL, path))
        self.verify(settings, verify_strict=verify_connection)

        self.path = path
        self.settings = settings
        self.visible = True
        self.props = {}
        self.props['Unsaved'] = False

        self.dbus_interface_add(IFACE_CONNECTION, self.__get_props, None)
        self.export()

    def get_id(self, settings=None):
        if settings is None:
            settings = self.settings
        if 'connection' in settings:
            s_con = settings['connection']
            if 'id' in s_con:
                return s_con['id']
        return None

    def get_uuid(self, settings=None):
        if settings is None:
            settings = self.settings
        if 'connection' in settings:
            s_con = settings['connection']
            if 'uuid' in s_con:
                return s_con['uuid']
        return None

    def verify(self, settings=None, verify_strict=True):
        if settings is None:
            settings = self.settings;
        if 'connection' not in settings:
            raise MissingSettingException('connection: setting is required')
        s_con = settings['connection']
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

    def update_connection(self, settings, verify_connection):
        self.verify(settings, verify_strict=verify_connection)

        old_uuid = self.get_uuid()
        new_uuid = self.get_uuid(settings)
        if old_uuid != new_uuid:
            raise InvalidPropertyException('connection.uuid: cannot change the uuid from %s to %s' % (old_uuid, new_uuid))

        self.settings = settings;
        self.Updated()

    def __get_props(self):
        return self.props

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
        gl.settings.delete_connection(self)

    @dbus.service.method(dbus_interface=IFACE_CONNECTION, in_signature='a{sa{sv}}', out_signature='')
    def Update(self, settings):
        self.update_connection(settings, TRUE)

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

class Settings(ExportedObj):
    def __init__(self, object_path):
        ExportedObj.__init__(self, object_path)
        self.connections = {}
        self.c_counter = 0
        self.remove_next_connection = False
        self.props = {}
        self.props['Hostname'] = "foobar.baz"
        self.props['CanModify'] = True
        self.props['Connections'] = dbus.Array([], 'o')

        self.dbus_interface_add(IFACE_SETTINGS, self.__get_props, Settings.PropertiesChanged)
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
    def AddConnection(self, settings):
        return self.add_connection(settings)

    def add_connection(self, settings, verify_connection=True):
        self.c_counter += 1
        con = Connection(self.c_counter, settings, verify_connection)

        uuid = con.get_uuid()
        if uuid in [c.get_uuid() for c in self.connections.values()]:
            raise InvalidSettingException('cannot add duplicate connection with uuid %s' % (uuid))

        self.connections[con.path] = con
        self.props['Connections'] = dbus.Array(self.connections.keys(), 'o')
        self.NewConnection(con.path)
        self._dbus_property_notify(IFACE_SETTINGS, 'Connections')

        if self.remove_next_connection:
            self.remove_next_connection = False
            self.connections[con.path].Delete()

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
        self.props['Connections'] = dbus.Array(self.connections.keys(), 'o')
        self._dbus_property_notify(IFACE_SETTINGS, 'Connections')
        connection.Removed()
        connection.unexport()

    @dbus.service.method(dbus_interface=IFACE_SETTINGS, in_signature='s', out_signature='')
    def SaveHostname(self, hostname):
        # Arbitrary requirement to test error handling
        if hostname.find('.') == -1:
            raise InvalidHostnameException()
        self.props['Hostname'] = hostname
        self._dbus_property_notify(IFACE_SETTINGS, 'Hostname')

    def __get_props(self):
        return self.props

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
    def __init__(self, object_path):
        dbus.service.Object.__init__(self, gl.bus, object_path)
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

    def get_secrets(self, connection, path, setting_name):
        if len(self.agents) == 0:
            return None

        secrets = {}
        for sender in self.agents:
            agent = self.agents[sender]
            try:
                secrets = agent.GetSecrets(connection, path, setting_name,
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

PATH_OBJECT_MANAGER = '/org/freedesktop'

class ObjectManager(dbus.service.Object):
    def __init__(self, object_path):
        dbus.service.Object.__init__(self, gl.bus, object_path)
        self.objs = []

    def add_object(self, obj):
        name, ifaces = obj.get_managed_ifaces()
        self.objs.append(obj)
        self.InterfacesAdded(name, ifaces)

    def remove_object(self, obj):
        name, ifaces = obj.get_managed_ifaces()
        self.objs.remove(obj)
        self.InterfacesRemoved(name, ifaces.keys())

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
            name, ifaces = obj.get_managed_ifaces()
            managed_objects[name] = ifaces
        return managed_objects

###############################################################################

IFACE_DNS_MANAGER = 'org.freedesktop.NetworkManager.DnsManager'

class DnsManager(ExportedObj):
    def __init__(self, object_path):
        ExportedObj.__init__(self, object_path)
        self.props = {}
        self.props['Mode'] = "dnsmasq"
        self.props['RcManager'] = "symlink"
        self.props['Configuration'] = dbus.Array([
            dbus.Dictionary(
                { 'nameservers' : dbus.Array(['1.2.3.4', '5.6.7.8'], 's'),
                  'priority'    : dbus.Int32(100) },
                'sv') ],
            'a{sv}')

        self.dbus_interface_add(IFACE_DNS_MANAGER, self.__get_props, None)
        self.export()

    @dbus.service.method(dbus_interface=dbus.PROPERTIES_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, iface):
        if iface != IFACE_DNS_MANAGER:
            raise UnknownInterfaceException()
        return self.props

    @dbus.service.method(dbus_interface=dbus.PROPERTIES_IFACE, in_signature='ss', out_signature='v')
    def Get(self, iface, name):
        if iface != IFACE_DNS_MANAGER:
            raise UnknownInterfaceException()
        if not name in self.props.keys():
            raise UnknownPropertyException()
        return self.props[name]

    def __get_props(self):
        return self.props

###############################################################################

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    random.seed()


    gl.mainloop = GLib.MainLoop()
    gl.bus = dbus.SessionBus()

    gl.object_manager = ObjectManager(PATH_OBJECT_MANAGER)
    gl.manager = NetworkManager("/org/freedesktop/NetworkManager")
    gl.settings = Settings("/org/freedesktop/NetworkManager/Settings")
    gl.agent_manager = AgentManager("/org/freedesktop/NetworkManager/AgentManager")
    gl.dns_manager = DnsManager("/org/freedesktop/NetworkManager/DnsManager")

    if not gl.bus.request_name("org.freedesktop.NetworkManager"):
        raise AssertionError("Failure to request D-Bus name org.freedesktop.NetworkManager")

    # Watch stdin; if it closes, assume our parent has crashed, and exit
    io = GLib.IOChannel(0)
    io.add_watch(GLib.IOCondition.HUP,
                 lambda io, condition: gl.mainloop.quit())

    # also quit after inactivity to ensure we don't stick around if the above fails somehow
    GLib.timeout_add_seconds(20,
                             lambda: gl.mainloop.quit())

    gl.mainloop.run()

    sys.exit(0)

if __name__ == '__main__':
    main()
