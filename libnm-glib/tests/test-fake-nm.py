#!/usr/bin/env python
# -*- Mode: python; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*-

from __future__ import print_function

from gi.repository import GLib, GObject
import sys
import dbus
import dbus.service
import dbus.mainloop.glib
import random

mainloop = GObject.MainLoop()
quit_id = 0

# NM State
NM_STATE_UNKNOWN          = 0
NM_STATE_ASLEEP           = 10
NM_STATE_DISCONNECTED     = 20
NM_STATE_DISCONNECTING    = 30
NM_STATE_CONNECTING       = 40
NM_STATE_CONNECTED_LOCAL  = 50
NM_STATE_CONNECTED_SITE   = 60
NM_STATE_CONNECTED_GLOBAL = 70

# Device state
NM_DEVICE_STATE_UNKNOWN      = 0
NM_DEVICE_STATE_UNMANAGED    = 10
NM_DEVICE_STATE_UNAVAILABLE  = 20
NM_DEVICE_STATE_DISCONNECTED = 30
NM_DEVICE_STATE_PREPARE      = 40
NM_DEVICE_STATE_CONFIG       = 50
NM_DEVICE_STATE_NEED_AUTH    = 60
NM_DEVICE_STATE_IP_CONFIG    = 70
NM_DEVICE_STATE_IP_CHECK     = 80
NM_DEVICE_STATE_SECONDARIES  = 90
NM_DEVICE_STATE_ACTIVATED    = 100
NM_DEVICE_STATE_DEACTIVATING = 110
NM_DEVICE_STATE_FAILED       = 120

NM_DEVICE_TYPE_UNKNOWN    = 0
NM_DEVICE_TYPE_ETHERNET   = 1
NM_DEVICE_TYPE_WIFI       = 2
NM_DEVICE_TYPE_UNUSED1    = 3
NM_DEVICE_TYPE_UNUSED2    = 4
NM_DEVICE_TYPE_BT         = 5
NM_DEVICE_TYPE_OLPC_MESH  = 6
NM_DEVICE_TYPE_WIMAX      = 7
NM_DEVICE_TYPE_MODEM      = 8
NM_DEVICE_TYPE_INFINIBAND = 9
NM_DEVICE_TYPE_BOND       = 10
NM_DEVICE_TYPE_VLAN       = 11
NM_DEVICE_TYPE_ADSL       = 12
NM_DEVICE_TYPE_BRIDGE     = 13
NM_DEVICE_TYPE_GENERIC    = 14
NM_DEVICE_TYPE_TEAM       = 15

#########################################################
IFACE_DBUS = 'org.freedesktop.DBus'

class UnknownInterfaceException(dbus.DBusException):
    _dbus_error_name = IFACE_DBUS + '.UnknownInterface'

class UnknownPropertyException(dbus.DBusException):
    _dbus_error_name = IFACE_DBUS + '.UnknownProperty'

def to_path_array(src):
    array = dbus.Array([], signature=dbus.Signature('o'))
    for o in src:
        array.append(o.path)
    return array

def to_path(src):
    if src:
        return dbus.ObjectPath(src.path)
    return dbus.ObjectPath("/")

class ExportedObj(dbus.service.Object):
    def __init__(self, bus, object_path):
        dbus.service.Object.__init__(self, bus, object_path)
        self._bus = bus
        self.path = object_path
        self.__dbus_ifaces = {}

    def add_dbus_interface(self, dbus_iface, get_props_func):
        self.__dbus_ifaces[dbus_iface] = get_props_func

    def _get_dbus_properties(self, iface):
        return self.__dbus_ifaces[iface]()

    @dbus.service.method(dbus_interface=dbus.PROPERTIES_IFACE, in_signature='s', out_signature='a{sv}')
    def GetAll(self, iface):
        if iface not in self.__dbus_ifaces.keys():
            raise UnknownInterfaceException()
        return self._get_dbus_properties(iface)

    @dbus.service.method(dbus_interface=dbus.PROPERTIES_IFACE, in_signature='ss', out_signature='v')
    def Get(self, iface, name):
        if iface not in self.__dbus_ifaces.keys():
            raise UnknownInterfaceException()
        props = self._get_dbus_properties(iface)
        if not name in props.keys():
            raise UnknownPropertyException()
        return props[name]

###################################################################
IFACE_DEVICE = 'org.freedesktop.NetworkManager.Device'

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
    counter = 1

    def __init__(self, bus, iface, devtype):
        object_path = "/org/freedesktop/NetworkManager/Devices/%d" % Device.counter
        Device.counter = Device.counter + 1
        ExportedObj.__init__(self, bus, object_path)
        self.add_dbus_interface(IFACE_DEVICE, self.__get_props)

        self.iface = iface
        self.udi = "/sys/devices/virtual/%s" % iface
        self.devtype = devtype
        self.active_connection = None
        self.state = NM_DEVICE_STATE_UNAVAILABLE
        self.ip4_config = None
        self.ip6_config = None
        self.dhcp4_config = None
        self.dhcp6_config = None
        self.available_connections = []

    # Properties interface
    def __get_props(self):
        props = {}
        props[PD_UDI] = self.udi
        props[PD_IFACE] = self.iface
        props[PD_DRIVER] = "virtual"
        props[PD_STATE] = dbus.UInt32(self.state)
        props[PD_ACTIVE_CONNECTION] = to_path(self.active_connection)
        props[PD_IP4_CONFIG] = to_path(self.ip4_config)
        props[PD_IP6_CONFIG] = to_path(self.ip6_config)
        props[PD_DHCP4_CONFIG] = to_path(self.dhcp4_config)
        props[PD_DHCP6_CONFIG] = to_path(self.dhcp6_config)
        props[PD_MANAGED] = True
        props[PD_AUTOCONNECT] = True
        props[PD_DEVICE_TYPE] = dbus.UInt32(self.devtype)
        props[PD_AVAILABLE_CONNECTIONS] = to_path_array(self.available_connections)
        return props

    # methods
    @dbus.service.method(dbus_interface=IFACE_DEVICE, in_signature='', out_signature='')
    def Disconnect(self):
        pass

    def __notify(self, propname):
        props = self._get_dbus_properties(IFACE_DEVICE)
        changed = { propname: props[propname] }
        Device.PropertiesChanged(self, changed)

    @dbus.service.signal(IFACE_DEVICE, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass


###################################################################

def random_mac():
    return '%02X:%02X:%02X:%02X:%02X:%02X' % (
        random.randint(0, 255), random.randint(0, 255), random.randint(0, 255),
        random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)
      )

###################################################################
IFACE_WIRED = 'org.freedesktop.NetworkManager.Device.Wired'

PE_HW_ADDRESS = "HwAddress"
PE_PERM_HW_ADDRESS = "PermHwAddress"
PE_SPEED = "Speed"
PE_CARRIER = "Carrier"

class WiredDevice(Device):
    def __init__(self, bus, iface):
        Device.__init__(self, bus, iface, NM_DEVICE_TYPE_ETHERNET)
        self.add_dbus_interface(IFACE_WIRED, self.__get_props)

        self.mac = random_mac()
        self.carrier = False

    # Properties interface
    def __get_props(self):
        props = {}
        props[PE_HW_ADDRESS] = self.mac
        props[PE_PERM_HW_ADDRESS] = self.mac
        props[PE_SPEED] = dbus.UInt32(100)
        props[PE_CARRIER] = self.carrier
        return props

    def __notify(self, propname):
        props = self._get_dbus_properties(IFACE_WIRED)
        changed = { propname: props[propname] }
        WiredDevice.PropertiesChanged(self, changed)

    @dbus.service.signal(IFACE_WIRED, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

###################################################################
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
    counter = 0

    def __init__(self, bus, ssid, mac, flags, wpaf, rsnf, freq):
        path = "/org/freedesktop/NetworkManager/AccessPoint/%d" % WifiAp.counter
        WifiAp.counter = WifiAp.counter + 1
        ExportedObj.__init__(self, bus, path)
        self.add_dbus_interface(IFACE_WIFI_AP, self.__get_props)

        self.ssid = ssid
        if mac:
            self.bssid = mac
        else:
            self.bssid = random_mac()
        self.flags = flags
        self.wpaf = wpaf
        self.rsnf = rsnf
        self.freq = freq
        self.strength = random.randint(0, 100)
        self.strength_id = GLib.timeout_add_seconds(10, self.strength_cb, None)

    def __del__(self):
        if self.strength_id > 0:
            GLib.source_remove(self.strength_id)
        self.strength_id = 0

    def strength_cb(self, ignored):
        self.strength = random.randint(0, 100)
        self.__notify(PP_STRENGTH)
        return True

    # Properties interface
    def __get_props(self):
        props = {}
        props[PP_FLAGS] = dbus.UInt32(self.flags)
        props[PP_WPA_FLAGS] = dbus.UInt32(self.wpaf)
        props[PP_RSN_FLAGS] = dbus.UInt32(self.rsnf)
        props[PP_SSID] = dbus.ByteArray(self.ssid)
        props[PP_FREQUENCY] = dbus.UInt32(self.freq)
        props[PP_HW_ADDRESS] = self.bssid
        props[PP_MODE] = dbus.UInt32(2)  # NM_802_11_MODE_INFRA
        props[PP_MAX_BITRATE] = dbus.UInt32(54000)
        props[PP_STRENGTH] = dbus.Byte(self.strength)
        return props

    def __notify(self, propname):
        props = self._get_dbus_properties(IFACE_WIFI_AP)
        changed = { propname: props[propname] }
        WifiAp.PropertiesChanged(self, changed)

    @dbus.service.signal(IFACE_WIFI_AP, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

###################################################################
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
    def __init__(self, bus, iface):
        Device.__init__(self, bus, iface, NM_DEVICE_TYPE_WIFI)
        self.add_dbus_interface(IFACE_WIFI, self.__get_props)

        self.mac = random_mac()
        self.aps = []
        self.active_ap = None

    # methods
    @dbus.service.method(dbus_interface=IFACE_WIFI, in_signature='', out_signature='ao')
    def GetAccessPoints(self):
        # only include non-hidden APs
        array = []
        for a in self.aps:
            if a.ssid():
                array.append(a)
        return to_path_array(array)

    @dbus.service.method(dbus_interface=IFACE_WIFI, in_signature='', out_signature='ao')
    def GetAllAccessPoints(self):
        # include all APs including hidden ones
        return to_path_array(self.aps)

    @dbus.service.method(dbus_interface=IFACE_WIFI, in_signature='a{sv}', out_signature='')
    def RequestScan(self, props):
        pass

    @dbus.service.signal(IFACE_WIFI, signature='o')
    def AccessPointAdded(self, ap_path):
        pass

    def add_ap(self, ap):
        self.aps.append(ap)
        self.__notify(PW_ACCESS_POINTS)
        self.AccessPointAdded(to_path(ap))

    @dbus.service.signal(IFACE_WIFI, signature='o')
    def AccessPointRemoved(self, ap_path):
        pass

    def remove_ap(self, ap):
        self.aps.remove(ap)
        self.__notify(PW_ACCESS_POINTS)
        self.AccessPointRemoved(to_path(ap))

    # Properties interface
    def __get_props(self):
        props = {}
        props[PW_HW_ADDRESS] = self.mac
        props[PW_PERM_HW_ADDRESS] = self.mac
        props[PW_MODE] = dbus.UInt32(3)  # NM_802_11_MODE_INFRA
        props[PW_BITRATE] = dbus.UInt32(21000)
        props[PW_WIRELESS_CAPABILITIES] = dbus.UInt32(0xFF)
        props[PW_ACCESS_POINTS] = to_path_array(self.aps)
        props[PW_ACTIVE_ACCESS_POINT] = to_path(self.active_ap)
        return props

    def __notify(self, propname):
        props = self._get_dbus_properties(IFACE_WIFI)
        changed = { propname: props[propname] }
        WifiDevice.PropertiesChanged(self, changed)

    @dbus.service.signal(IFACE_WIFI, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

    # test functions
    def add_test_ap(self, ssid, mac):
        ap = WifiAp(self._bus, ssid, mac, 0x1, 0x1cc, 0x1cc, 2412)
        self.add_ap(ap)
        return ap.path

    def remove_ap_by_path(self, path):
        for ap in self.aps:
            if ap.path == path:
                self.remove_ap(ap)
                return
        raise ApNotFoundException("AP %s not found" % path)


###################################################################
IFACE_WIMAX_NSP = 'org.freedesktop.NetworkManager.WiMax.Nsp'

PN_NAME = "Name"
PN_SIGNAL_QUALITY = "SignalQuality"
PN_NETWORK_TYPE = "NetworkType"

class WimaxNsp(ExportedObj):
    counter = 0

    def __init__(self, bus, name):
        path = "/org/freedesktop/NetworkManager/Nsp/%d" % WimaxNsp.counter
        WimaxNsp.counter = WimaxNsp.counter + 1
        ExportedObj.__init__(self, bus, path)
        self.add_dbus_interface(IFACE_WIMAX_NSP, self.__get_props)

        self.name = name
        self.strength = random.randint(0, 100)
        self.strength_id = GLib.timeout_add_seconds(10, self.strength_cb, None)

    def __del__(self):
        if self.strength_id > 0:
            GLib.source_remove(self.strength_id)
        self.strength_id = 0

    def strength_cb(self, ignored):
        self.strength = random.randint(0, 100)
        self.__notify(PN_SIGNAL_QUALITY)
        return True

    # Properties interface
    def __get_props(self):
        props = {}
        props[PN_NAME] = self.name
        props[PN_SIGNAL_QUALITY] = dbus.UInt32(self.strength)
        props[PN_NETWORK_TYPE] = dbus.UInt32(0x1)  # NM_WIMAX_NSP_NETWORK_TYPE_HOME
        return props

    def __notify(self, propname):
        props = self._get_dbus_properties(IFACE_WIMAX_NSP)
        changed = { propname: props[propname] }
        WimaxNsp.PropertiesChanged(self, changed)

    @dbus.service.signal(IFACE_WIMAX_NSP, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

###################################################################
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
    def __init__(self, bus, iface):
        Device.__init__(self, bus, iface, NM_DEVICE_TYPE_WIMAX)
        self.add_dbus_interface(IFACE_WIMAX, self.__get_props)

        self.mac = random_mac()
        self.bsid = random_mac()
        self.nsps = []
        self.active_nsp = None

    # methods
    @dbus.service.method(dbus_interface=IFACE_WIMAX, in_signature='', out_signature='ao')
    def GetNspList(self):
        # include all APs including hidden ones
        return to_path_array(self.nsps)

    @dbus.service.signal(IFACE_WIMAX, signature='o')
    def NspAdded(self, nsp_path):
        pass

    def add_nsp(self, nsp):
        self.nsps.append(nsp)
        self.__notify(PX_NSPS)
        self.NspAdded(to_path(nsp))

    @dbus.service.signal(IFACE_WIMAX, signature='o')
    def NspRemoved(self, nsp_path):
        pass

    def remove_nsp(self, nsp):
        self.nsps.remove(nsp)
        self.__notify(PX_NSPS)
        self.NspRemoved(to_path(nsp))

    # Properties interface
    def __get_props(self):
        props = {}
        props[PX_HW_ADDRESS] = self.mac
        props[PX_CENTER_FREQUENCY] = dbus.UInt32(2525)
        props[PX_RSSI] = dbus.Int32(-48)
        props[PX_CINR] = dbus.Int32(24)
        props[PX_TX_POWER] = dbus.Int32(9)
        props[PX_BSID] = self.bsid
        props[PX_NSPS] = to_path_array(self.nsps)
        props[PX_ACTIVE_NSP] = to_path(self.active_nsp)
        return props

    def __notify(self, propname):
        props = self._get_dbus_properties(IFACE_WIMAX)
        changed = { propname: props[propname] }
        WimaxDevice.PropertiesChanged(self, changed)

    @dbus.service.signal(IFACE_WIMAX, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

    # test functions
    def add_test_nsp(self, name):
        nsp = WimaxNsp(self._bus, name)
        self.add_nsp(nsp)
        return nsp.path

    def remove_nsp_by_path(self, path):
        for nsp in self.nsps:
            if nsp.path == path:
                self.remove_nsp(nsp)
                return
        raise NspNotFoundException("NSP %s not found" % path)

###################################################################
IFACE_TEST = 'org.freedesktop.NetworkManager.LibnmGlibTest'
IFACE_NM = 'org.freedesktop.NetworkManager'

class PermissionDeniedException(dbus.DBusException):
    _dbus_error_name = IFACE_NM + '.PermissionDenied'

class UnknownDeviceException(dbus.DBusException):
    _dbus_error_name = IFACE_NM + '.UnknownDevice'

PM_DEVICES = 'Devices'
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
    def __init__(self, bus, object_path):
        ExportedObj.__init__(self, bus, object_path)
        self.add_dbus_interface(IFACE_NM, self.__get_props)

        self.devices = []
        self.active_connections = []
        self.primary_connection = None
        self.activating_connection = None
        self.state = NM_STATE_DISCONNECTED
        self.connectivity = 1

    @dbus.service.signal(IFACE_NM, signature='u')
    def StateChanged(self, new_state):
        pass

    def set_state(self, new_state):
        self.state = new_state
        self.__notify(PM_STATE)
        self.StateChanged(dbus.UInt32(self.state))

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='', out_signature='ao')
    def GetDevices(self):
        return self._get_dbus_properties(IFACE_NM)[PM_DEVICES]

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='s', out_signature='o')
    def GetDeviceByIpIface(self, ip_iface):
        for d in self.devices:
            # ignore iface/ip_iface distinction for now
            if d.iface == ip_iface:
                return d.path
        raise UnknownDeviceException("No device found for the requested iface.")

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='ooo', out_signature='o')
    def ActivateConnection(self, conpath, devpath, specific_object):
        device = None
        for d in self.devices:
            if d.path == devpath:
                device = d
                break
        if not device:
            raise UnknownDeviceException("No device found for the requested iface.")
        raise PermissionDeniedException("Not yet implemented")

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='a{sa{sv}}oo', out_signature='oo')
    def AddAndActivateConnection(self, connection, devpath, specific_object):
        device = None
        for d in self.devices:
            if d.path == devpath:
                device = d
                break
        if not device:
            raise UnknownDeviceException("No device found for the requested iface.")
        raise PermissionDeniedException("Not yet implemented")

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='o', out_signature='')
    def DeactivateConnection(self, active_connection):
        pass

    @dbus.service.method(dbus_interface=IFACE_NM, in_signature='b', out_signature='')
    def Sleep(self, do_sleep):
        if do_sleep:
            self.state = NM_STATE_ASLEEP
        else:
            self.state = NM_STATE_DISCONNECTED
        self.__notify(PM_STATE)

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
                 "org.freedesktop.NetworkManager.settings.modify.hostname": "yes" }

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

    def add_device(self, device):
        self.devices.append(device)
        self.__notify(PM_DEVICES)
        self.DeviceAdded(to_path(device))

    @dbus.service.signal(IFACE_NM, signature='o')
    def DeviceRemoved(self, devpath):
        pass

    def remove_device(self, device):
        self.devices.remove(device)
        self.__notify(PM_DEVICES)
        self.DeviceRemoved(to_path(device))

    ################# D-Bus Properties interface
    def __get_props(self):
        props = {}
        props[PM_DEVICES] = to_path_array(self.devices)
        props[PM_NETWORKING_ENABLED] = True
        props[PM_WWAN_ENABLED] = True
        props[PM_WWAN_HARDWARE_ENABLED] = True
        props[PM_WIRELESS_ENABLED] = True
        props[PM_WIRELESS_HARDWARE_ENABLED] = True
        props[PM_WIMAX_ENABLED] = True
        props[PM_WIMAX_HARDWARE_ENABLED] = True
        props[PM_ACTIVE_CONNECTIONS] = to_path_array(self.active_connections)
        props[PM_PRIMARY_CONNECTION] = to_path(self.primary_connection)
        props[PM_ACTIVATING_CONNECTION] = to_path(self.activating_connection)
        props[PM_STARTUP] = False
        props[PM_STATE] = dbus.UInt32(self.state)
        props[PM_VERSION] = "0.9.9.0"
        props[PM_CONNECTIVITY] = dbus.UInt32(self.connectivity)
        return props

    def __notify(self, propname):
        props = self._get_dbus_properties(IFACE_NM)
        changed = { propname: props[propname] }
        NetworkManager.PropertiesChanged(self, changed)

    @dbus.service.signal(IFACE_NM, signature='a{sv}')
    def PropertiesChanged(self, changed):
        pass

    ################# Testing methods
    @dbus.service.method(IFACE_TEST, in_signature='', out_signature='')
    def Quit(self):
        mainloop.quit()

    @dbus.service.method(IFACE_TEST, in_signature='s', out_signature='o')
    def AddWiredDevice(self, ifname):
        for d in self.devices:
            if d.iface == ifname:
                raise PermissionDeniedError("Device already added")
        dev = WiredDevice(self._bus, ifname)
        self.add_device(dev)
        return dbus.ObjectPath(dev.path)

    @dbus.service.method(IFACE_TEST, in_signature='s', out_signature='o')
    def AddWifiDevice(self, ifname):
        for d in self.devices:
            if d.iface == ifname:
                raise PermissionDeniedError("Device already added")
        dev = WifiDevice(self._bus, ifname)
        self.add_device(dev)
        return dbus.ObjectPath(dev.path)

    @dbus.service.method(IFACE_TEST, in_signature='s', out_signature='o')
    def AddWimaxDevice(self, ifname):
        for d in self.devices:
            if d.iface == ifname:
                raise PermissionDeniedError("Device already added")
        dev = WimaxDevice(self._bus, ifname)
        self.add_device(dev)
        return dbus.ObjectPath(dev.path)

    @dbus.service.method(IFACE_TEST, in_signature='o', out_signature='')
    def RemoveDevice(self, path):
        for d in self.devices:
            if d.path == path:
                self.remove_device(d)
                return
        raise UnknownDeviceException("Device not found")

    @dbus.service.method(IFACE_TEST, in_signature='sss', out_signature='o')
    def AddWifiAp(self, ifname, ssid, mac):
        for d in self.devices:
            if d.iface == ifname:
                return dbus.ObjectPath(d.add_test_ap(ssid, mac))
        raise UnknownDeviceException("Device not found")

    @dbus.service.method(IFACE_TEST, in_signature='so', out_signature='')
    def RemoveWifiAp(self, ifname, ap_path):
        for d in self.devices:
            if d.iface == ifname:
                d.remove_ap_by_path(ap_path)
                return
        raise UnknownDeviceException("Device not found")

    @dbus.service.method(IFACE_TEST, in_signature='ss', out_signature='o')
    def AddWimaxNsp(self, ifname, name):
        for d in self.devices:
            if d.iface == ifname:
                return dbus.ObjectPath(d.add_test_nsp(name))
        raise UnknownDeviceException("Device not found")

    @dbus.service.method(IFACE_TEST, in_signature='so', out_signature='')
    def RemoveWimaxNsp(self, ifname, nsp_path):
        for d in self.devices:
            if d.iface == ifname:
                d.remove_nsp_by_path(nsp_path)
                return
        raise UnknownDeviceException("Device not found")

def quit_cb(user_data):
    mainloop.quit()

def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    random.seed()

    bus = dbus.SessionBus()
    nm = NetworkManager(bus, "/org/freedesktop/NetworkManager")
    if not bus.request_name("org.freedesktop.NetworkManager"):
        sys.exit(1)

    # quit after inactivity to ensure we don't stick around if tests fail
    quit_id = GLib.timeout_add_seconds(20, quit_cb, None)

    try:
        mainloop.run()
    except Exception as e:
        pass

    sys.exit(0)

if __name__ == '__main__':
    main()

