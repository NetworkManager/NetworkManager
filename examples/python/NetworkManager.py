#!/usr/bin/python

import dbus
from  dbus_bindings import DBusException

NM_SERVICE="org.freedesktop.NetworkManager"
NM_PATH="/org/freedesktop/NetworkManager"
NM_INTERFACE=NM_SERVICE

# i can append device names like eth0 to this path to get more info
NM_PATH_DEVICES="/org/freedesktop/NetworkManager/Devices"
NM_INTERFACE_DEVICES="org.freedesktop.NetworkManager.Devices"

NMI_SERVICE="org.freedesktop.NetworkManagerInfo"
NMI_PATH="/org/freedesktop/NetworkManagerInfo"
NMI_INTERFACE=NMI_SERVICE

HAL_SERVICE="org.freedesktop.Hal"
HAL_PATH="/org/freedesktop/Hal/Manager"
HAL_INTERFACE="org.freedesktop.Hal.Manager"
HAL_INTERFACE_DEVICE="org.freedesktop.Hal.Device"

class NetworkManager:
    WIRED_DEVICE    = 1
    WIRELESS_DEVICE = 2

    CONNECTED       = "connected"
    CONNECTING      = "connecting"
    DISCONNECTED    = "disconnected"

    NM_SIGNALS = [ "DeviceNoLongerActive",
                   "DeviceNowActive",
                   "DeviceActivating",
                   "DevicesChanged",
                   "DeviceIP4AddressChange",
                   "WirelessNetworkDisappeared",
                   "WirelessNetworkAppeared"
                   ]

    NMI_SIGNALS = [ "TrustedNetworkUpdate",
                    "PreferredNetworkUpdate"
                    ]
    
    def __init__(self):
        self.__init_dbus__()

        # dictionary of devices
        self.__devices = {}

    def __init_dbus__(self):
        try:
            self._bus = dbus.SystemBus()
            try:
                self._nm_service = self._bus.get_service(NM_SERVICE)
                self.nm_object  = self._nm_service.get_object(NM_PATH,
                                                              NM_INTERFACE)
            except Exception, e:
                print "Counldn't get the %s service" % NM_SERVICE
                print e
                
            try:
                self._nmi_service = self._bus.get_service(NMI_SERVICE)
                self.nmi_object  = self._nmi_service.get_object(NMI_PATH,
                                                                NMI_INTERFACE)
            except Exception, e:
                print "Counldn't get the %s service" % NMI_SERVICE
                print e

            try:
                self._hal_service = self._bus.get_service(HAL_SERVICE)
                self._hal_manager = self._hal_service.get_object(HAL_PATH,
                                                                 HAL_INTERFACE)
            except Exception, e:
                print "Counldn't get the %s service" % HAL_SERVICE
                print e
                
        except Exception, e:
            print e

    """
    returns dictionary of the active device information
    if device does not exist returns get_device failure method
    """
    def get_active_device(self):
        active_device = self.nm_object.getActiveDevice()
        return self.get_device(active_device)

    """
    pass device string /org/freedesktop/NetworkManager/Device/eth0
    returns dictionary of device information
    if device does not exist returns None
    """
    def get_device(self, device):
        try:
            nm_dev_obj  = self._nm_service.get_object(device,
                                                      NM_INTERFACE_DEVICES)
            d = {}
            d["nm.device"]      = device
            d["nm.name"]        = nm_dev_obj.getName(device)
            d["nm.type"]        = nm_dev_obj.getType(device)
            d["nm.udi"]         = nm_dev_obj.getHalUdi(device)
            d["nm.ip4"]         = nm_dev_obj.getIP4Address(device)
            d["nm.link_active"] = nm_dev_obj.getLinkActive(device)
            
            try:
                d["nm.active_network"] = nm_dev_obj.getActiveNetwork(device)
                d["nm.strength"] = nm_dev_obj.getStrength(device)
            except DBusException, e:
                pass
        
            try:
                d["nm.networks"] = {}
                networks = nm_dev_obj.getNetworks(device)
                for network in networks:
                    nm_network_object  = self._nm_service.get_object(network,
                                                                     NM_INTERFACE_DEVICES)
                    n = {}
                    n["network"]    = network
                    n["name"]       = nm_network_object.getName()
                    n["address"]    = nm_network_object.getAddress()
                    n["strength"]    = nm_network_object.getStrength()
                    n["frequency"]  = nm_network_object.getFrequency()
                    n["rate"]       = nm_network_object.getRate()
                    n["encrypted"]  = nm_network_object.getEncrypted()

                    d["nm.networks"][network] = n

            except DBusException, e:
                pass

            active_device = self.nm_object.getActiveDevice()
        
            if device == active_device:
                d["nm.status"] = self.nm_object.status()
            else:
                d["nm.status"] = self.DISCONNECTED

            # we already have this device cached, so just update the status
            if device in self.__devices:
                for k,v in d.iteritems():
                    self.__devices[device][k] = v
            # it's a new device so get the info from HAL
            else:
                hal = self._get_hal_info(d["nm.udi"])
                for k,v in hal.iteritems():
                    d[k] = v
                self.__devices[device] = d

            return self.__devices[device]
            
        except Exception, e:
            print e
            return None

    """
    Returns list of dictionary objects of all active devices
    Returns empty list if no active devices
    """
    def get_devices(self):
        
        active_devices = self.nm_object.getDevices()
        devices = []

        for device in active_devices:
            devices.append(self.get_device(device))

        return devices

    """
    Returns list of dictionary objects of all devices active or not
    Returns empty list if no active devices
    """
    def get_all_devices(self):
        return self.__devices.values()

    def has_type_device (self, type):
        for device in self.get_devices():
            if device["nm.type"] == type:
                return True
        return False        

    def number_device_types(self, type):
        count = 0
        for device in self.get_devices():
            if device["nm.type"] == type:
                count = count + 1
        return count

    def number_wired_devices(self):
        return self.number_device_types(self.WIRED_DEVICE)

    def number_wireless_devices(self):
        return self.number_device_types(self.WIRELESS_DEVICE)
    
    def has_wired_device(self):
        return self.has_type_device(self.WIRED_DEVICE)

    def has_wireless_device(self):
        return self.has_type_device(self.WIRELESS_DEVICE)
    
    def _get_hal_info(self, udi):
        hal_devices = self._hal_manager.FindDeviceStringMatch("info.udi",
                                                              udi)
        for hal_device in hal_devices:
            device_dbus_obj = self._hal_service.get_object(hal_device,
                                                           HAL_INTERFACE_DEVICE)
            properties = device_dbus_obj.GetAllProperties()
            return  properties

if __name__ == "__main__":
    nm = NetworkManager()


    
