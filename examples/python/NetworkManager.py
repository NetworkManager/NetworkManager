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
        self._bus = dbus.SystemBus()
        self._nm_service = self._bus.get_service(NM_SERVICE)
        self.nm_object  = self._nm_service.get_object(NM_PATH,
                                                      NM_INTERFACE)

        self._nmi_service = self._bus.get_service(NMI_SERVICE)
        self.nmi_object  = self._nmi_service.get_object(NMI_PATH,
                                                        NMI_INTERFACE)

        self._hal_service = self._bus.get_service(HAL_SERVICE)
        self._hal_manager = self._hal_service.get_object(HAL_PATH,
                                                         HAL_INTERFACE)


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
            nm_device_object  = self._nm_service.get_object(device,
                                                            NM_INTERFACE_DEVICES)
            d = {}
            d["nm.name"] = nm_device_object.getName(device)
            d["nm.type"] = nm_device_object.getType(device)
            d["nm.udi"]  = nm_device_object.getHalUdi(device)
            d["nm.ip4"]  = nm_device_object.getIP4Address(device)
            d["nm.quality"] = nm_device_object.getMaxQuality(device)
        
            try:
                d["nm.active_network"] = nm_device_object.getActiveNetwork(device)
            except DBusException, e:
                pass
        
            try:
                d["nm.networks"] = {}
                networks = nm_device_object.getNetworks(device)
                for network in networks:
                    nm_network_object  = self._nm_service.get_object(network,
                                                                     NM_INTERFACE_DEVICES)
                    n = {}
                    n["name"]       = nm_network_object.getName()
                    n["address"]    = nm_network_object.getAddress()
                    n["quality"]    = nm_network_object.getQuality()
                    n["frequency"]  = nm_network_object.getFrequency()
                    n["rate"]       = nm_network_object.getRate()
                    n["encrypted"]  = nm_network_object.getEncrypted()

                    d["nm.networks"][network] = n

            except DBusException, e:
                pass

            active_device = self.nm_object.getActiveDevice()
            active_device_status = self.nm_object.status()
        
            if device == active_device:
                d["nm.status"] = active_device_status
            else:
                d["nm.status"] = "not connected"

            if device in self.__devices:
                for k,v in d.iteritems():
                    self.__devices[device][k] = v
                return self.__devices[device]
            else:
                hal = self._get_hal_info(d["nm.udi"])
                for k,v in hal.iteritems():
                    d[k] = v
                self.__devices[device] = d
                return self.__devices[device]
        except:
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


    
