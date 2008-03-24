#ifndef NM_DEVICE_802_11_WIRELESS_H
#define NM_DEVICE_802_11_WIRELESS_H

#include "nm-device.h"
#include "nm-access-point.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_802_11_WIRELESS            (nm_device_802_11_wireless_get_type ())
#define NM_DEVICE_802_11_WIRELESS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211Wireless))
#define NM_DEVICE_802_11_WIRELESS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessClass))
#define NM_IS_DEVICE_802_11_WIRELESS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_802_11_WIRELESS))
#define NM_IS_DEVICE_802_11_WIRELESS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DEVICE_802_11_WIRELESS))
#define NM_DEVICE_802_11_WIRELESS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessClass))

#define NM_DEVICE_802_11_WIRELESS_HW_ADDRESS          "hw-address"
#define NM_DEVICE_802_11_WIRELESS_MODE                "mode"
#define NM_DEVICE_802_11_WIRELESS_BITRATE             "bitrate"
#define NM_DEVICE_802_11_WIRELESS_ACTIVE_ACCESS_POINT "active-access-point"
#define NM_DEVICE_802_11_WIRELESS_CAPABILITIES        "wireless-capabilities"

typedef struct {
	NMDevice parent;
} NMDevice80211Wireless;

typedef struct {
	NMDeviceClass parent;

	/* Signals */
	void (*access_point_added) (NMDevice80211Wireless *device, NMAccessPoint *ap);
	void (*access_point_removed) (NMDevice80211Wireless *device, NMAccessPoint *ap);
} NMDevice80211WirelessClass;

GType nm_device_802_11_wireless_get_type (void);

GObject *nm_device_802_11_wireless_new (DBusGConnection *connection, const char *path);

const char *    nm_device_802_11_wireless_get_hw_address           (NMDevice80211Wireless *device);
int             nm_device_802_11_wireless_get_mode                 (NMDevice80211Wireless *device);
guint32         nm_device_802_11_wireless_get_bitrate              (NMDevice80211Wireless *device);
guint32         nm_device_802_11_wireless_get_capabilities         (NMDevice80211Wireless *device);
NMAccessPoint * nm_device_802_11_wireless_get_active_access_point  (NMDevice80211Wireless *device);

NMAccessPoint * nm_device_802_11_wireless_get_access_point_by_path (NMDevice80211Wireless *device,
                                                                    const char *path);

GPtrArray *     nm_device_802_11_wireless_get_access_points        (NMDevice80211Wireless *device);

G_END_DECLS

#endif /* NM_DEVICE_802_11_WIRELESS_H */
