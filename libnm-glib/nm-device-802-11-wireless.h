#ifndef NM_DEVICE_802_11_WIRELESS_H
#define NM_DEVICE_802_11_WIRELESS_H

#include "nm-device.h"
#include "nm-access-point.h"

#define NM_TYPE_DEVICE_802_11_WIRELESS            (nm_device_802_11_wireless_get_type ())
#define NM_DEVICE_802_11_WIRELESS(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211Wireless))
#define NM_DEVICE_802_11_WIRELESS_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessClass))
#define NM_IS_DEVICE_802_11_WIRELESS(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_802_11_WIRELESS))
#define NM_IS_DEVICE_802_11_WIRELESS_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DEVICE_802_11_WIRELESS))
#define NM_DEVICE_802_11_WIRELESS_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessClass))

typedef struct {
	NMDevice parent;
} NMDevice80211Wireless;

typedef struct {
	NMDeviceClass parent;
} NMDevice80211WirelessClass;

GType nm_device_802_11_wireless_get_type (void);

NMDevice80211Wireless *nm_device_802_11_wireless_new         (DBusGConnection *connection,
															  const char *path);
int                   nm_device_802_11_wireless_get_speed   (NMDevice80211Wireless *device);
char                 *nm_device_802_11_wireless_get_address (NMDevice80211Wireless *device);

int                   nm_device_802_11_wireless_get_mode    (NMDevice80211Wireless *device);
NMAccessPoint        *nm_device_802_11_wireless_get_active_network (NMDevice80211Wireless *device);

GSList               *nm_device_802_11_wireless_get_networks (NMDevice80211Wireless *device);
void                  nm_device_802_11_wireless_activate     (NMDevice80211Wireless *device,
															  NMAccessPoint *ap,
															  gboolean user_requested);

#endif /* NM_DEVICE_802_11_WIRELESS_H */
