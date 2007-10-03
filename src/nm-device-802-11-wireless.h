/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2005 Red Hat, Inc.
 */

#ifndef NM_DEVICE_802_11_WIRELESS_H
#define NM_DEVICE_802_11_WIRELESS_H

#include <glib-object.h>
#include <dbus/dbus.h>
#include <net/ethernet.h>


#include "nm-device.h"
#include "NetworkManagerAP.h"

struct NMAccessPointList;

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_802_11_WIRELESS			(nm_device_802_11_wireless_get_type ())
#define NM_DEVICE_802_11_WIRELESS(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211Wireless))
#define NM_DEVICE_802_11_WIRELESS_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessClass))
#define NM_IS_DEVICE_802_11_WIRELESS(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_802_11_WIRELESS))
#define NM_IS_DEVICE_802_11_WIRELESS_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_802_11_WIRELESS))
#define NM_DEVICE_802_11_WIRELESS_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_802_11_WIRELESS, NMDevice80211WirelessClass))


#define NM_DEVICE_802_11_WIRELESS_HW_ADDRESS "hw-address"
#define NM_DEVICE_802_11_WIRELESS_MODE "mode"
#define NM_DEVICE_802_11_WIRELESS_BITRATE "bitrate"
#define NM_DEVICE_802_11_WIRELESS_ACTIVE_ACCESS_POINT "active-access-point"
#define NM_DEVICE_802_11_WIRELESS_CAPABILITIES "wireless-capabilities"

#ifndef NM_DEVICE_802_11_WIRELESS_DEFINED
#define NM_DEVICE_802_11_WIRELESS_DEFINED
typedef struct _NMDevice80211Wireless NMDevice80211Wireless;
#endif

typedef struct _NMDevice80211WirelessClass NMDevice80211WirelessClass;
typedef struct _NMDevice80211WirelessPrivate NMDevice80211WirelessPrivate;

struct _NMDevice80211Wireless
{
	NMDevice parent;

	/*< private >*/
	NMDevice80211WirelessPrivate *priv;
};

struct _NMDevice80211WirelessClass
{
	NMDeviceClass parent;

	/* Signals */
	void (*access_point_added) (NMDevice80211Wireless *device, NMAccessPoint *ap);
	void (*access_point_removed) (NMDevice80211Wireless *device, NMAccessPoint *ap);
};


GType nm_device_802_11_wireless_get_type (void);

NMDevice80211Wireless *nm_device_802_11_wireless_new (int index,
													  const char *udi,
													  const char *driver,
													  gboolean test_dev);

void			nm_device_802_11_wireless_set_ssid (NMDevice80211Wireless *self,
										  const GByteArray * ssid);

void nm_device_802_11_wireless_get_address (NMDevice80211Wireless *dev,
								   struct ether_addr *addr);

void			nm_device_802_11_wireless_get_bssid (NMDevice80211Wireless *dev,
                                                    struct ether_addr *bssid);

const GByteArray *	nm_device_802_11_wireless_get_ssid (NMDevice80211Wireless *self);

gboolean		nm_device_802_11_wireless_set_mode (NMDevice80211Wireless *self,
										 const int mode);

int			nm_device_802_11_wireless_get_bitrate (NMDevice80211Wireless *self);

void			nm_device_802_11_wireless_reset_scan_interval (NMDevice80211Wireless *dev);

NMAccessPoint *	nm_device_802_11_wireless_ap_list_get_ap_by_obj_path (NMDevice80211Wireless *dev,
													const char *obj_path);

NMAccessPoint *	nm_device_802_11_wireless_ap_list_get_ap_by_ssid (NMDevice80211Wireless *dev,
													const GByteArray * ssid);

int		nm_device_802_11_wireless_get_mode (NMDevice80211Wireless *self);

gboolean nm_device_802_11_wireless_can_activate (NMDevice80211Wireless * self);

NMAccessPoint * nm_device_802_11_wireless_get_activation_ap (NMDevice80211Wireless *self);


G_END_DECLS

#endif	/* NM_DEVICE_802_11_WIRELESS_H */
