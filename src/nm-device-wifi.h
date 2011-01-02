/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2005 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef NM_DEVICE_WIFI_H
#define NM_DEVICE_WIFI_H

#include <glib-object.h>
#include <dbus/dbus.h>
#include <net/ethernet.h>

#include "nm-rfkill.h"
#include "nm-device.h"
#include "nm-wifi-ap.h"

struct NMAccessPointList;

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_WIFI			(nm_device_wifi_get_type ())
#define NM_DEVICE_WIFI(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_WIFI, NMDeviceWifi))
#define NM_DEVICE_WIFI_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_WIFI, NMDeviceWifiClass))
#define NM_IS_DEVICE_WIFI(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_WIFI))
#define NM_IS_DEVICE_WIFI_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_WIFI))
#define NM_DEVICE_WIFI_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_WIFI, NMDeviceWifiClass))


#define NM_DEVICE_WIFI_HW_ADDRESS          "hw-address"
#define NM_DEVICE_WIFI_PERMANENT_HW_ADDRESS "perm-hw-address"
#define NM_DEVICE_WIFI_MODE                "mode"
#define NM_DEVICE_WIFI_BITRATE             "bitrate"
#define NM_DEVICE_WIFI_ACTIVE_ACCESS_POINT "active-access-point"
#define NM_DEVICE_WIFI_CAPABILITIES        "wireless-capabilities"
#define NM_DEVICE_WIFI_SCANNING            "scanning"
#define NM_DEVICE_WIFI_IPW_RFKILL_STATE    "ipw-rfkill-state"

#ifndef NM_DEVICE_WIFI_DEFINED
#define NM_DEVICE_WIFI_DEFINED
typedef struct _NMDeviceWifi NMDeviceWifi;
#endif

typedef struct _NMDeviceWifiClass NMDeviceWifiClass;
typedef struct _NMDeviceWifiPrivate NMDeviceWifiPrivate;

struct _NMDeviceWifi
{
	NMDevice parent;

	/*< private >*/
	NMDeviceWifiPrivate *priv;
};

struct _NMDeviceWifiClass
{
	NMDeviceClass parent;

	/* Signals */
	void (*access_point_added)   (NMDeviceWifi *device, NMAccessPoint *ap);
	void (*access_point_removed) (NMDeviceWifi *device, NMAccessPoint *ap);
	void (*hidden_ap_found)      (NMDeviceWifi *device, NMAccessPoint *ap);
	void (*properties_changed)   (NMDeviceWifi *device, GHashTable *properties);
	gboolean (*scanning_allowed) (NMDeviceWifi *device);
};


GType nm_device_wifi_get_type (void);

NMDevice *nm_device_wifi_new (const char *udi,
                              const char *iface,
                              const char *driver);

void nm_device_wifi_get_address (NMDeviceWifi *dev, struct ether_addr *addr);

void nm_device_wifi_get_bssid (NMDeviceWifi *dev, struct ether_addr *bssid);

const GByteArray * nm_device_wifi_get_ssid (NMDeviceWifi *self);

gboolean nm_device_wifi_set_mode (NMDeviceWifi *self, const NM80211Mode mode);

NM80211Mode nm_device_wifi_get_mode (NMDeviceWifi *self);

NMAccessPoint * nm_device_wifi_get_activation_ap (NMDeviceWifi *self);

RfKillState nm_device_wifi_get_ipw_rfkill_state (NMDeviceWifi *self);

G_END_DECLS

#endif	/* NM_DEVICE_WIFI_H */
