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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifndef NETWORK_MANAGER_DEVICE_H
#define NETWORK_MANAGER_DEVICE_H

#include "NetworkManager.h"

/*
 * Types of NetworkManager devices
 */
enum NMIfaceType
{
	NM_IFACE_TYPE_DONT_KNOW,
	NM_IFACE_TYPE_WIRED_ETHERNET,
	NM_IFACE_TYPE_WIRELESS_ETHERNET
};

typedef struct NMDevice		NMDevice;
typedef enum NMIfaceType		NMIfaceType;


NMDevice *	nm_device_new				(const char *iface);

void			nm_device_ref				(NMDevice *dev);
void			nm_device_unref			(NMDevice *dev);

char *		nm_device_get_udi			(NMDevice *dev);
void			nm_device_set_udi			(NMDevice *dev, const char *udi);

char *		nm_device_get_iface			(NMDevice *dev);

NMIfaceType	nm_device_get_iface_type		(NMDevice *dev);
/* There is no nm_device_set_iface_type() because that's determined when you set the device's iface */

gboolean		nm_device_get_link_active	(NMDevice *dev);
void			nm_device_set_link_active	(NMDevice *dev, const gboolean active);
gboolean		nm_device_update_link_active	(NMDevice *dev, gboolean check_mii);

gboolean		nm_device_check_link_status	(NMDevice *dev);

char *		nm_device_get_essid			(NMDevice *dev);
void			nm_device_set_essid			(NMDevice *dev, const char *essid);

gboolean		nm_device_get_supports_wireless_scan (NMDevice *dev);

/* There is no function to get the WEP key since that's a slight security risk */
void			nm_device_set_wep_key		(NMDevice *dev, const char *wep_key);

void			nm_device_bring_up			(NMDevice *dev);
void			nm_device_bring_down		(NMDevice *dev);
gboolean		nm_device_is_up			(NMDevice *dev);

void			nm_device_ap_list_add		(NMDevice *dev, NMAccessPoint *ap);
void			nm_device_ap_list_clear		(NMDevice *dev);
NMAccessPoint *nm_device_ap_list_get_ap		(NMDevice *dev, int index);

NMDevice *	nm_get_device_by_udi		(NMData *data, const char *udi);
NMDevice *	nm_get_device_by_iface		(NMData *data, const char *iface);

#endif
