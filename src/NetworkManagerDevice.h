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

#include <net/ethernet.h>
#include "NetworkManager.h"

/*
 * Types of NetworkManager devices
 */
enum NMDeviceType
{
	DEVICE_TYPE_DONT_KNOW = 0,
	DEVICE_TYPE_WIRED_ETHERNET,
	DEVICE_TYPE_WIRELESS_ETHERNET
};

typedef struct NMDevice		NMDevice;
typedef enum NMDeviceType	NMDeviceType;


NMDevice *	nm_device_new				(const char *iface, NMData *app_data);

void			nm_device_ref				(NMDevice *dev);
void			nm_device_unref			(NMDevice *dev);

char *		nm_device_get_udi			(NMDevice *dev);
void			nm_device_set_udi			(NMDevice *dev, const char *udi);

char *		nm_device_get_iface			(NMDevice *dev);

NMDeviceType	nm_device_get_type			(NMDevice *dev);
gboolean		nm_device_is_wireless		(NMDevice *dev);
gboolean		nm_device_is_wired			(NMDevice *dev);
/* There is no nm_device_set_iface_type() because that's determined when you set the device's iface */

gboolean		nm_device_get_link_active	(NMDevice *dev);
void			nm_device_set_link_active	(NMDevice *dev, const gboolean active);
void			nm_device_update_link_active	(NMDevice *dev, gboolean check_mii);

char *		nm_device_get_essid			(NMDevice *dev);
void			nm_device_set_essid			(NMDevice *dev, const char *essid);

void			nm_device_get_ap_address		(NMDevice *dev, struct ether_addr *addr);

guint32		nm_device_get_ip4_address	(NMDevice *dev);
void			nm_device_update_ip4_address	(NMDevice *dev);

void			nm_device_get_ip6_address	(NMDevice *dev);

gboolean		nm_device_get_supports_wireless_scan (NMDevice *dev);
void			nm_device_do_wireless_scan	(NMDevice *dev);

NMAccessPoint *nm_device_get_best_ap		(NMDevice *dev);
void			nm_device_set_best_ap		(NMDevice *dev, NMAccessPoint *ap);
void			nm_device_update_best_ap		(NMDevice *dev);
gboolean		nm_device_need_ap_switch		(NMDevice *dev);

char *		nm_device_get_path_for_ap	(NMDevice *dev, NMAccessPoint *ap);

/* There is no function to get the WEP key since that's a slight security risk */
void			nm_device_set_wep_key		(NMDevice *dev, const char *wep_key);

gboolean		nm_device_activate			(NMDevice *dev);
gboolean		nm_device_deactivate		(NMDevice *dev, gboolean just_added);

void			nm_device_bring_up			(NMDevice *dev);
void			nm_device_bring_down		(NMDevice *dev);
gboolean		nm_device_is_up			(NMDevice *dev);

gboolean		nm_device_pending_action		(NMDevice *dev);
void			nm_device_pending_action_cancel	(NMDevice *dev);
void			nm_device_pending_action_get_user_key (NMDevice *dev, NMAccessPoint *ap);
void			nm_device_pending_action_set_user_key (NMDevice *dev, unsigned char *key);

void			nm_device_ap_list_add		(NMDevice *dev, NMAccessPoint *ap);
void			nm_device_ap_list_clear		(NMDevice *dev);
struct NMAccessPointList *nm_device_ap_list_get	(NMDevice *dev);
NMAccessPoint *nm_device_ap_list_get_ap_by_essid	(NMDevice *dev, const char *essid);

NMDevice *	nm_get_device_by_udi		(NMData *data, const char *udi);
NMDevice *	nm_get_device_by_iface		(NMData *data, const char *iface);

#endif
