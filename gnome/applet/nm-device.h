/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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
 * (C) Copyright 2004-2005 Red Hat, Inc.
 */


#ifndef NM_DEVICE_H
#define NM_DEVICE_H

#include "NetworkManager.h"
#include "wireless-network.h"

typedef struct NetworkDevice NetworkDevice;
typedef void (*WirelessNetworkForeach) (NetworkDevice *dev, WirelessNetwork *net, gpointer user_data);


NetworkDevice *		network_device_new						(const char *iface, NMDeviceType type, const char *nm_path);
NetworkDevice *		network_device_copy						(NetworkDevice *src);

void					network_device_ref						(NetworkDevice *dev);
void					network_device_unref					(NetworkDevice *dev);

gboolean				network_device_is_wired					(NetworkDevice *dev);
gboolean				network_device_is_wireless				(NetworkDevice *dev);

NMDeviceType			network_device_get_type					(NetworkDevice *dev);

WirelessNetwork *		network_device_get_wireless_network_by_essid	(NetworkDevice *dev, const char *essid);
WirelessNetwork *		network_device_get_wireless_network_by_nm_path(NetworkDevice *dev, const char *essid);

WirelessNetwork *		network_device_get_active_wireless_network	(NetworkDevice *dev);

void					network_device_foreach_wireless_network		(NetworkDevice *dev, WirelessNetworkForeach func, gpointer user_data);

void					network_device_add_wireless_network		(NetworkDevice *dev, WirelessNetwork *net);
void					network_device_remove_wireless_network		(NetworkDevice *dev, WirelessNetwork *net);
void					network_device_clear_wireless_networks		(NetworkDevice *dev);

void					network_device_sort_wireless_networks		(NetworkDevice *dev);

guint				network_device_get_num_wireless_networks	(NetworkDevice *dev);

const char *			network_device_get_address				(NetworkDevice *dev);
void					network_device_set_address				(NetworkDevice *dev, const char *addr);

const char *			network_device_get_broadcast				(NetworkDevice *dev);
void					network_device_set_broadcast				(NetworkDevice *dev, const char *addr);

const char *			network_device_get_netmask				(NetworkDevice *dev);
void					network_device_set_netmask				(NetworkDevice *dev, const char *addr);

const char *			network_device_get_ip4_address			(NetworkDevice *dev);
void					network_device_set_ip4_address			(NetworkDevice *dev, const char *addr);

const char *			network_device_get_route					(NetworkDevice *dev);
void					network_device_set_route					(NetworkDevice *dev, const char *route);

const char *			network_device_get_primary_dns			(NetworkDevice *dev);
void					network_device_set_primary_dns			(NetworkDevice *dev, const char *dns);

const char *			network_device_get_secondary_dns			(NetworkDevice *dev);
void					network_device_set_secondary_dns			(NetworkDevice *dev, const char *dns);

guint32				network_device_get_capabilities			(NetworkDevice *dev);
void					network_device_set_capabilities			(NetworkDevice *dev, guint32 caps);

guint32				network_device_get_type_capabilities		(NetworkDevice *dev);
void					network_device_set_type_capabilities		(NetworkDevice *dev, guint32 type_caps);

const char *			network_device_get_iface					(NetworkDevice *dev);

const char *			network_device_get_nm_path				(NetworkDevice *dev);

gint					network_device_get_strength				(NetworkDevice *dev);
void					network_device_set_strength				(NetworkDevice *dev, gint strength);

const char *			network_device_get_hal_udi				(NetworkDevice *dev);
void					network_device_set_hal_udi				(NetworkDevice *dev, const char *hal_udi);

gboolean				network_device_get_link					(NetworkDevice *dev);
void					network_device_set_link					(NetworkDevice *dev, gboolean new_link);

int					network_device_get_speed					(NetworkDevice *dev);
void					network_device_set_speed					(NetworkDevice *dev, int speed);

gboolean				network_device_get_active				(NetworkDevice *dev);
void					network_device_set_active				(NetworkDevice *dev, gboolean active);

const char *			network_device_get_desc					(NetworkDevice *dev);
void					network_device_set_desc					(NetworkDevice *dev, const char *desc);

NMActStage			network_device_get_act_stage				(NetworkDevice *dev);
void					network_device_set_act_stage				(NetworkDevice *dev, NMActStage act_stage);

const char *			network_device_get_driver				(NetworkDevice *dev);
void					network_device_set_driver				(NetworkDevice *dev, const char *driver);

#endif
