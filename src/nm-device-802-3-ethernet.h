/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

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

#ifndef NM_DEVICE_802_3_ETHERNET_H
#define NM_DEVICE_802_3_ETHERNET_H

#include <glib-object.h>
#include <net/ethernet.h>

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_802_3_ETHERNET			(nm_device_802_3_ethernet_get_type ())
#define NM_DEVICE_802_3_ETHERNET(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023Ethernet))
#define NM_DEVICE_802_3_ETHERNET_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023EthernetClass))
#define NM_IS_DEVICE_802_3_ETHERNET(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_802_3_ETHERNET))
#define NM_IS_DEVICE_802_3_ETHERNET_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_802_3_ETHERNET))
#define NM_DEVICE_802_3_ETHERNET_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023EthernetClass))

#define NM_DEVICE_802_3_ETHERNET_HW_ADDRESS "hw-address"
#define NM_DEVICE_802_3_ETHERNET_SPEED "speed"

typedef struct {
	NMDevice parent;
} NMDevice8023Ethernet;

typedef struct {
	NMDeviceClass parent;
} NMDevice8023EthernetClass;


GType nm_device_802_3_ethernet_get_type (void);


NMDevice8023Ethernet *nm_device_802_3_ethernet_new (const char *udi,
										  const char *iface,
										  const char *driver);

void nm_device_802_3_ethernet_get_address (NMDevice8023Ethernet *dev,
								   struct ether_addr *addr);

G_END_DECLS

#endif	/* NM_DEVICE_802_3_ETHERNET_H */
