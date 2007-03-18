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
#include <dbus/dbus.h>

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_802_3_ETHERNET			(nm_device_802_3_ethernet_get_type ())
#define NM_DEVICE_802_3_ETHERNET(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023Ethernet))
#define NM_DEVICE_802_3_ETHERNET_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023EthernetClass))
#define NM_IS_DEVICE_802_3_ETHERNET(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_802_3_ETHERNET))
#define NM_IS_DEVICE_802_3_ETHERNET_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_802_3_ETHERNET))
#define NM_DEVICE_802_3_ETHERNET_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_802_3_ETHERNET, NMDevice8023EthernetClass))

typedef struct _NMDevice8023Ethernet NMDevice8023Ethernet;
typedef struct _NMDevice8023EthernetClass NMDevice8023EthernetClass;
typedef struct _NMDevice8023EthernetPrivate NMDevice8023EthernetPrivate;

struct _NMDevice8023Ethernet
{
	NMDevice parent;

	/*< private >*/
	NMDevice8023EthernetPrivate *priv;
};

struct _NMDevice8023EthernetClass
{
	NMDeviceClass parent;
};


GType nm_device_802_3_ethernet_get_type (void);


static inline gboolean nm_device_is_802_3_ethernet (NMDevice *dev);
static inline gboolean nm_device_is_802_3_ethernet (NMDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (G_OBJECT_TYPE (dev) == NM_TYPE_DEVICE_802_3_ETHERNET);
}

int nm_device_802_3_ethernet_get_speed (NMDevice8023Ethernet *self);

G_END_DECLS

#endif	/* NM_DEVICE_802_3_ETHERNET_H */
