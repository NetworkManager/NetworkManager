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


#include <glib.h>
#include <string.h>
#include "nm-device.h"


/*
 * Representation of network device
 *
 */
struct NetworkDevice
{
	int			refcount;
	char *		iface;
	char *		driver;
	char *		desc;
	char *		nm_path;
	NMDeviceType	type;
	gboolean		active;
	gboolean		link;
	guint32		caps;
	guint32		type_caps;
	char *		addr;
	char *		ip4addr;
	char *		broadcast;
	char *		netmask;
	char *		udi;
	char *		route;
	char *		primary_dns;
	char *		secondary_dns;
	gint			strength;
	gint			speed;
	GSList *		networks;
	NMActStage	act_stage;
};


/*
 * network_device_new
 *
 * Create a new network device representation
 *
 */
NetworkDevice *network_device_new (const char *iface, NMDeviceType type, const char *nm_path)
{
	NetworkDevice *dev = g_malloc0 (sizeof (NetworkDevice));

	dev->refcount = 1;
	dev->iface = g_strdup (iface);
	dev->type = type;
	dev->nm_path = g_strdup (nm_path);

	return dev;
}


/*
 * network_device_copy
 *
 * Create a new network device representation, filling its
 * data in from an already existing one.  Deep-copies the
 * wireless networks too.
 *
 */
NetworkDevice *network_device_copy (NetworkDevice *src)
{
	NetworkDevice	*dev;
	GSList		*elt;

	g_return_val_if_fail (src != NULL, NULL);

	dev = g_malloc0 (sizeof (NetworkDevice));

	network_device_ref (dev);
	dev->nm_path = g_strdup (src->nm_path);
	dev->driver = g_strdup (src->driver);
	dev->type = src->type;
	dev->link = src->link;
	dev->addr = g_strdup (src->addr);
	dev->ip4addr = g_strdup (src->ip4addr);
	dev->broadcast = g_strdup (src->broadcast);
	dev->netmask = g_strdup (src->netmask);
	dev->caps = src->caps;
	dev->iface = g_strdup (src->iface);
	dev->desc = g_strdup (src->desc);
	dev->route = g_strdup (src->route);
	dev->udi = g_strdup (src->udi);
	dev->active = src->active;
	dev->act_stage = src->act_stage;
	dev->strength = src->strength;

	for (elt = src->networks; elt; elt = g_slist_next (elt))
	{
		WirelessNetwork *net = (WirelessNetwork *)elt->data;
		if (net)
		{
			WirelessNetwork *copy = wireless_network_copy (net);
			dev->networks = g_slist_append (dev->networks, copy);
		}
	}

	return dev;
}


/*
 * network_device_ref
 *
 * Increment the reference count of the network device
 *
 */
void network_device_ref (NetworkDevice *dev)
{
	g_return_if_fail (dev != NULL);

	dev->refcount++;
}


/*
 * network_device_unref
 *
 * Unrefs (and possibly frees) the representation of a network device
 *
 */
void network_device_unref (NetworkDevice *dev)
{
	g_return_if_fail (dev != NULL);

	dev->refcount--;
	if (dev->refcount < 1)
	{
		if (dev->type == DEVICE_TYPE_802_11_WIRELESS)
			network_device_clear_wireless_networks (dev);
		g_free (dev->nm_path);
		g_free (dev->iface);
		g_free (dev->driver);
		g_free (dev->route);
		g_free (dev->udi);
		g_free (dev->desc);
		g_free (dev->addr);
		g_free (dev->broadcast);
		g_free (dev->netmask);
		g_free (dev->ip4addr);
		g_free (dev->primary_dns);
		g_free (dev->secondary_dns);
		memset (dev, 0, sizeof (NetworkDevice));
		g_free (dev);
	}
}


gboolean network_device_is_wired (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (network_device_get_type (dev) == DEVICE_TYPE_802_3_ETHERNET);
}


gboolean network_device_is_wireless (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (network_device_get_type (dev) == DEVICE_TYPE_802_11_WIRELESS);
}


/*
 * network_device_get_active_wireless_network
 *
 * Return the active wireless network.
 *
 */
WirelessNetwork *network_device_get_active_wireless_network (NetworkDevice *dev)
{
	GSList *			list;
	WirelessNetwork *	active = NULL;

	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (dev->type == DEVICE_TYPE_802_11_WIRELESS, NULL);

	for (list = dev->networks; list; list = list->next)
	{
		WirelessNetwork *net = (WirelessNetwork *) list->data;

		if (wireless_network_get_active (net))
		{
			active = net;
			break;
		}
	}

	return active;	
}


/*
 * network_device_get_wireless_network_by_essid
 *
 * Return the wireless network with the specified essid.
 *
 */
WirelessNetwork *network_device_get_wireless_network_by_essid (NetworkDevice *dev, const char *essid)
{
	GSList *			list;
	WirelessNetwork *	return_net = NULL;

	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (dev->type == DEVICE_TYPE_802_11_WIRELESS, NULL);
	g_return_val_if_fail (essid != NULL, NULL);

	for (list = dev->networks; list; list = list->next)
	{
		WirelessNetwork *net = (WirelessNetwork *) list->data;

		if (!strcmp (wireless_network_get_essid (net), essid))
		{
			return_net = net;
			break;
		}
	}

	return return_net;	
}


/*
 * network_device_get_wireless_network_by_nm_path
 *
 * Return the wireless network with the specified NetworkManager object path.
 *
 */
WirelessNetwork *network_device_get_wireless_network_by_nm_path (NetworkDevice *dev, const char *nm_path)
{
	GSList *			list;
	WirelessNetwork *	return_net = NULL;

	g_return_val_if_fail (dev != NULL, NULL);
	g_return_val_if_fail (dev->type == DEVICE_TYPE_802_11_WIRELESS, NULL);
	g_return_val_if_fail (nm_path != NULL, NULL);

	for (list = dev->networks; list; list = list->next)
	{
		WirelessNetwork *net = (WirelessNetwork *) list->data;

		if (!strcmp (wireless_network_get_nm_path (net), nm_path))
		{
			return_net = net;
			break;
		}
	}

	return return_net;	
}


/*
 * network_device_get_wireless_network_by_nm_path
 *
 * Return the wireless network with the specified NetworkManager object path.
 *
 */
void network_device_foreach_wireless_network (NetworkDevice *dev, WirelessNetworkForeach func, gpointer user_data)
{
	GSList *			list;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->type == DEVICE_TYPE_802_11_WIRELESS);
	g_return_if_fail (func != NULL);

	for (list = dev->networks; list; list = list->next)
	{
		WirelessNetwork *net = (WirelessNetwork *) list->data;

		if (net)
			(*func)(dev, net, user_data);
	}
}


/*
 * network_device_add_wireless_network
 *
 * Adds a wireless network to the network device's network list
 *
 */
void network_device_add_wireless_network (NetworkDevice *dev, WirelessNetwork *net)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->type == DEVICE_TYPE_802_11_WIRELESS);
	g_return_if_fail (net != NULL);

	wireless_network_ref (net);
	dev->networks = g_slist_append (dev->networks, net);
}


/*
 * network_device_clear_wireless_networks
 *
 */
void network_device_clear_wireless_networks (NetworkDevice *dev)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->type == DEVICE_TYPE_802_11_WIRELESS);

	g_slist_foreach (dev->networks, (GFunc) wireless_network_unref, NULL);
	g_slist_free (dev->networks);
	dev->networks = NULL;	
}


/*
 * network_device_remove_wireless_network
 *
 * Remove one wireless network from the wireless network list
 *
 */
void network_device_remove_wireless_network (NetworkDevice *dev, WirelessNetwork *net)
{
	GSList	*elt;

	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->type == DEVICE_TYPE_802_11_WIRELESS);
	g_return_if_fail (net != NULL);

	for (elt = dev->networks; elt; elt = g_slist_next (elt))
	{
		if (elt->data == net)
		{
			dev->networks = g_slist_remove_link (dev->networks, elt);
			wireless_network_unref ((WirelessNetwork *)elt->data);
			g_slist_free (elt);
			break;
		}
	}
}


static int sort_networks_function (WirelessNetwork *a, WirelessNetwork *b)
{
	const char *name_a = wireless_network_get_essid (a);
	const char *name_b = wireless_network_get_essid (b);

	if (name_a && !name_b)
		return -1;
	else if (!name_a && name_b)
		return 1;
	else if (!name_a && !name_b)
		return 0;
	else
		return strcasecmp (name_a, name_b);
}


/*
 * network_device_sort_wireless_networks
 *
 * Alphabetize the wireless networks list
 *
 */
void network_device_sort_wireless_networks (NetworkDevice *dev)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->type == DEVICE_TYPE_802_11_WIRELESS);

	dev->networks = g_slist_sort (dev->networks, (GCompareFunc) sort_networks_function);
}


/*
 * network_device_get_num_wireless_networks
 *
 * Return the number of wireless networks this device knows about.
 *
 */
guint network_device_get_num_wireless_networks (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, 0);
	g_return_val_if_fail (dev->type == DEVICE_TYPE_802_11_WIRELESS, 0);
	
	return g_slist_length (dev->networks);
}


/*
 * Accessors for driver name
 */
const char *network_device_get_driver (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return dev->driver;
}

void network_device_set_driver (NetworkDevice *dev, const char *driver)
{
	g_return_if_fail (dev != NULL);

	if (dev->driver)
		g_free (dev->driver);
	dev->driver = driver ? g_strdup (driver) : NULL;
}

/*
 * Accessors for hardware address
 */
const char *network_device_get_address (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->addr);
}

void network_device_set_address (NetworkDevice *dev, const char *addr)
{
	g_return_if_fail (dev != NULL);

	if (dev->addr)
		g_free (dev->addr);
	dev->addr = addr ? g_strdup (addr) : NULL;
}

/*
 * Accessors for broadcast address
 */
const char *network_device_get_broadcast (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->broadcast);
}

void network_device_set_broadcast (NetworkDevice *dev, const char *addr)
{
	g_return_if_fail (dev != NULL);

	if (dev->broadcast)
		g_free (dev->broadcast);
	dev->broadcast = addr ? g_strdup (addr) : NULL;
}

/*
 * Accessors for subnet address
 */
const char *network_device_get_netmask (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->netmask);
}

void network_device_set_netmask (NetworkDevice *dev, const char *addr)
{
	g_return_if_fail (dev != NULL);

	if (dev->netmask)
		g_free (dev->netmask);
	dev->netmask = addr ? g_strdup (addr) : NULL;
}

/*
 * Accessors for ip4 address
 */
const char *network_device_get_ip4_address (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->ip4addr);
}

void network_device_set_ip4_address (NetworkDevice *dev, const char *addr)
{
	g_return_if_fail (dev != NULL);

	if (dev->ip4addr)
		g_free (dev->ip4addr);
	dev->ip4addr = addr ? g_strdup (addr) : NULL;
}

/*
 * Accessors for default route
 */
const char *network_device_get_route (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->route);
}

void network_device_set_route (NetworkDevice *dev, const char *route)
{
	g_return_if_fail (dev != NULL);

	if (dev->route)
		g_free (dev->route);
	dev->route = route ? g_strdup (route) : NULL;
}

/*
 * Accessors for primary DNS
 */
const char *network_device_get_primary_dns (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->primary_dns);
}

void network_device_set_primary_dns (NetworkDevice *dev, const char *dns)
{
	g_return_if_fail (dev != NULL);

	if (dev->primary_dns)
		g_free (dev->primary_dns);
	dev->primary_dns = dns ? g_strdup (dns) : NULL;
}

/*
 * Accessors for secondary DNS
 */
const char *network_device_get_secondary_dns (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->secondary_dns);
}

void network_device_set_secondary_dns (NetworkDevice *dev, const char *dns)
{
	g_return_if_fail (dev != NULL);

	if (dev->secondary_dns)
		g_free (dev->secondary_dns);
	dev->secondary_dns = dns ? g_strdup (dns) : NULL;
}

/*
 * Accessors for device capabilities
 */
guint32 network_device_get_capabilities (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NM_DEVICE_CAP_NONE);

	return dev->caps;
}

void network_device_set_capabilities (NetworkDevice *dev, guint32 caps)
{
	g_return_if_fail (dev != NULL);

	dev->caps = caps;
}

/*
 * Accessors for type-specific device capabilities
 */
guint32 network_device_get_type_capabilities (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NM_DEVICE_CAP_NONE);

	return dev->type_caps;
}

void network_device_set_type_capabilities (NetworkDevice *dev, guint32 type_caps)
{
	g_return_if_fail (dev != NULL);

	dev->type_caps = type_caps;
}

/*
 * Accessors for NM object path
 */
const char *network_device_get_nm_path (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->nm_path);
}

/*
 * Accessors for device type
 */
NMDeviceType network_device_get_type (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, DEVICE_TYPE_UNKNOWN);

	return (dev->type);
}

/*
 * Accessors for strength
 */
gint network_device_get_strength (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, -1);
	g_return_val_if_fail (dev->type == DEVICE_TYPE_802_11_WIRELESS, -1);

	return (dev->strength);
}

void network_device_set_strength (NetworkDevice *dev, gint strength)
{
	g_return_if_fail (dev != NULL);
	g_return_if_fail (dev->type == DEVICE_TYPE_802_11_WIRELESS);

	dev->strength = strength;
}

/*
 * Accessors for device's interface name
 */
const char *network_device_get_iface (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->iface);
}

/*
 * Accessors for HAL udi
 */
const char *network_device_get_hal_udi (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->udi);
}

void network_device_set_hal_udi (NetworkDevice *dev, const char *hal_udi)
{
	g_return_if_fail (dev != NULL);

	if (dev->udi)
	{
		g_free (dev->udi);
		dev->udi = NULL;
	}
	if (hal_udi)
		dev->udi = g_strdup (hal_udi);
}

/*
 * Accessors for link
 */
gboolean network_device_get_link (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->link);
}

void network_device_set_link (NetworkDevice *dev, gboolean new_link)
{
	g_return_if_fail (dev != NULL);

	dev->link = new_link;
}

/*
 * Accessors for speed (in Mb/s)
 */
int network_device_get_speed (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->speed);
}

void network_device_set_speed (NetworkDevice *dev, int speed)
{
	g_return_if_fail (dev != NULL);

	dev->speed = speed;
}

/*
 * Accessors for active
 */
gboolean network_device_get_active (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->active);
}

void network_device_set_active (NetworkDevice *dev, gboolean active)
{
	g_return_if_fail (dev != NULL);

	dev->active = active;
}

/*
 * Accessors for desc
 */
const char *network_device_get_desc (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, NULL);

	return (dev->desc);
}

void network_device_set_desc (NetworkDevice *dev, const char *desc)
{
	g_return_if_fail (dev != NULL);

	if (dev->desc)
	{
		g_free (dev->desc);
		dev->desc = NULL;
	}
	if (desc)
		dev->desc = g_strdup (desc);
}

/*
 * Accessors for activation stage
 */
NMActStage network_device_get_act_stage (NetworkDevice *dev)
{
	g_return_val_if_fail (dev != NULL, FALSE);

	return (dev->act_stage);
}

void network_device_set_act_stage (NetworkDevice *dev, NMActStage act_stage)
{
	g_return_if_fail (dev != NULL);

	dev->act_stage = act_stage;
}

