/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <glib/gi18n.h>

#include "nm-setting-ip-config.h"
#include "nm-utils.h"
#include "nm-glib-compat.h"
#include "nm-setting-private.h"
#include "nm-utils-private.h"

static char *
canonicalize_ip (int family, const char *ip, gboolean null_any)
{
	guint8 addr_bytes[sizeof (struct in6_addr)];
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];
	int ret;

	if (!ip) {
		g_return_val_if_fail (null_any == TRUE, NULL);
		return NULL;
	}

	ret = inet_pton (family, ip, addr_bytes);
	g_return_val_if_fail (ret == 1, NULL);

	if (null_any) {
		int addrlen = (family == AF_INET ? sizeof (struct in_addr) : sizeof (struct in6_addr));

		if (!memcmp (addr_bytes, &in6addr_any, addrlen))
			return NULL;
	}

	return g_strdup (inet_ntop (family, addr_bytes, addr_str, sizeof (addr_str)));
}

static gboolean
valid_ip (int family, const char *ip, GError **error)
{
	if (!nm_utils_ipaddr_valid (family, ip)) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             family == AF_INET ? _("Invalid IPv4 address '%s'") : _("Invalid IPv6 address '%s"),
		             ip);
		return FALSE;
	} else
		return TRUE;
}

static gboolean
valid_prefix (int family, guint prefix, GError **error)
{
	if (   (family == AF_INET && prefix > 32)
	    || (family == AF_INET6 && prefix > 128)
	    || prefix == 0) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             family == AF_INET ? _("Invalid IPv4 address prefix '%u'") : _("Invalid IPv6 address prefix '%u"),
		             prefix);
		return FALSE;
	}

	return TRUE;
}


G_DEFINE_BOXED_TYPE (NMIPAddress, nm_ip_address, nm_ip_address_dup, nm_ip_address_unref)

struct NMIPAddress {
	guint refcount;

	char *address, *gateway;
	int prefix, family;

	GHashTable *attributes;
};

/**
 * nm_ip_address_new:
 * @family: the IP address family (%AF_INET or %AF_INET6)
 * @addr: the IP address
 * @prefix: the address prefix length
 * @gateway: (allow-none): the gateway
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMIPAddress object.
 *
 * Returns: (transfer full): the new #NMIPAddress object, or %NULL on error
 **/
NMIPAddress *
nm_ip_address_new (int family,
                   const char *addr, guint prefix, const char *gateway,
                   GError **error)
{
	NMIPAddress *address;

	g_return_val_if_fail (family == AF_INET || family == AF_INET6, NULL);
	g_return_val_if_fail (addr != NULL, NULL);

	if (!valid_ip (family, addr, error))
		return NULL;
	if (!valid_prefix (family, prefix, error))
		return NULL;
	if (gateway && !valid_ip (family, gateway, error))
		return NULL;

	address = g_slice_new0 (NMIPAddress);
	address->refcount = 1;

	address->family = family;
	address->address = canonicalize_ip (family, addr, FALSE);
	address->prefix = prefix;
	address->gateway = canonicalize_ip (family, gateway, TRUE);

	return address;
}

/**
 * nm_ip_address_new_binary:
 * @family: the IP address family (%AF_INET or %AF_INET6)
 * @addr: the IP address
 * @prefix: the address prefix length
 * @gateway: (allow-none): the gateway
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMIPAddress object. @addr and @gateway (if non-%NULL) must
 * point to buffers of the correct size for @family.
 *
 * Returns: (transfer full): the new #NMIPAddress object, or %NULL on error
 **/
NMIPAddress *
nm_ip_address_new_binary (int family,
                          gconstpointer addr, guint prefix, gconstpointer gateway,
                          GError **error)
{
	NMIPAddress *address;
	char string[NM_UTILS_INET_ADDRSTRLEN];

	g_return_val_if_fail (family == AF_INET || family == AF_INET6, NULL);
	g_return_val_if_fail (addr != NULL, NULL);

	if (!valid_prefix (family, prefix, error))
		return NULL;

	address = g_slice_new0 (NMIPAddress);
	address->refcount = 1;

	address->family = family;
	address->address = g_strdup (inet_ntop (family, addr, string, sizeof (string)));
	address->prefix = prefix;
	if (gateway)
		address->gateway = g_strdup (inet_ntop (family, gateway, string, sizeof (string)));

	return address;
}

/**
 * nm_ip_address_ref:
 * @address: the #NMIPAddress
 *
 * Increases the reference count of the object.
 **/
void
nm_ip_address_ref (NMIPAddress *address)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->refcount++;
}

/**
 * nm_ip_address_unref:
 * @address: the #NMIPAddress
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 **/
void
nm_ip_address_unref (NMIPAddress *address)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (address->refcount > 0);

	address->refcount--;
	if (address->refcount == 0) {
		g_free (address->address);
		g_free (address->gateway);
		if (address->attributes)
			g_hash_table_unref (address->attributes);
		g_slice_free (NMIPAddress, address);
	}
}

/**
 * nm_ip_address_equal:
 * @address: the #NMIPAddress
 * @other: the #NMIPAddress to compare @address to.
 *
 * Determines if two #NMIPAddress objects contain the same address, prefix, and
 * gateway (attributes are not compared).
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 **/
gboolean
nm_ip_address_equal (NMIPAddress *address, NMIPAddress *other)
{
	g_return_val_if_fail (address != NULL, FALSE);
	g_return_val_if_fail (address->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   address->family != other->family
	    || address->prefix != other->prefix
	    || strcmp (address->address, other->address) != 0
	    || g_strcmp0 (address->gateway, other->gateway) != 0)
		return FALSE;
	return TRUE;
}

/**
 * nm_ip_address_dup:
 * @address: the #NMIPAddress
 *
 * Creates a copy of @address
 *
 * Returns: (transfer full): a copy of @address
 **/
NMIPAddress *
nm_ip_address_dup (NMIPAddress *address)
{
	NMIPAddress *copy;

	g_return_val_if_fail (address != NULL, NULL);
	g_return_val_if_fail (address->refcount > 0, NULL);

	copy = nm_ip_address_new (address->family,
	                          address->address, address->prefix, address->gateway,
	                          NULL);
	if (address->attributes) {
		GHashTableIter iter;
		const char *key;
		GVariant *value;

		g_hash_table_iter_init (&iter, address->attributes);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value))
			nm_ip_address_set_attribute (copy, key, value);
	}

	return copy;
}

/**
 * nm_ip_address_get_family:
 * @address: the #NMIPAddress
 *
 * Gets the IP address family (eg, AF_INET) property of this address
 * object.
 *
 * Returns: the IP address family
 **/
int
nm_ip_address_get_family (NMIPAddress *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return address->family;
}

/**
 * nm_ip_address_get_address:
 * @address: the #NMIPAddress
 *
 * Gets the IP address property of this address object.
 *
 * Returns: the IP address
 **/
const char *
nm_ip_address_get_address (NMIPAddress *address)
{
	g_return_val_if_fail (address != NULL, NULL);
	g_return_val_if_fail (address->refcount > 0, NULL);

	return address->address;
}

/**
 * nm_ip_address_set_address:
 * @address: the #NMIPAddress
 * @addr: the IP address, as a string
 *
 * Sets the IP address property of this address object.
 *
 * @addr must be a valid address of @address's family. If you aren't sure you
 * have a valid address, use nm_utils_ipaddr_valid() to check it.
 **/
void
nm_ip_address_set_address (NMIPAddress *address,
                           const char *addr)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (addr != NULL);
	g_return_if_fail (nm_utils_ipaddr_valid (address->family, addr));

	g_free (address->address);
	address->address = canonicalize_ip (address->family, addr, FALSE);
}

/**
 * nm_ip_address_get_address_binary: (skip)
 * @address: the #NMIPAddress
 * @addr: a buffer in which to store the address in binary format.
 *
 * Gets the IP address property of this address object.
 *
 * @addr must point to a buffer that is the correct size for @address's family.
 **/
void
nm_ip_address_get_address_binary (NMIPAddress *address,
                                  gpointer addr)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (addr != NULL);

	inet_pton (address->family, address->address, addr);
}

/**
 * nm_ip_address_set_address_binary: (skip)
 * @address: the #NMIPAddress
 * @addr: the address, in binary format
 *
 * Sets the IP address property of this address object.
 *
 * @addr must point to a buffer that is the correct size for @address's family.
 **/
void
nm_ip_address_set_address_binary (NMIPAddress *address,
                                  gconstpointer addr)
{
	char string[NM_UTILS_INET_ADDRSTRLEN];

	g_return_if_fail (address != NULL);
	g_return_if_fail (addr != NULL);

	g_free (address->address);
	address->address = g_strdup (inet_ntop (address->family, addr, string, sizeof (string)));
}

/**
 * nm_ip_address_get_prefix:
 * @address: the #NMIPAddress
 *
 * Gets the IP address prefix (ie "24" or "30" etc) property of this address
 * object.
 *
 * Returns: the IP address prefix
 **/
guint
nm_ip_address_get_prefix (NMIPAddress *address)
{
	g_return_val_if_fail (address != NULL, 0);
	g_return_val_if_fail (address->refcount > 0, 0);

	return address->prefix;
}

/**
 * nm_ip_address_set_prefix:
 * @address: the #NMIPAddress
 * @prefix: the IP address prefix
 *
 * Sets the IP address prefix property of this address object.
 **/
void
nm_ip_address_set_prefix (NMIPAddress *address,
                          guint prefix)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (valid_prefix (address->family, prefix, NULL));

	address->prefix = prefix;
}

/**
 * nm_ip_address_get_gateway:
 * @address: the #NMIPAddress
 *
 * Gets the gateway property of this address object; this will be %NULL if the
 * address has no associated gateway.
 *
 * Returns: the gateway
 **/
const char *
nm_ip_address_get_gateway (NMIPAddress *address)
{
	g_return_val_if_fail (address != NULL, NULL);
	g_return_val_if_fail (address->refcount > 0, NULL);

	return address->gateway;
}

/**
 * nm_ip_address_set_gateway:
 * @address: the #NMIPAddress
 * @gateway: (allow-none): the gateway, as a string
 *
 * Sets the gateway property of this address object.
 *
 * @gateway (if non-%NULL) must be a valid address of @address's family. If you
 * aren't sure you have a valid address, use nm_utils_ipaddr_valid() to check
 * it.
 **/
void
nm_ip_address_set_gateway (NMIPAddress *address,
                           const char *gateway)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (!gateway || nm_utils_ipaddr_valid (address->family, gateway));

	g_free (address->gateway);
	address->gateway = canonicalize_ip (address->family, gateway, TRUE);
}

/**
 * nm_ip_address_get_attribute_names:
 * @address: the #NMIPAddress
 *
 * Gets an array of attribute names defined on @address.
 *
 * Returns: (transfer full): a %NULL-terminated array of attribute names,
 **/
char **
nm_ip_address_get_attribute_names (NMIPAddress *address)
{
	GHashTableIter iter;
	const char *key;
	GPtrArray *names;

	g_return_val_if_fail (address != NULL, NULL);

	names = g_ptr_array_new ();

	if (address->attributes) {
		g_hash_table_iter_init (&iter, address->attributes);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, NULL))
			g_ptr_array_add (names, g_strdup (key));
	}
	g_ptr_array_add (names, NULL);

	return (char **) g_ptr_array_free (names, FALSE);
}

/**
 * nm_ip_address_get_attribute:
 * @address: the #NMIPAddress
 * @name: the name of an address attribute
 *
 * Gets the value of the attribute with name @name on @address
 *
 * Returns: (transfer none): the value of the attribute with name @name on
 *   @address, or %NULL if @address has no such attribute.
 **/
GVariant *
nm_ip_address_get_attribute (NMIPAddress *address, const char *name)
{
	g_return_val_if_fail (address != NULL, NULL);
	g_return_val_if_fail (name != NULL && *name != '\0', NULL);

	if (address->attributes)
		return g_hash_table_lookup (address->attributes, name);
	else
		return NULL;
}

/**
 * nm_ip_address_set_attribute:
 * @address: the #NMIPAddress
 * @name: the name of an address attribute
 * @value: (transfer none) (allow-none): the value
 *
 * Sets or clears the named attribute on @address to the given value.
 **/
void
nm_ip_address_set_attribute (NMIPAddress *address, const char *name, GVariant *value)
{
	g_return_if_fail (address != NULL);
	g_return_if_fail (name != NULL && *name != '\0');

	if (!address->attributes) {
		address->attributes = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                             g_free, (GDestroyNotify) g_variant_unref);
	}

	if (value)
		g_hash_table_insert (address->attributes, g_strdup (name), g_variant_ref_sink (value));
	else
		g_hash_table_remove (address->attributes, name);
}


G_DEFINE_BOXED_TYPE (NMIPRoute, nm_ip_route, nm_ip_route_dup, nm_ip_route_unref)

struct NMIPRoute {
	guint refcount;

	int family;
	char *dest;
	guint prefix;
	char *next_hop;
	guint32 metric;

	GHashTable *attributes;
};

/**
 * nm_ip_route_new:
 * @family: the IP address family (%AF_INET or %AF_INET6)
 * @dest: the IP address of the route's destination
 * @prefix: the address prefix length
 * @next_hop: (allow-none): the IP address of the next hop (or %NULL)
 * @metric: the route metric (or 0 for "default")
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMIPRoute object.
 *
 * Returns: (transfer full): the new #NMIPRoute object, or %NULL on error
 **/
NMIPRoute *
nm_ip_route_new (int family,
                 const char *dest,
                 guint prefix,
                 const char *next_hop,
                 guint metric,
                 GError **error)
{
	NMIPRoute *route;

	g_return_val_if_fail (family == AF_INET || family == AF_INET6, NULL);

	if (!valid_ip (family, dest, error))
		return NULL;
	if (!valid_prefix (family, prefix, error))
		return NULL;
	if (next_hop && !valid_ip (family, next_hop, error))
		return NULL;

	route = g_slice_new0 (NMIPRoute);
	route->refcount = 1;

	route->family = family;
	route->dest = canonicalize_ip (family, dest, FALSE);
	route->prefix = prefix;
	route->next_hop = canonicalize_ip (family, next_hop, TRUE);
	route->metric = metric;

	return route;
}

/**
 * nm_ip_route_new_binary:
 * @family: the IP address family (%AF_INET or %AF_INET6)
 * @dest: the IP address of the route's destination
 * @prefix: the address prefix length
 * @next_hop: (allow-none): the IP address of the next hop (or %NULL)
 * @metric: the route metric (or 0 for "default")
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMIPRoute object. @dest and @next_hop (if non-%NULL) must
 * point to buffers of the correct size for @family.
 *
 * Returns: (transfer full): the new #NMIPRoute object, or %NULL on error
 **/
NMIPRoute *
nm_ip_route_new_binary (int family,
                        gconstpointer dest,
                        guint prefix,
                        gconstpointer next_hop,
                        guint metric,
                        GError **error)
{
	NMIPRoute *route;
	char string[NM_UTILS_INET_ADDRSTRLEN];

	g_return_val_if_fail (family == AF_INET || family == AF_INET6, NULL);

	if (!valid_prefix (family, prefix, error))
		return NULL;

	route = g_slice_new0 (NMIPRoute);
	route->refcount = 1;

	route->family = family;
	route->dest = g_strdup (inet_ntop (family, dest, string, sizeof (string)));
	route->prefix = prefix;
	if (next_hop)
		route->next_hop = g_strdup (inet_ntop (family, next_hop, string, sizeof (string)));
	route->metric = metric;

	return route;
}

/**
 * nm_ip_route_ref:
 * @route: the #NMIPRoute
 *
 * Increases the reference count of the object.
 **/
void
nm_ip_route_ref (NMIPRoute *route)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->refcount++;
}

/**
 * nm_ip_route_unref:
 * @route: the #NMIPRoute
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 **/
void
nm_ip_route_unref (NMIPRoute *route)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (route->refcount > 0);

	route->refcount--;
	if (route->refcount == 0) {
		g_free (route->dest);
		g_free (route->next_hop);
		if (route->attributes)
			g_hash_table_unref (route->attributes);
		g_slice_free (NMIPRoute, route);
	}
}

/**
 * nm_ip_route_equal:
 * @route: the #NMIPRoute
 * @other: the #NMIPRoute to compare @route to.
 *
 * Determines if two #NMIPRoute objects contain the same destination, prefix,
 * next hop, and metric. (Attributes are not compared.)
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 **/
gboolean
nm_ip_route_equal (NMIPRoute *route, NMIPRoute *other)
{
	g_return_val_if_fail (route != NULL, FALSE);
	g_return_val_if_fail (route->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   route->prefix != other->prefix
	    || route->metric != other->metric
	    || strcmp (route->dest, other->dest) != 0
	    || g_strcmp0 (route->next_hop, other->next_hop) != 0)
		return FALSE;
	return TRUE;
}

/**
 * nm_ip_route_dup:
 * @route: the #NMIPRoute
 *
 * Creates a copy of @route
 *
 * Returns: (transfer full): a copy of @route
 **/
NMIPRoute *
nm_ip_route_dup (NMIPRoute *route)
{
	NMIPRoute *copy;

	g_return_val_if_fail (route != NULL, NULL);
	g_return_val_if_fail (route->refcount > 0, NULL);

	copy = nm_ip_route_new (route->family,
	                        route->dest, route->prefix,
	                        route->next_hop, route->metric,
	                        NULL);
	if (route->attributes) {
		GHashTableIter iter;
		const char *key;
		GVariant *value;

		g_hash_table_iter_init (&iter, route->attributes);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value))
			nm_ip_route_set_attribute (copy, key, value);
	}

	return copy;
}

/**
 * nm_ip_route_get_family:
 * @route: the #NMIPRoute
 *
 * Gets the IP address family (eg, AF_INET) property of this route
 * object.
 *
 * Returns: the IP address family
 **/
int
nm_ip_route_get_family (NMIPRoute *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->family;
}

/**
 * nm_ip_route_get_dest:
 * @route: the #NMIPRoute
 *
 * Gets the IP destination address property of this route object.
 *
 * Returns: the IP address of the route's destination
 **/
const char *
nm_ip_route_get_dest (NMIPRoute *route)
{
	g_return_val_if_fail (route != NULL, NULL);
	g_return_val_if_fail (route->refcount > 0, NULL);

	return route->dest;
}

/**
 * nm_ip_route_set_dest:
 * @route: the #NMIPRoute
 * @dest: the route's destination, as a string
 *
 * Sets the destination property of this route object.
 *
 * @dest must be a valid address of @route's family. If you aren't sure you
 * have a valid address, use nm_utils_ipaddr_valid() to check it.
 **/
void
nm_ip_route_set_dest (NMIPRoute *route,
                      const char *dest)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (dest != NULL);
	g_return_if_fail (nm_utils_ipaddr_valid (route->family, dest));

	g_free (route->dest);
	route->dest = canonicalize_ip (route->family, dest, FALSE);
}

/**
 * nm_ip_route_get_dest_binary: (skip)
 * @route: the #NMIPRoute
 * @dest: a buffer in which to store the destination in binary format.
 *
 * Gets the destination property of this route object.
 *
 * @dest must point to a buffer that is the correct size for @route's family.
 **/
void
nm_ip_route_get_dest_binary (NMIPRoute *route,
                             gpointer dest)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (dest != NULL);

	inet_pton (route->family, route->dest, dest);
}

/**
 * nm_ip_route_set_dest_binary: (skip)
 * @route: the #NMIPRoute
 * @dest: the route's destination, in binary format
 *
 * Sets the destination property of this route object.
 *
 * @dest must point to a buffer that is the correct size for @route's family.
 **/
void
nm_ip_route_set_dest_binary (NMIPRoute *route,
                             gconstpointer dest)
{
	char string[NM_UTILS_INET_ADDRSTRLEN];

	g_return_if_fail (route != NULL);
	g_return_if_fail (dest != NULL);

	g_free (route->dest);
	route->dest = g_strdup (inet_ntop (route->family, dest, string, sizeof (string)));
}

/**
 * nm_ip_route_get_prefix:
 * @route: the #NMIPRoute
 *
 * Gets the IP prefix (ie "24" or "30" etc) of this route.
 *
 * Returns: the IP prefix
 **/
guint
nm_ip_route_get_prefix (NMIPRoute *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->prefix;
}

/**
 * nm_ip_route_set_prefix:
 * @route: the #NMIPRoute
 * @prefix: the route prefix
 *
 * Sets the prefix property of this route object.
 **/
void
nm_ip_route_set_prefix (NMIPRoute *route,
                        guint prefix)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (valid_prefix (route->family, prefix, NULL));

	route->prefix = prefix;
}

/**
 * nm_ip_route_get_next_hop:
 * @route: the #NMIPRoute
 *
 * Gets the IP address of the next hop of this route; this will be %NULL if the
 * route has no next hop.
 *
 * Returns: the IP address of the next hop, or %NULL if this is a device route.
 **/
const char *
nm_ip_route_get_next_hop (NMIPRoute *route)
{
	g_return_val_if_fail (route != NULL, NULL);
	g_return_val_if_fail (route->refcount > 0, NULL);

	return route->next_hop;
}

/**
 * nm_ip_route_set_next_hop:
 * @route: the #NMIPRoute
 * @next_hop: (allow-none): the route's next hop, as a string
 *
 * Sets the next-hop property of this route object.
 *
 * @next_hop (if non-%NULL) must be a valid address of @route's family. If you
 * aren't sure you have a valid address, use nm_utils_ipaddr_valid() to check
 * it.
 **/
void
nm_ip_route_set_next_hop (NMIPRoute *route,
                          const char *next_hop)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (!next_hop || nm_utils_ipaddr_valid (route->family, next_hop));

	g_free (route->next_hop);
	route->next_hop = canonicalize_ip (route->family, next_hop, TRUE);
}

/**
 * nm_ip_route_get_next_hop_binary: (skip)
 * @route: the #NMIPRoute
 * @next_hop: a buffer in which to store the next hop in binary format.
 *
 * Gets the next hop property of this route object.
 *
 * @next_hop must point to a buffer that is the correct size for @route's family.
 *
 * Returns: %TRUE if @route has a next hop, %FALSE if not (in which case
 * @next_hop will be zeroed out)
 **/
gboolean
nm_ip_route_get_next_hop_binary (NMIPRoute *route,
                                 gpointer next_hop)
{
	g_return_val_if_fail (route != NULL, FALSE);
	g_return_val_if_fail (next_hop != NULL, FALSE);

	if (route->next_hop) {
		inet_pton (route->family, route->next_hop, next_hop);
		return TRUE;
	} else {
		memset (next_hop, 0,
		        route->family == AF_INET ? sizeof (struct in_addr) : sizeof (struct in6_addr));
		return FALSE;
	}
}

/**
 * nm_ip_route_set_next_hop_binary: (skip)
 * @route: the #NMIPRoute
 * @next_hop: the route's next hop, in binary format
 *
 * Sets the destination property of this route object.
 *
 * @next_hop (if non-%NULL) must point to a buffer that is the correct size for
 * @route's family.
 **/
void
nm_ip_route_set_next_hop_binary (NMIPRoute *route,
                                 gconstpointer next_hop)
{
	char string[NM_UTILS_INET_ADDRSTRLEN];

	g_return_if_fail (route != NULL);

	g_free (route->next_hop);
	if (next_hop)
		route->next_hop = g_strdup (inet_ntop (route->family, next_hop, string, sizeof (string)));
	else
		route->next_hop = NULL;
}

/**
 * nm_ip_route_get_metric:
 * @route: the #NMIPRoute
 *
 * Gets the route metric property of this route object; lower values
 * indicate "better" or more preferred routes; 0 indicates "default"
 * (meaning NetworkManager will set it appropriately).
 *
 * Returns: the route metric
 **/
guint32
nm_ip_route_get_metric (NMIPRoute *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->metric;
}

/**
 * nm_ip_route_set_metric:
 * @route: the #NMIPRoute
 * @metric: the route metric
 *
 * Sets the metric property of this route object.
 **/
void
nm_ip_route_set_metric (NMIPRoute *route,
                        guint32 metric)
{
	g_return_if_fail (route != NULL);

	route->metric = metric;
}

/**
 * nm_ip_route_get_attribute_names:
 * @route: the #NMIPRoute
 *
 * Gets an array of attribute names defined on @route.
 *
 * Returns: (transfer full): a %NULL-terminated array of attribute names
 **/
char **
nm_ip_route_get_attribute_names (NMIPRoute *route)
{
	GHashTableIter iter;
	const char *key;
	GPtrArray *names;

	g_return_val_if_fail (route != NULL, NULL);

	names = g_ptr_array_new ();

	if (route->attributes) {
		g_hash_table_iter_init (&iter, route->attributes);
		while (g_hash_table_iter_next (&iter, (gpointer *) &key, NULL))
			g_ptr_array_add (names, g_strdup (key));
	}
	g_ptr_array_add (names, NULL);

	return (char **) g_ptr_array_free (names, FALSE);
}

/**
 * nm_ip_route_get_attribute:
 * @route: the #NMIPRoute
 * @name: the name of an route attribute
 *
 * Gets the value of the attribute with name @name on @route
 *
 * Returns: (transfer none): the value of the attribute with name @name on
 *   @route, or %NULL if @route has no such attribute.
 **/
GVariant *
nm_ip_route_get_attribute (NMIPRoute *route, const char *name)
{
	g_return_val_if_fail (route != NULL, NULL);
	g_return_val_if_fail (name != NULL && *name != '\0', NULL);

	if (route->attributes)
		return g_hash_table_lookup (route->attributes, name);
	else
		return NULL;
}

/**
 * nm_ip_route_set_attribute:
 * @route: the #NMIPRoute
 * @name: the name of a route attribute
 * @value: (transfer none) (allow-none): the value
 *
 * Sets the named attribute on @route to the given value.
 **/
void
nm_ip_route_set_attribute (NMIPRoute *route, const char *name, GVariant *value)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (name != NULL && *name != '\0');

	if (!route->attributes) {
		route->attributes = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                           g_free, (GDestroyNotify) g_variant_unref);
	}

	if (value)
		g_hash_table_insert (route->attributes, g_strdup (name), g_variant_ref_sink (value));
	else
		g_hash_table_remove (route->attributes, name);
}
