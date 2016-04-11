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

#include "nm-default.h"

#include <string.h>
#include <arpa/inet.h>

#include "nm-setting-ip-config.h"
#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"
#include "nm-utils.h"
#include "nm-setting-private.h"
#include "nm-utils-private.h"

/**
 * SECTION:nm-setting-ip-config
 * @short_description: Abstract base class for IPv4 and IPv6
 *   addressing, routing, and name service properties
 * @include: nm-setting-ip-config.h
 * @see_also: #NMSettingIP4Config, #NMSettingIP6Config
 *
 * #NMSettingIPConfig is the abstract base class of
 * #NMSettingIP4Config and #NMSettingIP6Config, providing properties
 * related to IP addressing, routing, and Domain Name Service.
 **/

const NMUtilsDNSOptionDesc _nm_utils_dns_option_descs[] = {
	{ NM_SETTING_DNS_OPTION_DEBUG,                 FALSE,   FALSE },
	{ NM_SETTING_DNS_OPTION_NDOTS,                 TRUE,    FALSE },
	{ NM_SETTING_DNS_OPTION_TIMEOUT,               TRUE,    FALSE },
	{ NM_SETTING_DNS_OPTION_ATTEMPTS,              TRUE,    FALSE },
	{ NM_SETTING_DNS_OPTION_ROTATE,                FALSE,   FALSE },
	{ NM_SETTING_DNS_OPTION_NO_CHECK_NAMES,        FALSE,   FALSE },
	{ NM_SETTING_DNS_OPTION_INET6,                 FALSE,   TRUE },
	{ NM_SETTING_DNS_OPTION_IP6_BYTESTRING,        FALSE,   TRUE },
	{ NM_SETTING_DNS_OPTION_IP6_DOTINT,            FALSE,   TRUE },
	{ NM_SETTING_DNS_OPTION_NO_IP6_DOTINT,         FALSE,   TRUE },
	{ NM_SETTING_DNS_OPTION_EDNS0,                 FALSE,   FALSE },
	{ NM_SETTING_DNS_OPTION_SINGLE_REQUEST,        FALSE,   FALSE },
	{ NM_SETTING_DNS_OPTION_SINGLE_REQUEST_REOPEN, FALSE,   FALSE },
	{ NM_SETTING_DNS_OPTION_NO_TLD_QUERY,          FALSE,   FALSE },
	{ NM_SETTING_DNS_OPTION_USE_VC,                FALSE,   FALSE },
	{ NULL,                                        FALSE,   FALSE }
};

static int
_addr_size (int family)
{
	switch (family) {
	case AF_INET:
		return sizeof (in_addr_t);
	case AF_INET6:
		return sizeof (struct in6_addr);
	default:
		g_return_val_if_reached (0);
	}
}

static char *
canonicalize_ip (int family, const char *ip, gboolean null_any)
{
	guint8 addr_bytes[sizeof (struct in6_addr)];
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];
	int ret;

	if (!ip) {
		if (null_any)
			return NULL;
		if (family == AF_INET)
			return g_strdup ("0.0.0.0");
		if (family == AF_INET6)
			return g_strdup ("::");
		g_return_val_if_reached (NULL);
	}

	ret = inet_pton (family, ip, addr_bytes);
	g_return_val_if_fail (ret == 1, NULL);

	if (null_any) {
		if (!memcmp (addr_bytes, &in6addr_any, _addr_size (family)))
			return NULL;
	}

	return g_strdup (inet_ntop (family, addr_bytes, addr_str, sizeof (addr_str)));
}

static char *
canonicalize_ip_binary (int family, gconstpointer ip, gboolean null_any)
{
	char string[NM_UTILS_INET_ADDRSTRLEN];

	if (!ip) {
		if (null_any)
			return NULL;
		if (family == AF_INET)
			return g_strdup ("0.0.0.0");
		if (family == AF_INET6)
			return g_strdup ("::");
		g_return_val_if_reached (NULL);
	}
	if (null_any) {
		if (!memcmp (ip, &in6addr_any, _addr_size (family)))
			return NULL;
	}
	return g_strdup (inet_ntop (family, ip, string, sizeof (string)));
}

static gboolean
valid_ip (int family, const char *ip, GError **error)
{
	if (!ip) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             family == AF_INET ? _("Missing IPv4 address") : _("Missing IPv6 address"));
		return FALSE;
	}
	if (!nm_utils_ipaddr_valid (family, ip)) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             family == AF_INET ? _("Invalid IPv4 address '%s'") : _("Invalid IPv6 address '%s'"),
		             ip);
		return FALSE;
	} else
		return TRUE;
}

static gboolean
valid_prefix (int family, guint prefix, GError **error)
{
	if (   (family == AF_INET  && prefix <= 32)
	    || (family == AF_INET6 && prefix <= 128))
		return TRUE;

	g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
	             family == AF_INET ? _("Invalid IPv4 address prefix '%u'") : _("Invalid IPv6 address prefix '%u'"),
	             prefix);
	return FALSE;
}

static gboolean
valid_metric (gint64 metric, GError **error)
{
	if (metric < -1 || metric > G_MAXUINT32) {
		if (error) {
			char buf[64];

			/* We can't concatenate G_GINT64_FORMAT into a translatable string */
			g_snprintf (buf, sizeof (buf), "%" G_GINT64_FORMAT, metric);
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
			             _("Invalid routing metric '%s'"), buf);
		}
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************
 * NMIPAddress
 *****************************************************************************/

G_DEFINE_BOXED_TYPE (NMIPAddress, nm_ip_address, nm_ip_address_dup, nm_ip_address_unref)

struct NMIPAddress {
	guint refcount;

	char *address;
	int prefix, family;

	GHashTable *attributes;
};

/**
 * nm_ip_address_new:
 * @family: the IP address family (<literal>AF_INET</literal> or
 *   <literal>AF_INET6</literal>)
 * @addr: the IP address
 * @prefix: the address prefix length
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMIPAddress object.
 *
 * Returns: (transfer full): the new #NMIPAddress object, or %NULL on error
 **/
NMIPAddress *
nm_ip_address_new (int family,
                   const char *addr, guint prefix,
                   GError **error)
{
	NMIPAddress *address;

	g_return_val_if_fail (family == AF_INET || family == AF_INET6, NULL);
	g_return_val_if_fail (addr != NULL, NULL);

	if (!valid_ip (family, addr, error))
		return NULL;
	if (!valid_prefix (family, prefix, error))
		return NULL;

	address = g_slice_new0 (NMIPAddress);
	address->refcount = 1;

	address->family = family;
	address->address = canonicalize_ip (family, addr, FALSE);
	address->prefix = prefix;

	return address;
}

/**
 * nm_ip_address_new_binary:
 * @family: the IP address family (<literal>AF_INET</literal> or
 *   <literal>AF_INET6</literal>)
 * @addr: the IP address
 * @prefix: the address prefix length
 * @error: location to store error, or %NULL
 *
 * Creates a new #NMIPAddress object. @addr must point to a buffer of the
 * correct size for @family.
 *
 * Returns: (transfer full): the new #NMIPAddress object, or %NULL on error
 **/
NMIPAddress *
nm_ip_address_new_binary (int family,
                          gconstpointer addr, guint prefix,
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
 * Determines if two #NMIPAddress objects contain the same address and prefix
 * (attributes are not compared).
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
	    || strcmp (address->address, other->address) != 0)
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
	                          address->address, address->prefix,
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
	g_return_if_fail (strcmp (name, "address") != 0 && strcmp (name, "prefix") != 0);

	if (!address->attributes) {
		address->attributes = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                             g_free, (GDestroyNotify) g_variant_unref);
	}

	if (value)
		g_hash_table_insert (address->attributes, g_strdup (name), g_variant_ref_sink (value));
	else
		g_hash_table_remove (address->attributes, name);
}

/*****************************************************************************
 * NMIPRoute
 *****************************************************************************/

G_DEFINE_BOXED_TYPE (NMIPRoute, nm_ip_route, nm_ip_route_dup, nm_ip_route_unref)

struct NMIPRoute {
	guint refcount;

	int family;
	char *dest;
	guint prefix;
	char *next_hop;
	gint64 metric;

	GHashTable *attributes;
};

/**
 * nm_ip_route_new:
 * @family: the IP address family (<literal>AF_INET</literal> or
 *   <literal>AF_INET6</literal>)
 * @dest: the IP address of the route's destination
 * @prefix: the address prefix length
 * @next_hop: (allow-none): the IP address of the next hop (or %NULL)
 * @metric: the route metric (or -1 for "default")
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
                 gint64 metric,
                 GError **error)
{
	NMIPRoute *route;

	g_return_val_if_fail (family == AF_INET || family == AF_INET6, NULL);
	g_return_val_if_fail (dest, NULL);

	if (!valid_ip (family, dest, error))
		return NULL;
	if (!valid_prefix (family, prefix, error))
		return NULL;
	if (next_hop && !valid_ip (family, next_hop, error))
		return NULL;
	if (!valid_metric (metric, error))
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
 * @family: the IP address family (<literal>AF_INET</literal> or
 *   <literal>AF_INET6</literal>)
 * @dest: the IP address of the route's destination
 * @prefix: the address prefix length
 * @next_hop: (allow-none): the IP address of the next hop (or %NULL)
 * @metric: the route metric (or -1 for "default")
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
                        gint64 metric,
                        GError **error)
{
	NMIPRoute *route;

	g_return_val_if_fail (family == AF_INET || family == AF_INET6, NULL);
	g_return_val_if_fail (dest, NULL);

	if (!valid_prefix (family, prefix, error))
		return NULL;
	if (!valid_metric (metric, error))
		return NULL;

	route = g_slice_new0 (NMIPRoute);
	route->refcount = 1;

	route->family = family;
	route->dest = canonicalize_ip_binary (family, dest, FALSE);
	route->prefix = prefix;
	route->next_hop = canonicalize_ip_binary (family, next_hop, TRUE);
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
		memset (next_hop, 0, _addr_size (route->family));
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
	g_return_if_fail (route != NULL);

	g_free (route->next_hop);
	route->next_hop = canonicalize_ip_binary (route->family, next_hop, TRUE);
}

/**
 * nm_ip_route_get_metric:
 * @route: the #NMIPRoute
 *
 * Gets the route metric property of this route object; lower values
 * indicate "better" or more preferred routes; -1 indicates "default"
 * (meaning NetworkManager will set it appropriately).
 *
 * Returns: the route metric
 **/
gint64
nm_ip_route_get_metric (NMIPRoute *route)
{
	g_return_val_if_fail (route != NULL, 0);
	g_return_val_if_fail (route->refcount > 0, 0);

	return route->metric;
}

/**
 * nm_ip_route_set_metric:
 * @route: the #NMIPRoute
 * @metric: the route metric (or -1 for "default")
 *
 * Sets the metric property of this route object.
 **/
void
nm_ip_route_set_metric (NMIPRoute *route,
                        gint64 metric)
{
	g_return_if_fail (route != NULL);
	g_return_if_fail (valid_metric (metric, NULL));

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
	g_return_if_fail (   strcmp (name, "dest") != 0 && strcmp (name, "prefix") != 0
	                  && strcmp (name, "next-hop") != 0 && strcmp (name, "metric") != 0);

	if (!route->attributes) {
		route->attributes = g_hash_table_new_full (g_str_hash, g_str_equal,
		                                           g_free, (GDestroyNotify) g_variant_unref);
	}

	if (value)
		g_hash_table_insert (route->attributes, g_strdup (name), g_variant_ref_sink (value));
	else
		g_hash_table_remove (route->attributes, name);
}

/*****************************************************************************/

G_DEFINE_ABSTRACT_TYPE (NMSettingIPConfig, nm_setting_ip_config, NM_TYPE_SETTING)

#define NM_SETTING_IP_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP_CONFIG, NMSettingIPConfigPrivate))

typedef struct {
	char *method;
	GPtrArray *dns;        /* array of IP address strings */
	GPtrArray *dns_search; /* array of domain name strings */
	GPtrArray *dns_options;/* array of DNS options */
	GPtrArray *addresses;  /* array of NMIPAddress */
	GPtrArray *routes;     /* array of NMIPRoute */
	gint64 route_metric;
	char *gateway;
	gboolean ignore_auto_routes;
	gboolean ignore_auto_dns;
	char *dhcp_hostname;
	gboolean dhcp_send_hostname;
	gboolean never_default;
	gboolean may_fail;
	gint dad_timeout;
	gint dhcp_timeout;
} NMSettingIPConfigPrivate;

enum {
	PROP_0,
	PROP_METHOD,
	PROP_DNS,
	PROP_DNS_SEARCH,
	PROP_DNS_OPTIONS,
	PROP_ADDRESSES,
	PROP_GATEWAY,
	PROP_ROUTES,
	PROP_ROUTE_METRIC,
	PROP_IGNORE_AUTO_ROUTES,
	PROP_IGNORE_AUTO_DNS,
	PROP_DHCP_HOSTNAME,
	PROP_DHCP_SEND_HOSTNAME,
	PROP_NEVER_DEFAULT,
	PROP_MAY_FAIL,
	PROP_DAD_TIMEOUT,
	PROP_DHCP_TIMEOUT,

	LAST_PROP
};

#define NM_SETTING_IP_CONFIG_GET_FAMILY(setting) (NM_IS_SETTING_IP4_CONFIG (setting) ? AF_INET : AF_INET6)

/**
 * nm_setting_ip_config_get_method:
 * @setting: the #NMSettingIPConfig
 *
 * Returns: the #NMSettingIPConfig:method property of the setting; see
 * #NMSettingIP4Config and #NMSettingIP6Config for details of the
 * methods available with each type.
 **/
const char *
nm_setting_ip_config_get_method (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), NULL);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->method;
}

/**
 * nm_setting_ip_config_get_num_dns:
 * @setting: the #NMSettingIPConfig
 *
 * Returns: the number of configured DNS servers
 **/
guint
nm_setting_ip_config_get_num_dns (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), 0);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->dns->len;
}

/**
 * nm_setting_ip_config_get_dns:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the DNS server to return
 *
 * Returns: the IP address of the DNS server at index @idx
 **/
const char *
nm_setting_ip_config_get_dns (NMSettingIPConfig *setting, int idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), NULL);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (idx < priv->dns->len, NULL);

	return priv->dns->pdata[idx];
}

/**
 * nm_setting_ip_config_add_dns:
 * @setting: the #NMSettingIPConfig
 * @dns: the IP address of the DNS server to add
 *
 * Adds a new DNS server to the setting.
 *
 * Returns: %TRUE if the DNS server was added; %FALSE if the server was already
 * known
 **/
gboolean
nm_setting_ip_config_add_dns (NMSettingIPConfig *setting, const char *dns)
{
	NMSettingIPConfigPrivate *priv;
	char *dns_canonical;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns != NULL, FALSE);
	g_return_val_if_fail (nm_utils_ipaddr_valid (NM_SETTING_IP_CONFIG_GET_FAMILY (setting), dns), FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	dns_canonical = canonicalize_ip (NM_SETTING_IP_CONFIG_GET_FAMILY (setting), dns, FALSE);
	for (i = 0; i < priv->dns->len; i++) {
		if (!strcmp (dns_canonical, priv->dns->pdata[i])) {
			g_free (dns_canonical);
			return FALSE;
		}
	}

	g_ptr_array_add (priv->dns, dns_canonical);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS);
	return TRUE;
}

/**
 * nm_setting_ip_config_remove_dns:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the DNS server to remove
 *
 * Removes the DNS server at index @idx.
 **/
void
nm_setting_ip_config_remove_dns (NMSettingIPConfig *setting, int idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_return_if_fail (idx < priv->dns->len);

	g_ptr_array_remove_index (priv->dns, idx);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS);
}

/**
 * nm_setting_ip_config_remove_dns_by_value:
 * @setting: the #NMSettingIPConfig
 * @dns: the DNS server to remove
 *
 * Removes the DNS server @dns.
 *
 * Returns: %TRUE if the DNS server was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip_config_remove_dns_by_value (NMSettingIPConfig *setting, const char *dns)
{
	NMSettingIPConfigPrivate *priv;
	char *dns_canonical;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns != NULL, FALSE);
	g_return_val_if_fail (nm_utils_ipaddr_valid (NM_SETTING_IP_CONFIG_GET_FAMILY (setting), dns), FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	dns_canonical = canonicalize_ip (NM_SETTING_IP_CONFIG_GET_FAMILY (setting), dns, FALSE);
	for (i = 0; i < priv->dns->len; i++) {
		if (!strcmp (dns_canonical, priv->dns->pdata[i])) {
			g_ptr_array_remove_index (priv->dns, i);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS);
			g_free (dns_canonical);
			return TRUE;
		}
	}
	g_free (dns_canonical);
	return FALSE;
}

/**
 * nm_setting_ip_config_clear_dns:
 * @setting: the #NMSettingIPConfig
 *
 * Removes all configured DNS servers.
 **/
void
nm_setting_ip_config_clear_dns (NMSettingIPConfig *setting)
{
	NMSettingIPConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_ptr_array_set_size (priv->dns, 0);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS);
}

/**
 * nm_setting_ip_config_get_num_dns_searches:
 * @setting: the #NMSettingIPConfig
 *
 * Returns: the number of configured DNS search domains
 **/
guint
nm_setting_ip_config_get_num_dns_searches (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), 0);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->dns_search->len;
}

/**
 * nm_setting_ip_config_get_dns_search:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the DNS search domain to return
 *
 * Returns: the DNS search domain at index @idx
 **/
const char *
nm_setting_ip_config_get_dns_search (NMSettingIPConfig *setting, int idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), NULL);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (idx < priv->dns_search->len, NULL);

	return priv->dns_search->pdata[idx];
}

/**
 * nm_setting_ip_config_add_dns_search:
 * @setting: the #NMSettingIPConfig
 * @dns_search: the search domain to add
 *
 * Adds a new DNS search domain to the setting.
 *
 * Returns: %TRUE if the DNS search domain was added; %FALSE if the search
 * domain was already known
 **/
gboolean
nm_setting_ip_config_add_dns_search (NMSettingIPConfig *setting,
                                     const char *dns_search)
{
	NMSettingIPConfigPrivate *priv;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_search != NULL, FALSE);
	g_return_val_if_fail (dns_search[0] != '\0', FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->dns_search->len; i++) {
		if (!strcmp (dns_search, priv->dns_search->pdata[i]))
			return FALSE;
	}

	g_ptr_array_add (priv->dns_search, g_strdup (dns_search));
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS_SEARCH);
	return TRUE;
}

/**
 * nm_setting_ip_config_remove_dns_search:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the DNS search domain
 *
 * Removes the DNS search domain at index @idx.
 **/
void
nm_setting_ip_config_remove_dns_search (NMSettingIPConfig *setting, int idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_return_if_fail (idx < priv->dns_search->len);

	g_ptr_array_remove_index (priv->dns_search, idx);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS_SEARCH);
}

/**
 * nm_setting_ip_config_remove_dns_search_by_value:
 * @setting: the #NMSettingIPConfig
 * @dns_search: the search domain to remove
 *
 * Removes the DNS search domain @dns_search.
 *
 * Returns: %TRUE if the DNS search domain was found and removed; %FALSE if it was not.
 *
 * Since 0.9.10
 **/
gboolean
nm_setting_ip_config_remove_dns_search_by_value (NMSettingIPConfig *setting,
                                                 const char *dns_search)
{
	NMSettingIPConfigPrivate *priv;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_search != NULL, FALSE);
	g_return_val_if_fail (dns_search[0] != '\0', FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->dns_search->len; i++) {
		if (!strcmp (dns_search, priv->dns_search->pdata[i])) {
			g_ptr_array_remove_index (priv->dns_search, i);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS_SEARCH);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_ip_config_clear_dns_searches:
 * @setting: the #NMSettingIPConfig
 *
 * Removes all configured DNS search domains.
 **/
void
nm_setting_ip_config_clear_dns_searches (NMSettingIPConfig *setting)
{
	NMSettingIPConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_ptr_array_set_size (priv->dns_search, 0);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS_SEARCH);
}

/**
 * nm_setting_ip_config_get_num_dns_options:
 * @setting: the #NMSettingIPConfig
 *
 * Returns: the number of configured DNS options
 *
 * Since: 1.2
 **/
guint
nm_setting_ip_config_get_num_dns_options (NMSettingIPConfig *setting)
{
	NMSettingIPConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), 0);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	return priv->dns_options ? priv->dns_options->len : 0;
}

/**
 * nm_setting_ip_config_has_dns_options:
 * @setting: the #NMSettingIPConfig
 *
 * NMSettingIPConfig can have a list of dns-options. If the list
 * is empty, there are two similar (but differentiated) states.
 * Either the options are explicitly set to have no values,
 * or the options are left undefined. The latter means to use
 * a default configuration, while the former explicitly means "no-options".
 *
 * Returns: whether DNS options are initalized or left unset (the default).
 **/
gboolean
nm_setting_ip_config_has_dns_options (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), 0);

	return !!NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->dns_options;
}

/**
 * nm_setting_ip_config_get_dns_option:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the DNS option
 *
 * Returns: the DNS option at index @idx
 *
 * Since: 1.2
 **/
const char *
nm_setting_ip_config_get_dns_option (NMSettingIPConfig *setting, guint idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), NULL);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (priv->dns_options, NULL);
	g_return_val_if_fail (idx < priv->dns_options->len, NULL);

	return priv->dns_options->pdata[idx];
}

/**
 * nm_setting_ip_config_next_valid_dns_option:
 * @setting: the #NMSettingIPConfig
 * @idx: index to start the search from
 *
 * Returns: the index, greater or equal than @idx, of the first valid
 * DNS option, or -1 if no valid option is found
 *
 * Since: 1.2
 **/
gint
nm_setting_ip_config_next_valid_dns_option (NMSettingIPConfig *setting, guint idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), -1);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	if (!priv->dns_options)
		return -1;

	for (; idx < priv->dns_options->len; idx++) {
		if (_nm_utils_dns_option_validate (priv->dns_options->pdata[idx], NULL, NULL,
		                                   NM_IS_SETTING_IP6_CONFIG (setting),
		                                   _nm_utils_dns_option_descs))
			return idx;
	}

	return -1;
}

/**
 * nm_setting_ip_config_add_dns_option:
 * @setting: the #NMSettingIPConfig
 * @dns_option: the DNS option to add
 *
 * Adds a new DNS option to the setting.
 *
 * Returns: %TRUE if the DNS option was added; %FALSE otherwise
 *
 * Since: 1.2
 **/
gboolean
nm_setting_ip_config_add_dns_option (NMSettingIPConfig *setting,
                                     const char *dns_option)
{
	NMSettingIPConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_option != NULL, FALSE);
	g_return_val_if_fail (dns_option[0] != '\0', FALSE);

	if (!_nm_utils_dns_option_validate (dns_option, NULL, NULL, FALSE, NULL))
		return FALSE;

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	if (!priv->dns_options)
		priv->dns_options = g_ptr_array_new_with_free_func (g_free);
	else {
		if (_nm_utils_dns_option_find_idx (priv->dns_options, dns_option) >= 0)
			return FALSE;
	}

	g_ptr_array_add (priv->dns_options, g_strdup (dns_option));
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS_OPTIONS);
	return TRUE;
}

/**
 * nm_setting_ip_config_remove_dns_option:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the DNS option
 *
 * Removes the DNS option at index @idx.
 *
 * Since: 1.2
 **/
void
nm_setting_ip_config_remove_dns_option (NMSettingIPConfig *setting, int idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_return_if_fail (priv->dns_options);
	g_return_if_fail (idx < priv->dns_options->len);

	g_ptr_array_remove_index (priv->dns_options, idx);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS_OPTIONS);
}

/**
 * nm_setting_ip_config_remove_dns_option_by_value:
 * @setting: the #NMSettingIPConfig
 * @dns_option: the DNS option to remove
 *
 * Removes the DNS option @dns_option.
 *
 * Returns: %TRUE if the DNS option was found and removed; %FALSE if it was not.
 *
 * Since: 1.2
 **/
gboolean
nm_setting_ip_config_remove_dns_option_by_value (NMSettingIPConfig *setting,
                                                 const char *dns_option)
{
	NMSettingIPConfigPrivate *priv;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_option != NULL, FALSE);
	g_return_val_if_fail (dns_option[0] != '\0', FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	if (!priv->dns_options)
		return FALSE;

	i = _nm_utils_dns_option_find_idx (priv->dns_options, dns_option);
	if (i >= 0) {
		g_ptr_array_remove_index (priv->dns_options, i);
		g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS_OPTIONS);
		return TRUE;
	}

	return FALSE;
}

/**
 * nm_setting_ip_config_clear_dns_options:
 * @setting: the #NMSettingIPConfig
 * @is_set: the dns-options can be either empty or unset (default).
 *   Specify how to clear the options.
 *
 * Removes all configured DNS options.
 *
 * Since: 1.2
 **/
void
nm_setting_ip_config_clear_dns_options (NMSettingIPConfig *setting, gboolean is_set)
{
	NMSettingIPConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	if (!priv->dns_options) {
		if (!is_set)
			return;
		priv->dns_options = g_ptr_array_new_with_free_func (g_free);
	} else {
		if (!is_set) {
			g_ptr_array_unref (priv->dns_options);
			priv->dns_options = NULL;
		} else {
			if (priv->dns_options->len == 0)
				return;
			g_ptr_array_set_size (priv->dns_options, 0);
		}
	}
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_DNS_OPTIONS);
}

/**
 * nm_setting_ip_config_get_num_addresses:
 * @setting: the #NMSettingIPConfig
 *
 * Returns: the number of configured addresses
 **/
guint
nm_setting_ip_config_get_num_addresses (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), 0);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->addresses->len;
}

/**
 * nm_setting_ip_config_get_address:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the address to return
 *
 * Returns: (transfer none): the address at index @idx
 **/
NMIPAddress *
nm_setting_ip_config_get_address (NMSettingIPConfig *setting, int idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), NULL);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (idx < priv->addresses->len, NULL);

	return priv->addresses->pdata[idx];
}

/**
 * nm_setting_ip_config_add_address:
 * @setting: the #NMSettingIPConfig
 * @address: the new address to add
 *
 * Adds a new IP address and associated information to the setting.  The
 * given address is duplicated internally and is not changed by this function.
 *
 * Returns: %TRUE if the address was added; %FALSE if the address was already
 * known.
 **/
gboolean
nm_setting_ip_config_add_address (NMSettingIPConfig *setting,
                                  NMIPAddress *address)
{
	NMSettingIPConfigPrivate *priv;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);
	g_return_val_if_fail (address->family == NM_SETTING_IP_CONFIG_GET_FAMILY (setting), FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->addresses->len; i++) {
		if (nm_ip_address_equal (priv->addresses->pdata[i], address))
			return FALSE;
	}

	g_ptr_array_add (priv->addresses, nm_ip_address_dup (address));

	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_ADDRESSES);
	return TRUE;
}

/**
 * nm_setting_ip_config_remove_address:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the address to remove
 *
 * Removes the address at index @idx.
 **/
void
nm_setting_ip_config_remove_address (NMSettingIPConfig *setting, int idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_return_if_fail (idx < priv->addresses->len);

	g_ptr_array_remove_index (priv->addresses, idx);

	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_ADDRESSES);
}

/**
 * nm_setting_ip_config_remove_address_by_value:
 * @setting: the #NMSettingIPConfig
 * @address: the IP address to remove
 *
 * Removes the address @address.
 *
 * Returns: %TRUE if the address was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip_config_remove_address_by_value (NMSettingIPConfig *setting,
                                              NMIPAddress *address)
{
	NMSettingIPConfigPrivate *priv;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->addresses->len; i++) {
		if (nm_ip_address_equal (priv->addresses->pdata[i], address)) {
			g_ptr_array_remove_index (priv->addresses, i);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_ADDRESSES);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_ip_config_clear_addresses:
 * @setting: the #NMSettingIPConfig
 *
 * Removes all configured addresses.
 **/
void
nm_setting_ip_config_clear_addresses (NMSettingIPConfig *setting)
{
	NMSettingIPConfigPrivate *priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	g_ptr_array_set_size (priv->addresses, 0);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_ADDRESSES);
}

/**
 * nm_setting_ip_config_get_gateway:
 * @setting: the #NMSettingIPConfig
 *
 * Returns: the IP address of the gateway associated with this configuration, or
 * %NULL.
 **/
const char *
nm_setting_ip_config_get_gateway (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), NULL);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->gateway;
}

/**
 * nm_setting_ip_config_get_num_routes:
 * @setting: the #NMSettingIPConfig
 *
 * Returns: the number of configured routes
 **/
guint
nm_setting_ip_config_get_num_routes (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), 0);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->routes->len;
}

/**
 * nm_setting_ip_config_get_route:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the route to return
 *
 * Returns: (transfer none): the route at index @idx
 **/
NMIPRoute *
nm_setting_ip_config_get_route (NMSettingIPConfig *setting, int idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), NULL);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_return_val_if_fail (idx < priv->routes->len, NULL);

	return priv->routes->pdata[idx];
}

/**
 * nm_setting_ip_config_add_route:
 * @setting: the #NMSettingIPConfig
 * @route: the route to add
 *
 * Adds a new route and associated information to the setting.  The
 * given route is duplicated internally and is not changed by this function.
 *
 * Returns: %TRUE if the route was added; %FALSE if the route was already known.
 **/
gboolean
nm_setting_ip_config_add_route (NMSettingIPConfig *setting,
                                NMIPRoute *route)
{
	NMSettingIPConfigPrivate *priv;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);
	g_return_val_if_fail (route->family == NM_SETTING_IP_CONFIG_GET_FAMILY (setting), FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->routes->len; i++) {
		if (nm_ip_route_equal (priv->routes->pdata[i], route))
			return FALSE;
	}

	g_ptr_array_add (priv->routes, nm_ip_route_dup (route));
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_ROUTES);
	return TRUE;
}

/**
 * nm_setting_ip_config_remove_route:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the route
 *
 * Removes the route at index @idx.
 **/
void
nm_setting_ip_config_remove_route (NMSettingIPConfig *setting, int idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_return_if_fail (idx < priv->routes->len);

	g_ptr_array_remove_index (priv->routes, idx);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_ROUTES);
}

/**
 * nm_setting_ip_config_remove_route_by_value:
 * @setting: the #NMSettingIPConfig
 * @route: the route to remove
 *
 * Removes the route @route.
 *
 * Returns: %TRUE if the route was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip_config_remove_route_by_value (NMSettingIPConfig *setting,
                                             NMIPRoute *route)
{
	NMSettingIPConfigPrivate *priv;
	int i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->routes->len; i++) {
		if (nm_ip_route_equal (priv->routes->pdata[i], route)) {
			g_ptr_array_remove_index (priv->routes, i);
			g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_ROUTES);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_ip_config_clear_routes:
 * @setting: the #NMSettingIPConfig
 *
 * Removes all configured routes.
 **/
void
nm_setting_ip_config_clear_routes (NMSettingIPConfig *setting)
{
	NMSettingIPConfigPrivate *priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	g_ptr_array_set_size (priv->routes, 0);
	g_object_notify (G_OBJECT (setting), NM_SETTING_IP_CONFIG_ROUTES);
}

/**
 * nm_setting_ip_config_get_route_metric:
 * @setting: the #NMSettingIPConfig
 *
 * Returns the value contained in the #NMSettingIPConfig:route-metric
 * property.
 *
 * Returns: the route metric that is used for routes that don't explicitly
 * specify a metric. See #NMSettingIPConfig:route-metric for more details.
 **/
gint64
nm_setting_ip_config_get_route_metric (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), -1);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->route_metric;
}


/**
 * nm_setting_ip_config_get_ignore_auto_routes:
 * @setting: the #NMSettingIPConfig
 *
 * Returns the value contained in the #NMSettingIPConfig:ignore-auto-routes
 * property.
 *
 * Returns: %TRUE if automatically configured (ie via DHCP) routes should be
 * ignored.
 **/
gboolean
nm_setting_ip_config_get_ignore_auto_routes (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->ignore_auto_routes;
}

/**
 * nm_setting_ip_config_get_ignore_auto_dns:
 * @setting: the #NMSettingIPConfig
 *
 * Returns the value contained in the #NMSettingIPConfig:ignore-auto-dns
 * property.
 *
 * Returns: %TRUE if automatically configured (ie via DHCP) DNS information
 * should be ignored.
 **/
gboolean
nm_setting_ip_config_get_ignore_auto_dns (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->ignore_auto_dns;
}

/**
 * nm_setting_ip_config_get_dhcp_hostname:
 * @setting: the #NMSettingIPConfig
 *
 * Returns the value contained in the #NMSettingIPConfig:dhcp-hostname
 * property.
 *
 * Returns: the configured hostname to send to the DHCP server
 **/
const char *
nm_setting_ip_config_get_dhcp_hostname (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), NULL);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->dhcp_hostname;
}

/**
 * nm_setting_ip_config_get_dhcp_send_hostname:
 * @setting: the #NMSettingIPConfig
 *
 * Returns the value contained in the #NMSettingIPConfig:dhcp-send-hostname
 * property.
 *
 * Returns: %TRUE if NetworkManager should send the machine hostname to the
 * DHCP server when requesting addresses to allow the server to automatically
 * update DNS information for this machine.
 **/
gboolean
nm_setting_ip_config_get_dhcp_send_hostname (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->dhcp_send_hostname;
}

/**
 * nm_setting_ip_config_get_never_default:
 * @setting: the #NMSettingIPConfig
 *
 * Returns the value contained in the #NMSettingIPConfig:never-default
 * property.
 *
 * Returns: %TRUE if this connection should never be the default
 *   connection
 **/
gboolean
nm_setting_ip_config_get_never_default (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->never_default;
}

/**
 * nm_setting_ip_config_get_may_fail:
 * @setting: the #NMSettingIPConfig
 *
 * Returns the value contained in the #NMSettingIPConfig:may-fail
 * property.
 *
 * Returns: %TRUE if this connection doesn't require this type of IP
 * addressing to complete for the connection to succeed.
 **/
gboolean
nm_setting_ip_config_get_may_fail (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->may_fail;
}

/**
 * nm_setting_ip_config_get_dad_timeout:
 * @setting: the #NMSettingIPConfig
 *
 * Returns: the #NMSettingIPConfig:dad-timeout property.
 *
 * Since: 1.2
 **/
gint
nm_setting_ip_config_get_dad_timeout (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), 0);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->dad_timeout;
}

/**
 * nm_setting_ip_config_get_dhcp_timeout:
 * @setting: the #NMSettingIPConfig
 *
 * Returns the value contained in the #NMSettingIPConfig:dhcp-timeout
 * property.
 *
 * Returns: the configured DHCP timeout in seconds. 0 = default for
 * the particular kind of device.
 *
 * Since: 1.2
 **/
gint
nm_setting_ip_config_get_dhcp_timeout (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), 0);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->dhcp_timeout;
}

static gboolean
verify_label (const char *label)
{
	const char *p;
	char *iface;

	p = strchr (label, ':');
	if (!p)
		return FALSE;
	iface = g_strndup (label, p - label);
	if (!nm_utils_iface_valid_name (iface)) {
		g_free (iface);
		return FALSE;
	}
	g_free (iface);

	for (p++; *p; p++) {
		if (!g_ascii_isalnum (*p) && *p != '_')
			return FALSE;
	}

	return TRUE;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingIPConfigPrivate *priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	int i;

	if (!priv->method) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_METHOD);
		return FALSE;
	}

	if (priv->dhcp_hostname && !*priv->dhcp_hostname) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_DHCP_HOSTNAME);
		return FALSE;
	}

	/* Validate DNS */
	for (i = 0; i < priv->dns->len; i++) {
		const char *dns = priv->dns->pdata[i];

		if (!nm_utils_ipaddr_valid (NM_SETTING_IP_CONFIG_GET_FAMILY (setting), dns)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("%d. DNS server address is invalid"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_DNS);
			return FALSE;
		}
	}

	/* Validate addresses */
	for (i = 0; i < priv->addresses->len; i++) {
		NMIPAddress *addr = (NMIPAddress *) priv->addresses->pdata[i];
		GVariant *label;

		if (nm_ip_address_get_family (addr) != NM_SETTING_IP_CONFIG_GET_FAMILY (setting)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("%d. IP address is invalid"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_ADDRESSES);
			return FALSE;
		}

		label = nm_ip_address_get_attribute (addr, "label");
		if (label) {
			if (!g_variant_is_of_type (label, G_VARIANT_TYPE_STRING)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("%d. IP address has 'label' property with invalid type"),
				             i+1);
				g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_ADDRESSES);
				return FALSE;
			}
			if (!verify_label (g_variant_get_string (label, NULL))) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("%d. IP address has invalid label '%s'"),
				             i+1, g_variant_get_string (label, NULL));
				g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_ADDRESSES);
				return FALSE;
			}
		}
	}

	/* Validate gateway */
	if (priv->gateway) {
		if (!priv->addresses->len) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("gateway cannot be set if there are no addresses configured"));
			g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_GATEWAY);
			return FALSE;
		}

		if (!nm_utils_ipaddr_valid (NM_SETTING_IP_CONFIG_GET_FAMILY (setting), priv->gateway)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("gateway is invalid"));
			g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_GATEWAY);
			return FALSE;
		}
	}

	/* Validate routes */
	for (i = 0; i < priv->routes->len; i++) {
		NMIPRoute *route = (NMIPRoute *) priv->routes->pdata[i];

		if (nm_ip_route_get_family (route) != NM_SETTING_IP_CONFIG_GET_FAMILY (setting)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("%d. route is invalid"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_ROUTES);
			return FALSE;
		}
		if (nm_ip_route_get_prefix (route) == 0) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("%d. route cannot be a default route"),
			             i+1);
			g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_ROUTES);
			return FALSE;
		}
	}

	return TRUE;
}


static void
nm_setting_ip_config_init (NMSettingIPConfig *setting)
{
	NMSettingIPConfigPrivate *priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	priv->dns = g_ptr_array_new_with_free_func (g_free);
	priv->dns_search = g_ptr_array_new_with_free_func (g_free);
	priv->dns_options = NULL;
	priv->addresses = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_address_unref);
	priv->routes = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_route_unref);
}

static void
finalize (GObject *object)
{
	NMSettingIPConfig *self = NM_SETTING_IP_CONFIG (object);
	NMSettingIPConfigPrivate *priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (self);

	g_free (priv->method);
	g_free (priv->gateway);
	g_free (priv->dhcp_hostname);

	g_ptr_array_unref (priv->dns);
	g_ptr_array_unref (priv->dns_search);
	if (priv->dns_options)
		g_ptr_array_unref (priv->dns_options);
	g_ptr_array_unref (priv->addresses);
	g_ptr_array_unref (priv->routes);

	G_OBJECT_CLASS (nm_setting_ip_config_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingIPConfig *setting = NM_SETTING_IP_CONFIG (object);
	NMSettingIPConfigPrivate *priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	const char *gateway;
	char **strv;
	int i;

	switch (prop_id) {
	case PROP_METHOD:
		g_free (priv->method);
		priv->method = g_value_dup_string (value);
		break;
	case PROP_DNS:
		g_ptr_array_unref (priv->dns);
		priv->dns = _nm_utils_strv_to_ptrarray (g_value_get_boxed (value));
		break;
	case PROP_DNS_SEARCH:
		g_ptr_array_unref (priv->dns_search);
		priv->dns_search = _nm_utils_strv_to_ptrarray (g_value_get_boxed (value));
		break;
	case PROP_DNS_OPTIONS:
		strv = g_value_get_boxed (value);
		if (!strv) {
			if (priv->dns_options) {
				g_ptr_array_unref (priv->dns_options);
				priv->dns_options = NULL;
			}
		} else {
			if (priv->dns_options)
				g_ptr_array_set_size (priv->dns_options, 0);
			else
				priv->dns_options = g_ptr_array_new_with_free_func (g_free);
			for (i = 0; strv[i]; i++) {
				if (   _nm_utils_dns_option_validate (strv[i], NULL, NULL, FALSE, NULL)
				    && _nm_utils_dns_option_find_idx (priv->dns_options, strv[i]) < 0)
					g_ptr_array_add (priv->dns_options, g_strdup (strv[i]));
			}
		}
		break;
	case PROP_ADDRESSES:
		g_ptr_array_unref (priv->addresses);
		priv->addresses = _nm_utils_copy_array (g_value_get_boxed (value),
		                                        (NMUtilsCopyFunc) nm_ip_address_dup,
		                                        (GDestroyNotify) nm_ip_address_unref);
		break;
	case PROP_GATEWAY:
		gateway = g_value_get_string (value);
		g_return_if_fail (!gateway || nm_utils_ipaddr_valid (NM_SETTING_IP_CONFIG_GET_FAMILY (setting), gateway));
		g_free (priv->gateway);
		priv->gateway = canonicalize_ip (NM_SETTING_IP_CONFIG_GET_FAMILY (setting), gateway, TRUE);
		break;
	case PROP_ROUTES:
		g_ptr_array_unref (priv->routes);
		priv->routes = _nm_utils_copy_array (g_value_get_boxed (value),
		                                     (NMUtilsCopyFunc) nm_ip_route_dup,
		                                     (GDestroyNotify) nm_ip_route_unref);
		break;
	case PROP_ROUTE_METRIC:
		priv->route_metric = g_value_get_int64 (value);
		break;
	case PROP_IGNORE_AUTO_ROUTES:
		priv->ignore_auto_routes = g_value_get_boolean (value);
		break;
	case PROP_IGNORE_AUTO_DNS:
		priv->ignore_auto_dns = g_value_get_boolean (value);
		break;
	case PROP_DHCP_HOSTNAME:
		g_free (priv->dhcp_hostname);
		priv->dhcp_hostname = g_value_dup_string (value);
		break;
	case PROP_DHCP_SEND_HOSTNAME:
		priv->dhcp_send_hostname = g_value_get_boolean (value);
		break;
	case PROP_NEVER_DEFAULT:
		priv->never_default = g_value_get_boolean (value);
		break;
	case PROP_MAY_FAIL:
		priv->may_fail = g_value_get_boolean (value);
		break;
	case PROP_DAD_TIMEOUT:
		priv->dad_timeout = g_value_get_int (value);
		break;
	case PROP_DHCP_TIMEOUT:
		priv->dhcp_timeout = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingIPConfig *setting = NM_SETTING_IP_CONFIG (object);
	NMSettingIPConfigPrivate *priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_METHOD:
		g_value_set_string (value, nm_setting_ip_config_get_method (setting));
		break;
	case PROP_DNS:
		g_value_take_boxed (value, _nm_utils_ptrarray_to_strv (priv->dns));
		break;
	case PROP_DNS_SEARCH:
		g_value_take_boxed (value, _nm_utils_ptrarray_to_strv (priv->dns_search));
		break;
	case PROP_DNS_OPTIONS:
		g_value_take_boxed (value, priv->dns_options ? _nm_utils_ptrarray_to_strv (priv->dns_options) : NULL);
		break;
	case PROP_ADDRESSES:
		g_value_take_boxed (value, _nm_utils_copy_array (priv->addresses,
		                                                 (NMUtilsCopyFunc) nm_ip_address_dup,
		                                                 (GDestroyNotify) nm_ip_address_unref));
		break;
	case PROP_GATEWAY:
		g_value_set_string (value, nm_setting_ip_config_get_gateway (setting));
		break;
	case PROP_ROUTES:
		g_value_take_boxed (value, _nm_utils_copy_array (priv->routes,
		                                                 (NMUtilsCopyFunc) nm_ip_route_dup,
		                                                 (GDestroyNotify) nm_ip_route_unref));
		break;
	case PROP_ROUTE_METRIC:
		g_value_set_int64 (value, priv->route_metric);
		break;
	case PROP_IGNORE_AUTO_ROUTES:
		g_value_set_boolean (value, nm_setting_ip_config_get_ignore_auto_routes (setting));
		break;
	case PROP_IGNORE_AUTO_DNS:
		g_value_set_boolean (value, nm_setting_ip_config_get_ignore_auto_dns (setting));
		break;
	case PROP_DHCP_HOSTNAME:
		g_value_set_string (value, nm_setting_ip_config_get_dhcp_hostname (setting));
		break;
	case PROP_DHCP_SEND_HOSTNAME:
		g_value_set_boolean (value, nm_setting_ip_config_get_dhcp_send_hostname (setting));
		break;
	case PROP_NEVER_DEFAULT:
		g_value_set_boolean (value, priv->never_default);
		break;
	case PROP_MAY_FAIL:
		g_value_set_boolean (value, priv->may_fail);
		break;
	case PROP_DAD_TIMEOUT:
		g_value_set_int (value, nm_setting_ip_config_get_dad_timeout (setting));
		break;
	case PROP_DHCP_TIMEOUT:
		g_value_set_int (value, nm_setting_ip_config_get_dhcp_timeout (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gboolean
ip_gateway_set (NMSetting  *setting,
                GVariant   *connection_dict,
                const char *property,
                GVariant   *value,
                NMSettingParseFlags parse_flags,
                GError    **error)
{
	/* FIXME: properly handle errors */

	/* Don't set from 'gateway' if we're going to use the gateway in 'addresses' */
	if (_nm_setting_use_legacy_property (setting, connection_dict, "addresses", "gateway"))
		return TRUE;

	g_object_set (setting, property, g_variant_get_string (value, NULL), NULL);
	return TRUE;
}

static void
nm_setting_ip_config_class_init (NMSettingIPConfigClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingIPConfigPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;

	/* Properties */

	/**
	 * NMSettingIPConfig:method:
	 *
	 * IP configuration method.
	 *
	 * #NMSettingIP4Config and #NMSettingIP6Config both support "auto",
	 * "manual", and "link-local". See the subclass-specific documentation for
	 * other values.
	 *
	 * In general, for the "auto" method, properties such as
	 * #NMSettingIPConfig:dns and #NMSettingIPConfig:routes specify information
	 * that is added on to the information returned from automatic
	 * configuration.  The #NMSettingIPConfig:ignore-auto-routes and
	 * #NMSettingIPConfig:ignore-auto-dns properties modify this behavior.
	 *
	 * For methods that imply no upstream network, such as "shared" or
	 * "link-local", these properties must be empty.
	 *
	 * For IPv4 method "shared", the IP subnet can be configured by adding one
	 * manual IPv4 address or otherwise 10.42.x.0/24 is chosen.
	 **/
	g_object_class_install_property
		(object_class, PROP_METHOD,
		 g_param_spec_string (NM_SETTING_IP_CONFIG_METHOD, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:dns:
	 *
	 * Array of IP addresses of DNS servers.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS,
		 g_param_spec_boxed (NM_SETTING_IP_CONFIG_DNS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:dns-search:
	 *
	 * Array of DNS search domains.
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS_SEARCH,
		 g_param_spec_boxed (NM_SETTING_IP_CONFIG_DNS_SEARCH, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:dns-options:
	 *
	 * Array of DNS options.
	 *
	 * %NULL means that the options are unset and left at the default.
	 * In this case NetworkManager will use default options. This is
	 * distinct from an empty list of properties.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_DNS_OPTIONS,
		 g_param_spec_boxed (NM_SETTING_IP_CONFIG_DNS_OPTIONS, "", "",
		                     G_TYPE_STRV,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:addresses:
	 *
	 * Array of IP addresses.
	 *
	 * Element-Type: NMIPAddress
	 **/
	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 g_param_spec_boxed (NM_SETTING_IP_CONFIG_ADDRESSES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     /* "addresses" is a legacy D-Bus property, because the
		                      * "addresses" GObject property normally gets set from
		                      * the "address-data" D-Bus property...
		                      */
		                     NM_SETTING_PARAM_LEGACY |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:gateway:
	 *
	 * The gateway associated with this configuration. This is only meaningful
	 * if #NMSettingIPConfig:addresses is also set.
	 **/
	g_object_class_install_property
		(object_class, PROP_GATEWAY,
		 g_param_spec_string (NM_SETTING_IP_CONFIG_GATEWAY, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	_nm_setting_class_override_property (parent_class,
	                                     NM_SETTING_IP_CONFIG_GATEWAY,
	                                     G_VARIANT_TYPE_STRING,
	                                     NULL,
	                                     ip_gateway_set,
	                                     NULL);

	/**
	 * NMSettingIPConfig:routes:
	 *
	 * Array of IP routes.
	 *
	 * Element-Type: NMIPRoute
	 **/
	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 g_param_spec_boxed (NM_SETTING_IP_CONFIG_ROUTES, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
		                     /* See :addresses above Re: LEGACY */
		                     NM_SETTING_PARAM_LEGACY |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:route-metric:
	 *
	 * The default metric for routes that don't explicitly specify a metric.
	 * The default value -1 means that the metric is choosen automatically
	 * based on the device type.
	 * The metric applies to dynamic routes, manual (static) routes that
	 * don't have an explicit metric setting, address prefix routes, and
	 * the default route.
	 * Note that for IPv6, the kernel accepts zero (0) but coerces it to
	 * 1024 (user default). Hence, setting this property to zero effectively
	 * mean setting it to 1024.
	 * For IPv4, zero is a regular value for the metric.
	 **/
	g_object_class_install_property
	    (object_class, PROP_ROUTE_METRIC,
	     g_param_spec_int64 (NM_SETTING_IP_CONFIG_ROUTE_METRIC, "", "",
	                         -1, G_MAXUINT32, -1,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:ignore-auto-routes:
	 *
	 * When #NMSettingIPConfig:method is set to "auto" and this property to
	 * %TRUE, automatically configured routes are ignored and only routes
	 * specified in the #NMSettingIPConfig:routes property, if any, are used.
	 **/
	g_object_class_install_property
		(object_class, PROP_IGNORE_AUTO_ROUTES,
		 g_param_spec_boolean (NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:ignore-auto-dns:
	 *
	 * When #NMSettingIPConfig:method is set to "auto" and this property to
	 * %TRUE, automatically configured nameservers and search domains are
	 * ignored and only nameservers and search domains specified in the
	 * #NMSettingIPConfig:dns and #NMSettingIPConfig:dns-search properties, if
	 * any, are used.
	 **/
	g_object_class_install_property
		(object_class, PROP_IGNORE_AUTO_DNS,
		 g_param_spec_boolean (NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:dhcp-hostname:
	 *
	 * If the #NMSettingIPConfig:dhcp-send-hostname property is %TRUE, then the
	 * specified name will be sent to the DHCP server when acquiring a lease.
	 * This property and #NMSettingIP4Config:dhcp-fqdn are mutually exclusive and
	 * cannot be set at the same time.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_HOSTNAME,
		 g_param_spec_string (NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:dhcp-send-hostname:
	 *
	 * If %TRUE, a hostname is sent to the DHCP server when acquiring a lease.
	 * Some DHCP servers use this hostname to update DNS databases, essentially
	 * providing a static hostname for the computer.  If the
	 * #NMSettingIPConfig:dhcp-hostname property is %NULL and this property is
	 * %TRUE, the current persistent hostname of the computer is sent.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_SEND_HOSTNAME,
		 g_param_spec_boolean (NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:never-default:
	 *
	 * If %TRUE, this connection will never be the default connection for this
	 * IP type, meaning it will never be assigned the default route by
	 * NetworkManager.
	 **/
	g_object_class_install_property
		(object_class, PROP_NEVER_DEFAULT,
		 g_param_spec_boolean (NM_SETTING_IP_CONFIG_NEVER_DEFAULT, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:may-fail:
	 *
	 * If %TRUE, allow overall network configuration to proceed even if the
	 * configuration specified by this property times out.  Note that at least
	 * one IP configuration must succeed or overall network configuration will
	 * still fail.  For example, in IPv6-only networks, setting this property to
	 * %TRUE on the #NMSettingIP4Config allows the overall network configuration
	 * to succeed if IPv4 configuration fails but IPv6 configuration completes
	 * successfully.
	 **/
	g_object_class_install_property
		(object_class, PROP_MAY_FAIL,
		 g_param_spec_boolean (NM_SETTING_IP_CONFIG_MAY_FAIL, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_CONSTRUCT |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingIPConfig:dad-timeout:
	 *
	 * Timeout in milliseconds used to check for the presence of duplicate IP
	 * addresses on the network.  If an address conflict is detected, the
	 * activation will fail.  A zero value means that no duplicate address
	 * detection is performed, -1 means the default value (either configuration
	 * ipvx.dad-timeout override or 3 seconds).  A value greater than zero is a
	 * timeout in milliseconds.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_DAD_TIMEOUT,
		 g_param_spec_int (NM_SETTING_IP_CONFIG_DAD_TIMEOUT, "", "",
		                    -1, NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX, -1,
		                    G_PARAM_READWRITE |
		                    G_PARAM_CONSTRUCT |
		                    NM_SETTING_PARAM_FUZZY_IGNORE |
		                    G_PARAM_STATIC_STRINGS));
	/**
	 * NMSettingIPConfig:dhcp-timeout:
	 *
	 * A timeout for a DHCP transaction in seconds.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP_TIMEOUT,
		 g_param_spec_int (NM_SETTING_IP_CONFIG_DHCP_TIMEOUT, "", "",
		                   0, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   NM_SETTING_PARAM_FUZZY_IGNORE |
		                   G_PARAM_STATIC_STRINGS));
}
