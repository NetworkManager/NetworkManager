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
 * Copyright 2007 - 2017 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-setting-ip-config.h"

#include <arpa/inet.h>
#include <linux/fib_rules.h>

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

/*****************************************************************************/

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
                   const char *addr,
                   guint prefix,
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
                          gconstpointer addr,
                          guint prefix,
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
 * _nm_ip_address_equal:
 * @address: the #NMIPAddress
 * @other: the #NMIPAddress to compare @address to.
 * @consider_attributes: whether to check for equality of attributes too.
 *
 * Determines if two #NMIPAddress objects are equal.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 **/
static gboolean
_nm_ip_address_equal (NMIPAddress *address, NMIPAddress *other, gboolean consider_attributes)
{
	g_return_val_if_fail (address != NULL, FALSE);
	g_return_val_if_fail (address->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	if (   address->family != other->family
	    || address->prefix != other->prefix
	    || strcmp (address->address, other->address) != 0)
		return FALSE;
	if (consider_attributes) {
		GHashTableIter iter;
		const char *key;
		GVariant *value, *value2;
		guint n;

		n = address->attributes ? g_hash_table_size (address->attributes) : 0;
		if (n != (other->attributes ? g_hash_table_size (other->attributes) : 0))
			return FALSE;
		if (n) {
			g_hash_table_iter_init (&iter, address->attributes);
			while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value)) {
				value2 = g_hash_table_lookup (other->attributes, key);
				if (!value2)
					return FALSE;
				if (!g_variant_equal (value, value2))
					return FALSE;
			}
		}
	}
	return TRUE;
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
	return _nm_ip_address_equal (address, other, FALSE);
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

const char **
_nm_ip_address_get_attribute_names (const NMIPAddress *address, gboolean sorted, guint *out_length)
{
	nm_assert (address);

	return nm_utils_strdict_get_keys (address->attributes, sorted, out_length);
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
	const char **names;

	g_return_val_if_fail (address, NULL);

	names = _nm_ip_address_get_attribute_names (address, TRUE, NULL);
	return nm_utils_strv_make_deep_copied_nonnull (names);
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
		address->attributes = g_hash_table_new_full (nm_str_hash, g_str_equal,
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
 * nm_ip_route_equal_full:
 * @route: the #NMIPRoute
 * @other: the #NMIPRoute to compare @route to.
 * @cmp_flags: tune how to compare attributes. Currently only
 *   NM_IP_ROUTE_EQUAL_CMP_FLAGS_NONE (0) and NM_IP_ROUTE_EQUAL_CMP_FLAGS_WITH_ATTRS (1)
 *   is supported.
 *
 * Determines if two #NMIPRoute objects contain the same destination, prefix,
 * next hop, and metric.
 *
 * Returns: %TRUE if the objects contain the same values, %FALSE if they do not.
 *
 * Since: 1.10
 **/
gboolean
nm_ip_route_equal_full (NMIPRoute *route, NMIPRoute *other, guint cmp_flags)
{
	g_return_val_if_fail (route != NULL, FALSE);
	g_return_val_if_fail (route->refcount > 0, FALSE);

	g_return_val_if_fail (other != NULL, FALSE);
	g_return_val_if_fail (other->refcount > 0, FALSE);

	g_return_val_if_fail (NM_IN_SET (cmp_flags,
	                                 NM_IP_ROUTE_EQUAL_CMP_FLAGS_NONE,
	                                 NM_IP_ROUTE_EQUAL_CMP_FLAGS_WITH_ATTRS), FALSE);

	if (   route->prefix != other->prefix
	    || route->metric != other->metric
	    || strcmp (route->dest, other->dest) != 0
	    || g_strcmp0 (route->next_hop, other->next_hop) != 0)
		return FALSE;
	if (cmp_flags == NM_IP_ROUTE_EQUAL_CMP_FLAGS_WITH_ATTRS) {
		GHashTableIter iter;
		const char *key;
		GVariant *value, *value2;
		guint n;

		n = route->attributes ? g_hash_table_size (route->attributes) : 0;
		if (n != (other->attributes ? g_hash_table_size (other->attributes) : 0))
			return FALSE;
		if (n) {
			g_hash_table_iter_init (&iter, route->attributes);
			while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value)) {
				value2 = g_hash_table_lookup (other->attributes, key);
				if (!value2)
					return FALSE;
				if (!g_variant_equal (value, value2))
					return FALSE;
			}
		}
	}
	return TRUE;
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
	return nm_ip_route_equal_full (route, other, NM_IP_ROUTE_EQUAL_CMP_FLAGS_NONE);
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

GHashTable *
_nm_ip_route_get_attributes (NMIPRoute *route)
{
	nm_assert (route);

	return route->attributes;
}

/**
 * _nm_ip_route_get_attribute_names:
 * @route: the #NMIPRoute
 * @sorted: whether to sort the names. Otherwise, their order is
 *   undefined and unstable.
 * @out_length: (allow-none) (out): the number of elements
 *
 * Gets an array of attribute names defined on @route.
 *
 * Returns: (array length=out_length) (transfer container): a %NULL-terminated array
 *   of attribute names or %NULL if there are no attributes. The order of the returned
 *   names depends on @sorted.
 **/
const char **
_nm_ip_route_get_attribute_names (const NMIPRoute *route, gboolean sorted, guint *out_length)
{
	nm_assert (route);

	return nm_utils_strdict_get_keys (route->attributes, sorted, out_length);
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
	const char **names;

	g_return_val_if_fail (route != NULL, NULL);

	names = _nm_ip_route_get_attribute_names (route, TRUE, NULL);
	return nm_utils_strv_make_deep_copied_nonnull (names);
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
		route->attributes = g_hash_table_new_full (nm_str_hash, g_str_equal,
		                                           g_free, (GDestroyNotify) g_variant_unref);
	}

	if (value)
		g_hash_table_insert (route->attributes, g_strdup (name), g_variant_ref_sink (value));
	else
		g_hash_table_remove (route->attributes, name);
}

#define ATTR_SPEC_PTR(name, type, v4, v6, str_type) \
	&(NMVariantAttributeSpec) { name, type, v4, v6, FALSE, FALSE, str_type }

static const NMVariantAttributeSpec * const ip_route_attribute_spec[] = {
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_TABLE,           G_VARIANT_TYPE_UINT32,   TRUE,  TRUE,  0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_SRC,             G_VARIANT_TYPE_STRING,   TRUE,  TRUE, 'a'),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_FROM,            G_VARIANT_TYPE_STRING,   FALSE, TRUE, 'p'),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_TOS,             G_VARIANT_TYPE_BYTE,     TRUE,  FALSE, 0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_ONLINK,          G_VARIANT_TYPE_BOOLEAN,  TRUE,  TRUE,  0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_WINDOW,          G_VARIANT_TYPE_UINT32,   TRUE,  TRUE,  0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_CWND,            G_VARIANT_TYPE_UINT32,   TRUE,  TRUE,  0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_INITCWND,        G_VARIANT_TYPE_UINT32,   TRUE,  TRUE,  0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_INITRWND,        G_VARIANT_TYPE_UINT32,   TRUE,  TRUE,  0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_MTU,             G_VARIANT_TYPE_UINT32,   TRUE,  TRUE,  0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_WINDOW,     G_VARIANT_TYPE_BOOLEAN,  TRUE,  TRUE,  0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_CWND,       G_VARIANT_TYPE_BOOLEAN,  TRUE,  TRUE,  0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_INITCWND,   G_VARIANT_TYPE_BOOLEAN,  TRUE,  TRUE,  0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_INITRWND,   G_VARIANT_TYPE_BOOLEAN,  TRUE,  TRUE,  0 ),
	ATTR_SPEC_PTR (NM_IP_ROUTE_ATTRIBUTE_LOCK_MTU,        G_VARIANT_TYPE_BOOLEAN,  TRUE,  TRUE,  0 ),
	NULL,
};

/**
 * nm_ip_route_get_variant_attribute_spec:
 *
 * Returns: the specifiers for route attributes
 *
 * Since: 1.8
 */
const NMVariantAttributeSpec *const *
nm_ip_route_get_variant_attribute_spec (void)
{
	return ip_route_attribute_spec;
}

/**
 * nm_ip_route_attribute_validate:
 * @name: the attribute name
 * @value: the attribute value
 * @family: IP address family of the route
 * @known: (out): on return, whether the attribute name is a known one
 * @error: (allow-none): return location for a #GError, or %NULL
 *
 * Validates a route attribute, i.e. checks that the attribute is a known one
 * and the value is of the correct type and well-formed.
 *
 * Returns: %TRUE if the attribute is valid, %FALSE otherwise
 *
 * Since: 1.8
 */
gboolean
nm_ip_route_attribute_validate  (const char *name,
                                 GVariant *value,
                                 int family,
                                 gboolean *known,
                                 GError **error)
{
	const NMVariantAttributeSpec *const *iter;
	const NMVariantAttributeSpec *spec = NULL;

	g_return_val_if_fail (name, FALSE);
	g_return_val_if_fail (value, FALSE);
	g_return_val_if_fail (family == AF_INET || family == AF_INET6, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	for (iter = ip_route_attribute_spec; *iter; iter++) {
		if (nm_streq (name, (*iter)->name)) {
			spec = *iter;
			break;
		}
	}

	if (!spec) {
		NM_SET_OUT (known, FALSE);
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_FAILED,
		                     _("unknown attribute"));
		return FALSE;
	}

	NM_SET_OUT (known, TRUE);

	if (!g_variant_is_of_type (value, spec->type)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_FAILED,
		             _("invalid attribute type '%s'"),
		             g_variant_get_type_string (value));
		return FALSE;
	}

	if (   (family == AF_INET && !spec->v4)
	    || (family == AF_INET6 && !spec->v6)) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_FAILED,
		             family == AF_INET ?
		                 _("attribute is not valid for a IPv4 route") :
		                 _("attribute is not valid for a IPv6 route"));
		return FALSE;
	}

	if (g_variant_type_equal (spec->type, G_VARIANT_TYPE_STRING)) {
		const char *string = g_variant_get_string (value, NULL);
		gs_free char *string_free = NULL;
		char *sep;

		switch (spec->str_type) {
		case 'a': /* IP address */
			if (!nm_utils_ipaddr_valid (family, string)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_FAILED,
				             family == AF_INET ?
				                 _("'%s' is not a valid IPv4 address") :
				                 _("'%s' is not a valid IPv6 address"),
				             string);
				return FALSE;
			}
			break;
		case 'p': /* IP address + optional prefix */
			string_free = g_strdup (string);
			sep = strchr (string_free, '/');
			if (sep) {
				*sep = 0;
				if (_nm_utils_ascii_str_to_int64 (sep + 1, 10, 1, family == AF_INET ? 32 : 128, -1) < 0) {
					g_set_error (error,
					             NM_CONNECTION_ERROR,
					             NM_CONNECTION_ERROR_FAILED,
					             _("invalid prefix %s"), sep + 1);
					return FALSE;
				}
			}
			if (!nm_utils_ipaddr_valid (family, string_free)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_FAILED,
				             family == AF_INET ?
				                 _("'%s' is not a valid IPv4 address") :
				                 _("'%s' is not a valid IPv6 address"),
				             string_free);
				return FALSE;
			}
			break;
		default:
			break;
		}
	}

	return TRUE;
}

gboolean
_nm_ip_route_attribute_validate_all (const NMIPRoute *route)
{
	GHashTableIter iter;
	const char *key;
	GVariant *val;

	g_return_val_if_fail (route, FALSE);

	if (!route->attributes)
		return TRUE;

	g_hash_table_iter_init (&iter, route->attributes);
	while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &val)) {
		if (!nm_ip_route_attribute_validate (key, val, route->family, NULL, NULL))
			return FALSE;
	}
	return TRUE;
}

/*****************************************************************************/

struct NMIPRoutingRule {
	NMIPAddr from_bin;
	NMIPAddr to_bin;
	char *from_str;
	char *to_str;
	char *iifname;
	char *oifname;
	guint ref_count;
	guint32 priority;
	guint32 table;
	guint32 fwmark;
	guint32 fwmask;
	guint16 sport_start;
	guint16 sport_end;
	guint16 dport_start;
	guint16 dport_end;
	guint8 action;
	guint8 from_len;
	guint8 to_len;
	guint8 tos;
	guint8 ipproto;
	bool is_v4:1;
	bool sealed:1;
	bool priority_has:1;
	bool from_has:1;
	bool from_valid:1;
	bool to_has:1;
	bool to_valid:1;
	bool invert:1;
};

static NMIPRoutingRule *_ip_routing_rule_dup (const NMIPRoutingRule *rule);

G_DEFINE_BOXED_TYPE (NMIPRoutingRule, nm_ip_routing_rule, _ip_routing_rule_dup, nm_ip_routing_rule_unref)

static gboolean
NM_IS_IP_ROUTING_RULE (const NMIPRoutingRule *self,
                       gboolean also_sealed)
{
	return    self
	       && self->ref_count > 0
	       && (   also_sealed
	           || !self->sealed);
}

static int
_ip_routing_rule_get_addr_family (const NMIPRoutingRule *self)
{
	nm_assert (NM_IS_IP_ROUTING_RULE (self, TRUE));

	return self->is_v4 ? AF_INET : AF_INET6;
}

static int
_ip_routing_rule_get_addr_size (const NMIPRoutingRule *self)
{
	nm_assert (NM_IS_IP_ROUTING_RULE (self, TRUE));

	return self->is_v4 ? sizeof (struct in_addr) : sizeof (struct in6_addr);
}

static NMIPRoutingRule *
_ip_routing_rule_dup (const NMIPRoutingRule *rule)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (rule, TRUE), NULL);

	if (rule->sealed)
		return nm_ip_routing_rule_ref ((NMIPRoutingRule *) rule);
	return nm_ip_routing_rule_new_clone (rule);
}

/**
 * nm_ip_routing_rule_new:
 * @addr_family: the address family of the routing rule. Must be either
 *   %AF_INET (2) or %AF_INET6 (10).
 *
 * Returns: (transfer full): a newly created rule instance with the
 *   provided address family. The instance is unsealed.
 *
 * Since: 1.18
 */
NMIPRoutingRule *
nm_ip_routing_rule_new (int addr_family)
{
	NMIPRoutingRule *self;

	g_return_val_if_fail (NM_IN_SET (addr_family, AF_INET, AF_INET6), NULL);

	self = g_slice_new (NMIPRoutingRule);
	*self = (NMIPRoutingRule) {
		.ref_count    = 1,
		.is_v4        = (addr_family == AF_INET),
		.action       = FR_ACT_TO_TBL,
		.table        = RT_TABLE_MAIN,
	};
	return self;
}

/**
 * nm_ip_routing_rule_new_clone:
 * @rule: the #NMIPRoutingRule to clone.
 *
 * Returns: (transfer full): a newly created rule instance with
 *   the same settings as @rule. Note that the instance will
 *   always be unsealred.
 *
 * Since: 1.18
 */
NMIPRoutingRule *
nm_ip_routing_rule_new_clone (const NMIPRoutingRule *rule)
{
	NMIPRoutingRule *self;

	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (rule, TRUE), NULL);

	self = g_slice_new (NMIPRoutingRule);
	*self = (NMIPRoutingRule) {
		.ref_count    = 1,
		.sealed       = FALSE,
		.is_v4        = rule->is_v4,

		.priority     = rule->priority,
		.priority_has = rule->priority_has,

		.invert       = rule->invert,

		.tos          = rule->tos,

		.fwmark       = rule->fwmark,
		.fwmask       = rule->fwmask,

		.sport_start  = rule->sport_start,
		.sport_end    = rule->sport_end,
		.dport_start  = rule->dport_start,
		.dport_end    = rule->dport_end,

		.ipproto      = rule->ipproto,

		.from_len     = rule->from_len,
		.from_bin     = rule->from_bin,
		.from_str     =   (   rule->from_has
		                   && !rule->from_valid)
		                ? g_strdup (rule->from_str)
		                : NULL,
		.from_has     = rule->from_has,
		.from_valid   = rule->from_valid,

		.to_len       = rule->to_len,
		.to_bin       = rule->to_bin,
		.to_str       =   (   rule->to_has
		                   && !rule->to_valid)
		                ? g_strdup (rule->to_str)
		                : NULL,
		.to_has       = rule->to_has,
		.to_valid     = rule->to_valid,

		.iifname      = g_strdup (rule->iifname),
		.oifname      = g_strdup (rule->oifname),

		.action       = rule->action,
		.table        = rule->table,
	};
	return self;
}

/**
 * nm_ip_routing_rule_ref:
 * @self: (allow-none): the #NMIPRoutingRule instance
 *
 * Increases the reference count of the instance.
 * This is not thread-safe.
 *
 * Returns: (transfer full): the @self argument with incremented
 *  reference count.
 *
 * Since: 1.18
 */
NMIPRoutingRule *
nm_ip_routing_rule_ref (NMIPRoutingRule *self)
{
	if (!self)
		return NULL;

	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), NULL);

	nm_assert (self->ref_count < G_MAXUINT);
	self->ref_count++;
	return self;
}

/**
 * nm_ip_routing_rule_unref:
 * @self: (allow-none): the #NMIPRoutingRule instance
 *
 * Decreases the reference count of the instance and destroys
 * the instance if the reference count reaches zero.
 * This is not thread-safe.
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_unref (NMIPRoutingRule *self)
{
	if (!self)
		return;

	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE));

	if (--self->ref_count > 0)
		return;

	g_free (self->from_str);
	g_free (self->to_str);
	g_free (self->iifname);
	g_free (self->oifname);

	g_slice_free (NMIPRoutingRule, self);
}

/**
 * nm_ip_routing_rule_is_sealed:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: whether @self is sealed. Once sealed, an instance
 *   cannot be modified nor unsealed.
 *
 * Since: 1.18
 */
gboolean
nm_ip_routing_rule_is_sealed (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), FALSE);

	return self->sealed;
}

/**
 * nm_ip_routing_rule_seal:
 * @self: the #NMIPRoutingRule instance
 *
 * Seals the routing rule. Afterwards, the instance can no longer be
 * modfied, and it is a bug to call any of the accessors that would
 * modify the rule. If @self was already sealed, this has no effect.
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_seal (NMIPRoutingRule *self)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE));

	self->sealed = TRUE;
}

/**
 * nm_ip_routing_rule_get_addr_family:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the address family of the rule. Either %AF_INET or %AF_INET6.
 *
 * Since: 1.18
 */
int
nm_ip_routing_rule_get_addr_family (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), AF_UNSPEC);

	return _ip_routing_rule_get_addr_family (self);
}

/**
 * nm_ip_routing_rule_get_priority:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the priority. A valid priority is in the range from
 *   0 to %G_MAXUINT32. If unset, -1 is returned.
 *
 * Since: 1.18
 */
gint64
nm_ip_routing_rule_get_priority (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), -1);

	return   self->priority_has
	       ? (gint64) self->priority
	       : (gint64) -1;
}

/**
 * nm_ip_routing_rule_set_priority:
 * @self: the #NMIPRoutingRule instance
 * @priority: the priority to set
 *
 * A valid priority ranges from 0 to %G_MAXUINT32. "-1" is also allowed
 * to reset the priority. It is a bug calling this function with any
 * other value.
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_priority (NMIPRoutingRule *self, gint64 priority)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	if (   priority >= 0
	    && priority <= (gint64) G_MAXUINT32) {
		self->priority = (guint32) priority;
		self->priority_has = TRUE;
	} else {
		g_return_if_fail (priority == -1);
		self->priority = 0;
		self->priority_has = FALSE;
	}
}

/**
 * nm_ip_routing_rule_get_invert:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the "invert" setting of the rule.
 *
 * Since: 1.18
 */
gboolean
nm_ip_routing_rule_get_invert (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), FALSE);

	return self->invert;
}

/**
 * nm_ip_routing_rule_set_invert:
 * @self: the #NMIPRoutingRule instance
 * @invert: the new value to set
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_invert (NMIPRoutingRule *self, gboolean invert)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	self->invert = invert;
}

/**
 * nm_ip_routing_rule_get_from_len:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the set prefix length for the from/src parameter.
 *
 * Since: 1.18
 */
guint8
nm_ip_routing_rule_get_from_len (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->from_len;
}

/**
 * nm_ip_routing_rule_get_from:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: (transfer none): the set from/src parameter or
 *   %NULL, if no value is set.
 *
 * Since: 1.18
 */
const char *
nm_ip_routing_rule_get_from (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), NULL);

	if (!self->from_has)
		return NULL;
	if (!self->from_str) {
		nm_assert (self->from_valid);
		((NMIPRoutingRule *) self)->from_str = nm_utils_inet_ntop_dup (_ip_routing_rule_get_addr_family (self),
		                                                               &self->from_bin);
	}
	return self->from_str;
}

const NMIPAddr *
nm_ip_routing_rule_get_from_bin (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), NULL);

	return   (   self->from_has
	          && self->from_valid)
	       ? &self->from_bin
	       : NULL;
}

void
nm_ip_routing_rule_set_from_bin (NMIPRoutingRule *self,
                                 gconstpointer from,
                                 guint8 len)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	nm_clear_g_free (&self->from_str);

	if (!from) {
		self->from_has = FALSE;
		self->from_len = len;
		return;
	}

	self->from_has = TRUE;
	self->from_len = len;
	self->from_valid = TRUE;
	nm_ip_addr_set (_ip_routing_rule_get_addr_family (self),
	                &self->from_bin,
	                from);
}

/**
 * nm_ip_routing_rule_set_from:
 * @self: the #NMIPRoutingRule instance
 * @from: (allow-none): the from/src address to set.
 *   The address family must match.
 * @len: the corresponding prefix length of the address.
 *
 * Setting invalid values is accepted, but will later fail
 * during nm_ip_routing_rule_validate().
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_from (NMIPRoutingRule *self,
                             const char *from,
                             guint8 len)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	if (!from) {
		nm_clear_g_free (&self->from_str);
		self->from_has = FALSE;
		self->from_len = len;
		return;
	}

	nm_clear_g_free (&self->from_str);
	self->from_has = TRUE;
	self->from_len = len;
	self->from_valid = nm_utils_parse_inaddr_bin (_ip_routing_rule_get_addr_family (self),
	                                              from,
	                                              NULL,
	                                              &self->from_bin);
	if (!self->from_valid)
		self->from_str = g_strdup (from);
}

/**
 * nm_ip_routing_rule_get_to_len:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the set prefix length for the to/dst parameter.
 *
 * Since: 1.18
 */
guint8
nm_ip_routing_rule_get_to_len (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->to_len;
}

/**
 * nm_ip_routing_rule_get_to:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: (transfer none): the set to/dst parameter or
 *   %NULL, if no value is set.
 *
 * Since: 1.18
 */
const char *
nm_ip_routing_rule_get_to (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), NULL);

	if (!self->to_has)
		return NULL;
	if (!self->to_str) {
		nm_assert (self->to_valid);
		((NMIPRoutingRule *) self)->to_str = nm_utils_inet_ntop_dup (_ip_routing_rule_get_addr_family (self),
		                                                             &self->to_bin);
	}
	return self->to_str;
}

const NMIPAddr *
nm_ip_routing_rule_get_to_bin (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), NULL);

	return   (   self->to_has
	          && self->to_valid)
	       ? &self->to_bin
	       : NULL;
}

void
nm_ip_routing_rule_set_to_bin (NMIPRoutingRule *self,
                               gconstpointer to,
                               guint8 len)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	nm_clear_g_free (&self->to_str);

	if (!to) {
		self->to_has = FALSE;
		self->to_len = len;
		return;
	}

	self->to_has = TRUE;
	self->to_len = len;
	self->to_valid = TRUE;
	nm_ip_addr_set (_ip_routing_rule_get_addr_family (self),
	                &self->to_bin,
	                to);
}

/**
 * nm_ip_routing_rule_set_to:
 * @self: the #NMIPRoutingRule instance
 * @to: (allow-none): the to/dst address to set.
 *   The address family must match.
 * @len: the corresponding prefix length of the address.
 *   If @to is %NULL, this valid is ignored.
 *
 * Setting invalid values is accepted, but will later fail
 * during nm_ip_routing_rule_validate().
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_to (NMIPRoutingRule *self,
                           const char *to,
                           guint8 len)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	if (!to) {
		nm_clear_g_free (&self->to_str);
		self->to_has = FALSE;
		self->to_len = len;
		return;
	}

	nm_clear_g_free (&self->to_str);
	self->to_has = TRUE;
	self->to_len = len;
	self->to_valid = nm_utils_parse_inaddr_bin (_ip_routing_rule_get_addr_family (self),
	                                            to,
	                                            NULL,
	                                            &self->to_bin);
	if (!self->to_valid)
		self->to_str = g_strdup (to);
}

/**
 * nm_ip_routing_rule_get_tos:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the tos of the rule.
 *
 * Since: 1.18
 */
guint8
nm_ip_routing_rule_get_tos (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->tos;
}

/**
 * nm_ip_routing_rule_set_tos:
 * @self: the #NMIPRoutingRule instance
 * @tos: the tos to set
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_tos (NMIPRoutingRule *self, guint8 tos)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	self->tos = tos;
}

/**
 * nm_ip_routing_rule_get_ipproto:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the ipproto of the rule.
 *
 * Since: 1.18
 */
guint8
nm_ip_routing_rule_get_ipproto (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->ipproto;
}

/**
 * nm_ip_routing_rule_set_ipproto:
 * @self: the #NMIPRoutingRule instance
 * @ipproto: the ipproto to set
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_ipproto (NMIPRoutingRule *self, guint8 ipproto)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	self->ipproto = ipproto;
}

/**
 * nm_ip_routing_rule_get_source_port_start:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the source port start setting.
 *
 * Since: 1.18
 */
guint16
nm_ip_routing_rule_get_source_port_start (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->sport_start;
}

/**
 * nm_ip_routing_rule_get_source_port_end:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the source port end setting.
 *
 * Since: 1.18
 */
guint16
nm_ip_routing_rule_get_source_port_end (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->sport_end;
}

/**
 * nm_ip_routing_rule_set_source_port:
 * @self: the #NMIPRoutingRule instance
 * @start: the start port to set.
 * @end: the end port to set.
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_source_port (NMIPRoutingRule *self, guint16 start, guint16 end)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	self->sport_start = start;
	self->sport_end   = end;
}

/**
 * nm_ip_routing_rule_get_destination_port_start:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the destination port start setting.
 *
 * Since: 1.18
 */
guint16
nm_ip_routing_rule_get_destination_port_start (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->dport_start;
}

/**
 * nm_ip_routing_rule_get_destination_port_end:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the destination port end setting.
 *
 * Since: 1.18
 */
guint16
nm_ip_routing_rule_get_destination_port_end (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->dport_end;
}

/**
 * nm_ip_routing_rule_set_destination_port:
 * @self: the #NMIPRoutingRule instance
 * @start: the start port to set.
 * @end: the end port to set.
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_destination_port (NMIPRoutingRule *self, guint16 start, guint16 end)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	self->dport_start = start;
	self->dport_end   = end;
}

/**
 * nm_ip_routing_rule_get_fwmark:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the fwmark setting.
 *
 * Since: 1.18
 */
guint32
nm_ip_routing_rule_get_fwmark (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->fwmark;
}

/**
 * nm_ip_routing_rule_get_fwmask:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the fwmask setting.
 *
 * Since: 1.18
 */
guint32
nm_ip_routing_rule_get_fwmask (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->fwmask;
}

/**
 * nm_ip_routing_rule_set_fwmark:
 * @self: the #NMIPRoutingRule instance
 * @fwmark: the fwmark
 * @fwmask: the fwmask
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_fwmark (NMIPRoutingRule *self, guint32 fwmark, guint32 fwmask)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	self->fwmark = fwmark;
	self->fwmask = fwmask;
}

/**
 * nm_ip_routing_rule_get_iifname:
 * @self: the #NMIPRoutingRule instance.
 *
 * Returns: (transfer none): the set iifname or %NULL if unset.
 *
 * Since: 1.18
 */
const char *
nm_ip_routing_rule_get_iifname (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), NULL);

	return self->iifname;
}

gboolean
nm_ip_routing_rule_get_xifname_bin (const NMIPRoutingRule *self,
                                    gboolean iif /* or else oif */,
                                    char out_xifname[static 16 /* IFNAMSIZ */])
{
	gs_free gpointer bin_to_free = NULL;
	const char *xifname;
	gconstpointer bin;
	gsize len;

	nm_assert (NM_IS_IP_ROUTING_RULE (self, TRUE));
	nm_assert (out_xifname);

	xifname = iif ? self->iifname : self->oifname;

	if (!xifname)
		return FALSE;

	bin = nm_utils_buf_utf8safe_unescape (xifname, &len, &bin_to_free);

	strncpy (out_xifname, bin, 16 /* IFNAMSIZ */);
	out_xifname[15] = '\0';
	return TRUE;
}

/**
 * nm_ip_routing_rule_set_iifname:
 * @self: the #NMIPRoutingRule instance.
 * @iifname: (allow-none): the iifname to set or %NULL to unset.
 *
 * The name supports C backslash escaping for non-UTF-8 characters.
 * Note that nm_ip_routing_rule_from_string() too uses backslash
 * escaping when tokenizing the words by whitespace. So, in string
 * representation you'd get double backslashs.
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_iifname (NMIPRoutingRule *self, const char *iifname)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	g_free (self->iifname);
	self->iifname = g_strdup (iifname);
}

/**
 * nm_ip_routing_rule_get_oifname:
 * @self: the #NMIPRoutingRule instance.
 *
 * Returns: (transfer none): the set oifname or %NULL if unset.
 *
 * Since: 1.18
 */
const char *
nm_ip_routing_rule_get_oifname (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), NULL);

	return self->oifname;
}

/**
 * nm_ip_routing_rule_set_oifname:
 * @self: the #NMIPRoutingRule instance.
 * @oifname: (allow-none): the oifname to set or %NULL to unset.
 *
 * The name supports C backslash escaping for non-UTF-8 characters.
 * Note that nm_ip_routing_rule_from_string() too uses backslash
 * escaping when tokenizing the words by whitespace. So, in string
 * representation you'd get double backslashs.
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_oifname (NMIPRoutingRule *self, const char *oifname)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	g_free (self->oifname);
	self->oifname = g_strdup (oifname);
}

/**
 * nm_ip_routing_rule_get_action:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the set action.
 *
 * Since: 1.18
 */
guint8
nm_ip_routing_rule_get_action (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->action;
}

/**
 * nm_ip_routing_rule_set_action:
 * @self: the #NMIPRoutingRule instance
 * @action: the action to set
 *
 * Note that currently only certain actions are allowed. nm_ip_routing_rule_validate()
 * will reject unsupported actions as invalid.
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_action (NMIPRoutingRule *self, guint8 action)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	self->action = action;
}

/**
 * nm_ip_routing_rule_get_table:
 * @self: the #NMIPRoutingRule instance
 *
 * Returns: the set table.
 *
 * Since: 1.18
 */
guint32
nm_ip_routing_rule_get_table (const NMIPRoutingRule *self)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), 0);

	return self->table;
}

/**
 * nm_ip_routing_rule_set_table:
 * @self: the #NMIPRoutingRule instance
 * @table: the table to set
 *
 * Since: 1.18
 */
void
nm_ip_routing_rule_set_table (NMIPRoutingRule *self, guint32 table)
{
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (self, FALSE));

	self->table = table;
}

/**
 * nm_ip_routing_rule_cmp:
 * @rule: (allow-none): the #NMIPRoutingRule instance to compare
 * @other: (allow-none): the other #NMIPRoutingRule instance to compare
 *
 * Returns: zero, a positive, or a negative integer to indicate
 *   equality or how the arguments compare.
 *
 * Since: 1.18
 */
int
nm_ip_routing_rule_cmp (const NMIPRoutingRule *rule,
                        const NMIPRoutingRule *other)
{
	NM_CMP_SELF (rule, other);

	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (rule, TRUE), 0);
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (other, TRUE), 0);

	NM_CMP_FIELD_UNSAFE (rule, other, priority_has);
	if (rule->priority_has)
		NM_CMP_FIELD (rule, other, priority);

	NM_CMP_FIELD_UNSAFE (rule, other, is_v4);

	NM_CMP_FIELD_UNSAFE (rule, other, invert);

	NM_CMP_FIELD (rule, other, tos);

	NM_CMP_FIELD (rule, other, fwmark);
	NM_CMP_FIELD (rule, other, fwmask);

	NM_CMP_FIELD (rule, other, action);

	NM_CMP_FIELD (rule, other, table);

	NM_CMP_FIELD (rule, other, sport_start);
	NM_CMP_FIELD (rule, other, sport_end);
	NM_CMP_FIELD (rule, other, dport_start);
	NM_CMP_FIELD (rule, other, dport_end);

	NM_CMP_FIELD (rule, other, ipproto);

	/* We compare the plain strings, not the binary values after utf8safe unescaping.
	 *
	 * The reason is, that the rules differ already when the direct strings differ, not
	 * only when the unescaped names differ. */
	NM_CMP_FIELD_STR0 (rule, other, iifname);
	NM_CMP_FIELD_STR0 (rule, other, oifname);

	NM_CMP_FIELD (rule, other, from_len);

	NM_CMP_FIELD_UNSAFE (rule, other, from_has);
	if (rule->from_has) {
		NM_CMP_FIELD_UNSAFE (rule, other, from_valid);
		if (rule->from_valid) {
			NM_CMP_RETURN (memcmp (&rule->from_bin,
			                       &other->from_bin,
			                       _ip_routing_rule_get_addr_size (rule)));
		} else
			NM_CMP_FIELD_STR (rule, other, from_str);
	}

	NM_CMP_FIELD (rule, other, to_len);

	NM_CMP_FIELD_UNSAFE (rule, other, to_has);
	if (rule->to_has) {
		NM_CMP_FIELD_UNSAFE (rule, other, to_valid);
		if (rule->to_valid) {
			NM_CMP_RETURN (memcmp (&rule->to_bin,
			                       &other->to_bin,
			                       _ip_routing_rule_get_addr_size (rule)));
		} else
			NM_CMP_FIELD_STR (rule, other, to_str);
	}

	return 0;
}

static gboolean
_rr_xport_range_valid (guint16 xport_start, guint16 xport_end)
{
	if (xport_start == 0)
		return (xport_end == 0);

	return    xport_start <= xport_end
	       && xport_end < 0xFFFFu;
}

static gboolean
_rr_xport_range_parse (char *str, gint64 *out_start, guint16 *out_end)
{
	guint16 start, end;
	gint64 i64;
	char *s;

	s = strchr (str, '-');
	if (s)
		*(s++) = '\0';

	i64 = _nm_utils_ascii_str_to_int64 (str, 10, 0, 0xFFFF, -1);
	if (i64 == -1)
		return FALSE;

	start = i64;
	if (s) {
		i64 = _nm_utils_ascii_str_to_int64 (s, 10, 0, 0xFFFF, -1);
		if (i64 == -1)
			return FALSE;
		end = i64;
	} else
		end = start;

	*out_start = start;
	*out_end = end;
	return TRUE;
}

/**
 * nm_ip_routing_rule_validate:
 * @self: the #NMIPRoutingRule instance to validate
 * @error: (allow-none) (out): the error result if validation fails.
 *
 * Returns: %TRUE if the rule validates.
 *
 * Since: 1.18
 */
gboolean
nm_ip_routing_rule_validate (const NMIPRoutingRule *self,
                             GError **error)
{
	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* Kernel may be more flexible about validating. We do a strict validation
	 * here and reject certain settings eagerly. We can always relax it later. */

	if (!self->priority_has) {
		/* iproute2 accepts not specifying the priority, in which case kernel will select
		 * an unused priority. We don't allow for that, and will always require the user to
		 * select a priority.
		 *
		 * Note that if the user selects priority 0 or a non-unique priority, this is problematic
		 * due to kernel bugs rh#1685816 and rh#1685816. It may result in NetworkManager wrongly being
		 * unable to add a rule or deleting the wrong rule.
		 * This problem is not at all specific to the priority, it affects all rules that
		 * have default values which confuse kernel. But setting a unique priority avoids
		 * this problem nicely. */
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("invalid priority"));
		return FALSE;
	}

	if (NM_IN_SET (self->action, FR_ACT_TO_TBL)) {
		if (self->table == 0) {
			/* with IPv4, kernel allows a table (in RTM_NEWRULE) of zero to automatically select
			 * an unused table. We don't. The user needs to specify the table.
			 *
			 * For IPv6, kernel doesn't allow a table of zero, so we are consistent here. */
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("missing table"));
			return FALSE;
		}
	} else {
		/* whitelist the actions that we currently. */
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("invalid action"));
		return FALSE;
	}

	if (self->from_len == 0) {
		if (self->from_has) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("has from/src but the prefix-length is zero"));
			return FALSE;
		}
	} else if (   self->from_len > 0
	           && self->from_len <= 8 * _ip_routing_rule_get_addr_size (self)) {
		if (!self->from_has) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("missing from/src for a non zero prefix-length"));
			return FALSE;
		}
		if (!self->from_valid) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("invalid from/src"));
			return FALSE;
		}
	} else {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("invalid prefix length for from/src"));
		return FALSE;
	}

	if (self->to_len == 0) {
		if (self->to_has) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("has to/dst but the prefix-length is zero"));
			return FALSE;
		}
	} else if (   self->to_len > 0
	           && self->to_len <= 8 * _ip_routing_rule_get_addr_size (self)) {
		if (!self->to_has) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("missing to/dst for a non zero prefix-length"));
			return FALSE;
		}
		if (!self->to_valid) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("invalid to/dst"));
			return FALSE;
		}
	} else {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("invalid prefix length for to/dst"));
		return FALSE;
	}

	if (   self->iifname
	    && (   !g_utf8_validate (self->iifname, -1, NULL)
	        || !nm_utils_is_valid_iface_name_utf8safe (self->iifname))) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("invalid iifname"));
		return FALSE;
	}

	if (   self->oifname
	    && (   !g_utf8_validate (self->oifname, -1, NULL)
	        || !nm_utils_is_valid_iface_name_utf8safe (self->oifname))) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("invalid oifname"));
		return FALSE;
	}

	if (!_rr_xport_range_valid (self->sport_start, self->sport_end)) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("invalid source port range"));
		return FALSE;
	}

	if (!_rr_xport_range_valid (self->dport_start, self->dport_end)) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("invalid destination port range"));
		return FALSE;
	}

	return TRUE;
}

/*****************************************************************************/

typedef enum {
	RR_DBUS_ATTR_ACTION,
	RR_DBUS_ATTR_DPORT_END,
	RR_DBUS_ATTR_DPORT_START,
	RR_DBUS_ATTR_FAMILY,
	RR_DBUS_ATTR_FROM,
	RR_DBUS_ATTR_FROM_LEN,
	RR_DBUS_ATTR_FWMARK,
	RR_DBUS_ATTR_FWMASK,
	RR_DBUS_ATTR_IIFNAME,
	RR_DBUS_ATTR_INVERT,
	RR_DBUS_ATTR_IPPROTO,
	RR_DBUS_ATTR_OIFNAME,
	RR_DBUS_ATTR_PRIORITY,
	RR_DBUS_ATTR_SPORT_END,
	RR_DBUS_ATTR_SPORT_START,
	RR_DBUS_ATTR_TABLE,
	RR_DBUS_ATTR_TO,
	RR_DBUS_ATTR_TOS,
	RR_DBUS_ATTR_TO_LEN,

	_RR_DBUS_ATTR_NUM,
} RRDbusAttr;

typedef struct {
	const char *name;
	const GVariantType *dbus_type;
} RRDbusData;

static const RRDbusData rr_dbus_data[_RR_DBUS_ATTR_NUM] = {
#define _D(attr, _name, type) [attr] = { .name = _name, .dbus_type = type, }
	_D (RR_DBUS_ATTR_ACTION,      NM_IP_ROUTING_RULE_ATTR_ACTION,      G_VARIANT_TYPE_BYTE),
	_D (RR_DBUS_ATTR_DPORT_END,   NM_IP_ROUTING_RULE_ATTR_DPORT_END,   G_VARIANT_TYPE_UINT16),
	_D (RR_DBUS_ATTR_DPORT_START, NM_IP_ROUTING_RULE_ATTR_DPORT_START, G_VARIANT_TYPE_UINT16),
	_D (RR_DBUS_ATTR_FAMILY,      NM_IP_ROUTING_RULE_ATTR_FAMILY,      G_VARIANT_TYPE_INT32),
	_D (RR_DBUS_ATTR_FROM,        NM_IP_ROUTING_RULE_ATTR_FROM,        G_VARIANT_TYPE_STRING),
	_D (RR_DBUS_ATTR_FROM_LEN,    NM_IP_ROUTING_RULE_ATTR_FROM_LEN,    G_VARIANT_TYPE_BYTE),
	_D (RR_DBUS_ATTR_FWMARK,      NM_IP_ROUTING_RULE_ATTR_FWMARK,      G_VARIANT_TYPE_UINT32),
	_D (RR_DBUS_ATTR_FWMASK,      NM_IP_ROUTING_RULE_ATTR_FWMASK,      G_VARIANT_TYPE_UINT32),
	_D (RR_DBUS_ATTR_IIFNAME,     NM_IP_ROUTING_RULE_ATTR_IIFNAME,     G_VARIANT_TYPE_STRING),
	_D (RR_DBUS_ATTR_INVERT,      NM_IP_ROUTING_RULE_ATTR_INVERT,      G_VARIANT_TYPE_BOOLEAN),
	_D (RR_DBUS_ATTR_IPPROTO,     NM_IP_ROUTING_RULE_ATTR_IPPROTO,     G_VARIANT_TYPE_BYTE),
	_D (RR_DBUS_ATTR_OIFNAME,     NM_IP_ROUTING_RULE_ATTR_OIFNAME,     G_VARIANT_TYPE_STRING),
	_D (RR_DBUS_ATTR_PRIORITY,    NM_IP_ROUTING_RULE_ATTR_PRIORITY,    G_VARIANT_TYPE_UINT32),
	_D (RR_DBUS_ATTR_SPORT_END,   NM_IP_ROUTING_RULE_ATTR_SPORT_END,   G_VARIANT_TYPE_UINT16),
	_D (RR_DBUS_ATTR_SPORT_START, NM_IP_ROUTING_RULE_ATTR_SPORT_START, G_VARIANT_TYPE_UINT16),
	_D (RR_DBUS_ATTR_TABLE,       NM_IP_ROUTING_RULE_ATTR_TABLE,       G_VARIANT_TYPE_UINT32),
	_D (RR_DBUS_ATTR_TO,          NM_IP_ROUTING_RULE_ATTR_TO,          G_VARIANT_TYPE_STRING),
	_D (RR_DBUS_ATTR_TOS,         NM_IP_ROUTING_RULE_ATTR_TOS,         G_VARIANT_TYPE_BYTE),
	_D (RR_DBUS_ATTR_TO_LEN,      NM_IP_ROUTING_RULE_ATTR_TO_LEN,      G_VARIANT_TYPE_BYTE),
#undef _D
};

static void
_rr_variants_free (GVariant *(*p_variants)[])
{
	int i;

	for (i = 0; i < _RR_DBUS_ATTR_NUM; i++) {
		if ((*p_variants)[i])
			g_variant_unref ((*p_variants)[i]);
	}
}

NMIPRoutingRule *
nm_ip_routing_rule_from_dbus (GVariant *variant,
                              gboolean strict,
                              GError **error)
{
	nm_auto (_rr_variants_free) GVariant *variants[_RR_DBUS_ATTR_NUM] = { };
	nm_auto_unref_ip_routing_rule NMIPRoutingRule *self = NULL;
	RRDbusAttr attr;
	GVariantIter iter;
	const char *iter_key;
	GVariant *iter_val;
	int addr_family;
	int i;

	g_variant_iter_init (&iter, variant);

#if NM_MORE_ASSERTS > 10
	for (attr = 0; attr < _RR_DBUS_ATTR_NUM; attr++) {
		nm_assert (rr_dbus_data[attr].name);
		nm_assert (g_variant_type_string_is_valid ((const char *) rr_dbus_data[attr].dbus_type));
	}
#endif

	while (g_variant_iter_next (&iter, "{&sv}", &iter_key, &iter_val)) {
		gs_unref_variant GVariant *iter_val2 = iter_val;

		for (attr = 0; attr < _RR_DBUS_ATTR_NUM; attr++) {
			if (nm_streq (iter_key, rr_dbus_data[attr].name)) {
				if (variants[attr]) {
					if (strict) {
						g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
						             _("duplicate key %s"),
						             iter_key);
						return NULL;
					}
					g_variant_unref (variants[attr]);
				}
				variants[attr] = g_steal_pointer (&iter_val2);
				break;
			}
		}

		if (   attr >= _RR_DBUS_ATTR_NUM
		    && strict) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("invalid key \"%s\""),
			             iter_key);
			return NULL;
		}
	}

	for (attr = 0; attr < _RR_DBUS_ATTR_NUM; attr++) {
		if (!variants[attr])
			continue;
		if (!g_variant_is_of_type (variants[attr], rr_dbus_data[attr].dbus_type)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("invalid variant type '%s' for \"%s\""),
			             (const char *) rr_dbus_data[attr].dbus_type,
			             rr_dbus_data[attr].name);
			return NULL;
		}
	}

	if (!variants[RR_DBUS_ATTR_FAMILY]) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("missing \""NM_IP_ROUTING_RULE_ATTR_FAMILY"\""));
		return NULL;
	}
	addr_family = g_variant_get_int32 (variants[RR_DBUS_ATTR_FAMILY]);
	if (!NM_IN_SET (addr_family, AF_INET, AF_INET6)) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("invalid \""NM_IP_ROUTING_RULE_ATTR_FAMILY"\""));
		return NULL;
	}

	self = nm_ip_routing_rule_new (addr_family);

	if (variants[RR_DBUS_ATTR_PRIORITY])
		nm_ip_routing_rule_set_priority (self, g_variant_get_uint32 (variants[RR_DBUS_ATTR_PRIORITY]));

	if (variants[RR_DBUS_ATTR_INVERT])
		nm_ip_routing_rule_set_invert (self, g_variant_get_boolean (variants[RR_DBUS_ATTR_INVERT]));

	if (variants[RR_DBUS_ATTR_TOS])
		nm_ip_routing_rule_set_tos (self, g_variant_get_byte (variants[RR_DBUS_ATTR_TOS]));

	if (variants[RR_DBUS_ATTR_IPPROTO])
		nm_ip_routing_rule_set_ipproto (self, g_variant_get_byte (variants[RR_DBUS_ATTR_IPPROTO]));

	for (i = 0; i < 2; i++) {
		GVariant *v_start = variants[i ? RR_DBUS_ATTR_SPORT_START : RR_DBUS_ATTR_DPORT_START];
		GVariant *v_end   = variants[i ? RR_DBUS_ATTR_SPORT_END   : RR_DBUS_ATTR_DPORT_END];
		guint16 start, end;

		if (!v_start && !v_end)
			continue;

		/* if start or end is missing, it defaults to the other parameter, respectively. */
		if (v_start)
			start = g_variant_get_uint16 (v_start);
		else
			start = g_variant_get_uint16 (v_end);
		if (v_end)
			end = g_variant_get_uint16 (v_end);
		else
			end = g_variant_get_uint16 (v_start);

		if (i)
			nm_ip_routing_rule_set_source_port (self, start, end);
		else
			nm_ip_routing_rule_set_destination_port (self, start, end);
	}

	if (   variants[RR_DBUS_ATTR_FWMARK]
	    || variants[RR_DBUS_ATTR_FWMASK]) {
		nm_ip_routing_rule_set_fwmark (self,
		                               variants[RR_DBUS_ATTR_FWMARK] ? g_variant_get_uint32 (variants[RR_DBUS_ATTR_FWMARK]) : 0u,
		                               variants[RR_DBUS_ATTR_FWMASK] ? g_variant_get_uint32 (variants[RR_DBUS_ATTR_FWMASK]) : 0u);
	}

	if (   variants[RR_DBUS_ATTR_FROM]
	    || variants[RR_DBUS_ATTR_FROM_LEN]) {
		nm_ip_routing_rule_set_from (self,
		                             variants[RR_DBUS_ATTR_FROM]     ? g_variant_get_string (variants[RR_DBUS_ATTR_FROM], NULL) : NULL,
		                             variants[RR_DBUS_ATTR_FROM_LEN] ? g_variant_get_byte   (variants[RR_DBUS_ATTR_FROM_LEN])   : 0u);
	}

	if (   variants[RR_DBUS_ATTR_TO]
	    || variants[RR_DBUS_ATTR_TO_LEN]) {
		nm_ip_routing_rule_set_to (self,
		                           variants[RR_DBUS_ATTR_TO]     ? g_variant_get_string (variants[RR_DBUS_ATTR_TO], NULL) : NULL,
		                           variants[RR_DBUS_ATTR_TO_LEN] ? g_variant_get_byte   (variants[RR_DBUS_ATTR_TO_LEN])   : 0u);
	}

	if (variants[RR_DBUS_ATTR_IIFNAME])
		nm_ip_routing_rule_set_iifname (self, g_variant_get_string (variants[RR_DBUS_ATTR_IIFNAME], NULL));

	if (variants[RR_DBUS_ATTR_OIFNAME])
		nm_ip_routing_rule_set_oifname (self, g_variant_get_string (variants[RR_DBUS_ATTR_OIFNAME], NULL));

	if (variants[RR_DBUS_ATTR_ACTION])
		nm_ip_routing_rule_set_action (self, g_variant_get_byte (variants[RR_DBUS_ATTR_ACTION]));

	if (variants[RR_DBUS_ATTR_TABLE])
		nm_ip_routing_rule_set_table (self, g_variant_get_uint32 (variants[RR_DBUS_ATTR_TABLE]));

	if (   strict
	    && !nm_ip_routing_rule_validate (self, error))
		return NULL;

	return g_steal_pointer (&self);
}

static void
_rr_to_dbus_add (GVariantBuilder *builder,
                 RRDbusAttr attr,
                 GVariant *value)
{
	nm_assert (builder);
	nm_assert (value);
	nm_assert (g_variant_is_floating (value));
	nm_assert (g_variant_is_of_type (value, rr_dbus_data[attr].dbus_type));

	g_variant_builder_add (builder,
	                       "{sv}",
	                       rr_dbus_data[attr].name,
	                       value);
}

GVariant *
nm_ip_routing_rule_to_dbus (const NMIPRoutingRule *self)
{
	GVariantBuilder builder;
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];

	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), NULL);

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	_rr_to_dbus_add (&builder, RR_DBUS_ATTR_FAMILY, g_variant_new_int32 (_ip_routing_rule_get_addr_family (self)));

	if (self->invert)
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_INVERT, g_variant_new_boolean (TRUE));

	if (self->priority_has)
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_PRIORITY, g_variant_new_uint32 (self->priority));

	if (self->tos != 0)
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_TOS, g_variant_new_byte (self->tos));

	if (self->ipproto != 0)
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_IPPROTO, g_variant_new_byte (self->ipproto));

	if (self->fwmark != 0)
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_FWMARK, g_variant_new_uint32 (self->fwmark));

	if (self->fwmask != 0)
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_FWMASK, g_variant_new_uint32 (self->fwmask));

	if (   self->sport_start != 0
	    || self->sport_end != 0) {
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_SPORT_START, g_variant_new_uint16 (self->sport_start));
		if (self->sport_start != self->sport_end)
			_rr_to_dbus_add (&builder, RR_DBUS_ATTR_SPORT_END, g_variant_new_uint16 (self->sport_end));
	}

	if (   self->dport_start != 0
	    || self->dport_end != 0) {
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_DPORT_START, g_variant_new_uint16 (self->dport_start));
		if (self->dport_start != self->dport_end)
			_rr_to_dbus_add (&builder, RR_DBUS_ATTR_DPORT_END, g_variant_new_uint16 (self->dport_end));
	}

	if (   self->from_has
	    || self->from_len != 0) {
		_rr_to_dbus_add (&builder,
		                 RR_DBUS_ATTR_FROM,
		                 g_variant_new_string (   self->from_str
		                                       ?: nm_utils_inet_ntop (_ip_routing_rule_get_addr_family (self),
		                                                              &self->from_bin,
		                                                              addr_str)));
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_FROM_LEN, g_variant_new_byte (self->from_len));
	}

	if (   self->to_has
	    || self->to_len != 0) {
		_rr_to_dbus_add (&builder,
		                 RR_DBUS_ATTR_TO,
		                 g_variant_new_string (   self->to_str
		                                       ?: nm_utils_inet_ntop (_ip_routing_rule_get_addr_family (self),
		                                                              &self->to_bin,
		                                                              addr_str)));
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_TO_LEN, g_variant_new_byte (self->to_len));
	}

	if (self->iifname)
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_IIFNAME, g_variant_new_string (self->iifname));

	if (self->oifname)
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_OIFNAME, g_variant_new_string (self->oifname));

	if (self->action != FR_ACT_TO_TBL)
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_ACTION, g_variant_new_byte (self->action));

	if (self->table != 0)
		_rr_to_dbus_add (&builder, RR_DBUS_ATTR_TABLE, g_variant_new_uint32 (self->table));

	return g_variant_builder_end (&builder);;
}

/*****************************************************************************/

static gboolean
_rr_string_validate (gboolean for_from /* or else to-string */,
                     NMIPRoutingRuleAsStringFlags to_string_flags,
                     GHashTable *extra_args,
                     GError **error)
{
	if (NM_FLAGS_ANY (to_string_flags, ~(  NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET
	                                     | NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET6
	                                     | NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE))) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		                     _("Unsupported to-string-flags argument"));
		return FALSE;
	}

	if (   extra_args
	    && g_hash_table_size (extra_args) > 0) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		                     _("Unsupported extra-argument"));
		return FALSE;
	}

	return TRUE;
}

static int
_rr_string_addr_family_from_flags (NMIPRoutingRuleAsStringFlags to_string_flags)
{
	if (NM_FLAGS_HAS (to_string_flags, NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET)) {
		if (!NM_FLAGS_HAS (to_string_flags, NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET6))
			return AF_INET;
	} else if (NM_FLAGS_HAS (to_string_flags, NM_IP_ROUTING_RULE_AS_STRING_FLAGS_AF_INET6))
		return AF_INET6;
	return AF_UNSPEC;
}

/**
 * nm_ip_routing_rule_from_string:
 * @str: the string representation to convert to an #NMIPRoutingRule
 * @to_string_flags: #NMIPRoutingRuleAsStringFlags for controlling the
 *   string conversion.
 * @extra_args: (allow-none): extra arguments for controlling the string
 *   conversion. Currently not extra arguments are supported.
 * @error: (allow-none) (out): the error reason.
 *
 * Returns: (transfer full): the new #NMIPRoutingRule or %NULL on error.
 *
 * Since: 1.18
 */
NMIPRoutingRule *
nm_ip_routing_rule_from_string (const char *str,
                                NMIPRoutingRuleAsStringFlags to_string_flags,
                                GHashTable *extra_args,
                                GError **error)
{
	nm_auto_unref_ip_routing_rule NMIPRoutingRule *self = NULL;
	gs_free const char **tokens = NULL;
	gsize i_token;
	gboolean any_words = FALSE;
	char *word0 = NULL;
	char *word1 = NULL;
	char *word_from = NULL;
	char *word_to = NULL;
	char *word_iifname = NULL;
	char *word_oifname = NULL;
	gint64 i64_priority = -1;
	gint64 i64_table = -1;
	gint64 i64_tos = -1;
	gint64 i64_fwmark = -1;
	gint64 i64_fwmask = -1;
	gint64 i64_sport_start = -1;
	gint64 i64_ipproto = -1;
	guint16 sport_end = 0;
	gint64 i64_dport_start = -1;
	guint16 dport_end = 0;
	gboolean val_invert = FALSE;
	int addr_family = AF_UNSPEC;
	NMIPAddr val_from = { };
	NMIPAddr val_to = { };
	int val_from_len = -1;
	int val_to_len = -1;
	char *s;

	g_return_val_if_fail (str, NULL);

	if (!_rr_string_validate (TRUE, to_string_flags, extra_args, error))
		return NULL;

	/* NM_IP_ROUTING_RULE_TO_STRING_TYPE_IPROUTE gives a string representation that is
	 * partly compatibly with iproute2. That is, the part after `ip -[46] rule add $ARGS`.
	 * There are differences though:
	 *
	 * - trying to convert an invalid rule to string may not be possible. The reason is for
	 *   example that an invalid rule can have nm_ip_routing_rule_get_from() like "bogus",
	 *   but we don't write that as "from bogus". In general, if you try to convert an invalid
	 *   rule to string, the operation may fail or the result may itself not be parsable.
	 *   Of course, valid rules can be converted to string and read back the same (round-trip).
	 *
	 * - iproute2 in may regards is flexible about the command lines. For example
	 *   - for tables it accepts table names from /etc/iproute2/rt_tables
	 *   - key names like "preference" can be abbreviated to "prefe", we don't do that.
	 *   - the "preference"/"priority" may be unspecified, in which kernel automatically
	 *     chooses an unused priority (during `ip rule add`). We don't allow for that, the
	 *     priority must be explicitly set.
	 *
	 * - iproute2 does not support any escaping. Well, it's the shell that supports quoting
	 *   and escaping and splits the command line. We need to split the command line ourself,
	 *   but we don't support full shell quotation.
	 *   from-string tokenizes words at (ASCII) whitespaces (removing the whitespaces).
	 *   It also supports backslash escaping (e.g. to contain whitespace), but it does
	 *   not support special escape sequences. Values are taken literally, meaning
	 *   "\n\ \111" gives results in "n 111".
	 *   The strings really shouldn't contain any special characters that require escaping,
	 *   but that's the rule.
	 *   This also goes together with the @allow_escaping parameter of nm_utils_strsplit_set().
	 *   If you concatenate multiple rule expressions with a delimiter, the delimiter inside
	 *   each word can be backslash escaped, and nm_utils_strsplit_set(allow_escaping=TRUE) will
	 *   properly split the words, preserving the backslashes, which then will be removed by
	 *   nm_ip_routing_rule_from_string().
	 */

	addr_family = _rr_string_addr_family_from_flags (to_string_flags);

	tokens = nm_utils_escaped_tokens_split (str, NM_ASCII_SPACES);
	for (i_token = 0; tokens && tokens[i_token]; i_token++) {
		char *str_word = (char *) tokens[i_token];

		any_words = TRUE;
		if (!word0)
			word0 = str_word;
		else {
			nm_assert (!word1);
			word1 = str_word;
		}

		/* iproute2 matches keywords with any partial prefix. We don't allow
		 * for that flexiblity. */

		if (NM_IN_STRSET (word0, "from")) {
			if (!word1)
				continue;
			if (word_from)
				goto next_fail_word0_duplicate_key;
			word_from = word1;
			goto next_words_consumed;
		}
		if (NM_IN_STRSET (word0, "to")) {
			if (!word1)
				continue;
			if (word_to)
				goto next_fail_word0_duplicate_key;
			word_to = word1;
			goto next_words_consumed;
		}
		if (NM_IN_STRSET (word0, "not")) {
			/* we accept multiple "not" specifiers. */
			val_invert = TRUE;
			goto next_words_consumed;
		}
		if (NM_IN_STRSET (word0, "priority",
		                         "order",
		                         "pref",
		                         "preference")) {
			if (!word1)
				continue;
			if (i64_priority != -1)
				goto next_fail_word0_duplicate_key;
			i64_priority = _nm_utils_ascii_str_to_int64 (word1, 0, 0, G_MAXUINT32, -1);
			if (i64_priority == -1)
				goto next_fail_word1_invalid_value;
			goto next_words_consumed;
		}
		if (NM_IN_STRSET (word0, "table",
		                         "lookup")) {
			if (!word1)
				continue;
			if (i64_table != -1)
				goto next_fail_word0_duplicate_key;
			i64_table = _nm_utils_ascii_str_to_int64 (word1, 0, 1, G_MAXUINT32, -1);
			if (i64_table == -1)
				goto next_fail_word1_invalid_value;
			goto next_words_consumed;
		}
		if (NM_IN_STRSET (word0, "tos",
		                         "dsfield")) {
			if (!word1)
				continue;
			if (i64_tos != -1)
				goto next_fail_word0_duplicate_key;
			i64_tos = _nm_utils_ascii_str_to_int64 (word1, 16, 0, G_MAXUINT8, -1);
			if (i64_tos == -1)
				goto next_fail_word1_invalid_value;
			goto next_words_consumed;
		}
		if (NM_IN_STRSET (word0, "ipproto")) {
			if (!word1)
				continue;
			if (i64_ipproto != -1)
				goto next_fail_word0_duplicate_key;
			i64_ipproto = _nm_utils_ascii_str_to_int64 (word1, 10, 0, G_MAXUINT8, -1);
			if (i64_ipproto == -1)
				goto next_fail_word1_invalid_value;
			goto next_words_consumed;
		}
		if (NM_IN_STRSET (word0, "sport")) {
			if (!word1)
				continue;
			if (i64_sport_start != -1)
				goto next_fail_word0_duplicate_key;
			if (!_rr_xport_range_parse (word1, &i64_sport_start, &sport_end))
				goto next_fail_word1_invalid_value;
			goto next_words_consumed;
		}
		if (NM_IN_STRSET (word0, "dport")) {
			if (!word1)
				continue;
			if (i64_dport_start != -1)
				goto next_fail_word0_duplicate_key;
			if (!_rr_xport_range_parse (word1, &i64_dport_start, &dport_end))
				goto next_fail_word1_invalid_value;
			goto next_words_consumed;
		}
		if (NM_IN_STRSET (word0, "fwmark")) {
			if (!word1)
				continue;
			if (i64_fwmark != -1)
				goto next_fail_word0_duplicate_key;
			s = strchr (word1, '/');
			if (s)
				*(s++) = '\0';
			i64_fwmark = _nm_utils_ascii_str_to_int64 (word1, 0, 0, G_MAXUINT32, -1);
			if (i64_fwmark == -1)
				goto next_fail_word1_invalid_value;
			if (s) {
				i64_fwmask = _nm_utils_ascii_str_to_int64 (s, 0, 0, G_MAXUINT32, -1);
				if (i64_fwmask == -1)
					goto next_fail_word1_invalid_value;
			} else
				i64_fwmask = 0xFFFFFFFFu;
			goto next_words_consumed;
		}
		if (NM_IN_STRSET (word0, "iif",
		                         "dev")) {
			if (!word1)
				continue;
			if (word_iifname)
				goto next_fail_word0_duplicate_key;
			word_iifname = word1;
			goto next_words_consumed;
		}
		if (NM_IN_STRSET (word0, "oif")) {
			if (!word1)
				continue;
			if (word_oifname)
				goto next_fail_word0_duplicate_key;
			word_oifname = word1;
			goto next_words_consumed;
		}

		/* also the action is still unsupported. For the moment, we only support
		 * FR_ACT_TO_TBL, which is the default (by not expressing it on the command
		 * line). */
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("unsupported key \"%s\""),
		             word0);
		return FALSE;
next_fail_word0_duplicate_key:
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("duplicate key \"%s\""),
		             word0);
		return FALSE;
next_fail_word1_invalid_value:
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("invalid value for \"%s\""),
		             word0);
		return FALSE;
next_words_consumed:
		word0 = NULL;
		word1 = NULL;
	}

	if (!any_words) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		                     _("empty text does not describe a rule"));
		return FALSE;
	}

	if (word0) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("missing argument for \"%s\""),
		             word0);
		return FALSE;
	}

	if (!NM_IN_STRSET (word_from, NULL, "all")) {
		if (!nm_utils_parse_inaddr_prefix_bin (addr_family,
		                                       word_from,
		                                       &addr_family,
		                                       &val_from,
		                                       &val_from_len)) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
			                     _("invalid \"from\" part"));
			return FALSE;
		}
		if (val_from_len == -1)
			val_from_len = nm_utils_addr_family_to_size (addr_family) * 8;
	}

	if (!NM_IN_STRSET (word_to, NULL, "all")) {
		if (!nm_utils_parse_inaddr_prefix_bin (addr_family,
		                                       word_to,
		                                       &addr_family,
		                                       &val_to,
		                                       &val_to_len)) {
			g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
			                     _("invalid \"to\" part"));
			return FALSE;
		}
		if (val_to_len == -1)
			val_to_len = nm_utils_addr_family_to_size (addr_family) * 8;
	}

	if (!NM_IN_SET (addr_family, AF_INET, AF_INET6)) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		             _("cannot detect address family for rule"));
		return FALSE;
	}

	self = nm_ip_routing_rule_new (addr_family);

	if (val_invert)
		self->invert = TRUE;

	if (i64_priority != -1)
		nm_ip_routing_rule_set_priority (self, i64_priority);

	if (i64_tos != -1)
		nm_ip_routing_rule_set_tos (self, i64_tos);

	if (i64_ipproto != -1)
		nm_ip_routing_rule_set_ipproto (self, i64_ipproto);

	if (i64_fwmark != -1)
		nm_ip_routing_rule_set_fwmark (self, i64_fwmark, i64_fwmask);

	if (i64_sport_start != -1)
		nm_ip_routing_rule_set_source_port (self, i64_sport_start, sport_end);

	if (i64_dport_start != -1)
		nm_ip_routing_rule_set_destination_port (self, i64_dport_start, dport_end);

	if (   val_from_len > 0
	    || (   val_from_len == 0
	        && !nm_ip_addr_is_null (addr_family, &val_from))) {
		nm_ip_routing_rule_set_from_bin (self,
		                                 &val_from,
		                                 val_from_len);
	}

	if (   val_to_len > 0
	    || (   val_to_len == 0
	        && !nm_ip_addr_is_null (addr_family, &val_to))) {
		nm_ip_routing_rule_set_to_bin (self,
		                               &val_to,
		                               val_to_len);
	}

	if (word_iifname)
		nm_ip_routing_rule_set_iifname (self, word_iifname);

	if (word_oifname)
		nm_ip_routing_rule_set_oifname (self, word_oifname);

	if (i64_table != -1)
		nm_ip_routing_rule_set_table (self, i64_table);

	if (NM_FLAGS_HAS (to_string_flags, NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE)) {
		gs_free_error GError *local = NULL;

		if (!nm_ip_routing_rule_validate (self, &local)) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
			             _("rule is invalid: %s"),
			             local->message);
			return NULL;
		}
	}

	return g_steal_pointer (&self);
}

static void
_rr_string_append_inet_addr (GString *str,
                             gboolean is_from /* or else is-to */,
                             gboolean required,
                             int addr_family,
                             const NMIPAddr *addr_bin,
                             guint8 addr_len)
{
	char addr_str[NM_UTILS_INET_ADDRSTRLEN];

	if (addr_len == 0) {
		if (required) {
			g_string_append_printf (nm_gstring_add_space_delimiter (str),
			                        "%s %s/0",
			                        is_from ? "from" : "to",
			                          (addr_family == AF_INET)
			                        ? "0.0.0.0"
			                        : "::");
		}
		return;
	}

	g_string_append_printf (nm_gstring_add_space_delimiter (str),
	                        "%s %s",
	                        is_from ? "from" : "to",
	                        nm_utils_inet_ntop (addr_family,
	                                            addr_bin,
	                                            addr_str));
	if (addr_len != nm_utils_addr_family_to_size (addr_family) * 8) {
		g_string_append_printf (str,
		                        "/%u",
		                        addr_len);
	}
}

/**
 * nm_ip_routing_rule_to_string:
 * @self: the #NMIPRoutingRule instance to convert to string.
 * @to_string_flags: #NMIPRoutingRuleAsStringFlags for controlling the
 *   string conversion.
 * @extra_args: (allow-none): extra arguments for controlling the string
 *   conversion. Currently not extra arguments are supported.
 * @error: (allow-none) (out): the error reason.
 *
 * Returns: (transfer full): the string representation or %NULL on error.
 *
 * Since: 1.18
 */
char *
nm_ip_routing_rule_to_string (const NMIPRoutingRule *self,
                              NMIPRoutingRuleAsStringFlags to_string_flags,
                              GHashTable *extra_args,
                              GError **error)
{
	nm_auto_free_gstring GString *str = NULL;
	int addr_family;

	g_return_val_if_fail (NM_IS_IP_ROUTING_RULE (self, TRUE), NULL);

	if (!_rr_string_validate (FALSE, to_string_flags, extra_args, error))
		return NULL;

	addr_family = nm_ip_routing_rule_get_addr_family (self);

	if (!NM_IN_SET (_rr_string_addr_family_from_flags (to_string_flags),
	                AF_UNSPEC,
	                addr_family)) {
		g_set_error_literal (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
		                     _("invalid address family"));
		return NULL;
	}

	/* It is only guaranteed that valid rules can be expressed as string.
	 *
	 * Still, unless requested proceed to convert to string without validating and
	 * hope for the best.
	 *
	 * That is, because self->from_str might contain an invalid IP address (indicated
	 * by self->from_valid). But we don't support serializing such arbitrary strings
	 * as "from %s". */
	if (NM_FLAGS_HAS (to_string_flags, NM_IP_ROUTING_RULE_AS_STRING_FLAGS_VALIDATE)) {
		gs_free_error GError *local = NULL;

		if (!nm_ip_routing_rule_validate (self, &local)) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_FAILED,
			             _("rule is invalid: %s"),
			             local->message);
			return NULL;
		}
	}

	str = g_string_sized_new (30);

	if (self->invert)
		g_string_append (str, "not");

	if (self->priority_has) {
		g_string_append_printf (nm_gstring_add_space_delimiter (str),
		                        "priority %u",
		                        (guint) self->priority);
	}

	_rr_string_append_inet_addr (str,
	                             TRUE,
	                             (   !self->to_has
	                              || !self->to_valid),
	                             addr_family,
	                             &self->from_bin,
	                               (self->from_has && self->from_valid)
	                             ? self->from_len
	                             : 0);

	_rr_string_append_inet_addr (str,
	                             FALSE,
	                             FALSE,
	                             addr_family,
	                             &self->to_bin,
	                               (self->to_has && self->to_valid)
	                             ? self->to_len
	                             : 0);

	if (self->tos != 0) {
		g_string_append_printf (nm_gstring_add_space_delimiter (str),
		                        "tos 0x%02x",
		                        (guint) self->tos);
	}

	if (self->ipproto != 0) {
		g_string_append_printf (nm_gstring_add_space_delimiter (str),
		                        "ipproto %u",
		                        (guint) self->ipproto);
	}

	if (   self->fwmark != 0
	    || self->fwmask != 0) {
		if (self->fwmark != 0) {
			g_string_append_printf (nm_gstring_add_space_delimiter (str),
			                        "fwmark 0x%x",
			                        self->fwmark);
		} else {
			g_string_append_printf (nm_gstring_add_space_delimiter (str),
			                        "fwmark 0");
		}
		if (self->fwmask != 0xFFFFFFFFu) {
			if (self->fwmask != 0)
				g_string_append_printf (str, "/0x%x", self->fwmask);
			else
				g_string_append_printf (str, "/0");
		}
	}

	if (   self->sport_start != 0
	    || self->sport_end != 0) {
		g_string_append_printf (nm_gstring_add_space_delimiter (str),
		                        "sport %u",
		                        self->sport_start);
		if (self->sport_start != self->sport_end) {
			g_string_append_printf (str,
			                        "-%u",
			                        self->sport_end);
		}
	}

	if (   self->dport_start != 0
	    || self->dport_end != 0) {
		g_string_append_printf (nm_gstring_add_space_delimiter (str),
		                        "dport %u",
		                        self->dport_start);
		if (self->dport_start != self->dport_end) {
			g_string_append_printf (str,
			                        "-%u",
			                        self->dport_end);
		}
	}

	if (self->iifname) {
		g_string_append (nm_gstring_add_space_delimiter (str),
		                 "iif ");
		nm_utils_escaped_tokens_escape_gstr (self->iifname,
		                                     NM_ASCII_SPACES,
		                                     str);
	}

	if (self->oifname) {
		g_string_append (nm_gstring_add_space_delimiter (str),
		                 "oif ");
		nm_utils_escaped_tokens_escape_gstr (self->oifname,
		                                     NM_ASCII_SPACES,
		                                     str);
	}

	if (self->table != 0) {
		g_string_append_printf (nm_gstring_add_space_delimiter (str),
		                        "table %u",
		                        (guint) self->table);
	}

	return g_string_free (g_steal_pointer (&str), FALSE);
}

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMSettingIPConfig,
	PROP_METHOD,
	PROP_DNS,
	PROP_DNS_SEARCH,
	PROP_DNS_OPTIONS,
	PROP_DNS_PRIORITY,
	PROP_ADDRESSES,
	PROP_GATEWAY,
	PROP_ROUTES,
	PROP_ROUTE_METRIC,
	PROP_ROUTE_TABLE,
	PROP_IGNORE_AUTO_ROUTES,
	PROP_IGNORE_AUTO_DNS,
	PROP_DHCP_HOSTNAME,
	PROP_DHCP_SEND_HOSTNAME,
	PROP_NEVER_DEFAULT,
	PROP_MAY_FAIL,
	PROP_DAD_TIMEOUT,
	PROP_DHCP_TIMEOUT,
);

typedef struct {
	char *method;
	GPtrArray *dns;        /* array of IP address strings */
	GPtrArray *dns_search; /* array of domain name strings */
	GPtrArray *dns_options;/* array of DNS options */
	int dns_priority;
	GPtrArray *addresses;  /* array of NMIPAddress */
	GPtrArray *routes;     /* array of NMIPRoute */
	GPtrArray *routing_rules;
	gint64 route_metric;
	guint32 route_table;
	char *gateway;
	gboolean ignore_auto_routes;
	gboolean ignore_auto_dns;
	char *dhcp_hostname;
	gboolean dhcp_send_hostname;
	gboolean never_default;
	gboolean may_fail;
	int dad_timeout;
	int dhcp_timeout;
} NMSettingIPConfigPrivate;

G_DEFINE_ABSTRACT_TYPE (NMSettingIPConfig, nm_setting_ip_config, NM_TYPE_SETTING)

#define NM_SETTING_IP_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_IP_CONFIG, NMSettingIPConfigPrivate))

/*****************************************************************************/

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
	g_return_val_if_fail (idx >= 0 && idx < priv->dns->len, NULL);

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
	guint i;

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
	_notify (setting, PROP_DNS);
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
	g_return_if_fail (idx >= 0 && idx < priv->dns->len);

	g_ptr_array_remove_index (priv->dns, idx);
	_notify (setting, PROP_DNS);
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
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns != NULL, FALSE);
	g_return_val_if_fail (nm_utils_ipaddr_valid (NM_SETTING_IP_CONFIG_GET_FAMILY (setting), dns), FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	dns_canonical = canonicalize_ip (NM_SETTING_IP_CONFIG_GET_FAMILY (setting), dns, FALSE);
	for (i = 0; i < priv->dns->len; i++) {
		if (!strcmp (dns_canonical, priv->dns->pdata[i])) {
			g_ptr_array_remove_index (priv->dns, i);
			_notify (setting, PROP_DNS);
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

	if (priv->dns->len != 0) {
		g_ptr_array_set_size (priv->dns, 0);
		_notify (setting, PROP_DNS);
	}
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
	g_return_val_if_fail (idx >= 0 && idx < priv->dns_search->len, NULL);

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
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_search != NULL, FALSE);
	g_return_val_if_fail (dns_search[0] != '\0', FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->dns_search->len; i++) {
		if (!strcmp (dns_search, priv->dns_search->pdata[i]))
			return FALSE;
	}

	g_ptr_array_add (priv->dns_search, g_strdup (dns_search));
	_notify (setting, PROP_DNS_SEARCH);
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
	g_return_if_fail (idx >= 0 && idx < priv->dns_search->len);

	g_ptr_array_remove_index (priv->dns_search, idx);
	_notify (setting, PROP_DNS_SEARCH);
}

/**
 * nm_setting_ip_config_remove_dns_search_by_value:
 * @setting: the #NMSettingIPConfig
 * @dns_search: the search domain to remove
 *
 * Removes the DNS search domain @dns_search.
 *
 * Returns: %TRUE if the DNS search domain was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip_config_remove_dns_search_by_value (NMSettingIPConfig *setting,
                                                 const char *dns_search)
{
	NMSettingIPConfigPrivate *priv;
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_search != NULL, FALSE);
	g_return_val_if_fail (dns_search[0] != '\0', FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->dns_search->len; i++) {
		if (!strcmp (dns_search, priv->dns_search->pdata[i])) {
			g_ptr_array_remove_index (priv->dns_search, i);
			_notify (setting, PROP_DNS_SEARCH);
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

	if (priv->dns_search->len != 0) {
		g_ptr_array_set_size (priv->dns_search, 0);
		_notify (setting, PROP_DNS_SEARCH);
	}
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
 * Returns: whether DNS options are initialized or left unset (the default).
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
int
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
	_notify (setting, PROP_DNS_OPTIONS);
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
	g_return_if_fail (idx >= 0 && idx < priv->dns_options->len);

	g_ptr_array_remove_index (priv->dns_options, idx);
	_notify (setting, PROP_DNS_OPTIONS);
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
	gssize i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (dns_option != NULL, FALSE);
	g_return_val_if_fail (dns_option[0] != '\0', FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	if (!priv->dns_options)
		return FALSE;

	i = _nm_utils_dns_option_find_idx (priv->dns_options, dns_option);
	if (i >= 0) {
		g_ptr_array_remove_index (priv->dns_options, i);
		_notify (setting, PROP_DNS_OPTIONS);
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
	_notify (setting, PROP_DNS_OPTIONS);
}

/**
 * nm_setting_ip_config_get_dns_priority:
 * @setting: the #NMSettingIPConfig
 *
 * Returns: the priority of DNS servers
 *
 * Since: 1.4
 **/
int
nm_setting_ip_config_get_dns_priority (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), 0);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->dns_priority;
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
	g_return_val_if_fail (idx >= 0 && idx < priv->addresses->len, NULL);

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
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);
	g_return_val_if_fail (address->family == NM_SETTING_IP_CONFIG_GET_FAMILY (setting), FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->addresses->len; i++) {
		if (nm_ip_address_equal (priv->addresses->pdata[i], address))
			return FALSE;
	}

	g_ptr_array_add (priv->addresses, nm_ip_address_dup (address));

	_notify (setting, PROP_ADDRESSES);
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
	g_return_if_fail (idx >= 0 && idx < priv->addresses->len);

	g_ptr_array_remove_index (priv->addresses, idx);

	_notify (setting, PROP_ADDRESSES);
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
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (address != NULL, FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->addresses->len; i++) {
		if (nm_ip_address_equal (priv->addresses->pdata[i], address)) {
			g_ptr_array_remove_index (priv->addresses, i);
			_notify (setting, PROP_ADDRESSES);
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

	if (priv->addresses->len != 0) {
		g_ptr_array_set_size (priv->addresses, 0);
		_notify (setting, PROP_ADDRESSES);
	}
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
	g_return_val_if_fail (idx >= 0 && idx < priv->routes->len, NULL);

	return priv->routes->pdata[idx];
}

/**
 * nm_setting_ip_config_add_route:
 * @setting: the #NMSettingIPConfig
 * @route: the route to add
 *
 * Appends a new route and associated information to the setting.  The
 * given route is duplicated internally and is not changed by this function.
 * If an identical route (considering attributes as well) already exists, the
 * route is not added and the function returns %FALSE.
 *
 * Note that before 1.10, this function would not consider route attributes
 * and not add a route that has an existing route with same dest/prefix,next_hop,metric
 * parameters.
 *
 * Returns: %TRUE if the route was added; %FALSE if the route was already known.
 **/
gboolean
nm_setting_ip_config_add_route (NMSettingIPConfig *setting,
                                NMIPRoute *route)
{
	NMSettingIPConfigPrivate *priv;
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);
	g_return_val_if_fail (route->family == NM_SETTING_IP_CONFIG_GET_FAMILY (setting), FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->routes->len; i++) {
		if (nm_ip_route_equal_full (priv->routes->pdata[i], route, NM_IP_ROUTE_EQUAL_CMP_FLAGS_WITH_ATTRS))
			return FALSE;
	}

	g_ptr_array_add (priv->routes, nm_ip_route_dup (route));
	_notify (setting, PROP_ROUTES);
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
	g_return_if_fail (idx >= 0 && idx < priv->routes->len);

	g_ptr_array_remove_index (priv->routes, idx);
	_notify (setting, PROP_ROUTES);
}

/**
 * nm_setting_ip_config_remove_route_by_value:
 * @setting: the #NMSettingIPConfig
 * @route: the route to remove
 *
 * Removes the first matching route that matches @route.
 * Note that before 1.10, this function would only compare dest/prefix,next_hop,metric
 * and ignore route attributes. Now, @route must match exactly.
 *
 * Returns: %TRUE if the route was found and removed; %FALSE if it was not.
 **/
gboolean
nm_setting_ip_config_remove_route_by_value (NMSettingIPConfig *setting,
                                            NMIPRoute *route)
{
	NMSettingIPConfigPrivate *priv;
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), FALSE);
	g_return_val_if_fail (route != NULL, FALSE);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	for (i = 0; i < priv->routes->len; i++) {
		if (nm_ip_route_equal_full (priv->routes->pdata[i], route, NM_IP_ROUTE_EQUAL_CMP_FLAGS_WITH_ATTRS)) {
			g_ptr_array_remove_index (priv->routes, i);
			_notify (setting, PROP_ROUTES);
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

	if (priv->routes->len != 0) {
		g_ptr_array_set_size (priv->routes, 0);
		_notify (setting, PROP_ROUTES);
	}
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
 * nm_setting_ip_config_get_route_table:
 * @setting: the #NMSettingIPConfig
 *
 * Returns the value contained in the #NMSettingIPConfig:route-table
 * property.
 *
 * Returns: the configured route-table.
 *
 * Since: 1.10
 **/
guint32
nm_setting_ip_config_get_route_table (NMSettingIPConfig *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), 0);

	return NM_SETTING_IP_CONFIG_GET_PRIVATE (setting)->route_table;
}

/*****************************************************************************/

static void
_routing_rules_notify (NMSettingIPConfig *setting)
{
	_nm_setting_emit_property_changed (NM_SETTING (setting));
}

/**
 * nm_setting_ip_config_get_num_routing_rules:
 * @setting: the #NMSettingIPConfig
 *
 * Returns: the number of configured routing rules
 *
 * Since: 1.18
 **/
guint
nm_setting_ip_config_get_num_routing_rules (NMSettingIPConfig *setting)
{
	NMSettingIPConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), 0);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	return priv->routing_rules ? priv->routing_rules->len : 0u;
}

/**
 * nm_setting_ip_config_get_routing_rule:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the routing_rule to return
 *
 * Returns: (transfer none): the routing rule at index @idx
 *
 * Since: 1.18
 **/
NMIPRoutingRule *
nm_setting_ip_config_get_routing_rule (NMSettingIPConfig *setting, guint idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_IP_CONFIG (setting), NULL);

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	g_return_val_if_fail (priv->routing_rules && idx < priv->routing_rules->len, NULL);

	return priv->routing_rules->pdata[idx];
}

/**
 * nm_setting_ip_config_add_routing_rule:
 * @setting: the #NMSettingIPConfig
 * @routing_rule: the #NMIPRoutingRule to add. The address family
 *   of the added rule must be compatible with the setting.
 *
 * Appends a new routing-rule and associated information to the setting. The
 * given routing rules gets sealed and the reference count is incremented.
 * The function does not check whether an identical rule already exists
 * and always appends the rule to the end of the list.
 *
 * Since: 1.18
 **/
void
nm_setting_ip_config_add_routing_rule (NMSettingIPConfig *setting,
                                       NMIPRoutingRule *routing_rule)
{
	NMSettingIPConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));
	g_return_if_fail (NM_IS_IP_ROUTING_RULE (routing_rule, TRUE));
	g_return_if_fail (_ip_routing_rule_get_addr_family (routing_rule) == NM_SETTING_IP_CONFIG_GET_FAMILY (setting));

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	if (!priv->routing_rules)
		priv->routing_rules = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_routing_rule_unref);

	nm_ip_routing_rule_seal (routing_rule);
	g_ptr_array_add (priv->routing_rules, nm_ip_routing_rule_ref (routing_rule));
	_routing_rules_notify (setting);
}

/**
 * nm_setting_ip_config_remove_routing_rule:
 * @setting: the #NMSettingIPConfig
 * @idx: index number of the routing_rule
 *
 * Removes the routing_rule at index @idx.
 *
 * Since: 1.18
 **/
void
nm_setting_ip_config_remove_routing_rule (NMSettingIPConfig *setting,
                                          guint idx)
{
	NMSettingIPConfigPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	g_return_if_fail (priv->routing_rules && idx < priv->routing_rules->len);

	g_ptr_array_remove_index (priv->routing_rules, idx);
	_routing_rules_notify (setting);
}

/**
 * nm_setting_ip_config_clear_routing_rules:
 * @setting: the #NMSettingIPConfig
 *
 * Removes all configured routing rules.
 *
 * Since: 1.18
 **/
void
nm_setting_ip_config_clear_routing_rules (NMSettingIPConfig *setting)
{
	NMSettingIPConfigPrivate *priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_IP_CONFIG (setting));

	if (   priv->routing_rules
	    && priv->routing_rules->len > 0) {
		g_ptr_array_set_size (priv->routing_rules, 0);
		_routing_rules_notify (setting);
	}
}

static GVariant *
_routing_rules_dbus_only_synth (const NMSettInfoSetting *sett_info,
                                guint property_idx,
                                NMConnection *connection,
                                NMSetting *setting,
                                NMConnectionSerializationFlags flags)
{
	NMSettingIPConfig *self = NM_SETTING_IP_CONFIG (setting);
	NMSettingIPConfigPrivate *priv;
	GVariantBuilder builder;
	gboolean any = FALSE;
	guint i;

	priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (self);

	if (   !priv->routing_rules
	    || priv->routing_rules->len == 0)
		return NULL;

	for (i = 0; i < priv->routing_rules->len; i++) {
		GVariant *variant;

		variant = nm_ip_routing_rule_to_dbus (priv->routing_rules->pdata[i]);
		if (!variant)
			continue;

		if (!any) {
			any = TRUE;
			g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));
		}
		g_variant_builder_add (&builder, "@a{sv}", variant);
	}

	return any ? g_variant_builder_end (&builder) : NULL;
}

static gboolean
_routing_rules_dbus_only_set (NMSetting     *setting,
                              GVariant      *connection_dict,
                              const char    *property,
                              GVariant      *value,
                              NMSettingParseFlags parse_flags,
                              GError       **error)
{
	GVariantIter iter_rules;
	GVariant *rule_var;
	guint i_rule;
	gboolean success = FALSE;
	gboolean rules_changed = FALSE;

	nm_assert (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")));

	g_variant_iter_init (&iter_rules, value);

	i_rule = 0;
	while (g_variant_iter_next (&iter_rules, "@a{sv}", &rule_var)) {
		_nm_unused gs_unref_variant GVariant *rule_var_unref = rule_var;
		nm_auto_unref_ip_routing_rule NMIPRoutingRule *rule = NULL;
		gs_free_error GError *local = NULL;

		i_rule++;

		rule = nm_ip_routing_rule_from_dbus (rule_var,
		                                     NM_FLAGS_HAS (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT),
		                                     &local);
		if (!rule) {
			if (NM_FLAGS_HAS (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT)) {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_PROPERTY,
				             _("rule #%u is invalid: %s"),
				             i_rule,
				             local->message);
				goto out;
			}
			continue;
		}

		nm_setting_ip_config_add_routing_rule (NM_SETTING_IP_CONFIG (setting), rule);
		rules_changed = TRUE;
	}

	success = TRUE;

out:
	if (rules_changed)
		_routing_rules_notify (NM_SETTING_IP_CONFIG (setting));
	return success;
}

/*****************************************************************************/

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
int
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
int
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
	if (!nm_utils_is_valid_iface_name (iface, NULL)) {
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
	guint i;

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
			             (int) (i + 1));
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
			             (int) (i + 1));
			g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_ADDRESSES);
			return FALSE;
		}

		label = nm_ip_address_get_attribute (addr, NM_IP_ADDRESS_ATTRIBUTE_LABEL);
		if (label) {
			if (!g_variant_is_of_type (label, G_VARIANT_TYPE_STRING)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("%d. IP address has 'label' property with invalid type"),
				             (int) (i + 1));
				g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_ADDRESSES);
				return FALSE;
			}
			if (!verify_label (g_variant_get_string (label, NULL))) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("%d. IP address has invalid label '%s'"),
				             (int) (i + 1), g_variant_get_string (label, NULL));
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
			             (int) (i + 1));
			g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_ROUTES);
			return FALSE;
		}
		if (nm_ip_route_get_prefix (route) == 0) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("%d. route cannot be a default route"),
			             (int) (i + 1));
			g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_ROUTES);
			return FALSE;
		}
	}

	if (priv->routing_rules) {
		for (i = 0; i < priv->routing_rules->len; i++) {
			NMIPRoutingRule *rule = priv->routing_rules->pdata[i];
			gs_free_error GError *local = NULL;

			if (_ip_routing_rule_get_addr_family (rule) != NM_SETTING_IP_CONFIG_GET_FAMILY (setting)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("%u. rule has wrong address-family"),
				             i + 1);
				g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_ROUTING_RULES);
				return FALSE;
			}
			if (!nm_ip_routing_rule_validate (rule, &local)) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("%u. rule is invalid: %s"),
				             i + 1,
				             local->message);
				g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_ROUTES);
				return FALSE;
			}
		}
	}

	if (priv->gateway && priv->never_default) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("a gateway is incompatible with '%s'"),
		             NM_SETTING_IP_CONFIG_NEVER_DEFAULT);
		g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_IP_CONFIG_GATEWAY);
		return NM_SETTING_VERIFY_NORMALIZABLE_ERROR;
	}

	return TRUE;
}

static NMTernary
compare_property (const NMSettInfoSetting *sett_info,
                  guint property_idx,
                  NMSetting *setting,
                  NMSetting *other,
                  NMSettingCompareFlags flags)
{
	NMSettingIPConfigPrivate *a_priv;
	NMSettingIPConfigPrivate *b_priv;
	guint i;

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_IP_CONFIG_ADDRESSES)) {
		if (other) {
			a_priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
			b_priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (other);

			if (a_priv->addresses->len != b_priv->addresses->len)
				return FALSE;
			for (i = 0; i < a_priv->addresses->len; i++) {
				if (!_nm_ip_address_equal (a_priv->addresses->pdata[i], b_priv->addresses->pdata[i], TRUE))
					return FALSE;
			}
		}
		return TRUE;
	}

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_IP_CONFIG_ROUTES)) {
		if (other) {
			a_priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
			b_priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (other);

			if (a_priv->routes->len != b_priv->routes->len)
				return FALSE;
			for (i = 0; i < a_priv->routes->len; i++) {
				if (!nm_ip_route_equal_full (a_priv->routes->pdata[i], b_priv->routes->pdata[i], NM_IP_ROUTE_EQUAL_CMP_FLAGS_WITH_ATTRS))
					return FALSE;
			}
		}
		return TRUE;
	}

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_IP_CONFIG_ROUTING_RULES)) {
		if (other) {
			guint n;

			a_priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
			b_priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (other);

			n = (a_priv->routing_rules) ? a_priv->routing_rules->len : 0u;
			if (n != (b_priv->routing_rules ? b_priv->routing_rules->len : 0u))
				return FALSE;
			for (i = 0; i < n; i++) {
				if (nm_ip_routing_rule_cmp (a_priv->routing_rules->pdata[i], b_priv->routing_rules->pdata[i]) != 0)
					return FALSE;
			}
		}
		return TRUE;
	}

	return NM_SETTING_CLASS (nm_setting_ip_config_parent_class)->compare_property (sett_info,
	                                                                               property_idx,
	                                                                               setting,
	                                                                               other,
	                                                                               flags);
}

static void
duplicate_copy_properties (const NMSettInfoSetting *sett_info,
                           NMSetting *src,
                           NMSetting *dst)
{
	NMSettingIPConfigPrivate *priv_src = NM_SETTING_IP_CONFIG_GET_PRIVATE (src);
	NMSettingIPConfigPrivate *priv_dst = NM_SETTING_IP_CONFIG_GET_PRIVATE (dst);
	guint i;
	gboolean changed = FALSE;

	NM_SETTING_CLASS (nm_setting_ip_config_parent_class)->duplicate_copy_properties (sett_info,
	                                                                                 src,
	                                                                                 dst);

	if (   priv_dst->routing_rules
	    && priv_dst->routing_rules->len > 0) {
		changed = TRUE;
		g_ptr_array_set_size (priv_dst->routing_rules, 0);
	}
	if (   priv_src->routing_rules
	    && priv_src->routing_rules->len > 0) {
		changed = TRUE;
		if (!priv_dst->routing_rules)
			priv_dst->routing_rules = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_routing_rule_unref);
		for (i = 0; i < priv_src->routing_rules->len; i++) {
			g_ptr_array_add (priv_dst->routing_rules,
			                 nm_ip_routing_rule_ref (priv_src->routing_rules->pdata[i]));
		}
	}
	if (changed)
		_routing_rules_notify (NM_SETTING_IP_CONFIG (dst));
}

static void
enumerate_values (const NMSettInfoProperty *property_info,
                  NMSetting *setting,
                  NMSettingValueIterFn func,
                  gpointer user_data)
{
	if (nm_streq (property_info->name, NM_SETTING_IP_CONFIG_ROUTING_RULES)) {
		NMSettingIPConfigPrivate *priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
		nm_auto_unset_gvalue GValue value = G_VALUE_INIT;
		GPtrArray *ptr = NULL;
		guint i;

		if (priv->routing_rules && priv->routing_rules->len > 0) {
			ptr = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_ip_routing_rule_unref);
			for (i = 0; i < priv->routing_rules->len; i++)
				g_ptr_array_add (ptr, nm_ip_routing_rule_ref (priv->routing_rules->pdata[i]));
		}
		g_value_init (&value, G_TYPE_PTR_ARRAY);
		g_value_take_boxed (&value, ptr);
		func (setting,
		      property_info->name,
		      &value,
		      0,
		      user_data);
		return;
	}

	NM_SETTING_CLASS (nm_setting_ip_config_parent_class)->enumerate_values (property_info,
	                                                                        setting,
	                                                                        func,
	                                                                        user_data);
}

/*****************************************************************************/

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

GArray *
_nm_sett_info_property_override_create_array_ip_config (void)
{
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	_properties_override_add_override (properties_override,
	                                   obj_properties[PROP_GATEWAY],
	                                   G_VARIANT_TYPE_STRING,
	                                   NULL,
	                                   ip_gateway_set,
	                                   NULL);

	/* ---dbus---
	 * property: routing-rules
	 * format: array of 'a{sv}'
	 * description: Array of dictionaries for routing rules.
	 * ---end---
	 */
	_properties_override_add_dbus_only (properties_override,
	                                    NM_SETTING_IP_CONFIG_ROUTING_RULES,
	                                    G_VARIANT_TYPE ("aa{sv}"),
	                                    _routing_rules_dbus_only_synth,
	                                    _routing_rules_dbus_only_set);

	return properties_override;
}

/*****************************************************************************/

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
	case PROP_DNS_PRIORITY:
		g_value_set_int (value, priv->dns_priority);
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
	case PROP_ROUTE_TABLE:
		g_value_set_uint (value, priv->route_table);
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

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingIPConfig *setting = NM_SETTING_IP_CONFIG (object);
	NMSettingIPConfigPrivate *priv = NM_SETTING_IP_CONFIG_GET_PRIVATE (setting);
	const char *gateway;
	char **strv;
	guint i;

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
	case PROP_DNS_PRIORITY:
		priv->dns_priority = g_value_get_int (value);
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
	case PROP_ROUTE_TABLE:
		priv->route_table = g_value_get_uint (value);
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

/*****************************************************************************/

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
	if (priv->routing_rules)
		g_ptr_array_unref (priv->routing_rules);

	G_OBJECT_CLASS (nm_setting_ip_config_parent_class)->finalize (object);
}

static void
nm_setting_ip_config_class_init (NMSettingIPConfigClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMSettingIPConfigPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify                    = verify;
	setting_class->compare_property          = compare_property;
	setting_class->duplicate_copy_properties = duplicate_copy_properties;
	setting_class->enumerate_values          = enumerate_values;

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
	 * manual IPv4 address or otherwise 10.42.x.0/24 is chosen. Note that the
	 * shared method must be configured on the interface which shares the internet
	 * to a subnet, not on the uplink which is shared.
	 **/
	obj_properties[PROP_METHOD] =
	    g_param_spec_string (NM_SETTING_IP_CONFIG_METHOD, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:dns:
	 *
	 * Array of IP addresses of DNS servers.
	 **/
	obj_properties[PROP_DNS] =
	    g_param_spec_boxed (NM_SETTING_IP_CONFIG_DNS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:dns-search:
	 *
	 * Array of DNS search domains. Domains starting with a tilde ('~')
	 * are considered 'routing' domains and are used only to decide the
	 * interface over which a query must be forwarded; they are not used
	 * to complete unqualified host names.
	 **/
	obj_properties[PROP_DNS_SEARCH] =
	    g_param_spec_boxed (NM_SETTING_IP_CONFIG_DNS_SEARCH, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:dns-options:
	 *
	 * Array of DNS options as described in man 5 resolv.conf.
	 *
	 * %NULL means that the options are unset and left at the default.
	 * In this case NetworkManager will use default options. This is
	 * distinct from an empty list of properties.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_DNS_OPTIONS] =
	    g_param_spec_boxed (NM_SETTING_IP_CONFIG_DNS_OPTIONS, "", "",
	                        G_TYPE_STRV,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:dns-priority:
	 *
	 * DNS servers priority.
	 *
	 * The relative priority for DNS servers specified by this setting.  A lower
	 * value is better (higher priority). Zero selects a globally configured
	 * default value. If the latter is missing or zero too, it defaults to
	 * 50 for VPNs and 100 for other connections.
	 *
	 * Note that the priority is to order DNS settings for multiple active
	 * connections.  It does not disambiguate multiple DNS servers within the
	 * same connection profile.
	 *
	 * When using dns=default, servers with higher priority will be on top of
	 * resolv.conf.  To prioritize a given server over another one within the
	 * same connection, just specify them in the desired order.  When multiple
	 * devices have configurations with the same priority, the one with an
	 * active default route will be preferred.  Negative values have the special
	 * effect of excluding other configurations with a greater priority value;
	 * so in presence of at least a negative priority, only DNS servers from
	 * connections with the lowest priority value will be used.
	 *
	 * When using a DNS resolver that supports split-DNS as dns=dnsmasq or
	 * dns=systemd-resolved, each connection is used to query domains in its
	 * search list.  Queries for domains not present in any search list are
	 * routed through connections having the '~.' special wildcard domain, which
	 * is added automatically to connections with the default route (or can be
	 * added manually).  When multiple connections specify the same domain, the
	 * one with the highest priority (lowest numerical value) wins.  If a
	 * connection specifies a domain which is subdomain of another domain with a
	 * negative DNS priority value, the subdomain is ignored.
	 *
	 * Since: 1.4
	 **/
	obj_properties[PROP_DNS_PRIORITY] =
	     g_param_spec_int (NM_SETTING_IP_CONFIG_DNS_PRIORITY, "", "",
	                       G_MININT32, G_MAXINT32, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:addresses: (type GPtrArray(NMIPAddress))
	 *
	 * Array of IP addresses.
	 **/
	obj_properties[PROP_ADDRESSES] =
	    g_param_spec_boxed (NM_SETTING_IP_CONFIG_ADDRESSES, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_INFERRABLE |
	                        /* "addresses" is a legacy D-Bus property, because the
	                         * "addresses" GObject property normally gets set from
	                         * the "address-data" D-Bus property...
	                         */
	                        NM_SETTING_PARAM_LEGACY |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:gateway:
	 *
	 * The gateway associated with this configuration. This is only meaningful
	 * if #NMSettingIPConfig:addresses is also set.
	 **/
	obj_properties[PROP_GATEWAY] =
	    g_param_spec_string (NM_SETTING_IP_CONFIG_GATEWAY, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:routes: (type GPtrArray(NMIPRoute))
	 *
	 * Array of IP routes.
	 **/
	obj_properties[PROP_ROUTES] =
	    g_param_spec_boxed (NM_SETTING_IP_CONFIG_ROUTES, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READWRITE |
	                        NM_SETTING_PARAM_INFERRABLE |
	                        /* See :addresses above Re: LEGACY */
	                        NM_SETTING_PARAM_LEGACY |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:route-metric:
	 *
	 * The default metric for routes that don't explicitly specify a metric.
	 * The default value -1 means that the metric is chosen automatically
	 * based on the device type.
	 * The metric applies to dynamic routes, manual (static) routes that
	 * don't have an explicit metric setting, address prefix routes, and
	 * the default route.
	 * Note that for IPv6, the kernel accepts zero (0) but coerces it to
	 * 1024 (user default). Hence, setting this property to zero effectively
	 * mean setting it to 1024.
	 * For IPv4, zero is a regular value for the metric.
	 **/
	obj_properties[PROP_ROUTE_METRIC] =
	     g_param_spec_int64 (NM_SETTING_IP_CONFIG_ROUTE_METRIC, "", "",
	                         -1, G_MAXUINT32, -1,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:route-table:
	 *
	 * Enable policy routing (source routing) and set the routing table used when adding routes.
	 *
	 * This affects all routes, including device-routes, IPv4LL, DHCP, SLAAC, default-routes
	 * and static routes. But note that static routes can individually overwrite the setting
	 * by explicitly specifying a non-zero routing table.
	 *
	 * If the table setting is left at zero, it is eligible to be overwritten via global
	 * configuration. If the property is zero even after applying the global configuration
	 * value, policy routing is disabled for the address family of this connection.
	 *
	 * Policy routing disabled means that NetworkManager will add all routes to the main
	 * table (except static routes that explicitly configure a different table). Additionally,
	 * NetworkManager will not delete any extraneous routes from tables except the main table.
	 * This is to preserve backward compatibility for users who manage routing tables outside
	 * of NetworkManager.
	 *
	 * Since: 1.10
	 **/
	obj_properties[PROP_ROUTE_TABLE] =
	    g_param_spec_uint (NM_SETTING_IP_CONFIG_ROUTE_TABLE, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READWRITE |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);
	/**
	 * NMSettingIPConfig:ignore-auto-routes:
	 *
	 * When #NMSettingIPConfig:method is set to "auto" and this property to
	 * %TRUE, automatically configured routes are ignored and only routes
	 * specified in the #NMSettingIPConfig:routes property, if any, are used.
	 **/
	obj_properties[PROP_IGNORE_AUTO_ROUTES] =
	    g_param_spec_boolean (NM_SETTING_IP_CONFIG_IGNORE_AUTO_ROUTES, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:ignore-auto-dns:
	 *
	 * When #NMSettingIPConfig:method is set to "auto" and this property to
	 * %TRUE, automatically configured nameservers and search domains are
	 * ignored and only nameservers and search domains specified in the
	 * #NMSettingIPConfig:dns and #NMSettingIPConfig:dns-search properties, if
	 * any, are used.
	 **/
	obj_properties[PROP_IGNORE_AUTO_DNS] =
	    g_param_spec_boolean (NM_SETTING_IP_CONFIG_IGNORE_AUTO_DNS, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:dhcp-hostname:
	 *
	 * If the #NMSettingIPConfig:dhcp-send-hostname property is %TRUE, then the
	 * specified name will be sent to the DHCP server when acquiring a lease.
	 * This property and #NMSettingIP4Config:dhcp-fqdn are mutually exclusive and
	 * cannot be set at the same time.
	 **/
	obj_properties[PROP_DHCP_HOSTNAME] =
	    g_param_spec_string (NM_SETTING_IP_CONFIG_DHCP_HOSTNAME, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:dhcp-send-hostname:
	 *
	 * If %TRUE, a hostname is sent to the DHCP server when acquiring a lease.
	 * Some DHCP servers use this hostname to update DNS databases, essentially
	 * providing a static hostname for the computer.  If the
	 * #NMSettingIPConfig:dhcp-hostname property is %NULL and this property is
	 * %TRUE, the current persistent hostname of the computer is sent.
	 **/
	obj_properties[PROP_DHCP_SEND_HOSTNAME] =
	    g_param_spec_boolean (NM_SETTING_IP_CONFIG_DHCP_SEND_HOSTNAME, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:never-default:
	 *
	 * If %TRUE, this connection will never be the default connection for this
	 * IP type, meaning it will never be assigned the default route by
	 * NetworkManager.
	 **/
	obj_properties[PROP_NEVER_DEFAULT] =
	    g_param_spec_boolean (NM_SETTING_IP_CONFIG_NEVER_DEFAULT, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_MAY_FAIL] =
	    g_param_spec_boolean (NM_SETTING_IP_CONFIG_MAY_FAIL, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:dad-timeout:
	 *
	 * Timeout in milliseconds used to check for the presence of duplicate IP
	 * addresses on the network.  If an address conflict is detected, the
	 * activation will fail.  A zero value means that no duplicate address
	 * detection is performed, -1 means the default value (either configuration
	 * ipvx.dad-timeout override or zero).  A value greater than zero is a
	 * timeout in milliseconds.
	 *
	 * The property is currently implemented only for IPv4.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_DAD_TIMEOUT] =
	    g_param_spec_int (NM_SETTING_IP_CONFIG_DAD_TIMEOUT, "", "",
	                       -1, NM_SETTING_IP_CONFIG_DAD_TIMEOUT_MAX, -1,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingIPConfig:dhcp-timeout:
	 *
	 * A timeout for a DHCP transaction in seconds.
	 **/
	obj_properties[PROP_DHCP_TIMEOUT] =
	    g_param_spec_int (NM_SETTING_IP_CONFIG_DHCP_TIMEOUT, "", "",
	                      0, G_MAXINT32, 0,
	                      G_PARAM_READWRITE |
	                      NM_SETTING_PARAM_FUZZY_IGNORE |
	                      G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
