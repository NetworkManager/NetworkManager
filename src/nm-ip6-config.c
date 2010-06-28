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

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include "nm-ip6-config.h"
#include "nm-dbus-manager.h"
#include "NetworkManager.h"
#include "NetworkManagerUtils.h"
#include "nm-setting-ip6-config.h"
#include "nm-utils.h"

#include <netlink/route/addr.h>
#include <netlink/utils.h>
#include <netinet/in.h>

#include "nm-ip6-config-glue.h"
#include "nm-dbus-glib-types.h"


G_DEFINE_TYPE (NMIP6Config, nm_ip6_config, G_TYPE_OBJECT)

#define NM_IP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP6_CONFIG, NMIP6ConfigPrivate))

typedef struct {
	char *path;

	GSList *addresses;
	struct in6_addr ptp_address;

	guint32	mss;	/* Maximum Segment Size of the route */

	GArray *nameservers;
	GPtrArray *domains;
	GPtrArray *searches;

	GSList *routes;

	gboolean never_default;
} NMIP6ConfigPrivate;


enum {
	PROP_0,
	PROP_ADDRESSES,
	PROP_NAMESERVERS,
	PROP_DOMAINS,
	PROP_ROUTES,

	LAST_PROP
};


static struct nl_addr *
nm_utils_ip6_addr_to_nl_addr (const struct in6_addr *ip6_addr)
{
	struct nl_addr * nla = NULL;

	if (!(nla = nl_addr_alloc (sizeof (struct in6_addr))))
		return NULL;
	nl_addr_set_family (nla, AF_INET6);
	nl_addr_set_binary_addr (nla, (struct in6_addr *)ip6_addr, sizeof (struct in6_addr));

	return nla;
}


NMIP6Config *
nm_ip6_config_new (void)
{
	return (NMIP6Config *) g_object_new (NM_TYPE_IP6_CONFIG, NULL);
}

void
nm_ip6_config_export (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv;
	NMDBusManager *dbus_mgr;
	DBusGConnection *connection;
	static guint32 counter = 0;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	g_return_if_fail (priv->path == NULL);

	dbus_mgr = nm_dbus_manager_get ();
	connection = nm_dbus_manager_get_connection (dbus_mgr);
	priv->path = g_strdup_printf (NM_DBUS_PATH "/IP6Config/%d", counter++);

	dbus_g_connection_register_g_object (connection, priv->path, G_OBJECT (config));
	g_object_unref (dbus_mgr);
}

const char *
nm_ip6_config_get_dbus_path (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), FALSE);

	return NM_IP6_CONFIG_GET_PRIVATE (config)->path;
}

void
nm_ip6_config_take_address (NMIP6Config *config, NMIP6Address *address)
{
	NMIP6ConfigPrivate *priv;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));
	g_return_if_fail (address != NULL);

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	priv->addresses = g_slist_append (priv->addresses, address);
}

void
nm_ip6_config_add_address (NMIP6Config *config,
                           NMIP6Address *address)
{
	NMIP6ConfigPrivate *priv;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));
	g_return_if_fail (address != NULL);

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	priv->addresses = g_slist_append (priv->addresses, nm_ip6_address_dup (address));
}

void
nm_ip6_config_replace_address (NMIP6Config *config,
                               guint i,
                               NMIP6Address *new_address)
{
	NMIP6ConfigPrivate *priv;
	GSList *old;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	old = g_slist_nth (priv->addresses, i);
	g_return_if_fail (old != NULL);
	nm_ip6_address_unref ((NMIP6Address *) old->data);

	old->data = nm_ip6_address_dup (new_address);
}

NMIP6Address *nm_ip6_config_get_address (NMIP6Config *config, guint i)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	return (NMIP6Address *) g_slist_nth_data (NM_IP6_CONFIG_GET_PRIVATE (config)->addresses, i);
}

guint32 nm_ip6_config_get_num_addresses (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), 0);

	return g_slist_length (NM_IP6_CONFIG_GET_PRIVATE (config)->addresses);
}

const struct in6_addr *nm_ip6_config_get_ptp_address (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), 0);

	return &NM_IP6_CONFIG_GET_PRIVATE (config)->ptp_address;
}

void nm_ip6_config_set_ptp_address (NMIP6Config *config, const struct in6_addr *ptp_addr)
{
	g_return_if_fail (NM_IS_IP6_CONFIG (config));

	NM_IP6_CONFIG_GET_PRIVATE (config)->ptp_address = *ptp_addr;
}

void nm_ip6_config_add_nameserver (NMIP6Config *config, const struct in6_addr *nameserver)
{
	NMIP6ConfigPrivate *priv;
	struct in6_addr *nameservers;
	int i;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));
	g_return_if_fail (nameserver != NULL);

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	/* No dupes */
	nameservers = (struct in6_addr *)priv->nameservers->data;
	for (i = 0; i < priv->nameservers->len; i++)
		g_return_if_fail (IN6_ARE_ADDR_EQUAL (nameserver, &nameservers[i]) == FALSE);

	g_array_append_val (priv->nameservers, *nameserver);
}

const struct in6_addr *nm_ip6_config_get_nameserver (NMIP6Config *config, guint i)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), 0);

	return &g_array_index (NM_IP6_CONFIG_GET_PRIVATE (config)->nameservers, struct in6_addr, i);
}

guint32 nm_ip6_config_get_num_nameservers (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), 0);

	return NM_IP6_CONFIG_GET_PRIVATE (config)->nameservers->len;
}

void nm_ip6_config_reset_nameservers (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	if (priv->nameservers->len)
		g_array_remove_range (priv->nameservers, 0, priv->nameservers->len);
}

void
nm_ip6_config_take_route (NMIP6Config *config, NMIP6Route *route)
{
	NMIP6ConfigPrivate *priv;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));
	g_return_if_fail (route != NULL);

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	priv->routes = g_slist_append (priv->routes, route);
}

void
nm_ip6_config_add_route (NMIP6Config *config, NMIP6Route *route)
{
	NMIP6ConfigPrivate *priv;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));
	g_return_if_fail (route != NULL);

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	priv->routes = g_slist_append (priv->routes, nm_ip6_route_dup (route));
}

void
nm_ip6_config_replace_route (NMIP6Config *config,
							 guint i,
							 NMIP6Route *new_route)
{
	NMIP6ConfigPrivate *priv;
	GSList *old;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	old = g_slist_nth (priv->routes, i);
	g_return_if_fail (old != NULL);
	nm_ip6_route_unref ((NMIP6Route *) old->data);

	old->data = nm_ip6_route_dup (new_route);
}

NMIP6Route *
nm_ip6_config_get_route (NMIP6Config *config, guint i)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	return (NMIP6Route *) g_slist_nth_data (NM_IP6_CONFIG_GET_PRIVATE (config)->routes, i);
}

guint32 nm_ip6_config_get_num_routes (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), 0);

	return g_slist_length (NM_IP6_CONFIG_GET_PRIVATE (config)->routes);
}

void nm_ip6_config_reset_routes (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	g_slist_foreach (priv->routes, (GFunc) g_free, NULL);
	priv->routes = NULL;
}

void nm_ip6_config_add_domain (NMIP6Config *config, const char *domain)
{
	NMIP6ConfigPrivate *priv;
	int i;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));
	g_return_if_fail (domain != NULL);
	g_return_if_fail (strlen (domain) > 0);

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	for (i = 0; i < priv->domains->len; i++) {
		if (!strcmp (g_ptr_array_index (priv->domains, i), domain))
			return;
	}

	g_ptr_array_add (priv->domains, g_strdup (domain));
}

const char *nm_ip6_config_get_domain (NMIP6Config *config, guint i)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	return (const char *) g_ptr_array_index (NM_IP6_CONFIG_GET_PRIVATE (config)->domains, i);
}

guint32 nm_ip6_config_get_num_domains (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), 0);

	return NM_IP6_CONFIG_GET_PRIVATE (config)->domains->len;
}

void nm_ip6_config_reset_domains (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv;
	int i;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	for (i = 0; i < priv->domains->len; i++)
		g_free (g_ptr_array_index (priv->domains, i));
	g_ptr_array_free (priv->domains, TRUE);
	priv->domains = g_ptr_array_sized_new (3);
}

void nm_ip6_config_add_search (NMIP6Config *config, const char *search)
{
	NMIP6ConfigPrivate *priv;
	int i;

	g_return_if_fail (config != NULL);
	g_return_if_fail (search != NULL);
	g_return_if_fail (strlen (search) > 0);

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	for (i = 0; i < priv->searches->len; i++) {
		if (!strcmp (g_ptr_array_index (priv->searches, i), search))
			return;
	}

	g_ptr_array_add (priv->searches, g_strdup (search));
}

const char *nm_ip6_config_get_search (NMIP6Config *config, guint i)
{
	g_return_val_if_fail (config != NULL, NULL);

	return (const char *) g_ptr_array_index (NM_IP6_CONFIG_GET_PRIVATE (config)->searches, i);
}

guint32 nm_ip6_config_get_num_searches (NMIP6Config *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return NM_IP6_CONFIG_GET_PRIVATE (config)->searches->len;
}

void nm_ip6_config_reset_searches (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv;
	int i;

	g_return_if_fail (NM_IS_IP6_CONFIG (config));

	priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	for (i = 0; i < priv->searches->len; i++)
		g_free (g_ptr_array_index (priv->searches, i));
	g_ptr_array_free (priv->searches, TRUE);
	priv->searches = g_ptr_array_sized_new (3);
}

guint32 nm_ip6_config_get_mss (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), 0);

	return NM_IP6_CONFIG_GET_PRIVATE (config)->mss;
}

void nm_ip6_config_set_mss (NMIP6Config *config, guint32 mss)
{
	g_return_if_fail (NM_IS_IP6_CONFIG (config));

	NM_IP6_CONFIG_GET_PRIVATE (config)->mss = mss;
}

gboolean
nm_ip6_config_get_never_default (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), FALSE);

	return NM_IP6_CONFIG_GET_PRIVATE (config)->never_default;
}

void
nm_ip6_config_set_never_default (NMIP6Config *config, gboolean never_default)
{
	g_return_if_fail (NM_IS_IP6_CONFIG (config));

	NM_IP6_CONFIG_GET_PRIVATE (config)->never_default = never_default;
}

/* libnl convenience/conversion functions */

static int ip6_addr_to_rtnl_local (const struct in6_addr *ip6_address, struct rtnl_addr *addr)
{
	struct nl_addr * local = NULL;
	int err = 0;

	g_return_val_if_fail (addr != NULL, -1);

	local = nm_utils_ip6_addr_to_nl_addr (ip6_address);
	err = rtnl_addr_set_local (addr, local);
	nl_addr_put (local);

	return err;
}

static int ip6_addr_to_rtnl_peer (const struct in6_addr *ip6_address, struct rtnl_addr *addr)
{
	struct nl_addr * peer = NULL;
	int err = 0;

	g_return_val_if_fail (addr != NULL, -1);

	peer = nm_utils_ip6_addr_to_nl_addr (ip6_address);
	err = rtnl_addr_set_peer (addr, peer);
	nl_addr_put (peer);

	return err;
}

struct rtnl_addr *
nm_ip6_config_to_rtnl_addr (NMIP6Config *config, guint32 i, guint32 flags)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	NMIP6Address *config_addr;
	struct rtnl_addr *addr;
	gboolean success = TRUE;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	config_addr = nm_ip6_config_get_address (config, i);
	g_return_val_if_fail (config_addr != NULL, NULL);

	if (!(addr = rtnl_addr_alloc()))
		return NULL;

	if (flags & NM_RTNL_ADDR_ADDR)
		success = (ip6_addr_to_rtnl_local (nm_ip6_address_get_address (config_addr), addr) >= 0);

	if (flags & NM_RTNL_ADDR_PTP_ADDR)
		success = (ip6_addr_to_rtnl_peer (&priv->ptp_address, addr) >= 0);

	if (flags & NM_RTNL_ADDR_PREFIX)
		rtnl_addr_set_prefixlen (addr, nm_ip6_address_get_prefix (config_addr));

	if (!success) {
		rtnl_addr_put (addr);
		addr = NULL;
	}

	return addr;
}

static gboolean
addr_slist_compare (GSList *a, GSList *b)
{
	GSList *iter_a, *iter_b;
	gboolean found = FALSE;

	for (iter_a = a; iter_a; iter_a = g_slist_next (iter_a)) {
		NMIP6Address *addr_a = (NMIP6Address *) iter_a->data;

		for (iter_b = b, found = FALSE; iter_b; iter_b = g_slist_next (iter_b)) {
			NMIP6Address *addr_b = (NMIP6Address *) iter_b->data;

			if (nm_ip6_address_compare (addr_a, addr_b)) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			return FALSE;
	}
	return TRUE;
}

static gboolean
route_slist_compare (GSList *a, GSList *b)
{
	GSList *iter_a, *iter_b;
	gboolean found = FALSE;

	for (iter_a = a; iter_a; iter_a = g_slist_next (iter_a)) {
		NMIP6Route *route_a = (NMIP6Route *) iter_a->data;

		for (iter_b = b, found = FALSE; iter_b; iter_b = g_slist_next (iter_b)) {
			NMIP6Route *route_b = (NMIP6Route *) iter_b->data;

			if (nm_ip6_route_compare (route_a, route_b)) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			return FALSE;
	}
	return TRUE;
}

static gboolean
string_array_compare (GPtrArray *a, GPtrArray *b)
{
	int i, j;
	gboolean found = FALSE;

	for (i = 0; i < a->len; i++) {
		for (j = 0, found = FALSE; j < b->len; j++) {
			const char *item_a = g_ptr_array_index (a, i);
			const char *item_b = g_ptr_array_index (b, j);

			if ((!item_a && !item_b) || (item_a && item_b && !strcmp (item_a, item_b))) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			return FALSE;
	}
	return TRUE;
}

static gboolean
addr_array_compare (GArray *a, GArray *b)
{
	struct in6_addr *addrs_a, *addrs_b;
	int i, j;
	gboolean found = FALSE;

	addrs_a = (struct in6_addr *)a->data;
	addrs_b = (struct in6_addr *)b->data;
	for (i = 0; i < a->len; i++) {
		for (j = 0, found = FALSE; j < b->len; j++) {
			if (IN6_ARE_ADDR_EQUAL (&addrs_a[i], &addrs_b[j])) {
				found = TRUE;
				break;
			}
		}

		if (!found)
			return FALSE;
	}
	return TRUE;
}

NMIP6ConfigCompareFlags
nm_ip6_config_diff (NMIP6Config *a, NMIP6Config *b)
{
	NMIP6ConfigPrivate *a_priv;
	NMIP6ConfigPrivate *b_priv;
	NMIP6ConfigCompareFlags flags = NM_IP6_COMPARE_FLAG_NONE;

	if ((a && !b) || (b && !a))
		return 0xFFFFFFFF;
	if (!a && !b)
		return NM_IP6_COMPARE_FLAG_NONE;

	a_priv = NM_IP6_CONFIG_GET_PRIVATE (a);
	b_priv = NM_IP6_CONFIG_GET_PRIVATE (b);

	if (   !addr_slist_compare (a_priv->addresses, b_priv->addresses)
	    || !addr_slist_compare (b_priv->addresses, a_priv->addresses))
		flags |= NM_IP6_COMPARE_FLAG_ADDRESSES;

	if (memcmp (&a_priv->ptp_address, &b_priv->ptp_address, sizeof (struct in6_addr)) != 0)
		flags |= NM_IP6_COMPARE_FLAG_PTP_ADDRESS;

	if (   (a_priv->nameservers->len != b_priv->nameservers->len)
	    || !addr_array_compare (a_priv->nameservers, b_priv->nameservers)
	    || !addr_array_compare (b_priv->nameservers, a_priv->nameservers))
		flags |= NM_IP6_COMPARE_FLAG_NAMESERVERS;

	if (   !route_slist_compare (a_priv->routes, b_priv->routes)
	    || !route_slist_compare (b_priv->routes, a_priv->routes))
		flags |= NM_IP6_COMPARE_FLAG_ROUTES;

	if (   (a_priv->domains->len != b_priv->domains->len)
	    || !string_array_compare (a_priv->domains, b_priv->domains)
	    || !string_array_compare (b_priv->domains, a_priv->domains))
		flags |= NM_IP6_COMPARE_FLAG_DOMAINS;

	if (   (a_priv->searches->len != b_priv->searches->len)
	    || !string_array_compare (a_priv->searches, b_priv->searches)
	    || !string_array_compare (b_priv->searches, a_priv->searches))
		flags |= NM_IP6_COMPARE_FLAG_SEARCHES;

	if (a_priv->mss != b_priv->mss)
		flags |= NM_IP6_COMPARE_FLAG_MSS;

	return flags;
}

static void
nm_ip6_config_init (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	priv->nameservers = g_array_new (FALSE, TRUE, sizeof (struct in6_addr));
	priv->domains = g_ptr_array_sized_new (3);
	priv->searches = g_ptr_array_sized_new (3);
}

static void
finalize (GObject *object)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	nm_utils_slist_free (priv->addresses, (GDestroyNotify) nm_ip6_address_unref);
	nm_utils_slist_free (priv->routes, (GDestroyNotify) nm_ip6_route_unref);
	g_array_free (priv->nameservers, TRUE);
	g_ptr_array_free (priv->domains, TRUE);
	g_ptr_array_free (priv->searches, TRUE);

	G_OBJECT_CLASS (nm_ip6_config_parent_class)->finalize (object);
}

static void
nameservers_to_gvalue (GArray *array, GValue *value)
{
	GPtrArray *dns;
	guint i = 0;

	dns = g_ptr_array_new ();

	while (array && (i < array->len)) {
		struct in6_addr *addr;
		GByteArray *bytearray;
		addr = &g_array_index (array, struct in6_addr, i++);

		bytearray = g_byte_array_sized_new (16);
		g_byte_array_append (bytearray, (guint8 *) addr->s6_addr, 16);
		g_ptr_array_add (dns, bytearray);
	}

	g_value_take_boxed (value, dns);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_ADDRESSES:
		nm_utils_ip6_addresses_to_gvalue (priv->addresses, value);
		break;
	case PROP_NAMESERVERS:
		nameservers_to_gvalue (priv->nameservers, value);
		break;
	case PROP_DOMAINS:
		g_value_set_boxed (value, priv->domains);
		break;
	case PROP_ROUTES:
		nm_utils_ip6_routes_to_gvalue (priv->routes, value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ip6_config_class_init (NMIP6ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMIP6ConfigPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property (object_class, PROP_ADDRESSES,
		g_param_spec_boxed (NM_IP6_CONFIG_ADDRESSES,
		                    "Addresses",
		                    "IP6 addresses",
		                    DBUS_TYPE_G_ARRAY_OF_IP6_ADDRESS,
		                    G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_NAMESERVERS,
		g_param_spec_boxed (NM_IP6_CONFIG_NAMESERVERS,
		                    "Nameservers",
		                    "DNS list",
		                    DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR,
		                    G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_DOMAINS,
		g_param_spec_boxed (NM_IP6_CONFIG_DOMAINS,
		                    "Domains",
		                    "Domains",
		                    DBUS_TYPE_G_ARRAY_OF_STRING,
		                    G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_ROUTES,
		g_param_spec_boxed (NM_IP6_CONFIG_ROUTES,
		                    "Routes",
		                    "Routes",
		                    DBUS_TYPE_G_ARRAY_OF_IP6_ROUTE,
		                    G_PARAM_READABLE));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (config_class),
									 &dbus_glib_nm_ip6_config_object_info);
}
