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
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2008 - 2014 Red Hat, Inc.
 */

#include <string.h>

#include <nm-setting-ip6-config.h>
#include "nm-ip6-config.h"
#include "nm-dbus-interface.h"
#include "nm-object-private.h"
#include "nm-utils.h"
#include "nm-dbus-glib-types.h"
#include "nm-core-internal.h"

G_DEFINE_TYPE (NMIP6Config, nm_ip6_config, NM_TYPE_OBJECT)

#define NM_IP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP6_CONFIG, NMIP6ConfigPrivate))

typedef struct {
	DBusGProxy *proxy;

	char *gateway;
	GSList *addresses;
	GSList *routes;
	char **nameservers;
	char **domains;
	char **searches;
} NMIP6ConfigPrivate;

enum {
	PROP_0,
	PROP_GATEWAY,
	PROP_ADDRESSES,
	PROP_ROUTES,
	PROP_NAMESERVERS,
	PROP_DOMAINS,
	PROP_SEARCHES,

	LAST_PROP
};

static gboolean
demarshal_ip6_address_array (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip6_address_unref);
	priv->addresses = NULL;

	priv->addresses = nm_utils_ip6_addresses_from_gvalue (value);
	_nm_object_queue_notify (object, NM_IP6_CONFIG_ADDRESSES);

	return TRUE;
}

static gboolean
demarshal_ip6_nameserver_array (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	GPtrArray *ip_array;
	char ***obj_field;
	int i;

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR))
		return FALSE;

	ip_array = g_value_get_boxed (value);

	obj_field = field;
	if (*obj_field)
		g_strfreev (*obj_field);

	*obj_field = g_new (char *, ip_array ? ip_array->len + 1 : 1);
	for (i = 0; ip_array && i < ip_array->len; i++) {
		GByteArray *ip = g_ptr_array_index (ip_array, i);
		const char *str;

		str = nm_utils_inet6_ntop ((struct in6_addr *) ip->data, NULL);
		(*obj_field)[i] = g_strdup (str);
	}
	(*obj_field)[i] = NULL;

	_nm_object_queue_notify (object, pspec->name);
	return TRUE;
}

static gboolean
demarshal_ip6_routes_array (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip6_route_unref);
	priv->routes = NULL;

	priv->routes = nm_utils_ip6_routes_from_gvalue (value);
	_nm_object_queue_notify (object, NM_IP6_CONFIG_ROUTES);

	return TRUE;
}

static void
init_dbus (NMObject *object)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_IP6_CONFIG_GATEWAY,      &priv->gateway, },
		{ NM_IP6_CONFIG_ADDRESSES,    &priv->addresses, demarshal_ip6_address_array },
		{ NM_IP6_CONFIG_ROUTES,       &priv->routes, demarshal_ip6_routes_array },
		{ NM_IP6_CONFIG_NAMESERVERS,  &priv->nameservers, demarshal_ip6_nameserver_array },
		{ NM_IP6_CONFIG_DOMAINS,      &priv->domains, },
		{ NM_IP6_CONFIG_SEARCHES,     &priv->searches, },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_ip6_config_parent_class)->init_dbus (object);

	priv->proxy = _nm_object_new_proxy (object, NULL, NM_DBUS_INTERFACE_IP6_CONFIG);
	_nm_object_register_properties (object,
	                                priv->proxy,
	                                property_info);
}

/**
 * nm_ip6_config_get_gateway:
 * @config: a #NMIP6Config
 *
 * Gets the IP6 gateway.
 *
 * Returns: the IPv6 gateway of the configuration.
 **/
const char *
nm_ip6_config_get_gateway (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	return NM_IP6_CONFIG_GET_PRIVATE (config)->gateway;
}

/**
 * nm_ip6_config_get_addresses:
 * @config: a #NMIP6Config
 *
 * Gets the IP6 addresses (containing the address, prefix, and gateway).
 *
 * Returns: (element-type NMIP6Address): the #GSList containing
 * #NMIP6Address<!-- -->es. This is the internal copy used by the configuration
 * and must not be modified.
 **/
const GSList *
nm_ip6_config_get_addresses (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	return NM_IP6_CONFIG_GET_PRIVATE (config)->addresses;
}

/**
 * nm_ip6_config_get_nameservers:
 * @config: a #NMIP6Config
 *
 * Gets the domain name servers (DNS).
 *
 * Returns: the array of nameserver IP addresses
 **/
const char * const *
nm_ip6_config_get_nameservers (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	return (const char * const *) NM_IP6_CONFIG_GET_PRIVATE (config)->nameservers;
}

/**
 * nm_ip6_config_get_domains:
 * @config: a #NMIP6Config
 *
 * Gets the domain names.
 *
 * Returns: the array of domains. (This is never %NULL, though it may be 0-length).
 **/
const char * const *
nm_ip6_config_get_domains (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	return (const char * const *) NM_IP6_CONFIG_GET_PRIVATE (config)->domains;
}

/**
 * nm_ip6_config_get_searches:
 * @config: a #NMIP6Config
 *
 * Gets the DNS search strings.
 *
 * Returns: the array of DNS search strings. (This is never %NULL, though it may be 0-length).
 **/
const char * const *
nm_ip6_config_get_searches (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	return (const char * const *) NM_IP6_CONFIG_GET_PRIVATE (config)->searches;
}

/**
 * nm_ip6_config_get_routes:
 * @config: a #NMIP6Config
 *
 * Gets the routes.
 *
 * Returns: (element-type NMIP6Route): the #GSList containing
 * #NMIP6Routes. This is the internal copy used by the configuration,
 * and must not be modified.
 **/
const GSList *
nm_ip6_config_get_routes (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	return NM_IP6_CONFIG_GET_PRIVATE (config)->routes;
}

static void
finalize (GObject *object)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	g_free (priv->gateway);

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip6_address_unref);
	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip6_route_unref);

	g_strfreev (priv->nameservers);
	g_strfreev (priv->domains);
	g_strfreev (priv->searches);

	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_ip6_config_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMIP6Config *self = NM_IP6_CONFIG (object);
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_GATEWAY:
		g_value_set_string (value, nm_ip6_config_get_gateway (self));
		break;
	case PROP_ADDRESSES:
		g_value_take_boxed (value, _nm_utils_copy_slist_to_array (priv->addresses,
		                                                          (NMUtilsCopyFunc) nm_ip6_address_dup,
		                                                          (GDestroyNotify) nm_ip6_address_unref));
		break;
	case PROP_ROUTES:
		g_value_take_boxed (value, _nm_utils_copy_slist_to_array (priv->routes,
		                                                          (NMUtilsCopyFunc) nm_ip6_route_dup,
		                                                          (GDestroyNotify) nm_ip6_route_unref));
		break;
	case PROP_NAMESERVERS:
		g_value_set_boxed (value, (char **) nm_ip6_config_get_nameservers (self));
		break;
	case PROP_DOMAINS:
		g_value_set_boxed (value, (char **) nm_ip6_config_get_domains (self));
		break;
	case PROP_SEARCHES:
		g_value_set_boxed (value, (char **) nm_ip6_config_get_searches (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ip6_config_init (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	priv->nameservers = g_new0 (char *, 1);
	priv->domains = g_new0 (char *, 1);
	priv->searches = g_new0 (char *, 1);
}

static void
nm_ip6_config_class_init (NMIP6ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMIP6ConfigPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	/* properties */

	/**
	 * NMIP6Config:gateway:
	 *
	 * The IPv6 gateway as string
	 **/
	g_object_class_install_property
	    (object_class, PROP_GATEWAY,
	     g_param_spec_string (NM_IP6_CONFIG_GATEWAY, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP6Config:addresses:
	 *
	 * The #GPtrArray containing the IPv6 addresses (#NMIP6Address).
	 **/
	g_object_class_install_property
	    (object_class, PROP_ADDRESSES,
	     g_param_spec_boxed (NM_IP6_CONFIG_ADDRESSES, "", "",
	                         G_TYPE_PTR_ARRAY,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP6Config:routes:
	 *
	 * The #GPtrArray containing the IPv6 routes (#NMIP6Route).
	 **/
	g_object_class_install_property
	    (object_class, PROP_ROUTES,
	     g_param_spec_boxed (NM_IP6_CONFIG_ROUTES, "", "",
	                         G_TYPE_PTR_ARRAY,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP6Config:nameservers:
	 *
	 * The #GPtrArray containing elements of type 'struct ip6_addr' which
	 * contain the addresses of nameservers of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_NAMESERVERS,
	     g_param_spec_boxed (NM_IP6_CONFIG_NAMESERVERS, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP6Config:domains:
	 *
	 * The #GPtrArray containing domain strings of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_DOMAINS,
	     g_param_spec_boxed (NM_IP6_CONFIG_DOMAINS, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP6Config:searches:
	 *
	 * The #GPtrArray containing dns search strings of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_SEARCHES,
	     g_param_spec_boxed (NM_IP6_CONFIG_SEARCHES, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

}
