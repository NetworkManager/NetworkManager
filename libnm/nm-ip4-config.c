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
 * Copyright 2007 - 2011 Novell, Inc.
 * Copyright 2008 Red Hat, Inc.
 */

#include <string.h>

#include <nm-setting-ip4-config.h>
#include "nm-ip4-config.h"
#include "nm-dbus-interface.h"
#include "nm-types-private.h"
#include "nm-object-private.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMIP4Config, nm_ip4_config, NM_TYPE_OBJECT)

#define NM_IP4_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP4_CONFIG, NMIP4ConfigPrivate))

typedef struct {
	DBusGProxy *proxy;

	char *gateway;
	GSList *addresses;
	GSList *routes;
	char **nameservers;
	char **domains;
	char **searches;
	char **wins;
} NMIP4ConfigPrivate;

enum {
	PROP_0,
	PROP_GATEWAY,
	PROP_ADDRESSES,
	PROP_ROUTES,
	PROP_NAMESERVERS,
	PROP_DOMAINS,
	PROP_SEARCHES,
	PROP_WINS_SERVERS,

	LAST_PROP
};

static void
nm_ip4_config_init (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);

	priv->nameservers = g_new0 (char *, 1);
	priv->domains = g_new0 (char *, 1);
	priv->searches = g_new0 (char *, 1);
	priv->wins = g_new0 (char *, 1);
}

static gboolean
demarshal_ip4_address_array (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip4_address_unref);
	priv->addresses = NULL;

	priv->addresses = nm_utils_ip4_addresses_from_gvalue (value);
	_nm_object_queue_notify (object, NM_IP4_CONFIG_ADDRESSES);

	return TRUE;
}

static gboolean
demarshal_ip4_array (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	GArray *ip_array;
	char ***obj_field;
	int i;

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_UINT_ARRAY))
		return FALSE;

	ip_array = g_value_get_boxed (value);

	obj_field = field;
	if (*obj_field)
		g_strfreev (*obj_field);

	*obj_field = g_new (char *, ip_array->len + 1);
	for (i = 0; i < ip_array->len; i++) {
		guint32 ip = g_array_index (ip_array, guint32, i);
		const char *str;

		str = nm_utils_inet4_ntop (ip, NULL);
		(*obj_field)[i] = g_strdup (str);
	}
	(*obj_field)[i] = NULL;

	_nm_object_queue_notify (object, pspec->name);
	return TRUE;
}

static gboolean
demarshal_ip4_routes_array (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip4_route_unref);
	priv->routes = NULL;

	priv->routes = nm_utils_ip4_routes_from_gvalue (value);
	_nm_object_queue_notify (object, NM_IP4_CONFIG_ROUTES);

	return TRUE;
}

static void
init_dbus (NMObject *object)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_IP4_CONFIG_GATEWAY,      &priv->gateway, },
		{ NM_IP4_CONFIG_ADDRESSES,    &priv->addresses, demarshal_ip4_address_array },
		{ NM_IP4_CONFIG_ROUTES,       &priv->routes, demarshal_ip4_routes_array },
		{ NM_IP4_CONFIG_NAMESERVERS,  &priv->nameservers, demarshal_ip4_array },
		{ NM_IP4_CONFIG_DOMAINS,      &priv->domains, },
		{ NM_IP4_CONFIG_SEARCHES,     &priv->searches, },
		{ NM_IP4_CONFIG_WINS_SERVERS, &priv->wins, demarshal_ip4_array },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_ip4_config_parent_class)->init_dbus (object);

	priv->proxy = _nm_object_new_proxy (object, NULL, NM_DBUS_INTERFACE_IP4_CONFIG);
	_nm_object_register_properties (object,
	                                priv->proxy,
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	g_free (priv->gateway);

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip4_address_unref);
	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip4_route_unref);

	g_strfreev (priv->nameservers);
	g_strfreev (priv->domains);
	g_strfreev (priv->searches);
	g_strfreev (priv->wins);

	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_ip4_config_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMIP4Config *self = NM_IP4_CONFIG (object);
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_GATEWAY:
		g_value_set_string (value, nm_ip4_config_get_gateway (self));
		break;
	case PROP_ADDRESSES:
		nm_utils_ip4_addresses_to_gvalue (priv->addresses, value);
		break;
	case PROP_ROUTES:
		nm_utils_ip4_routes_to_gvalue (priv->routes, value);
		break;
	case PROP_NAMESERVERS:
		g_value_set_boxed (value, (char **) nm_ip4_config_get_nameservers (self));
		break;
	case PROP_DOMAINS:
		g_value_set_boxed (value, (char **) nm_ip4_config_get_domains (self));
		break;
	case PROP_SEARCHES:
		g_value_set_boxed (value, (char **) nm_ip4_config_get_searches (self));
		break;
	case PROP_WINS_SERVERS:
		g_value_set_boxed (value, (char **) nm_ip4_config_get_wins_servers (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ip4_config_class_init (NMIP4ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMIP4ConfigPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	/* properties */

	/**
	 * NMIP4Config:gateway:
	 *
	 * The IP4 gateway address of the configuration as string.
	 **/
	g_object_class_install_property
	    (object_class, PROP_GATEWAY,
	     g_param_spec_string (NM_IP4_CONFIG_GATEWAY, "", "",
	                          NULL,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP4Config:addresses:
	 *
	 * The #GPtrArray containing #NMIP4Address<!-- -->es of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_ADDRESSES,
	     g_param_spec_pointer (NM_IP4_CONFIG_ADDRESSES, "", "",
	                           G_PARAM_READABLE |
	                           G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP4Config:routes:
	 *
	 * The #GPtrArray containing #NMSettingIP4Routes of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_ROUTES,
	     g_param_spec_pointer (NM_IP4_CONFIG_ROUTES, "", "",
	                           G_PARAM_READABLE |
	                           G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP4Config:nameservers:
	 *
	 * The array containing name server IP addresses of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_NAMESERVERS,
	     g_param_spec_boxed (NM_IP4_CONFIG_NAMESERVERS, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP4Config:domains:
	 *
	 * The array containing domain strings of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_DOMAINS,
	     g_param_spec_boxed (NM_IP4_CONFIG_DOMAINS, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP4Config:searches:
	 *
	 * The array containing DNS search strings of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_SEARCHES,
	     g_param_spec_boxed (NM_IP4_CONFIG_SEARCHES, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP4Config:wins-servers:
	 *
	 * The array containing WINS server IP addresses of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_WINS_SERVERS,
	     g_param_spec_boxed (NM_IP4_CONFIG_WINS_SERVERS, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));
}

/**
 * nm_ip4_config_get_gateway:
 * @config: a #NMIP4Config
 *
 * Gets the IP4 gateway address.
 *
 * Returns: the IP4 address of the gateway.
 **/
const char *
nm_ip4_config_get_gateway (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->gateway;
}

/**
 * nm_ip4_config_get_addresses:
 * @config: a #NMIP4Config
 *
 * Gets the IP4 addresses (containing the address, prefix, and gateway).
 *
 * Returns: (element-type NMIP4Address): the #GSList containing #NMIP4Address<!-- -->es.
 * This is the internal copy used by the configuration and must not be modified.
 **/
const GSList *
nm_ip4_config_get_addresses (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->addresses;
}

/**
 * nm_ip4_config_get_nameservers:
 * @config: a #NMIP4Config
 *
 * Gets the domain name servers (DNS).
 *
 * Returns: the array of nameserver IP addresses
 **/
const char * const *
nm_ip4_config_get_nameservers (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	return (const char * const *) NM_IP4_CONFIG_GET_PRIVATE (config)->nameservers;
}

/**
 * nm_ip4_config_get_domains:
 * @config: a #NMIP4Config
 *
 * Gets the domain names.
 *
 * Returns: the array of domains. (This is never %NULL, though it may be 0-length).
 **/
const char * const *
nm_ip4_config_get_domains (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	return (const char * const *) NM_IP4_CONFIG_GET_PRIVATE (config)->domains;
}

/**
 * nm_ip4_config_get_searches:
 * @config: a #NMIP4Config
 *
 * Gets the DNS searches.
 *
 * Returns: the array of DNS search strings. (This is never %NULL, though it may be 0-length).
 **/
const char * const *
nm_ip4_config_get_searches (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	return (const char * const *) NM_IP4_CONFIG_GET_PRIVATE (config)->searches;
}

/**
 * nm_ip4_config_get_wins_servers:
 * @config: a #NMIP4Config
 *
 * Gets the Windows Internet Name Service servers (WINS).
 *
 * Returns: (element-type guint32): the #GArray containing #guint32s.
 * This is the internal copy used by the configuration and must not be
 * modified.
 **/
const char * const *
nm_ip4_config_get_wins_servers (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	return (const char * const *) NM_IP4_CONFIG_GET_PRIVATE (config)->wins;
}

/**
 * nm_ip4_config_get_routes:
 * @config: a #NMIP4Config
 *
 * Gets the routes.
 *
 * Returns: (element-type NMIP4Route): the #GSList containing
 * #NMIP4Routes. This is the internal copy used by the configuration,
 * and must not be modified.
 **/
const GSList *
nm_ip4_config_get_routes (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	return NM_IP4_CONFIG_GET_PRIVATE (config)->routes;
}
