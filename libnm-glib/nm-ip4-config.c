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

#include "nm-default.h"

#include <string.h>

#include "nm-setting-ip4-config.h"
#include "nm-ip4-config.h"
#include "NetworkManager.h"
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
	GArray *nameservers;
	GPtrArray *domains;
	GPtrArray *searches;
	GArray *wins;
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
	if (!_nm_uint_array_demarshal (value, (GArray **) field))
		return FALSE;

	if (!strcmp (pspec->name, NM_IP4_CONFIG_NAMESERVERS))
		_nm_object_queue_notify (object, NM_IP4_CONFIG_NAMESERVERS);
	else if (!strcmp (pspec->name, NM_IP4_CONFIG_WINS_SERVERS))
		_nm_object_queue_notify (object, NM_IP4_CONFIG_WINS_SERVERS);

	return TRUE;
}

static gboolean
demarshal_string_array (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	if (!_nm_string_array_demarshal (value, (GPtrArray **) field))
		return FALSE;

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
register_properties (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	const NMPropertiesInfo property_info[] = {
		{ NM_IP4_CONFIG_GATEWAY,      &priv->gateway, },
		{ NM_IP4_CONFIG_ADDRESSES,    &priv->addresses, demarshal_ip4_address_array },
		{ NM_IP4_CONFIG_ROUTES,       &priv->routes, demarshal_ip4_routes_array },
		{ NM_IP4_CONFIG_NAMESERVERS,  &priv->nameservers, demarshal_ip4_array },
		{ NM_IP4_CONFIG_DOMAINS,      &priv->domains, demarshal_string_array },
		{ NM_IP4_CONFIG_SEARCHES,     &priv->searches, demarshal_string_array },
		{ NM_IP4_CONFIG_WINS_SERVERS, &priv->wins, demarshal_ip4_array },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (config),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_ip4_config_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_IP4_CONFIG);
	register_properties (NM_IP4_CONFIG (object));
}

static void
finalize (GObject *object)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	g_free (priv->gateway);

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip4_address_unref);
	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip4_route_unref);

	if (priv->nameservers)
		g_array_free (priv->nameservers, TRUE);

	if (priv->wins)
		g_array_free (priv->wins, TRUE);

	if (priv->domains) {
		g_ptr_array_set_free_func (priv->domains, g_free);
		g_ptr_array_free (priv->domains, TRUE);
	}

	if (priv->searches) {
		g_ptr_array_set_free_func (priv->searches, g_free);
		g_ptr_array_free (priv->searches, TRUE);
	}

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

	_nm_object_ensure_inited (NM_OBJECT (object));

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
		g_value_set_boxed (value, nm_ip4_config_get_nameservers (self));
		break;
	case PROP_DOMAINS:
		g_value_set_boxed (value, nm_ip4_config_get_domains (self));
		break;
	case PROP_SEARCHES:
		g_value_set_boxed (value, nm_ip4_config_get_searches (self));
		break;
	case PROP_WINS_SERVERS:
		g_value_set_boxed (value, nm_ip4_config_get_wins_servers (self));
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

	g_type_class_add_private (config_class, sizeof (NMIP4ConfigPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMIP4Config:gateway:
	 *
	 * The IP4 gateway address of the configuration as string.
	 *
	 * Since: 0.9.10
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
	 * The #GArray containing name servers (#guint32s) of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_NAMESERVERS,
	     g_param_spec_boxed (NM_IP4_CONFIG_NAMESERVERS, "", "",
	                         NM_TYPE_UINT_ARRAY,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP4Config:domains:
	 *
	 * The #GPtrArray containing domain strings of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_DOMAINS,
	     g_param_spec_boxed (NM_IP4_CONFIG_DOMAINS, "", "",
	                         NM_TYPE_STRING_ARRAY,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP4Config:searches:
	 *
	 * The #GPtrArray containing dns search strings of the configuration.
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
	    (object_class, PROP_SEARCHES,
	     g_param_spec_boxed (NM_IP4_CONFIG_SEARCHES, "", "",
	                         NM_TYPE_STRING_ARRAY,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP4Config:wins-servers:
	 *
	 * The #GArray containing WINS servers (#guint32s) of the configuration.
	 **/
	g_object_class_install_property
	    (object_class, PROP_WINS_SERVERS,
	     g_param_spec_boxed (NM_IP4_CONFIG_WINS_SERVERS, "", "",
	                         NM_TYPE_UINT_ARRAY,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));
}

/**
 * nm_ip4_config_new:
 * @connection: the #DBusGConnection
 * @object_path: the DBus object path of the device
 *
 * Creates a new #NMIP4Config.
 *
 * Returns: (transfer full): a new IP4 configuration
 **/
GObject *
nm_ip4_config_new (DBusGConnection *connection, const char *object_path)
{
	return (GObject *) g_object_new (NM_TYPE_IP4_CONFIG,
	                                 NM_OBJECT_DBUS_CONNECTION, connection,
	                                 NM_OBJECT_DBUS_PATH, object_path,
	                                 NULL);
}

/**
 * nm_ip4_config_get_gateway:
 * @config: a #NMIP4Config
 *
 * Gets the IP4 gateway address.
 *
 * Returns: the IP4 address of the gateway.
 *
 * Since: 0.9.10
 **/
const char *
nm_ip4_config_get_gateway (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	_nm_object_ensure_inited (NM_OBJECT (config));
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

	_nm_object_ensure_inited (NM_OBJECT (config));
	return NM_IP4_CONFIG_GET_PRIVATE (config)->addresses;
}

/**
 * nm_ip4_config_get_nameservers:
 * @config: a #NMIP4Config
 *
 * Gets the domain name servers (DNS).
 *
 * Returns: (element-type guint32): the #GArray containing #guint32s.
 * This is the internal copy used by the configuration and must not be
 * modified.
 **/
const GArray *
nm_ip4_config_get_nameservers (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	_nm_object_ensure_inited (NM_OBJECT (config));
	return NM_IP4_CONFIG_GET_PRIVATE (config)->nameservers;
}

/**
 * nm_ip4_config_get_domains:
 * @config: a #NMIP4Config
 *
 * Gets the domain names.
 *
 * Returns: (element-type utf8): the #GPtrArray containing domains as strings. This is the
 * internal copy used by the configuration, and must not be modified.
 **/
const GPtrArray *
nm_ip4_config_get_domains (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	_nm_object_ensure_inited (NM_OBJECT (config));
	return handle_ptr_array_return (NM_IP4_CONFIG_GET_PRIVATE (config)->domains);
}

/**
 * nm_ip4_config_get_searches:
 * @config: a #NMIP4Config
 *
 * Gets the dns searches.
 *
 * Returns: (element-type utf8): the #GPtrArray containing dns searches as strings. This is the
 * internal copy used by the configuration, and must not be modified.
 *
 * Since: 0.9.10
 **/
const GPtrArray *
nm_ip4_config_get_searches (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	_nm_object_ensure_inited (NM_OBJECT (config));
	return handle_ptr_array_return (NM_IP4_CONFIG_GET_PRIVATE (config)->searches);
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
const GArray *
nm_ip4_config_get_wins_servers (NMIP4Config *config)
{
	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	_nm_object_ensure_inited (NM_OBJECT (config));
	return NM_IP4_CONFIG_GET_PRIVATE (config)->wins;
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

	_nm_object_ensure_inited (NM_OBJECT (config));
	return NM_IP4_CONFIG_GET_PRIVATE (config)->routes;
}
