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

#include "nm-default.h"

#include <string.h>

#include "nm-setting-ip6-config.h"
#include "nm-ip6-config.h"
#include "NetworkManager.h"
#include "nm-types-private.h"
#include "nm-object-private.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMIP6Config, nm_ip6_config, NM_TYPE_OBJECT)

#define NM_IP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP6_CONFIG, NMIP6ConfigPrivate))

typedef struct {
	DBusGProxy *proxy;

	char *gateway;
	GSList *addresses;
	GSList *routes;
	GSList *nameservers;
	GPtrArray *domains;
	GPtrArray *searches;
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

/**
 * nm_ip6_config_new:
 * @connection: the #DBusGConnection
 * @object_path: the DBus object path of the device
 *
 * Creates a new #NMIP6Config.
 *
 * Returns: (transfer full): a new IP6 configuration
 **/
GObject *
nm_ip6_config_new (DBusGConnection *connection, const char *object_path)
{
	return (GObject *) g_object_new (NM_TYPE_IP6_CONFIG,
	                                 NM_OBJECT_DBUS_CONNECTION, connection,
	                                 NM_OBJECT_DBUS_PATH, object_path,
	                                 NULL);
}

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
	if (!_nm_ip6_address_array_demarshal (value, (GSList **) field))
		return FALSE;

	if (pspec && !strcmp (pspec->name, NM_IP6_CONFIG_NAMESERVERS))
		_nm_object_queue_notify (object, NM_IP6_CONFIG_NAMESERVERS);

	return TRUE;
}

static gboolean
demarshal_domains (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	if (!_nm_string_array_demarshal (value, (GPtrArray **) field))
		return FALSE;

	_nm_object_queue_notify (object, NM_IP6_CONFIG_DOMAINS);
	return TRUE;
}

static gboolean
demarshal_searches (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	if (!_nm_string_array_demarshal (value, (GPtrArray **) field))
		return FALSE;

	_nm_object_queue_notify (object, NM_IP6_CONFIG_SEARCHES);
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
register_properties (NMIP6Config *config)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (config);
	const NMPropertiesInfo property_info[] = {
		{ NM_IP6_CONFIG_GATEWAY,      &priv->gateway, },
		{ NM_IP6_CONFIG_ADDRESSES,    &priv->addresses, demarshal_ip6_address_array },
		{ NM_IP6_CONFIG_ROUTES,       &priv->routes, demarshal_ip6_routes_array },
		{ NM_IP6_CONFIG_NAMESERVERS,  &priv->nameservers, demarshal_ip6_nameserver_array },
		{ NM_IP6_CONFIG_DOMAINS,      &priv->domains, demarshal_domains },
		{ NM_IP6_CONFIG_SEARCHES,     &priv->searches, demarshal_searches },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (config),
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
 *
 * Since: 0.9.10
 **/
const char *
nm_ip6_config_get_gateway (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	_nm_object_ensure_inited (NM_OBJECT (config));
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

	_nm_object_ensure_inited (NM_OBJECT (config));
	return NM_IP6_CONFIG_GET_PRIVATE (config)->addresses;
}

/**
 * nm_ip6_config_get_num_nameservers:
 * @config: a #NMIP6Config
 *
 * Gets the number of the domain name servers in the configuration.
 *
 * Returns: the number of domain name servers
 *
 * Since: 0.9.10
 **/
guint32
nm_ip6_config_get_num_nameservers (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), 0);

	_nm_object_ensure_inited (NM_OBJECT (config));
	return g_slist_length (NM_IP6_CONFIG_GET_PRIVATE (config)->nameservers);
}

/**
 * nm_ip6_config_get_nameserver:
 * @config: a #NMIP6Config
 * @idx: index of the nameserver to return
 *
 * Gets the domain name server at index @idx in the configuration.
 *
 * Returns: (array fixed-size=16) (element-type guint8) (transfer none):
 *          the IPv6 address of domain name server at index @iidx
 *
 * Since: 0.9.10
 **/
const struct in6_addr *
nm_ip6_config_get_nameserver (NMIP6Config *config, guint32 idx)
{
	NMIP6ConfigPrivate *priv;
	GSList *item;
	guint32 i = 0;

	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	_nm_object_ensure_inited (NM_OBJECT (config));
	priv = NM_IP6_CONFIG_GET_PRIVATE (config);

	for (item = priv->nameservers; item && i < idx; i++)
		item = item->next;

	g_return_val_if_fail (item, NULL);
	return item ? (const struct in6_addr *) item->data : NULL;
}

/* FIXME: like in libnm_util, in6_addr is not introspectable, so skipping here */
/**
 * nm_ip6_config_get_nameservers: (skip)
 * @config: a #NMIP6Config
 *
 * Gets the domain name servers (DNS).
 *
 * Returns: a #GSList containing elements of type 'struct in6_addr' which
 * contain the addresses of nameservers of the configuration.  This is the
 * internal copy used by the configuration and must not be modified.
 **/
const GSList *
nm_ip6_config_get_nameservers (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	_nm_object_ensure_inited (NM_OBJECT (config));
	return NM_IP6_CONFIG_GET_PRIVATE (config)->nameservers;
}

/**
 * nm_ip6_config_get_domains:
 * @config: a #NMIP6Config
 *
 * Gets the domain names.
 *
 * Returns: (element-type utf8): the #GPtrArray containing domains as strings.
 * This is the internal copy used by the configuration, and must not be modified.
 **/
const GPtrArray *
nm_ip6_config_get_domains (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	_nm_object_ensure_inited (NM_OBJECT (config));
	return handle_ptr_array_return (NM_IP6_CONFIG_GET_PRIVATE (config)->domains);
}

/**
 * nm_ip6_config_get_searches:
 * @config: a #NMIP6Config
 *
 * Gets the dns searches.
 *
 * Returns: (element-type utf8): the #GPtrArray containing dns searches as strings.
 * This is the internal copy used by the configuration, and must not be modified.
 *
 * Since: 0.9.10
 **/
const GPtrArray *
nm_ip6_config_get_searches (NMIP6Config *config)
{
	g_return_val_if_fail (NM_IS_IP6_CONFIG (config), NULL);

	_nm_object_ensure_inited (NM_OBJECT (config));
	return handle_ptr_array_return (NM_IP6_CONFIG_GET_PRIVATE (config)->searches);
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

	_nm_object_ensure_inited (NM_OBJECT (config));
	return NM_IP6_CONFIG_GET_PRIVATE (config)->routes;
}

static void
constructed (GObject *object)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_ip6_config_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_IP6_CONFIG);
	register_properties (NM_IP6_CONFIG (object));
}

static void
finalize (GObject *object)
{
	NMIP6ConfigPrivate *priv = NM_IP6_CONFIG_GET_PRIVATE (object);

	g_free (priv->gateway);

	g_slist_free_full (priv->addresses, (GDestroyNotify) nm_ip6_address_unref);
	g_slist_free_full (priv->routes, (GDestroyNotify) nm_ip6_route_unref);
	g_slist_free_full (priv->nameservers, g_free);

	if (priv->domains) {
		g_ptr_array_set_free_func (priv->domains, g_free);
		g_ptr_array_free (priv->domains, TRUE);
	}

	if (priv->searches) {
		g_ptr_array_set_free_func (priv->searches, g_free);
		g_ptr_array_free (priv->searches, TRUE);
	}

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

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_GATEWAY:
		g_value_set_string (value, nm_ip6_config_get_gateway (self));
		break;
	case PROP_ADDRESSES:
		nm_utils_ip6_addresses_to_gvalue (priv->addresses, value);
		break;
	case PROP_ROUTES:
		nm_utils_ip6_routes_to_gvalue (priv->routes, value);
		break;
	case PROP_NAMESERVERS:
		g_value_set_boxed (value, nm_ip6_config_get_nameservers (self));
		break;
	case PROP_DOMAINS:
		g_value_set_boxed (value, nm_ip6_config_get_domains (self));
		break;
	case PROP_SEARCHES:
		g_value_set_boxed (value, nm_ip6_config_get_searches (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ip6_config_init (NMIP6Config *config)
{
}

static void
nm_ip6_config_class_init (NMIP6ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMIP6ConfigPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMIP6Config:gateway:
	 *
	 * The IPv6 gateway as string
	 *
	 * Since: 0.9.10
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
	 * The #GPtrArray containing the IPv6 addresses;  use
	 * nm_utils_ip6_addresses_from_gvalue() to return a #GSList of
	 * #NMSettingIP6Address objects that is more usable than the raw data.
	 **/
	g_object_class_install_property
	    (object_class, PROP_ADDRESSES,
	     g_param_spec_boxed (NM_IP6_CONFIG_ADDRESSES, "", "",
	                         NM_TYPE_IP6_ADDRESS_OBJECT_ARRAY,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP6Config:routes:
	 *
	 * The #GPtrArray containing the IPv6 routes;  use
	 * nm_utils_ip6_routes_from_gvalue() to return a #GSList of
	 * #NMSettingIP6Address objects that is more usable than the raw data.
	 **/
	g_object_class_install_property
	    (object_class, PROP_ROUTES,
	     g_param_spec_boxed (NM_IP6_CONFIG_ROUTES, "", "",
	                         NM_TYPE_IP6_ROUTE_OBJECT_ARRAY,
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
	                         NM_TYPE_IP6_ADDRESS_ARRAY,
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
	                         NM_TYPE_STRING_ARRAY,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/**
	 * NMIP6Config:searches:
	 *
	 * The #GPtrArray containing dns search strings of the configuration.
	 *
	 * Since: 0.9.10
	 **/
	g_object_class_install_property
	    (object_class, PROP_SEARCHES,
	     g_param_spec_boxed (NM_IP6_CONFIG_SEARCHES, "", "",
	                         NM_TYPE_STRING_ARRAY,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

}
