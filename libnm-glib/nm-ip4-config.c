/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include <string.h>

#include <nm-setting-ip4-config.h>
#include "nm-ip4-config.h"
#include "NetworkManager.h"
#include "nm-types-private.h"
#include "nm-object-private.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMIP4Config, nm_ip4_config, NM_TYPE_OBJECT)

#define NM_IP4_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IP4_CONFIG, NMIP4ConfigPrivate))

typedef struct {
	DBusGProxy *proxy;

	GSList *addresses;
	GArray *nameservers;
	GPtrArray *domains;
	GSList *routes;
	GArray *wins;
} NMIP4ConfigPrivate;

enum {
	PROP_0,
	PROP_ADDRESSES,
	PROP_HOSTNAME,
	PROP_NAMESERVERS,
	PROP_DOMAINS,
	PROP_ROUTES,
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

	g_slist_foreach (priv->addresses, (GFunc) nm_ip4_address_unref, NULL);
	g_slist_free (priv->addresses);
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
demarshal_domains (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	if (!_nm_string_array_demarshal (value, (GPtrArray **) field))
		return FALSE;

	_nm_object_queue_notify (object, NM_IP4_CONFIG_DOMAINS);
	return TRUE;
}

static gboolean
demarshal_ip4_routes_array (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	g_slist_foreach (priv->routes, (GFunc) g_free, NULL);
	g_slist_free (priv->routes);
	priv->routes = NULL;

	priv->routes = nm_utils_ip4_routes_from_gvalue (value);
	_nm_object_queue_notify (object, NM_IP4_CONFIG_ROUTES);

	return TRUE;
}

static void
register_for_property_changed (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_IP4_CONFIG_ADDRESSES,    demarshal_ip4_address_array,  &priv->addresses },
		{ NM_IP4_CONFIG_NAMESERVERS,  demarshal_ip4_array,          &priv->nameservers },
		{ NM_IP4_CONFIG_DOMAINS,      demarshal_domains,            &priv->domains },
		{ NM_IP4_CONFIG_ROUTES,       demarshal_ip4_routes_array,   &priv->routes },
		{ NM_IP4_CONFIG_WINS_SERVERS, demarshal_ip4_array,          &priv->wins },
		{ NULL },
	};

	_nm_object_handle_properties_changed (NM_OBJECT (config),
	                                     priv->proxy,
	                                     property_changed_info);
}

static GObject*
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	NMObject *object;
	DBusGConnection *connection;
	NMIP4ConfigPrivate *priv;

	object = (NMObject *) G_OBJECT_CLASS (nm_ip4_config_parent_class)->constructor (type,
																 n_construct_params,
																 construct_params);
	if (!object)
		return NULL;

	priv = NM_IP4_CONFIG_GET_PRIVATE (object);
	connection = nm_object_get_connection (object);

	priv->proxy = dbus_g_proxy_new_for_name (connection,
										   NM_DBUS_SERVICE,
										   nm_object_get_path (object),
										   NM_DBUS_INTERFACE_IP4_CONFIG);

	register_for_property_changed (NM_IP4_CONFIG (object));

	return G_OBJECT (object);
}

static void
finalize (GObject *object)
{
	NMIP4ConfigPrivate *priv = NM_IP4_CONFIG_GET_PRIVATE (object);

	g_slist_foreach (priv->addresses, (GFunc) g_free, NULL);
	g_slist_free (priv->addresses);

	g_slist_foreach (priv->routes, (GFunc) g_free, NULL);
	g_slist_free (priv->routes);

	if (priv->nameservers)
		g_array_free (priv->nameservers, TRUE);

	if (priv->wins)
		g_array_free (priv->wins, TRUE);

	if (priv->domains) {
		g_ptr_array_foreach (priv->domains, (GFunc) g_free, NULL);
		g_ptr_array_free (priv->domains, TRUE);
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

	switch (prop_id) {
	case PROP_ADDRESSES:
		nm_utils_ip4_addresses_to_gvalue (priv->addresses, value);
		break;
	case PROP_HOSTNAME:
		g_value_set_string (value, NULL);
		break;
	case PROP_NAMESERVERS:
		g_value_set_boxed (value, nm_ip4_config_get_nameservers (self));
		break;
	case PROP_DOMAINS:
		g_value_set_boxed (value, nm_ip4_config_get_domains (self));
		break;
	case PROP_ROUTES:
		nm_utils_ip4_routes_to_gvalue (priv->routes, value);
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
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMIP4Config:addresses:
	 *
	 * The #GPtrArray containing #NMSettingIP4Address<!-- -->es of the configuration.
	 **/
	g_object_class_install_property
		(object_class, PROP_ADDRESSES,
		 g_param_spec_pointer (NM_IP4_CONFIG_ADDRESSES,
						       "Addresses",
						       "Addresses",
						       G_PARAM_READABLE));

	/**
	 * NMIP4Config:hostname:
	 *
	 * DEPRECATED.  Don't use.
	 **/
	g_object_class_install_property
		(object_class, PROP_HOSTNAME,
		 g_param_spec_string (NM_IP4_CONFIG_HOSTNAME,
						    "Hostname",
						    "Hostname",
						    NULL,
						    G_PARAM_READABLE));

	/**
	 * NMIP4Config:nameservers:
	 *
	 * The #GArray containing name servers (%guint32<!-- -->es) of the configuration.
	 **/
	g_object_class_install_property
		(object_class, PROP_NAMESERVERS,
		 g_param_spec_boxed (NM_IP4_CONFIG_NAMESERVERS,
						    "Nameservers",
						    "Nameservers",
						    NM_TYPE_UINT_ARRAY,
						    G_PARAM_READABLE));

	/**
	 * NMIP4Config:domains:
	 *
	 * The #GPtrArray containing domain strings of the configuration.
	 **/
	g_object_class_install_property
		(object_class, PROP_DOMAINS,
		 g_param_spec_boxed (NM_IP4_CONFIG_DOMAINS,
						    "Domains",
						    "Domains",
						    NM_TYPE_STRING_ARRAY,
						    G_PARAM_READABLE));

	/**
	 * NMIP4Config:routes:
	 *
	 * The #GPtrArray containing #NMSettingIP4Route<!-- -->s of the configuration.
	 **/
	g_object_class_install_property
		(object_class, PROP_ROUTES,
		 g_param_spec_pointer (NM_IP4_CONFIG_ROUTES,
						       "Routes",
						       "Routes",
						       G_PARAM_READABLE));

	/**
	 * NMIP4Config:wins-servers:
	 *
	 * The #GArray containing WINS servers (%guint32<!-- -->es) of the configuration.
	 **/
	g_object_class_install_property
		(object_class, PROP_WINS_SERVERS,
		 g_param_spec_boxed (NM_IP4_CONFIG_WINS_SERVERS,
						    "WINS Servers",
						    "WINS Servers",
						    NM_TYPE_UINT_ARRAY,
						    G_PARAM_READABLE));
}

/**
 * nm_ip4_config_new:
 * @connection: the #DBusGConnection
 * @object_path: the DBus object path of the device
 *
 * Creates a new #NMIP4Config.
 *
 * Returns: a new IP4 configuration
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
 * nm_ip4_config_get_addresses:
 * @config: a #NMIP4Config
 *
 * Gets the IP4 addresses (containing the address, prefix, and gateway).
 *
 * Returns: the #GSList containing #NMSettingIP4Address<!-- -->es. This is the internal copy
 * used by the configuration and must not be modified.
 **/
const GSList *
nm_ip4_config_get_addresses (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	if (priv->addresses)
		return priv->addresses;

	if (!_nm_object_get_property (NM_OBJECT (config),
	                              NM_DBUS_INTERFACE_IP4_CONFIG,
	                              "Addresses",
	                              &value)) {
		return NULL;
	}

	demarshal_ip4_address_array (NM_OBJECT (config), NULL, &value, &priv->addresses);	
	g_value_unset (&value);

	return priv->addresses;
}

/**
 * nm_ip4_config_get_hostname:
 * @config: a #NMIP4Config
 *
 * DEPRECATED.  Don't use.
 *
 * Returns: NULL
 **/
const char *
nm_ip4_config_get_hostname (NMIP4Config *config)
{
	return NULL;
}

/**
 * nm_ip4_config_get_nameservers:
 * @config: a #NMIP4Config
 *
 * Gets the domain name servers (DNS).
 *
 * Returns: the #GArray containing %guint32<!-- -->s. This is the internal copy used by the
 * configuration and must not be modified.
 **/
const GArray *
nm_ip4_config_get_nameservers (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv;
	GArray *array = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	if (!priv->nameservers) {
		if (_nm_object_get_property (NM_OBJECT (config),
		                             NM_DBUS_INTERFACE_IP4_CONFIG,
		                             "Nameservers",
		                             &value)) {
			array = (GArray *) g_value_get_boxed (&value);
			if (array && array->len) {
				priv->nameservers = g_array_sized_new (FALSE, TRUE, sizeof (guint32), array->len);
				g_array_append_vals (priv->nameservers, array->data, array->len);
			}
			g_value_unset (&value);
		}
	}

	return priv->nameservers;
}

/**
 * nm_ip4_config_get_domains:
 * @config: a #NMIP4Config
 *
 * Gets the domain names.
 *
 * Returns: the #GPtrArray containing domains as strings. This is the 
 * internal copy used by the configuration, and must not be modified.
 **/
const GPtrArray *
nm_ip4_config_get_domains (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	if (priv->domains)
		return handle_ptr_array_return (priv->domains);

	if (_nm_object_get_property (NM_OBJECT (config),
	                             NM_DBUS_INTERFACE_IP4_CONFIG,
	                             "Domains",
	                             &value)) {
		char **array = NULL, **p;

		array = (char **) g_value_get_boxed (&value);
		if (array && g_strv_length (array)) {
			priv->domains = g_ptr_array_sized_new (g_strv_length (array));
			for (p = array; *p; p++)
				g_ptr_array_add (priv->domains, g_strdup (*p));
		}
		g_value_unset (&value);
	}

	return handle_ptr_array_return (priv->domains);
}

/**
 * nm_ip4_config_get_wins_servers:
 * @config: a #NMIP4Config
 *
 * Gets the Windows Internet Name Service servers (WINS).
 *
 * Returns: the #GArray containing %guint32<!-- -->s. This is the internal copy used by the
 * configuration and must not be modified.
 **/
const GArray *
nm_ip4_config_get_wins_servers (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv;
	GArray *array = NULL;
	GValue value = {0,};

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), NULL);

	priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	if (!priv->nameservers) {
		if (_nm_object_get_property (NM_OBJECT (config),
		                             NM_DBUS_INTERFACE_IP4_CONFIG,
		                             "Nameservers",
		                             &value)) {
			array = (GArray *) g_value_get_boxed (&value);
			if (array && array->len) {
				priv->nameservers = g_array_sized_new (FALSE, TRUE, sizeof (guint32), array->len);
				g_array_append_vals (priv->nameservers, array->data, array->len);
			}
			g_value_unset (&value);
		}
	}

	return priv->nameservers;
}

/**
 * nm_ip4_config_get_routes:
 * @config: a #NMIP4Config
 *
 * Gets the routes.
 *
 * Returns: the #GSList containing #NMSettingIP4Route<!-- -->s. This is the 
 * internal copy used by the configuration, and must not be modified.
 **/
const GSList *
nm_ip4_config_get_routes (NMIP4Config *config)
{
	NMIP4ConfigPrivate *priv;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_IP4_CONFIG (config), 0);

	priv = NM_IP4_CONFIG_GET_PRIVATE (config);
	if (priv->routes)
		return priv->routes;

	if (!_nm_object_get_property (NM_OBJECT (config),
	                              NM_DBUS_INTERFACE_IP4_CONFIG,
	                              "Routes",
	                              &value)) {
		return NULL;
	}

	demarshal_ip4_routes_array (NM_OBJECT (config), NULL, &value, &priv->routes);
	g_value_unset (&value);

	return priv->routes;
}

