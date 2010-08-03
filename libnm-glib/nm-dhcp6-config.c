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
 * Copyright (C) 2008 - 2010 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#include <string.h>

#include "nm-dhcp6-config.h"
#include "NetworkManager.h"
#include "nm-types-private.h"
#include "nm-object-private.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMDHCP6Config, nm_dhcp6_config, NM_TYPE_OBJECT)

#define NM_DHCP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP6_CONFIG, NMDHCP6ConfigPrivate))

typedef struct {
	DBusGProxy *proxy;

	GHashTable *options;
} NMDHCP6ConfigPrivate;

enum {
	PROP_0,
	PROP_OPTIONS,

	LAST_PROP
};

static void
nm_dhcp6_config_init (NMDHCP6Config *config)
{
}

static void
copy_options (gpointer key, gpointer data, gpointer user_data)
{
	GHashTable *options = (GHashTable *) user_data;
	GValue *value = (GValue *) data;

	g_hash_table_insert (options, g_strdup (key), g_value_dup_string (value));
}

static gboolean
demarshal_dhcp6_options (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMDHCP6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);
	GHashTable *new_options;

	g_hash_table_remove_all (priv->options);

	new_options = g_value_get_boxed (value);
	if (new_options)
		g_hash_table_foreach (new_options, copy_options, priv->options);

	_nm_object_queue_notify (object, NM_DHCP6_CONFIG_OPTIONS);
	return TRUE;
}

static void
register_for_property_changed (NMDHCP6Config *config)
{
	NMDHCP6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (config);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_DHCP6_CONFIG_OPTIONS,   demarshal_dhcp6_options,  &priv->options },
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
	NMDHCP6ConfigPrivate *priv;

	object = (NMObject *) G_OBJECT_CLASS (nm_dhcp6_config_parent_class)->constructor (type,
																 n_construct_params,
																 construct_params);
	if (!object)
		return NULL;

	priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);
	priv->options = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	connection = nm_object_get_connection (object);

	priv->proxy = dbus_g_proxy_new_for_name (connection,
										   NM_DBUS_SERVICE,
										   nm_object_get_path (object),
										   NM_DBUS_INTERFACE_DHCP6_CONFIG);

	register_for_property_changed (NM_DHCP6_CONFIG (object));

	return G_OBJECT (object);
}

static void
finalize (GObject *object)
{
	NMDHCP6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);

	if (priv->options)
		g_hash_table_destroy (priv->options);

	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_dhcp6_config_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDHCP6Config *self = NM_DHCP6_CONFIG (object);

	switch (prop_id) {
	case PROP_OPTIONS:
		g_value_set_boxed (value, nm_dhcp6_config_get_options (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_dhcp6_config_class_init (NMDHCP6ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMDHCP6ConfigPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMDHCP6Config:options:
	 *
	 * The #GHashTable containing options of the configuration.
	 **/
	g_object_class_install_property
		(object_class, PROP_OPTIONS,
		 g_param_spec_boxed (NM_DHCP6_CONFIG_OPTIONS,
						       "Options",
						       "Options",
						       G_TYPE_HASH_TABLE,
						       G_PARAM_READABLE));
}

/**
 * nm_dhcp6_config_new:
 * @connection: the #DBusGConnection
 * @object_path: the DBus object path of the device
 *
 * Creates a new #NMDHCP6Config.
 *
 * Returns: a new configuration
 **/
GObject *
nm_dhcp6_config_new (DBusGConnection *connection, const char *object_path)
{
	return (GObject *) g_object_new (NM_TYPE_DHCP6_CONFIG,
									 NM_OBJECT_DBUS_CONNECTION, connection,
									 NM_OBJECT_DBUS_PATH, object_path,
									 NULL);
}

/**
 * nm_dhcp6_config_get_options:
 * @config: a #NMDHCP6Config
 *
 * Gets all the options contained in the configuration.
 *
 * Returns: the #GHashTable containing strings for keys and values.
 * This is the internal copy used by the configuration, and must not be modified.
 **/
GHashTable *
nm_dhcp6_config_get_options (NMDHCP6Config *config)
{
	NMDHCP6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (config);
	GValue value = { 0, };

	if (g_hash_table_size (priv->options))
		return priv->options;

	if (!_nm_object_get_property (NM_OBJECT (config),
	                              NM_DBUS_INTERFACE_DHCP6_CONFIG,
	                              "Options",
	                              &value))
		goto out;

	demarshal_dhcp6_options (NM_OBJECT (config), NULL, &value, &priv->options);	
	g_value_unset (&value);

out:
	return priv->options;
}

/**
 * nm_dhcp6_config_get_one_option:
 * @config: a #NMDHCP6Config
 * @option: the option to retrieve
 *
 * Gets one option by option name.
 *
 * Returns: the configuration option's value. This is the internal string used by the
 * configuration, and must not be modified.
 **/
const char *
nm_dhcp6_config_get_one_option (NMDHCP6Config *config, const char *option)
{
	g_return_val_if_fail (NM_IS_DHCP6_CONFIG (config), NULL);

	return g_hash_table_lookup (nm_dhcp6_config_get_options (config), option);
}

