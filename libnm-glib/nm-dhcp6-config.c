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
 * Copyright 2008 - 2011 Red Hat, Inc.
 * Copyright 2008 Novell, Inc.
 */

#include "nm-default.h"

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

static gboolean
demarshal_dhcp6_options (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMDHCP6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);
	GHashTable *new_options;
	GHashTableIter iter;
	const char *key;
	GValue *opt;

	g_hash_table_remove_all (priv->options);

	new_options = g_value_get_boxed (value);
	if (new_options) {
		g_hash_table_iter_init (&iter, new_options);
		while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &opt))
			g_hash_table_insert (priv->options, g_strdup (key), g_value_dup_string (opt));
	}

	_nm_object_queue_notify (object, NM_DHCP6_CONFIG_OPTIONS);
	return TRUE;
}

static void
register_properties (NMDHCP6Config *config)
{
	NMDHCP6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (config);
	const NMPropertiesInfo property_info[] = {
		{ NM_DHCP6_CONFIG_OPTIONS,   &priv->options, demarshal_dhcp6_options },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (config),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMDHCP6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_dhcp6_config_parent_class)->constructed (object);

	priv->options = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_DHCP6_CONFIG);
	register_properties (NM_DHCP6_CONFIG (object));
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

	_nm_object_ensure_inited (NM_OBJECT (object));

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
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMDHCP6Config:options:
	 *
	 * The #GHashTable containing options of the configuration.
	 *
	 * Type: GLib.HashTable(utf8,GObject.Value)
	 **/
	g_object_class_install_property
		(object_class, PROP_OPTIONS,
		 g_param_spec_boxed (NM_DHCP6_CONFIG_OPTIONS, "", "",
		                     G_TYPE_HASH_TABLE,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
}

/**
 * nm_dhcp6_config_new:
 * @connection: the #DBusGConnection
 * @object_path: the DBus object path of the device
 *
 * Creates a new #NMDHCP6Config.
 *
 * Returns: (transfer full): a new configuration
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
 * Returns: (transfer none) (element-type utf8 GObject.Value): the #GHashTable containing strings for keys and values.
 * This is the internal copy used by the configuration, and must not be modified.
 **/
GHashTable *
nm_dhcp6_config_get_options (NMDHCP6Config *config)
{
	g_return_val_if_fail (NM_IS_DHCP6_CONFIG (config), NULL);

	_nm_object_ensure_inited (NM_OBJECT (config));
	return NM_DHCP6_CONFIG_GET_PRIVATE (config)->options;
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
