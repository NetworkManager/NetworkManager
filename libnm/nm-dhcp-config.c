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
 * Copyright 2008 - 2014 Red Hat, Inc.
 * Copyright 2008 Novell, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-dhcp-config.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"
#include "nm-dbus-interface.h"
#include "nm-object-private.h"
#include "nm-utils.h"

G_DEFINE_ABSTRACT_TYPE (NMDhcpConfig, nm_dhcp_config, NM_TYPE_OBJECT)

#define NM_DHCP_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_CONFIG, NMDhcpConfigPrivate))

typedef struct {
	GHashTable *options;
} NMDhcpConfigPrivate;

enum {
	PROP_0,
	PROP_FAMILY,
	PROP_OPTIONS,

	LAST_PROP
};

static void
nm_dhcp_config_init (NMDhcpConfig *config)
{
	NMDhcpConfigPrivate *priv = NM_DHCP_CONFIG_GET_PRIVATE (config);

	priv->options = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_free);
}

static gboolean
demarshal_dhcp_options (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field)
{
	NMDhcpConfigPrivate *priv = NM_DHCP_CONFIG_GET_PRIVATE (object);
	GVariantIter iter;
	const char *key;
	GVariant *opt;

	g_hash_table_remove_all (priv->options);

	g_variant_iter_init (&iter, value);
	while (g_variant_iter_next (&iter, "{&sv}", &key, &opt)) {
		g_hash_table_insert (priv->options, g_strdup (key), g_variant_dup_string (opt, NULL));
		g_variant_unref (opt);
	}

	_nm_object_queue_notify (object, NM_DHCP_CONFIG_OPTIONS);
	return TRUE;
}

static void
init_dbus (NMObject *object)
{
	NMDhcpConfigPrivate *priv = NM_DHCP_CONFIG_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DHCP_CONFIG_OPTIONS, &priv->options, demarshal_dhcp_options },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_dhcp_config_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                (NM_IS_DHCP4_CONFIG (object) ?
	                                 NM_DBUS_INTERFACE_DHCP4_CONFIG :
	                                 NM_DBUS_INTERFACE_DHCP6_CONFIG),
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMDhcpConfigPrivate *priv = NM_DHCP_CONFIG_GET_PRIVATE (object);

	if (priv->options)
		g_hash_table_destroy (priv->options);

	G_OBJECT_CLASS (nm_dhcp_config_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDhcpConfig *self = NM_DHCP_CONFIG (object);

	switch (prop_id) {
	case PROP_FAMILY:
		g_value_set_int (value, nm_dhcp_config_get_family (self));
		break;
	case PROP_OPTIONS:
		g_value_set_boxed (value, nm_dhcp_config_get_options (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_dhcp_config_class_init (NMDhcpConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMDhcpConfigPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	/* properties */

	/**
	 * NMDhcpConfig:family:
	 *
	 * The IP address family of the configuration; either
	 * <literal>AF_INET</literal> or <literal>AF_INET6</literal>.
	 **/
	g_object_class_install_property
		(object_class, PROP_FAMILY,
		 g_param_spec_int (NM_DHCP_CONFIG_FAMILY, "", "",
		                   0, 255, AF_UNSPEC,
		                   G_PARAM_READABLE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMDhcpConfig:options: (type GHashTable(utf8,utf8)):
	 *
	 * The #GHashTable containing options of the configuration.
	 **/
	g_object_class_install_property
		(object_class, PROP_OPTIONS,
		 g_param_spec_boxed (NM_DHCP_CONFIG_OPTIONS, "", "",
		                     G_TYPE_HASH_TABLE,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
}

/**
 * nm_dhcp_config_get_family:
 * @config: a #NMDhcpConfig
 *
 * Gets the IP address family of the configuration
 *
 * Returns: the IP address family; either <literal>AF_INET</literal> or
 *   <literal>AF_INET6</literal>
 **/
int
nm_dhcp_config_get_family (NMDhcpConfig *config)
{
	g_return_val_if_fail (NM_IS_DHCP_CONFIG (config), AF_UNSPEC);

	return NM_IS_DHCP4_CONFIG (config) ? AF_INET : AF_INET6;
}

/**
 * nm_dhcp_config_get_options:
 * @config: a #NMDhcpConfig
 *
 * Gets all the options contained in the configuration.
 *
 * Returns: (transfer none) (element-type utf8 utf8): the #GHashTable containing
 * strings for keys and values.  This is the internal copy used by the
 * configuration, and must not be modified.
 **/
GHashTable *
nm_dhcp_config_get_options (NMDhcpConfig *config)
{
	g_return_val_if_fail (NM_IS_DHCP_CONFIG (config), NULL);

	return NM_DHCP_CONFIG_GET_PRIVATE (config)->options;
}

/**
 * nm_dhcp_config_get_one_option:
 * @config: a #NMDhcpConfig
 * @option: the option to retrieve
 *
 * Gets one option by option name.
 *
 * Returns: the configuration option's value. This is the internal string used by the
 * configuration, and must not be modified.
 **/
const char *
nm_dhcp_config_get_one_option (NMDhcpConfig *config, const char *option)
{
	g_return_val_if_fail (NM_IS_DHCP_CONFIG (config), NULL);

	return g_hash_table_lookup (nm_dhcp_config_get_options (config), option);
}
