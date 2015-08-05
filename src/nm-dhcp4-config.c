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
 * Copyright (C) 2008 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>

#include "nm-default.h"
#include "nm-dbus-interface.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp4-config-glue.h"
#include "nm-dbus-glib-types.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMDhcp4Config, nm_dhcp4_config, NM_TYPE_EXPORTED_OBJECT)

#define NM_DHCP4_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP4_CONFIG, NMDhcp4ConfigPrivate))

typedef struct {
	GVariant *options;
} NMDhcp4ConfigPrivate;


enum {
	PROP_0,
	PROP_OPTIONS,

	LAST_PROP
};


NMDhcp4Config *
nm_dhcp4_config_new (void)
{
	return NM_DHCP4_CONFIG (g_object_new (NM_TYPE_DHCP4_CONFIG, NULL));
}

void
nm_dhcp4_config_set_options (NMDhcp4Config *self,
                             GHashTable *options)
{
	NMDhcp4ConfigPrivate *priv = NM_DHCP4_CONFIG_GET_PRIVATE (self);
	GHashTableIter iter;
	const char *key, *value;
	GVariantBuilder builder;

	g_return_if_fail (NM_IS_DHCP4_CONFIG (self));
	g_return_if_fail (options != NULL);

	g_variant_unref (priv->options);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_hash_table_iter_init (&iter, options);
	while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &value))
		g_variant_builder_add (&builder, "{sv}", key, g_variant_new_string (value));

	priv->options = g_variant_builder_end (&builder);
	g_variant_ref_sink (priv->options);
	g_object_notify (G_OBJECT (self), NM_DHCP4_CONFIG_OPTIONS);
}

const char *
nm_dhcp4_config_get_option (NMDhcp4Config *self, const char *key)
{
	NMDhcp4ConfigPrivate *priv = NM_DHCP4_CONFIG_GET_PRIVATE (self);
	const char *value;

	g_return_val_if_fail (NM_IS_DHCP4_CONFIG (self), NULL);
	g_return_val_if_fail (key != NULL, NULL);

	if (g_variant_lookup (priv->options, key, "&s", &value))
		return value;
	else
		return NULL;
}

GVariant *
nm_dhcp4_config_get_options (NMDhcp4Config *self)
{
	g_return_val_if_fail (NM_IS_DHCP4_CONFIG (self), NULL);

	return g_variant_ref (NM_DHCP4_CONFIG_GET_PRIVATE (self)->options);
}

static void
nm_dhcp4_config_init (NMDhcp4Config *self)
{
	NMDhcp4ConfigPrivate *priv = NM_DHCP4_CONFIG_GET_PRIVATE (self);

	nm_exported_object_export (NM_EXPORTED_OBJECT (self));

	priv->options = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0);
	g_variant_ref_sink (priv->options);
}

static void
finalize (GObject *object)
{
	NMDhcp4ConfigPrivate *priv = NM_DHCP4_CONFIG_GET_PRIVATE (object);

	g_variant_unref (priv->options);

	G_OBJECT_CLASS (nm_dhcp4_config_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMDhcp4ConfigPrivate *priv = NM_DHCP4_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_OPTIONS:
		/* dbus_g_value_parse_g_variant() will call g_value_init(), but
		 * @value is already inited.
		 */
		g_value_unset (value);
		dbus_g_value_parse_g_variant (priv->options, value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_dhcp4_config_class_init (NMDhcp4ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMDhcp4ConfigPrivate));

	exported_object_class->export_path = NM_DBUS_PATH "/DHCP4Config/%u";

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_OPTIONS,
		 g_param_spec_boxed (NM_DHCP4_CONFIG_OPTIONS, "", "",
		                     DBUS_TYPE_G_MAP_OF_VARIANT,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (config_class),
	                                        &dbus_glib_nm_dhcp4_config_object_info);
}
