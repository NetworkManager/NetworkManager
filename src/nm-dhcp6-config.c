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

#include "nm-default.h"

#include <string.h>

#include "nm-dbus-interface.h"
#include "nm-dhcp6-config.h"
#include "nm-utils.h"

#include "nmdbus-dhcp6-config.h"

G_DEFINE_TYPE (NMDhcp6Config, nm_dhcp6_config, NM_TYPE_EXPORTED_OBJECT)

#define NM_DHCP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP6_CONFIG, NMDhcp6ConfigPrivate))

typedef struct {
	GVariant *options;
} NMDhcp6ConfigPrivate;


enum {
	PROP_0,
	PROP_OPTIONS,

	LAST_PROP
};


NMDhcp6Config *
nm_dhcp6_config_new (void)
{
	return NM_DHCP6_CONFIG (g_object_new (NM_TYPE_DHCP6_CONFIG, NULL));
}

void
nm_dhcp6_config_set_options (NMDhcp6Config *self,
                             GHashTable *options)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (self);
	GHashTableIter iter;
	const char *key, *value;
	GVariantBuilder builder;

	g_return_if_fail (NM_IS_DHCP6_CONFIG (self));
	g_return_if_fail (options != NULL);

	g_variant_unref (priv->options);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	g_hash_table_iter_init (&iter, options);
	while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &value))
		g_variant_builder_add (&builder, "{sv}", key, g_variant_new_string (value));

	priv->options = g_variant_builder_end (&builder);
	g_variant_ref_sink (priv->options);
	g_object_notify (G_OBJECT (self), NM_DHCP6_CONFIG_OPTIONS);
}

const char *
nm_dhcp6_config_get_option (NMDhcp6Config *self, const char *key)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (self);
	const char *value;

	g_return_val_if_fail (NM_IS_DHCP6_CONFIG (self), NULL);
	g_return_val_if_fail (key != NULL, NULL);

	if (g_variant_lookup (priv->options, key, "&s", &value))
		return value;
	else
		return NULL;
}

GVariant *
nm_dhcp6_config_get_options (NMDhcp6Config *self)
{
	g_return_val_if_fail (NM_IS_DHCP6_CONFIG (self), NULL);

	return g_variant_ref (NM_DHCP6_CONFIG_GET_PRIVATE (self)->options);
}

static void
nm_dhcp6_config_init (NMDhcp6Config *self)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (self);

	priv->options = g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0);
	g_variant_ref_sink (priv->options);
}

static void
finalize (GObject *object)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);

	g_variant_unref (priv->options);

	G_OBJECT_CLASS (nm_dhcp6_config_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMDhcp6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_OPTIONS:
		g_value_set_variant (value, priv->options);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_dhcp6_config_class_init (NMDhcp6ConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMDhcp6ConfigPrivate));

	exported_object_class->export_path = NM_DBUS_PATH "/DHCP6Config/%u";
	exported_object_class->export_on_construction = TRUE;

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_OPTIONS,
		 g_param_spec_variant (NM_DHCP6_CONFIG_OPTIONS, "", "",
		                       G_VARIANT_TYPE ("a{sv}"),
		                       NULL,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (config_class),
	                                        NMDBUS_TYPE_DHCP6_CONFIG_SKELETON,
	                                        NULL);
}
