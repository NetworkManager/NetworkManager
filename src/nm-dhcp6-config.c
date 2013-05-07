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

#include <glib.h>
#include <string.h>

#include "NetworkManager.h"
#include "nm-dbus-manager.h"
#include "nm-dhcp6-config.h"
#include "nm-dhcp6-config-glue.h"
#include "nm-dbus-glib-types.h"
#include "nm-utils.h"


G_DEFINE_TYPE (NMDHCP6Config, nm_dhcp6_config, G_TYPE_OBJECT)

#define NM_DHCP6_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP6_CONFIG, NMDHCP6ConfigPrivate))

typedef struct {
	char *dbus_path;
	GHashTable *options;
} NMDHCP6ConfigPrivate;


enum {
	PROP_0,
	PROP_OPTIONS,

	LAST_PROP
};


NMDHCP6Config *
nm_dhcp6_config_new (void)
{
	return NM_DHCP6_CONFIG (g_object_new (NM_TYPE_DHCP6_CONFIG, NULL));
}

void
nm_dhcp6_config_add_option (NMDHCP6Config *self,
                            const char *key,
                            const char *option)
{
	GValue *svalue;

	g_return_if_fail (NM_IS_DHCP6_CONFIG (self));
	g_return_if_fail (key != NULL);
	g_return_if_fail (option != NULL);

	svalue = g_slice_new0 (GValue);
	g_value_init (svalue, G_TYPE_STRING);
	g_value_set_string (svalue, option);
	g_hash_table_insert (NM_DHCP6_CONFIG_GET_PRIVATE (self)->options, g_strdup (key), svalue);
	g_object_notify (G_OBJECT (self), NM_DHCP6_CONFIG_OPTIONS);
}

void
nm_dhcp6_config_reset (NMDHCP6Config *self)
{
	g_return_if_fail (NM_IS_DHCP6_CONFIG (self));

	g_hash_table_remove_all (NM_DHCP6_CONFIG_GET_PRIVATE (self)->options);
	g_object_notify (G_OBJECT (self), NM_DHCP6_CONFIG_OPTIONS);
}

const char *
nm_dhcp6_config_get_option (NMDHCP6Config *self, const char *key)
{
	GValue *value;

	g_return_val_if_fail (NM_IS_DHCP6_CONFIG (self), NULL);
	g_return_val_if_fail (key != NULL, NULL);

	value = g_hash_table_lookup (NM_DHCP6_CONFIG_GET_PRIVATE (self)->options, key);
	return value ? g_value_get_string (value) : NULL;
}

/* Caller owns the list, but not the values in the list */
GSList *
nm_dhcp6_config_list_options (NMDHCP6Config *self)
{
	GHashTableIter iter;
	const char *option = NULL;
	GSList *list = NULL;

	g_return_val_if_fail (NM_IS_DHCP6_CONFIG (self), NULL);

	g_hash_table_iter_init (&iter, NM_DHCP6_CONFIG_GET_PRIVATE (self)->options);
	while (g_hash_table_iter_next (&iter, (gpointer) &option, NULL))
		list = g_slist_prepend (list, (gpointer) option);

	return list;
}

const char *
nm_dhcp6_config_get_dbus_path (NMDHCP6Config *self)
{
	g_return_val_if_fail (NM_IS_DHCP6_CONFIG (self), NULL);

	return NM_DHCP6_CONFIG_GET_PRIVATE (self)->dbus_path;
}

static void
nm_gvalue_destroy (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static void
nm_dhcp6_config_init (NMDHCP6Config *self)
{
	NMDHCP6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (self);
	static guint32 counter = 0;

	priv->dbus_path = g_strdup_printf (NM_DBUS_PATH "/DHCP6Config/%d", counter++);
	nm_dbus_manager_register_object (nm_dbus_manager_get (), priv->dbus_path, self);

	priv->options = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, nm_gvalue_destroy);
}

static void
finalize (GObject *object)
{
	NMDHCP6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);

	g_free (priv->dbus_path);
	g_hash_table_destroy (priv->options);

	G_OBJECT_CLASS (nm_dhcp6_config_parent_class)->finalize (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMDHCP6ConfigPrivate *priv = NM_DHCP6_CONFIG_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_OPTIONS:
		g_value_set_boxed (value, priv->options);
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
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_OPTIONS,
		 g_param_spec_boxed (NM_DHCP6_CONFIG_OPTIONS,
		                     "Options",
		                     "DHCP configuration options returned by the server",
		                     DBUS_TYPE_G_MAP_OF_VARIANT,
		                     G_PARAM_READABLE));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (config_class),
	                                        &dbus_glib_nm_dhcp6_config_object_info);
}
