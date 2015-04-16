/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager system settings service
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
 * Copyright 2014 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <gmodule.h>

#include <nm-setting-connection.h>

#include "nm-default.h"
#include "nm-settings-plugin.h"
#include "NetworkManagerUtils.h"

#include "plugin.h"
#include "reader.h"
#include "nm-ibft-connection.h"

static void settings_plugin_interface_init (NMSettingsPluginInterface *plugin_iface);

G_DEFINE_TYPE_EXTENDED (SettingsPluginIbft, settings_plugin_ibft, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_PLUGIN,
                                               settings_plugin_interface_init))

#define SETTINGS_PLUGIN_IBFT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SETTINGS_TYPE_PLUGIN_IBFT, SettingsPluginIbftPrivate))


typedef struct {
	GHashTable *connections;  /* uuid::connection */
	gboolean initialized;
} SettingsPluginIbftPrivate;

static SettingsPluginIbft *settings_plugin_ibft_get (void);
NM_DEFINE_SINGLETON_GETTER (SettingsPluginIbft, settings_plugin_ibft_get, SETTINGS_TYPE_PLUGIN_IBFT);

static void
read_connections (SettingsPluginIbft *self)
{
	SettingsPluginIbftPrivate *priv = SETTINGS_PLUGIN_IBFT_GET_PRIVATE (self);
	GSList *blocks = NULL, *iter;
	GError *error = NULL;
	NMIbftConnection *connection;

	if (!read_ibft_blocks ("/sbin/iscsiadm", &blocks, &error)) {
		nm_log_dbg (LOGD_SETTINGS, "ibft: failed to read iscsiadm records: %s", error->message);
		g_error_free (error);
		return;
	}

	for (iter = blocks; iter; iter = iter->next) {
		connection = nm_ibft_connection_new (iter->data, &error);
		if (connection) {
			nm_log_info (LOGD_SETTINGS, "ibft: read connection '%s'",
			             nm_connection_get_id (NM_CONNECTION (connection)));
			g_hash_table_insert (priv->connections,
			                     g_strdup (nm_connection_get_uuid (NM_CONNECTION (connection))),
			                     connection);
		} else {
			nm_log_warn (LOGD_SETTINGS, "ibft: failed to read iscsiadm record: %s", error->message);
			g_clear_error (&error);
		}
	}

	g_slist_free_full (blocks, (GDestroyNotify) g_ptr_array_unref);
}

static GSList *
get_connections (NMSettingsPlugin *config)
{
	SettingsPluginIbft *self = SETTINGS_PLUGIN_IBFT (config);
	SettingsPluginIbftPrivate *priv = SETTINGS_PLUGIN_IBFT_GET_PRIVATE (self);
	GSList *list = NULL;
	GHashTableIter iter;
	NMIbftConnection *connection;

	if (!priv->initialized) {
		read_connections (self);
		priv->initialized = TRUE;
	}

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &connection))
		list = g_slist_prepend (list, connection);

	return list;
}

static void
init (NMSettingsPlugin *config)
{
}

static void
settings_plugin_ibft_init (SettingsPluginIbft *self)
{
	SettingsPluginIbftPrivate *priv = SETTINGS_PLUGIN_IBFT_GET_PRIVATE (self);

	priv->connections = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
}

static void
dispose (GObject *object)
{
	SettingsPluginIbft *self = SETTINGS_PLUGIN_IBFT (object);
	SettingsPluginIbftPrivate *priv = SETTINGS_PLUGIN_IBFT_GET_PRIVATE (self);

	if (priv->connections) {
		g_hash_table_destroy (priv->connections);
		priv->connections = NULL;
	}

	G_OBJECT_CLASS (settings_plugin_ibft_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_SETTINGS_PLUGIN_PROP_NAME:
		g_value_set_string (value, "iBFT");
		break;
	case NM_SETTINGS_PLUGIN_PROP_INFO:
		g_value_set_string (value, "(c) 2014 Red Hat, Inc.  To report bugs please use the NetworkManager mailing list.");
		break;
	case NM_SETTINGS_PLUGIN_PROP_CAPABILITIES:
		g_value_set_uint (value, NM_SETTINGS_PLUGIN_CAP_NONE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
}

static void
settings_plugin_ibft_class_init (SettingsPluginIbftClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SettingsPluginIbftPrivate));

	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	g_object_class_override_property (object_class,
	                                  NM_SETTINGS_PLUGIN_PROP_NAME,
	                                  NM_SETTINGS_PLUGIN_NAME);

	g_object_class_override_property (object_class,
	                                  NM_SETTINGS_PLUGIN_PROP_INFO,
	                                  NM_SETTINGS_PLUGIN_INFO);

	g_object_class_override_property (object_class,
	                                  NM_SETTINGS_PLUGIN_PROP_CAPABILITIES,
	                                  NM_SETTINGS_PLUGIN_CAPABILITIES);
}

static void
settings_plugin_interface_init (NMSettingsPluginInterface *plugin_iface)
{
	/* interface implementation */
	plugin_iface->get_connections = get_connections;
	plugin_iface->init = init;
}

G_MODULE_EXPORT GObject *
nm_settings_plugin_factory (void)
{
	return g_object_ref (settings_plugin_ibft_get ());
}
