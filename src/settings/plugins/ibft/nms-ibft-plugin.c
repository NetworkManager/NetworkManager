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

#include "nm-default.h"

#include "nms-ibft-plugin.h"

#include <unistd.h>
#include <gmodule.h>

#include "nm-setting-connection.h"
#include "settings/nm-settings-plugin.h"
#include "NetworkManagerUtils.h"

#include "nms-ibft-reader.h"
#include "nms-ibft-connection.h"

/*****************************************************************************/

typedef struct {
	GHashTable *connections;  /* uuid::connection */
	gboolean initialized;
} NMSIbftPluginPrivate;

struct _NMSIbftPlugin {
	NMSettingsPlugin parent;
	NMSIbftPluginPrivate _priv;
};

struct _NMSIbftPluginClass {
	NMSettingsPluginClass parent;
};

G_DEFINE_TYPE (NMSIbftPlugin, nms_ibft_plugin, NM_TYPE_SETTINGS_PLUGIN);

#define NMS_IBFT_PLUGIN_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSIbftPlugin, NMS_IS_IBFT_PLUGIN)

/*****************************************************************************/

static NMSIbftPlugin *nms_ibft_plugin_get (void);

NM_DEFINE_SINGLETON_GETTER (NMSIbftPlugin, nms_ibft_plugin_get, NMS_TYPE_IBFT_PLUGIN);

/*****************************************************************************/

static void
read_connections (NMSIbftPlugin *self)
{
	NMSIbftPluginPrivate *priv = NMS_IBFT_PLUGIN_GET_PRIVATE (self);
	GSList *blocks = NULL, *iter;
	GError *error = NULL;
	NMSIbftConnection *connection;

	if (!nms_ibft_reader_load_blocks ("/sbin/iscsiadm", &blocks, &error)) {
		nm_log_dbg (LOGD_SETTINGS, "ibft: failed to read iscsiadm records: %s", error->message);
		g_error_free (error);
		return;
	}

	for (iter = blocks; iter; iter = iter->next) {
		connection = nms_ibft_connection_new (iter->data, &error);
		if (connection) {
			nm_log_info (LOGD_SETTINGS, "ibft: read connection '%s'",
			             nm_settings_connection_get_id (NM_SETTINGS_CONNECTION (connection)));
			g_hash_table_insert (priv->connections,
			                     g_strdup (nm_settings_connection_get_uuid (NM_SETTINGS_CONNECTION (connection))),
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
	NMSIbftPlugin *self = NMS_IBFT_PLUGIN (config);
	NMSIbftPluginPrivate *priv = NMS_IBFT_PLUGIN_GET_PRIVATE (self);
	GSList *list = NULL;
	GHashTableIter iter;
	NMSIbftConnection *connection;

	if (!priv->initialized) {
		read_connections (self);
		priv->initialized = TRUE;
	}

	g_hash_table_iter_init (&iter, priv->connections);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer) &connection))
		list = g_slist_prepend (list, connection);

	return list;
}

/*****************************************************************************/

static void
nms_ibft_plugin_init (NMSIbftPlugin *self)
{
	NMSIbftPluginPrivate *priv = NMS_IBFT_PLUGIN_GET_PRIVATE (self);

	priv->connections = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_object_unref);
}

static void
dispose (GObject *object)
{
	NMSIbftPlugin *self = NMS_IBFT_PLUGIN (object);
	NMSIbftPluginPrivate *priv = NMS_IBFT_PLUGIN_GET_PRIVATE (self);

	if (priv->connections) {
		g_hash_table_destroy (priv->connections);
		priv->connections = NULL;
	}

	G_OBJECT_CLASS (nms_ibft_plugin_parent_class)->dispose (object);
}

static void
nms_ibft_plugin_class_init (NMSIbftPluginClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingsPluginClass *plugin_class = NM_SETTINGS_PLUGIN_CLASS (klass);

	object_class->dispose = dispose;

	plugin_class->get_connections = get_connections;
}

/*****************************************************************************/

G_MODULE_EXPORT NMSettingsPlugin *
nm_settings_plugin_factory (void)
{
	return NM_SETTINGS_PLUGIN (g_object_ref (nms_ibft_plugin_get ()));
}
