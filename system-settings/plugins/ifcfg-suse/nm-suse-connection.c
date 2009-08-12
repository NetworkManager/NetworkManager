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
 * (C) Copyright 2008 Novell, Inc.
 */

#include <string.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <NetworkManager.h>
#include <nm-settings-connection-interface.h>
#include <nm-setting-connection.h>
#include "nm-suse-connection.h"
#include "parser.h"
#include "nm-system-config-error.h"

G_DEFINE_TYPE (NMSuseConnection, nm_suse_connection, NM_TYPE_SYSCONFIG_CONNECTION)

#define NM_SUSE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SUSE_CONNECTION, NMSuseConnectionPrivate))

typedef struct {
	GFileMonitor *monitor;
	guint monitor_id;

	const char *iface;
	NMDeviceType dev_type;
	char *filename;
} NMSuseConnectionPrivate;

static void
ignore_cb (NMSettingsConnectionInterface *connection,
           GError *error,
           gpointer user_data)
{
}

static void
file_changed (GFileMonitor *monitor,
              GFile *file,
              GFile *other_file,
              GFileMonitorEvent event_type,
              gpointer user_data)
{
	NMSuseConnection *self = NM_SUSE_CONNECTION (user_data);
	NMSuseConnectionPrivate *priv = NM_SUSE_CONNECTION_GET_PRIVATE (self);
	NMConnection *new;

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
		new = parse_ifcfg (priv->iface, priv->dev_type);
		if (new) {
			GError *error = NULL;
			GHashTable *settings;

			if (!nm_connection_compare (new,
			                            NM_CONNECTION (self),
			                            NM_SETTING_COMPARE_FLAG_EXACT)) {
				settings = nm_connection_to_hash (new);
				if (!nm_connection_replace_settings (NM_CONNECTION (self), settings, &error)) {
					g_warning ("%s: '%s' / '%s' invalid: %d",
					           __func__,
					           error ? g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)) : "(none)",
					           (error && error->message) ? error->message : "(none)",
					           error ? error->code : -1);
					g_clear_error (&error);
				}
				g_hash_table_destroy (settings);
				nm_settings_connection_interface_update (NM_SETTINGS_CONNECTION_INTERFACE (self),
				                                         ignore_cb,
				                                         NULL);
			}
			g_object_unref (new);
		} else
			g_signal_emit_by_name (self, "removed");
		break;
	case G_FILE_MONITOR_EVENT_DELETED:
		g_signal_emit_by_name (self, "removed");
		break;
	default:
		break;
	}
}

NMSuseConnection *
nm_suse_connection_new (const char *iface, NMDeviceType dev_type)
{
	NMConnection *tmp;
	GFile *file;
	GFileMonitor *monitor;
	NMSuseConnection *exported;
	NMSuseConnectionPrivate *priv;
	GHashTable *settings;
	NMSettingConnection *s_con;

	g_return_val_if_fail (iface != NULL, NULL);

	tmp = parse_ifcfg (iface, dev_type);
	if (!tmp)
		return NULL;

	/* Ensure the read connection is read-only since we don't have write capability yet */
	s_con = (NMSettingConnection *) nm_connection_get_setting (tmp, NM_TYPE_SETTING_CONNECTION);
	g_assert (s_con);
	if (!nm_setting_connection_get_read_only (s_con)) {
		g_warning ("%s: expected read-only connection!", __func__);
		g_object_unref (tmp);
		return NULL;
	}

	exported = (NMSuseConnection *) g_object_new (NM_TYPE_SUSE_CONNECTION, NULL);
	if (!exported) {
		g_object_unref (tmp);
		return NULL;
	}

	/* Update our settings with what was read from the file */
	settings = nm_connection_to_hash (tmp);
	nm_connection_replace_settings (NM_CONNECTION (exported), settings, NULL);
	g_hash_table_destroy (settings);
	g_object_unref (tmp);

	priv = NM_SUSE_CONNECTION_GET_PRIVATE (exported);

	priv->iface = g_strdup (iface);
	priv->dev_type = dev_type;
	priv->filename = g_strdup_printf (SYSCONFDIR "/sysconfig/network/ifcfg-%s", iface);

	file = g_file_new_for_path (priv->filename);
	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		priv->monitor_id = g_signal_connect (monitor, "changed", G_CALLBACK (file_changed), exported);
		priv->monitor = monitor;
	}

	return exported;
}

/* GObject */

static void
nm_suse_connection_init (NMSuseConnection *connection)
{
}

static void
finalize (GObject *object)
{
	NMSuseConnectionPrivate *priv = NM_SUSE_CONNECTION_GET_PRIVATE (object);

	if (priv->monitor) {
		if (priv->monitor_id)
			g_signal_handler_disconnect (priv->monitor, priv->monitor_id);

		g_file_monitor_cancel (priv->monitor);
		g_object_unref (priv->monitor);
	}

	nm_connection_clear_secrets (NM_CONNECTION (object));
	g_free (priv->filename);

	G_OBJECT_CLASS (nm_suse_connection_parent_class)->finalize (object);
}

static void
nm_suse_connection_class_init (NMSuseConnectionClass *suse_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (suse_connection_class);

	g_type_class_add_private (suse_connection_class, sizeof (NMSuseConnectionPrivate));

	/* Virtual methods */
	object_class->finalize = finalize;
}
