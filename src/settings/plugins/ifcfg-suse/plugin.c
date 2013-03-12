/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
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
 * (C) Copyright 2007 - 2011 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <config.h>
#include <string.h>

#include <gmodule.h>
#include <glib-object.h>
#include <gio/gio.h>

#include "plugin.h"
#include "nm-system-config-interface.h"

#define IFCFG_PLUGIN_NAME "ifcfg-suse"
#define IFCFG_PLUGIN_INFO "(C) 2008 Novell, Inc.  To report bugs please use the NetworkManager mailing list."
#define IFCFG_DIR SYSCONFDIR "/sysconfig/network"
#define CONF_DHCP IFCFG_DIR "/dhcp"
#define HOSTNAME_FILE "/etc/HOSTNAME"

static void system_config_interface_init (NMSystemConfigInterface *system_config_interface_class);

G_DEFINE_TYPE_EXTENDED (SCPluginIfcfg, sc_plugin_ifcfg, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SYSTEM_CONFIG_INTERFACE,
                                               system_config_interface_init))

#define SC_PLUGIN_IFCFG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), SC_TYPE_PLUGIN_IFCFG, SCPluginIfcfgPrivate))


#define IFCFG_FILE_PATH_TAG "ifcfg-file-path"

typedef struct {
	GFileMonitor *hostname_monitor;
	GFileMonitor *dhcp_monitor;
	char *hostname;
} SCPluginIfcfgPrivate;

GQuark
ifcfg_plugin_error_quark (void)
{
	static GQuark error_quark = 0;

	if (G_UNLIKELY (error_quark == 0))
		error_quark = g_quark_from_static_string ("ifcfg-plugin-error-quark");

	return error_quark;
}

typedef void (*FileChangedFn) (gpointer user_data);

typedef struct {
	FileChangedFn callback;
	gpointer user_data;
} FileMonitorInfo;

static void
file_changed (GFileMonitor *monitor,
		    GFile *file,
		    GFile *other_file,
		    GFileMonitorEvent event_type,
		    gpointer user_data)
{
	FileMonitorInfo *info;

	switch (event_type) {
	case G_FILE_MONITOR_EVENT_CHANGES_DONE_HINT:
	case G_FILE_MONITOR_EVENT_DELETED:
		info = (FileMonitorInfo *) user_data;
		info->callback (info->user_data);
		break;
	default:
		break;
	}
}

static GFileMonitor *
monitor_file_changes (const char *filename,
				  FileChangedFn callback,
				  gpointer user_data)
{
	GFile *file;
	GFileMonitor *monitor;
	FileMonitorInfo *info;

	file = g_file_new_for_path (filename);
	monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, NULL);
	g_object_unref (file);

	if (monitor) {
		info = g_new0 (FileMonitorInfo, 1);
		info->callback = callback;
		info->user_data = user_data;
		g_object_weak_ref (G_OBJECT (monitor), (GWeakNotify) g_free, info);
		g_signal_connect (monitor, "changed", G_CALLBACK (file_changed), info);
	}

	return monitor;
}

static gboolean
hostname_is_dynamic (void)
{
	GIOChannel *channel;
	const char *pattern = "DHCLIENT_SET_HOSTNAME=";
	char *str = NULL;
	int pattern_len;
	gboolean dynamic = FALSE;

	channel = g_io_channel_new_file (CONF_DHCP, "r", NULL);
	if (!channel)
		return dynamic;

	pattern_len = strlen (pattern);

	while (g_io_channel_read_line (channel, &str, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
		if (!strncmp (str, pattern, pattern_len)) {
			if (!strncmp (str + pattern_len, "\"yes\"", 5))
				dynamic = TRUE;
			break;
		}
		g_free (str);
	}

	g_io_channel_shutdown (channel, FALSE, NULL);
	g_io_channel_unref (channel);

	return dynamic;
}

static char *
hostname_read ()
{
	GIOChannel *channel;
	char *hostname = NULL;

	channel = g_io_channel_new_file (HOSTNAME_FILE, "r", NULL);
	if (channel) {
		g_io_channel_read_line (channel, &hostname, NULL, NULL, NULL);
		g_io_channel_shutdown (channel, FALSE, NULL);
		g_io_channel_unref (channel);

		if (hostname)
			hostname = g_strchomp (hostname);
	}

	return hostname;
}

static void
hostname_changed (gpointer data)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (data);

	g_free (priv->hostname);
	if (hostname_is_dynamic ())
		priv->hostname = NULL;
	else
		priv->hostname = hostname_read ();

	g_object_notify (G_OBJECT (data), NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
}

static void
plugin_set_hostname (SCPluginIfcfg *plugin, const char *hostname)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (plugin);
	GIOChannel *channel;

	channel = g_io_channel_new_file (HOSTNAME_FILE, "w", NULL);
	if (channel) {
		g_io_channel_write_chars (channel, hostname, -1, NULL, NULL);
		g_io_channel_write_chars (channel, "\n", -1, NULL, NULL);
		g_io_channel_shutdown (channel, TRUE, NULL);
		g_io_channel_unref (channel);
	}

	g_free (priv->hostname);
	priv->hostname = g_strdup (hostname);
}

static void
init (NMSystemConfigInterface *config)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (config);

	priv->hostname_monitor = monitor_file_changes (HOSTNAME_FILE, hostname_changed, config);
	priv->dhcp_monitor = monitor_file_changes (CONF_DHCP, hostname_changed, config);

	if (!hostname_is_dynamic ())
		priv->hostname = hostname_read ();
}

static void
sc_plugin_ifcfg_init (SCPluginIfcfg *self)
{
}

static void
dispose (GObject *object)
{
	SCPluginIfcfgPrivate *priv = SC_PLUGIN_IFCFG_GET_PRIVATE (object);

	if (priv->dhcp_monitor)
		g_object_unref (priv->dhcp_monitor);

	if (priv->hostname_monitor)
		g_object_unref (priv->hostname_monitor);

	g_free (priv->hostname);

	G_OBJECT_CLASS (sc_plugin_ifcfg_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME:
		g_value_set_string (value, IFCFG_PLUGIN_NAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO:
		g_value_set_string (value, IFCFG_PLUGIN_INFO);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES:
		g_value_set_uint (value, NM_SYSTEM_CONFIG_INTERFACE_CAP_MODIFY_HOSTNAME);
		break;
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		g_value_set_string (value, SC_PLUGIN_IFCFG_GET_PRIVATE (object)->hostname);
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
	const char *hostname;

	switch (prop_id) {
	case NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME:
		hostname = g_value_get_string (value);
		if (hostname && strlen (hostname) < 1)
			hostname = NULL;
		plugin_set_hostname (SC_PLUGIN_IFCFG (object), hostname);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
sc_plugin_ifcfg_class_init (SCPluginIfcfgClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	g_type_class_add_private (req_class, sizeof (SCPluginIfcfgPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	g_object_class_override_property (object_class,
							    NM_SYSTEM_CONFIG_INTERFACE_PROP_NAME,
							    NM_SYSTEM_CONFIG_INTERFACE_NAME);

	g_object_class_override_property (object_class,
							    NM_SYSTEM_CONFIG_INTERFACE_PROP_INFO,
							    NM_SYSTEM_CONFIG_INTERFACE_INFO);

	g_object_class_override_property (object_class,
							    NM_SYSTEM_CONFIG_INTERFACE_PROP_CAPABILITIES,
							    NM_SYSTEM_CONFIG_INTERFACE_CAPABILITIES);

	g_object_class_override_property (object_class,
							    NM_SYSTEM_CONFIG_INTERFACE_PROP_HOSTNAME,
							    NM_SYSTEM_CONFIG_INTERFACE_HOSTNAME);
}

static void
system_config_interface_init (NMSystemConfigInterface *system_config_interface_class)
{
	/* interface implementation */
	system_config_interface_class->init = init;
}

G_MODULE_EXPORT GObject *
nm_system_config_factory (void)
{
	static SCPluginIfcfg *singleton = NULL;

	if (!singleton)
		singleton = SC_PLUGIN_IFCFG (g_object_new (SC_TYPE_PLUGIN_IFCFG, NULL));
	else
		g_object_ref (singleton);

	return G_OBJECT (singleton);
}
