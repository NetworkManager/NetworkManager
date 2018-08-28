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
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nms-ifcfg-rh-connection.h"

#include <string.h>
#include <sys/inotify.h>
#include <glib/gstdio.h>

#include "nm-dbus-interface.h"
#include "nm-setting-connection.h"
#include "nm-setting-wired.h"
#include "nm-setting-wireless.h"
#include "nm-setting-gsm.h"
#include "nm-setting-cdma.h"
#include "nm-setting-pppoe.h"
#include "nm-setting-wireless-security.h"
#include "nm-setting-8021x.h"
#include "platform/nm-platform.h"
#include "nm-config.h"

#include "nms-ifcfg-rh-common.h"
#include "nms-ifcfg-rh-reader.h"
#include "nms-ifcfg-rh-writer.h"
#include "nms-ifcfg-rh-utils.h"
#include "nm-inotify-helper.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_UNMANAGED_SPEC,
	PROP_UNRECOGNIZED_SPEC,
);

enum {
	IFCFG_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	gulong ih_event_id;

	int file_wd;

	char *keyfile;
	int keyfile_wd;

	char *routefile;
	int routefile_wd;

	char *route6file;
	int route6file_wd;

	char *unmanaged_spec;
	char *unrecognized_spec;

	gulong devtimeout_link_changed_handler;
	guint devtimeout_timeout_id;

	NMInotifyHelper *inotify_helper;
} NMIfcfgConnectionPrivate;

struct _NMIfcfgConnection {
	NMSettingsConnection parent;
	NMIfcfgConnectionPrivate _priv;
};

struct _NMIfcfgConnectionClass {
	NMSettingsConnectionClass parent;
};

G_DEFINE_TYPE (NMIfcfgConnection, nm_ifcfg_connection, NM_TYPE_SETTINGS_CONNECTION)

#define NM_IFCFG_CONNECTION_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMIfcfgConnection, NM_IS_IFCFG_CONNECTION)

/*****************************************************************************/

static gboolean
devtimeout_ready (gpointer user_data)
{
	NMIfcfgConnection *self = user_data;
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (self);

	priv->devtimeout_timeout_id = 0;
	nm_settings_connection_set_ready (NM_SETTINGS_CONNECTION (self), TRUE);
	return FALSE;
}

static void
link_changed (NMPlatform *platform, int obj_type_i, int ifindex, const NMPlatformLink *link,
              int change_type_i,
              NMConnection *self)
{
	const NMPlatformSignalChangeType change_type = change_type_i;
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE ((NMIfcfgConnection *) self);
	const char *ifname;

	ifname = nm_connection_get_interface_name (self);
	if (g_strcmp0 (link->name, ifname) != 0)
		return;

	if (change_type == NM_PLATFORM_SIGNAL_REMOVED)
		return;

	nm_log_info (LOGD_SETTINGS, "Device %s appeared; connection '%s' now ready",
	             ifname, nm_connection_get_id (self));

	g_signal_handler_disconnect (platform, priv->devtimeout_link_changed_handler);
	priv->devtimeout_link_changed_handler = 0;
	g_source_remove (priv->devtimeout_timeout_id);

	/* Don't declare the connection ready right away, since NMManager may not have
	 * started processing the device yet.
	 */
	priv->devtimeout_timeout_id = g_idle_add (devtimeout_ready, self);
}

static gboolean
devtimeout_expired (gpointer user_data)
{
	NMIfcfgConnection *self = user_data;
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (self);

	nm_log_info (LOGD_SETTINGS, "Device for connection '%s' did not appear before timeout",
	             nm_settings_connection_get_id (NM_SETTINGS_CONNECTION (self)));

	g_signal_handler_disconnect (NM_PLATFORM_GET, priv->devtimeout_link_changed_handler);
	priv->devtimeout_link_changed_handler = 0;
	priv->devtimeout_timeout_id = 0;

	nm_settings_connection_set_ready (NM_SETTINGS_CONNECTION (self), TRUE);
	return FALSE;
}

static void
nm_ifcfg_connection_check_devtimeout (NMIfcfgConnection *self)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (self);
	NMSettingConnection *s_con;
	const char *ifname;
	const char *filename;
	guint devtimeout;
	const NMPlatformLink *pllink;

	s_con = nm_connection_get_setting_connection (nm_settings_connection_get_connection (NM_SETTINGS_CONNECTION (self)));

	if (!nm_setting_connection_get_autoconnect (s_con))
		return;
	ifname = nm_setting_connection_get_interface_name (s_con);
	if (!ifname)
		return;
	filename = nm_settings_connection_get_filename (NM_SETTINGS_CONNECTION (self));
	if (!filename)
		return;

	pllink = nm_platform_link_get_by_ifname (NM_PLATFORM_GET, ifname);
	if (pllink && pllink->initialized)
		return;

	devtimeout = devtimeout_from_file (filename);
	if (!devtimeout)
		return;

	/* ONBOOT=yes, DEVICE and DEVTIMEOUT are set, but device is not present */
	nm_settings_connection_set_ready (NM_SETTINGS_CONNECTION (self), FALSE);

	nm_log_info (LOGD_SETTINGS, "Waiting %u seconds for %s to appear for connection '%s'",
	             devtimeout, ifname, nm_settings_connection_get_id (NM_SETTINGS_CONNECTION (self)));

	priv->devtimeout_link_changed_handler =
	    g_signal_connect (NM_PLATFORM_GET, NM_PLATFORM_SIGNAL_LINK_CHANGED,
	                      G_CALLBACK (link_changed), self);
	priv->devtimeout_timeout_id = g_timeout_add_seconds (devtimeout, devtimeout_expired, self);
}

static void
files_changed_cb (NMInotifyHelper *ih,
                  struct inotify_event *evt,
                  const char *path,
                  gpointer user_data)
{
	NMIfcfgConnection *self = NM_IFCFG_CONNECTION (user_data);
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (self);

	if (   (evt->wd != priv->file_wd)
	    && (evt->wd != priv->keyfile_wd)
	    && (evt->wd != priv->routefile_wd)
	    && (evt->wd != priv->route6file_wd))
		return;

	/* push the event up to the plugin */
	g_signal_emit (self, signals[IFCFG_CHANGED], 0);
}

static void
path_watch_stop (NMIfcfgConnection *self)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (self);

	nm_clear_g_signal_handler (priv->inotify_helper, &priv->ih_event_id);

	nm_inotify_helper_clear_watch (priv->inotify_helper, &priv->file_wd);
	nm_inotify_helper_clear_watch (priv->inotify_helper, &priv->keyfile_wd);
	nm_inotify_helper_clear_watch (priv->inotify_helper, &priv->routefile_wd);
	nm_inotify_helper_clear_watch (priv->inotify_helper, &priv->route6file_wd);

	nm_clear_g_free (&priv->keyfile);
	nm_clear_g_free (&priv->routefile);
	nm_clear_g_free (&priv->route6file);
}

static void
filename_changed (GObject *object,
                  GParamSpec *pspec,
                  gpointer user_data)
{
	NMIfcfgConnection *self = NM_IFCFG_CONNECTION (object);
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (self);
	const char *ifcfg_path;

	path_watch_stop (self);

	ifcfg_path = nm_settings_connection_get_filename (NM_SETTINGS_CONNECTION (self));
	if (!ifcfg_path)
		return;

	priv->keyfile = utils_get_keys_path (ifcfg_path);
	priv->routefile = utils_get_route_path (ifcfg_path);
	priv->route6file = utils_get_route6_path (ifcfg_path);

	if (nm_config_get_monitor_connection_files (nm_config_get ())) {
		NMInotifyHelper *ih;

		if (!priv->inotify_helper)
			priv->inotify_helper = g_object_ref (nm_inotify_helper_get ());
		ih = priv->inotify_helper;

		priv->ih_event_id = g_signal_connect (ih, "event", G_CALLBACK (files_changed_cb), self);
		priv->file_wd = nm_inotify_helper_add_watch (ih, ifcfg_path);
		priv->keyfile_wd = nm_inotify_helper_add_watch (ih, priv->keyfile);
		priv->routefile_wd = nm_inotify_helper_add_watch (ih, priv->routefile);
		priv->route6file_wd = nm_inotify_helper_add_watch (ih, priv->route6file);
	}
}

const char *
nm_ifcfg_connection_get_unmanaged_spec (NMIfcfgConnection *self)
{
	g_return_val_if_fail (NM_IS_IFCFG_CONNECTION (self), NULL);

	return NM_IFCFG_CONNECTION_GET_PRIVATE (self)->unmanaged_spec;
}

const char *
nm_ifcfg_connection_get_unrecognized_spec (NMIfcfgConnection *self)
{
	g_return_val_if_fail (NM_IS_IFCFG_CONNECTION (self), NULL);

	return NM_IFCFG_CONNECTION_GET_PRIVATE (self)->unrecognized_spec;
}

static gboolean
commit_changes (NMSettingsConnection *connection,
                NMConnection *new_connection,
                NMSettingsConnectionCommitReason commit_reason,
                NMConnection **out_reread_connection,
                char **out_logmsg_change,
                GError **error)
{
	const char *filename;
	gs_unref_object NMConnection *reread = NULL;
	gboolean reread_same = TRUE;
	const char *operation_message;
	gs_free char *ifcfg_path = NULL;

	nm_assert (out_reread_connection && !*out_reread_connection);
	nm_assert (!out_logmsg_change || !*out_logmsg_change);

	filename = nm_settings_connection_get_filename (connection);
	if (!nms_ifcfg_rh_writer_write_connection (new_connection,
	                                           IFCFG_DIR,
	                                           filename,
	                                           &ifcfg_path,
	                                           &reread,
	                                           &reread_same,
	                                           error))
		return FALSE;

	nm_assert ((!filename && ifcfg_path) || (filename && !ifcfg_path));
	if (ifcfg_path) {
		nm_settings_connection_set_filename (connection, ifcfg_path);
		operation_message = "persist";
	} else
		operation_message = "update";

	if (reread && !reread_same)
		*out_reread_connection = g_steal_pointer (&reread);

	NM_SET_OUT (out_logmsg_change,
	            g_strdup_printf ("ifcfg-rh: %s %s",
	                             operation_message, filename));
	return TRUE;
}

static gboolean
delete (NMSettingsConnection *connection,
        GError **error)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE ((NMIfcfgConnection *) connection);
	const char *filename;

	filename = nm_settings_connection_get_filename (connection);
	if (filename) {
		g_unlink (filename);
		if (priv->keyfile)
			g_unlink (priv->keyfile);
		if (priv->routefile)
			g_unlink (priv->routefile);
		if (priv->route6file)
			g_unlink (priv->route6file);
	}

	return TRUE;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE ((NMIfcfgConnection *) object);

	switch (prop_id) {
	case PROP_UNMANAGED_SPEC:
		g_value_set_string (value, priv->unmanaged_spec);
		break;
	case PROP_UNRECOGNIZED_SPEC:
		g_value_set_string (value, priv->unrecognized_spec);
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
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE ((NMIfcfgConnection *) object);

	switch (prop_id) {
	case PROP_UNMANAGED_SPEC:
		priv->unmanaged_spec = g_value_dup_string (value);
		break;
	case PROP_UNRECOGNIZED_SPEC:
		priv->unrecognized_spec = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_ifcfg_connection_init (NMIfcfgConnection *connection)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (connection);

	priv->file_wd = -1;
	priv->keyfile_wd = -1;
	priv->routefile_wd = -1;
	priv->route6file_wd = -1;

	g_signal_connect (connection, "notify::" NM_SETTINGS_CONNECTION_FILENAME,
	                  G_CALLBACK (filename_changed), NULL);
}

NMIfcfgConnection *
nm_ifcfg_connection_new (NMConnection *source,
                         const char *full_path,
                         GError **error,
                         gboolean *out_ignore_error)
{
	GObject *object;
	NMConnection *tmp;
	char *unhandled_spec = NULL;
	const char *unmanaged_spec = NULL, *unrecognized_spec = NULL;

	g_assert (source || full_path);

	if (out_ignore_error)
		*out_ignore_error = FALSE;

	/* If we're given a connection already, prefer that instead of re-reading */
	if (source)
		tmp = g_object_ref (source);
	else {
		tmp = connection_from_file (full_path,
		                            &unhandled_spec,
		                            error,
		                            out_ignore_error);
		if (!tmp)
			return NULL;
	}

	if (unhandled_spec && g_str_has_prefix (unhandled_spec, "unmanaged:"))
		unmanaged_spec = unhandled_spec + strlen ("unmanaged:");
	else if (unhandled_spec && g_str_has_prefix (unhandled_spec, "unrecognized:"))
		unrecognized_spec = unhandled_spec + strlen ("unrecognized:");

	object = (GObject *) g_object_new (NM_TYPE_IFCFG_CONNECTION,
	                                   NM_SETTINGS_CONNECTION_FILENAME, full_path,
	                                   NM_IFCFG_CONNECTION_UNMANAGED_SPEC, unmanaged_spec,
	                                   NM_IFCFG_CONNECTION_UNRECOGNIZED_SPEC, unrecognized_spec,
	                                   NULL);
	/* Update our settings with what was read from the file */
	if (nm_settings_connection_update (NM_SETTINGS_CONNECTION (object),
	                                   tmp,
	                                   full_path
	                                     ? NM_SETTINGS_CONNECTION_PERSIST_MODE_KEEP_SAVED
	                                     : NM_SETTINGS_CONNECTION_PERSIST_MODE_UNSAVED,
	                                   NM_SETTINGS_CONNECTION_COMMIT_REASON_NONE,
	                                   NULL,
	                                   error))
		nm_ifcfg_connection_check_devtimeout (NM_IFCFG_CONNECTION (object));
	else
		g_clear_object (&object);

	g_object_unref (tmp);
	g_free (unhandled_spec);
	return (NMIfcfgConnection *) object;
}

static void
dispose (GObject *object)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE ((NMIfcfgConnection *) object);

	path_watch_stop (NM_IFCFG_CONNECTION (object));

	nm_clear_g_signal_handler (NM_PLATFORM_GET, &priv->devtimeout_link_changed_handler);
	nm_clear_g_source (&priv->devtimeout_timeout_id);

	g_clear_object (&priv->inotify_helper);

	g_clear_pointer (&priv->unmanaged_spec, g_free);
	g_clear_pointer (&priv->unrecognized_spec, g_free);

	G_OBJECT_CLASS (nm_ifcfg_connection_parent_class)->dispose (object);
}

static void
nm_ifcfg_connection_class_init (NMIfcfgConnectionClass *ifcfg_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ifcfg_connection_class);
	NMSettingsConnectionClass *settings_class = NM_SETTINGS_CONNECTION_CLASS (ifcfg_connection_class);

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose      = dispose;

	settings_class->delete = delete;
	settings_class->commit_changes = commit_changes;

	obj_properties[PROP_UNMANAGED_SPEC] =
	     g_param_spec_string (NM_IFCFG_CONNECTION_UNMANAGED_SPEC, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_UNRECOGNIZED_SPEC] =
	     g_param_spec_string (NM_IFCFG_CONNECTION_UNRECOGNIZED_SPEC, "", "",
	                          NULL,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[IFCFG_CHANGED] =
	    g_signal_new ("ifcfg-changed",
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0, NULL, NULL,
	                  g_cclosure_marshal_VOID__VOID,
	                  G_TYPE_NONE, 0);
}

