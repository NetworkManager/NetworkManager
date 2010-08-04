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
 * Copyright (C) 2008 - 2009 Red Hat, Inc.
 */

#include <string.h>
#include <net/ethernet.h>
#include <netinet/ether.h>

#include <glib/gstdio.h>

#include <NetworkManager.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-setting-wireless.h>
#include <nm-setting-gsm.h>
#include <nm-setting-cdma.h>
#include <nm-setting-pppoe.h>
#include <nm-setting-wireless-security.h>
#include <nm-setting-8021x.h>
#include <nm-settings-connection-interface.h>

#include "common.h"
#include "nm-ifcfg-connection.h"
#include "reader.h"
#include "writer.h"
#include "nm-inotify-helper.h"

static NMSettingsConnectionInterface *parent_settings_connection_iface;

static void settings_connection_interface_init (NMSettingsConnectionInterface *klass);

G_DEFINE_TYPE_EXTENDED (NMIfcfgConnection, nm_ifcfg_connection, NM_TYPE_SYSCONFIG_CONNECTION, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_SETTINGS_CONNECTION_INTERFACE,
                                               settings_connection_interface_init))

#define NM_IFCFG_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_IFCFG_CONNECTION, NMIfcfgConnectionPrivate))

typedef struct {
	gulong ih_event_id;

	char *filename;
	int file_wd;

	char *keyfile;
	int keyfile_wd;

	char *routefile;
	int routefile_wd;

	char *route6file;
	int route6file_wd;

	char *udi;
	char *unmanaged;
} NMIfcfgConnectionPrivate;

enum {
	PROP_0,
	PROP_FILENAME,
	PROP_UNMANAGED,
	PROP_UDI,

	LAST_PROP
};

/* Signals */
enum {
	IFCFG_CHANGED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
files_changed_cb (NMInotifyHelper *ih,
                  struct inotify_event *evt,
                  const char *path,
                  gpointer user_data)
{
	NMIfcfgConnection *self = NM_IFCFG_CONNECTION (user_data);
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (self);

	if ((evt->wd != priv->file_wd) && (evt->wd != priv->keyfile_wd) && (evt->wd != priv->routefile_wd) && (evt->wd != priv->route6file_wd))
		return;

	/* push the event up to the plugin */
	g_signal_emit (self, signals[IFCFG_CHANGED], 0);
}

NMIfcfgConnection *
nm_ifcfg_connection_new (const char *filename,
                         GError **error,
                         gboolean *ignore_error)
{
	GObject *object;
	NMIfcfgConnectionPrivate *priv;
	NMConnection *tmp;
	char *unmanaged = NULL;
	char *keyfile = NULL;
	char *routefile = NULL;
	char *route6file = NULL;
	NMInotifyHelper *ih;

	g_return_val_if_fail (filename != NULL, NULL);

	tmp = connection_from_file (filename, NULL, NULL, NULL, &unmanaged, &keyfile, &routefile, &route6file, error, ignore_error);
	if (!tmp)
		return NULL;

	object = (GObject *) g_object_new (NM_TYPE_IFCFG_CONNECTION,
	                                   NM_IFCFG_CONNECTION_FILENAME, filename,
	                                   NM_IFCFG_CONNECTION_UNMANAGED, unmanaged,
	                                   NULL);
	if (!object) {
		g_object_unref (tmp);
		return NULL;
	}

	/* Update our settings with what was read from the file */
	nm_sysconfig_connection_update (NM_SYSCONFIG_CONNECTION (object), tmp, FALSE, NULL);
	g_object_unref (tmp);

	priv = NM_IFCFG_CONNECTION_GET_PRIVATE (object);

	ih = nm_inotify_helper_get ();
	priv->ih_event_id = g_signal_connect (ih, "event", G_CALLBACK (files_changed_cb), object);

	priv->file_wd = nm_inotify_helper_add_watch (ih, filename);

	priv->keyfile = keyfile;
	priv->keyfile_wd = nm_inotify_helper_add_watch (ih, keyfile);

	priv->routefile = routefile;
	priv->routefile_wd = nm_inotify_helper_add_watch (ih, routefile);

	priv->route6file = route6file;
	priv->route6file_wd = nm_inotify_helper_add_watch (ih, route6file);

	return NM_IFCFG_CONNECTION (object);
}

const char *
nm_ifcfg_connection_get_filename (NMIfcfgConnection *self)
{
	g_return_val_if_fail (NM_IS_IFCFG_CONNECTION (self), NULL);

	return NM_IFCFG_CONNECTION_GET_PRIVATE (self)->filename;
}

const char *
nm_ifcfg_connection_get_unmanaged_spec (NMIfcfgConnection *self)
{
	g_return_val_if_fail (NM_IS_IFCFG_CONNECTION (self), FALSE);

	return NM_IFCFG_CONNECTION_GET_PRIVATE (self)->unmanaged;
}

static gboolean
update (NMSettingsConnectionInterface *connection,
	    NMSettingsConnectionInterfaceUpdateFunc callback,
	    gpointer user_data)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (connection);
	GError *error = NULL;
	NMConnection *reread;
	char *unmanaged = NULL, *keyfile = NULL, *routefile = NULL, *route6file = NULL;

	/* To ensure we don't rewrite files that are only changed from other
	 * processes on-disk, read the existing connection back in and only rewrite
	 * it if it's really changed.
	 */
	reread = connection_from_file (priv->filename, NULL, NULL, NULL,
	                               &unmanaged, &keyfile, &routefile, &route6file,
	                               NULL, NULL);
	g_free (unmanaged);
	g_free (keyfile);
	g_free (routefile);
	g_free (route6file);

	if (reread && nm_connection_compare (NM_CONNECTION (connection),
	                                     reread,
	                                     NM_SETTING_COMPARE_FLAG_EXACT))
		goto out;

	if (!writer_update_connection (NM_CONNECTION (connection),
	                               IFCFG_DIR,
	                               priv->filename,
	                               priv->keyfile,
	                               &error)) {
		callback (connection, error, user_data);
		g_error_free (error);
		return FALSE;
	}

out:
	if (reread)
		g_object_unref (reread);
	return parent_settings_connection_iface->update (connection, callback, user_data);
}

static gboolean 
do_delete (NMSettingsConnectionInterface *connection,
	       NMSettingsConnectionInterfaceDeleteFunc callback,
	       gpointer user_data)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (connection);

	g_unlink (priv->filename);
	if (priv->keyfile)
		g_unlink (priv->keyfile);
	if (priv->routefile)
		g_unlink (priv->routefile);

	if (priv->route6file)
		g_unlink (priv->route6file);

	return parent_settings_connection_iface->delete (connection, callback, user_data);
}

/* GObject */

static void
settings_connection_interface_init (NMSettingsConnectionInterface *iface)
{
	parent_settings_connection_iface = g_type_interface_peek_parent (iface);
	iface->update = update;
	iface->delete = do_delete;
}

static void
nm_ifcfg_connection_init (NMIfcfgConnection *connection)
{
}

static void
finalize (GObject *object)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (object);
	NMInotifyHelper *ih;

	g_free (priv->udi);

	nm_connection_clear_secrets (NM_CONNECTION (object));

	ih = nm_inotify_helper_get ();

	g_signal_handler_disconnect (ih, priv->ih_event_id);

	g_free (priv->filename);
	if (priv->file_wd >= 0)
		nm_inotify_helper_remove_watch (ih, priv->file_wd);

	g_free (priv->keyfile);
	if (priv->keyfile_wd >= 0)
		nm_inotify_helper_remove_watch (ih, priv->keyfile_wd);

	g_free (priv->routefile);
	if (priv->routefile_wd >= 0)
		nm_inotify_helper_remove_watch (ih, priv->routefile_wd);

	g_free (priv->route6file);
	if (priv->route6file_wd >= 0)
		nm_inotify_helper_remove_watch (ih, priv->route6file_wd);

	G_OBJECT_CLASS (nm_ifcfg_connection_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FILENAME:
		/* Construct only */
		priv->filename = g_value_dup_string (value);
		break;
	case PROP_UNMANAGED:
		priv->unmanaged = g_value_dup_string (value);
		break;
	case PROP_UDI:
		/* Construct only */
		priv->udi = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
		    GValue *value, GParamSpec *pspec)
{
	NMIfcfgConnectionPrivate *priv = NM_IFCFG_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_FILENAME:
		g_value_set_string (value, priv->filename);
		break;
	case PROP_UNMANAGED:
		g_value_set_string (value, priv->unmanaged);
		break;
	case PROP_UDI:
		g_value_set_string (value, priv->udi);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_ifcfg_connection_class_init (NMIfcfgConnectionClass *ifcfg_connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ifcfg_connection_class);

	g_type_class_add_private (ifcfg_connection_class, sizeof (NMIfcfgConnectionPrivate));

	/* Virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_FILENAME,
		 g_param_spec_string (NM_IFCFG_CONNECTION_FILENAME,
						  "FileName",
						  "File name",
						  NULL,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_UNMANAGED,
		 g_param_spec_string (NM_IFCFG_CONNECTION_UNMANAGED,
						  "Unmanaged",
						  "Unmanaged",
						  NULL,
						  G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_UDI,
		 g_param_spec_string (NM_IFCFG_CONNECTION_UDI,
						  "UDI",
						  "UDI",
						  NULL,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	signals[IFCFG_CHANGED] =
		g_signal_new ("ifcfg-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              0, NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);
}

