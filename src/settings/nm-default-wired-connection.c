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
 * (C) Copyright 2009 - 2011 Red Hat, Inc.
 */

#include "config.h"

#include <netinet/ether.h>

#include <NetworkManager.h>
#include <nm-setting-connection.h>
#include <nm-setting-wired.h>
#include <nm-utils.h>

#include "nm-dbus-glib-types.h"
#include "nm-marshal.h"
#include "nm-default-wired-connection.h"

G_DEFINE_TYPE (NMDefaultWiredConnection, nm_default_wired_connection, NM_TYPE_SETTINGS_CONNECTION)

#define NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEFAULT_WIRED_CONNECTION, NMDefaultWiredConnectionPrivate))

typedef struct {
	gboolean disposed;
	NMDevice *device;
	GByteArray *mac;
} NMDefaultWiredConnectionPrivate;

enum {
	TRY_UPDATE,
	DELETED,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/****************************************************************/

NMDevice *
nm_default_wired_connection_get_device (NMDefaultWiredConnection *wired)
{
	g_return_val_if_fail (NM_IS_DEFAULT_WIRED_CONNECTION (wired), NULL);

	return NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (wired)->device;
}

static void
commit_changes (NMSettingsConnection *connection,
                NMSettingsConnectionCommitFunc callback,
                gpointer user_data)
{
	NMDefaultWiredConnection *self = NM_DEFAULT_WIRED_CONNECTION (connection);

	/* Keep the object alive over try-update since it might get removed
	 * from the settings service there, but we still need it for the callback.
	 */
	g_object_ref (connection);
	g_signal_emit (self, signals[TRY_UPDATE], 0);
	callback (connection, NULL, user_data);
	g_object_unref (connection);
}

static void 
do_delete (NMSettingsConnection *connection,
	       NMSettingsConnectionDeleteFunc callback,
	       gpointer user_data)
{
	NMDefaultWiredConnection *self = NM_DEFAULT_WIRED_CONNECTION (connection);
	NMDefaultWiredConnectionPrivate *priv = NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (connection);

	g_signal_emit (self, signals[DELETED], 0, priv->mac);
	NM_SETTINGS_CONNECTION_CLASS (nm_default_wired_connection_parent_class)->delete (connection,
	                                                                                 callback,
	                                                                                 user_data);
}

/****************************************************************/

NMDefaultWiredConnection *
nm_default_wired_connection_new (const GByteArray *mac,
                                 NMDevice *device,
                                 const char *defname,
                                 gboolean read_only)
{
	NMDefaultWiredConnection *self;
	NMDefaultWiredConnectionPrivate *priv;
	NMSetting *setting;
	char *uuid;

	g_return_val_if_fail (mac != NULL, NULL);
	g_return_val_if_fail (mac->len == ETH_ALEN, NULL);
	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (defname != NULL, NULL);

	self = (NMDefaultWiredConnection *) g_object_new (NM_TYPE_DEFAULT_WIRED_CONNECTION, NULL);
	if (self) {
		priv = NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (self);
		priv->device = g_object_ref (device);
		priv->mac = g_byte_array_sized_new (ETH_ALEN);
		g_byte_array_append (priv->mac, mac->data, mac->len);

		setting = nm_setting_connection_new ();

		uuid = nm_utils_uuid_generate ();
		g_object_set (setting,
		              NM_SETTING_CONNECTION_ID, defname,
		              NM_SETTING_CONNECTION_TYPE, NM_SETTING_WIRED_SETTING_NAME,
		              NM_SETTING_CONNECTION_AUTOCONNECT, TRUE,
		              NM_SETTING_CONNECTION_UUID, uuid,
		              NM_SETTING_CONNECTION_READ_ONLY, read_only,
		              NM_SETTING_CONNECTION_TIMESTAMP, (guint64) time (NULL),
		              NULL);
		g_free (uuid);

		nm_connection_add_setting (NM_CONNECTION (self), setting);

		/* Lock the connection to the specific device */
		setting = nm_setting_wired_new ();
		g_object_set (setting, NM_SETTING_WIRED_MAC_ADDRESS, priv->mac, NULL);
		nm_connection_add_setting (NM_CONNECTION (self), setting);
	}

	return self;
}

static void
nm_default_wired_connection_init (NMDefaultWiredConnection *self)
{
}

static void
dispose (GObject *object)
{
	NMDefaultWiredConnectionPrivate *priv = NM_DEFAULT_WIRED_CONNECTION_GET_PRIVATE (object);

	if (priv->disposed == FALSE) {
		priv->disposed = TRUE;
		g_object_unref (priv->device);
		g_byte_array_free (priv->mac, TRUE);
	}

	G_OBJECT_CLASS (nm_default_wired_connection_parent_class)->dispose (object);
}

static void
nm_default_wired_connection_class_init (NMDefaultWiredConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingsConnectionClass *settings_class = NM_SETTINGS_CONNECTION_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDefaultWiredConnectionPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;
	settings_class->commit_changes = commit_changes;
	settings_class->delete = do_delete;

	/* Signals */
	signals[TRY_UPDATE] =
		g_signal_new ("try-update",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0, NULL, NULL,
			      g_cclosure_marshal_VOID__VOID,
			      G_TYPE_NONE, 0);

	/* The 'deleted' signal is used to signal intentional deletions (like
	 * updating or user-requested deletion) rather than using the
	 * superclass' 'removed' signal, since that signal doesn't have the
	 * semantics we want; it gets emitted as a side-effect of various operations
	 * and is meant more for D-Bus clients instead of in-service uses.
	 */
	signals[DELETED] =
		g_signal_new ("deleted",
			      G_OBJECT_CLASS_TYPE (object_class),
			      G_SIGNAL_RUN_LAST,
			      0, NULL, NULL,
			      g_cclosure_marshal_VOID__POINTER,
			      G_TYPE_NONE, 1, G_TYPE_POINTER);
}
