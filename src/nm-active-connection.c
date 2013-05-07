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
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#include <glib.h>
#include "nm-types.h"
#include "nm-active-connection.h"
#include "NetworkManager.h"
#include "nm-logging.h"
#include "nm-dbus-glib-types.h"
#include "nm-dbus-manager.h"
#include "nm-device.h"
#include "nm-settings-connection.h"

#include "nm-active-connection-glue.h"

/* Base class for anything implementing the Connection.Active D-Bus interface */
G_DEFINE_ABSTRACT_TYPE (NMActiveConnection, nm_active_connection, G_TYPE_OBJECT)

#define NM_ACTIVE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                             NM_TYPE_ACTIVE_CONNECTION, \
                                             NMActiveConnectionPrivate))

typedef struct {
	NMConnection *connection;
	char *path;
	char *specific_object;
	NMDevice *device;

	gboolean is_default;
	gboolean is_default6;
	NMActiveConnectionState state;
	gboolean vpn;

	gboolean user_requested;
	gulong user_uid;
	gboolean assumed;
	NMDevice *master;
} NMActiveConnectionPrivate;

enum {
	PROP_0,
	PROP_CONNECTION,
	PROP_UUID,
	PROP_SPECIFIC_OBJECT,
	PROP_DEVICES,
	PROP_STATE,
	PROP_DEFAULT,
	PROP_DEFAULT6,
	PROP_VPN,
	PROP_MASTER,

	PROP_INT_CONNECTION,
	PROP_INT_DEVICE,
	PROP_INT_USER_REQUESTED,
	PROP_INT_USER_UID,
	PROP_INT_ASSUMED,
	PROP_INT_MASTER,

	LAST_PROP
};

/****************************************************************/

NMActiveConnectionState
nm_active_connection_get_state (NMActiveConnection *self)
{
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->state;
}

void
nm_active_connection_set_state (NMActiveConnection *self,
                                NMActiveConnectionState new_state)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	NMActiveConnectionState old_state;

	if (priv->state == new_state)
		return;

	/* DEACTIVATED is a terminal state */
	if (priv->state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED)
		g_return_if_fail (new_state != NM_ACTIVE_CONNECTION_STATE_DEACTIVATED);

	old_state = priv->state;
	priv->state = new_state;
	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_STATE);

	if (   new_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED
	    || old_state == NM_ACTIVE_CONNECTION_STATE_ACTIVATED) {
		nm_settings_connection_update_timestamp (NM_SETTINGS_CONNECTION (priv->connection),
		                                         (guint64) time (NULL), TRUE);
	}

	if (priv->state == NM_ACTIVE_CONNECTION_STATE_DEACTIVATED) {
		/* Device is no longer relevant when deactivated */
		g_clear_object (&priv->device);
		g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_DEVICES);
	}
}

const char *
nm_active_connection_get_name (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NULL);

	return nm_connection_get_id (NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->connection);
}

NMConnection *
nm_active_connection_get_connection (NMActiveConnection *self)
{
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->connection;
}

const char *
nm_active_connection_get_path (NMActiveConnection *self)
{
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->path;
}

const char *
nm_active_connection_get_specific_object (NMActiveConnection *self)
{
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->specific_object;
}

void
nm_active_connection_set_specific_object (NMActiveConnection *self,
                                          const char *specific_object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	if (g_strcmp0 (priv->specific_object, specific_object) == 0)
		return;

	g_free (priv->specific_object);
	priv->specific_object = g_strdup (specific_object);
	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT);
}

void
nm_active_connection_set_default (NMActiveConnection *self, gboolean is_default)
{
	NMActiveConnectionPrivate *priv;

	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (self));

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	if (priv->is_default == is_default)
		return;

	priv->is_default = is_default;
	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_DEFAULT);
}

gboolean
nm_active_connection_get_default (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), FALSE);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->is_default;
}

void
nm_active_connection_set_default6 (NMActiveConnection *self, gboolean is_default6)
{
	NMActiveConnectionPrivate *priv;

	g_return_if_fail (NM_IS_ACTIVE_CONNECTION (self));

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	if (priv->is_default6 == is_default6)
		return;

	priv->is_default6 = is_default6;
	g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_DEFAULT6);
}

gboolean
nm_active_connection_get_default6 (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), FALSE);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->is_default6;
}

void
nm_active_connection_export (NMActiveConnection *self)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);
	static guint32 counter = 0;

	priv->path = g_strdup_printf (NM_DBUS_PATH "/ActiveConnection/%d", counter++);
	nm_dbus_manager_register_object (nm_dbus_manager_get (), priv->path, self);
}

gboolean
nm_active_connection_get_user_requested (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), FALSE);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->user_requested;
}

gulong
nm_active_connection_get_user_uid (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), G_MAXULONG);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->user_uid;
}

gboolean
nm_active_connection_get_assumed (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), FALSE);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->assumed;
}

NMDevice *
nm_active_connection_get_device (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NULL);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->device;
}

NMDevice *
nm_active_connection_get_master (NMActiveConnection *self)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (self), NULL);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (self)->master;
}

/****************************************************************/

static void
nm_active_connection_init (NMActiveConnection *self)
{
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_INT_CONNECTION:
		g_warn_if_fail (priv->connection == NULL);
		priv->connection = g_value_dup_object (value);
		break;
	case PROP_INT_DEVICE:
		g_warn_if_fail (priv->device == NULL);
		priv->device = g_value_dup_object (value);
		if (priv->device)
			g_warn_if_fail (priv->device != priv->master);
		break;
	case PROP_INT_USER_REQUESTED:
		priv->user_requested = g_value_get_boolean (value);
		break;
	case PROP_INT_USER_UID:
		priv->user_uid = g_value_get_ulong (value);
		break;
	case PROP_INT_ASSUMED:
		priv->assumed = g_value_get_boolean (value);
		break;
	case PROP_INT_MASTER:
		g_warn_if_fail (priv->master == NULL);
		priv->master = g_value_dup_object (value);
		if (priv->master)
			g_warn_if_fail (priv->master != priv->device);
		break;
	case PROP_SPECIFIC_OBJECT:
		priv->specific_object = g_value_dup_boxed (value);
		break;
	case PROP_DEFAULT:
		priv->is_default = g_value_get_boolean (value);
		break;
	case PROP_DEFAULT6:
		priv->is_default6 = g_value_get_boolean (value);
		break;
	case PROP_VPN:
		priv->vpn = g_value_get_boolean (value);
		break;
	case PROP_MASTER:
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
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);
	GPtrArray *devices;

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_boxed (value, nm_connection_get_path (priv->connection));
		break;
	case PROP_UUID:
		g_value_set_string (value, nm_connection_get_uuid (priv->connection));
		break;
	case PROP_SPECIFIC_OBJECT:
		g_value_set_boxed (value, priv->specific_object ? priv->specific_object : "/");
		break;
	case PROP_DEVICES:
		devices = g_ptr_array_sized_new (1);
		if (priv->device)
			g_ptr_array_add (devices, g_strdup (nm_device_get_path (priv->device)));
		g_value_take_boxed (value, devices);
		break;
	case PROP_STATE:
		g_value_set_uint (value, priv->state);
		break;
	case PROP_DEFAULT:
		g_value_set_boolean (value, priv->is_default);
		break;
	case PROP_DEFAULT6:
		g_value_set_boolean (value, priv->is_default6);
		break;
	case PROP_VPN:
		g_value_set_boolean (value, priv->vpn);
		break;
	case PROP_MASTER:
		g_value_set_boxed (value, priv->master ? nm_device_get_path (priv->master) : "/");
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	g_free (priv->path);
	priv->path = NULL;
	g_free (priv->specific_object);
	priv->specific_object = NULL;

	g_clear_object (&priv->connection);
	g_clear_object (&priv->device);
	g_clear_object (&priv->master);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->dispose (object);
}

static void
nm_active_connection_class_init (NMActiveConnectionClass *ac_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ac_class);

	g_type_class_add_private (ac_class, sizeof (NMActiveConnectionPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	/* D-Bus exported properties */
	g_object_class_install_property (object_class, PROP_CONNECTION,
		g_param_spec_boxed (NM_ACTIVE_CONNECTION_CONNECTION,
		                    "Connection",
		                    "Connection",
		                    DBUS_TYPE_G_OBJECT_PATH,
		                    G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_UUID,
		g_param_spec_string (NM_ACTIVE_CONNECTION_UUID,
		                     "Connection UUID",
		                     "Connection UUID",
		                     NULL,
		                     G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_SPECIFIC_OBJECT,
		g_param_spec_boxed (NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT,
		                    "Specific object",
		                    "Specific object",
		                    DBUS_TYPE_G_OBJECT_PATH,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (object_class, PROP_DEVICES,
		g_param_spec_boxed (NM_ACTIVE_CONNECTION_DEVICES,
		                    "Devices",
		                    "Devices",
		                    DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
		                    G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_STATE,
		g_param_spec_uint (NM_ACTIVE_CONNECTION_STATE,
		                   "State",
		                   "State",
		                   NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
		                   NM_ACTIVE_CONNECTION_STATE_DEACTIVATING,
		                   NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
		                   G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_DEFAULT,
		g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT,
		                      "Default",
		                      "Is the default IPv4 active connection",
		                      FALSE,
		                      G_PARAM_READWRITE));

	g_object_class_install_property (object_class, PROP_DEFAULT6,
		g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT6,
		                      "Default6",
		                      "Is the default IPv6 active connection",
		                      FALSE,
		                      G_PARAM_READWRITE));

	g_object_class_install_property (object_class, PROP_VPN,
		g_param_spec_boolean (NM_ACTIVE_CONNECTION_VPN,
		                      "VPN",
		                      "Is a VPN connection",
		                      FALSE,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (object_class, PROP_MASTER,
		g_param_spec_boxed (NM_ACTIVE_CONNECTION_MASTER,
		                    "Master",
		                    "Path of master device",
		                    DBUS_TYPE_G_OBJECT_PATH,
		                    G_PARAM_READABLE));

	/* Internal properties */
	g_object_class_install_property (object_class, PROP_INT_CONNECTION,
		g_param_spec_object (NM_ACTIVE_CONNECTION_INT_CONNECTION,
		                     "Internal Connection",
		                     "Internal connection",
		                     NM_TYPE_CONNECTION,
		                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (object_class, PROP_INT_DEVICE,
		g_param_spec_object (NM_ACTIVE_CONNECTION_INT_DEVICE,
		                     "Internal device",
		                     "Internal device",
		                     NM_TYPE_DEVICE,
		                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (object_class, PROP_INT_USER_REQUESTED,
		g_param_spec_boolean (NM_ACTIVE_CONNECTION_INT_USER_REQUESTED,
		                      "User requested",
		                      "User requested",
		                      FALSE,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (object_class, PROP_INT_USER_UID,
		g_param_spec_ulong (NM_ACTIVE_CONNECTION_INT_USER_UID,
		                    "User UID",
		                    "User UID (if user requested)",
		                    0, G_MAXULONG, 0,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (object_class, PROP_INT_ASSUMED,
		g_param_spec_boolean (NM_ACTIVE_CONNECTION_INT_ASSUMED,
		                      "Assumed",
		                      "Assumed",
		                      FALSE,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (object_class, PROP_INT_MASTER,
		g_param_spec_object (NM_ACTIVE_CONNECTION_INT_MASTER,
		                     "Internal master device",
		                     "Internal device",
		                     NM_TYPE_DEVICE,
		                     G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (ac_class),
	                                        &dbus_glib_nm_active_connection_object_info);
}

