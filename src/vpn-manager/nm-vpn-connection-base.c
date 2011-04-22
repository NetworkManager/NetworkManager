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
 * Copyright (C) 2005 - 2011 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "NetworkManager.h"
#include "nm-vpn-connection-base.h"
#include "nm-active-connection.h"
#include "nm-vpn-connection-base-glue.h"
#include "nm-dbus-manager.h"

G_DEFINE_ABSTRACT_TYPE (NMVpnConnectionBase, nm_vpn_connection_base, G_TYPE_OBJECT)

#define NM_VPN_CONNECTION_BASE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                               NM_TYPE_VPN_CONNECTION_BASE, \
                                               NMVpnConnectionBasePrivate))

typedef struct {
	gboolean disposed;

	NMConnection *connection;
	char *ac_path;
	gboolean is_default;
	gboolean is_default6;
	NMActiveConnectionState state;
} NMVpnConnectionBasePrivate;

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

	LAST_PROP
};

/****************************************************************/

void
nm_vpn_connection_base_set_state (NMVpnConnectionBase *self,
                                  NMVPNConnectionState vpn_state)
{
	NMVpnConnectionBasePrivate *priv = NM_VPN_CONNECTION_BASE_GET_PRIVATE (self);
	NMActiveConnectionState new_ac_state = NM_ACTIVE_CONNECTION_STATE_UNKNOWN;

	/* Set the NMActiveConnection state based on VPN state */
	switch (vpn_state) {
	case NM_VPN_CONNECTION_STATE_PREPARE:
	case NM_VPN_CONNECTION_STATE_NEED_AUTH:
	case NM_VPN_CONNECTION_STATE_CONNECT:
	case NM_VPN_CONNECTION_STATE_IP_CONFIG_GET:
		new_ac_state = NM_ACTIVE_CONNECTION_STATE_ACTIVATING;
		break;
	case NM_VPN_CONNECTION_STATE_ACTIVATED:
		new_ac_state = NM_ACTIVE_CONNECTION_STATE_ACTIVATED;
		break;
	default:
		break;
	}

	if (new_ac_state != priv->state) {
		priv->state = new_ac_state;
		g_object_notify (G_OBJECT (self), NM_ACTIVE_CONNECTION_STATE);
	}
}

const char *
nm_vpn_connection_base_get_ac_path (NMVpnConnectionBase *self)
{
	return NM_VPN_CONNECTION_BASE_GET_PRIVATE (self)->ac_path;
}

void
nm_vpn_connection_base_export (NMVpnConnectionBase *self,
                               NMConnection *connection)
{
	NMVpnConnectionBasePrivate *priv = NM_VPN_CONNECTION_BASE_GET_PRIVATE (self);
	NMDBusManager *dbus_mgr;

	g_return_if_fail (priv->connection == NULL);

	priv->connection = g_object_ref (connection);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (dbus_mgr),
	                                     priv->ac_path, G_OBJECT (self));
	g_object_unref (dbus_mgr);
}

/****************************************************************/

static void
nm_vpn_connection_base_init (NMVpnConnectionBase *self)
{
	NMVpnConnectionBasePrivate *priv = NM_VPN_CONNECTION_BASE_GET_PRIVATE (self);

	priv->state = NM_ACTIVE_CONNECTION_STATE_UNKNOWN;
	priv->ac_path = nm_active_connection_get_next_object_path ();
}

static void
dispose (GObject *object)
{
	NMVpnConnectionBasePrivate *priv = NM_VPN_CONNECTION_BASE_GET_PRIVATE (object);

	if (!priv->disposed) {
		priv->disposed = TRUE;

		g_free (priv->ac_path);
		g_object_unref (priv->connection);
	}

	G_OBJECT_CLASS (nm_vpn_connection_base_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMVpnConnectionBasePrivate *priv = NM_VPN_CONNECTION_BASE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_boxed (value, nm_connection_get_path (priv->connection));
		break;
	case PROP_UUID:
		g_value_set_boxed (value, nm_connection_get_uuid (priv->connection));
		break;
	case PROP_SPECIFIC_OBJECT:
		g_value_set_boxed (value, priv->ac_path);
		break;
	case PROP_DEVICES:
		g_value_take_boxed (value, g_ptr_array_new ());
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
		g_value_set_boolean (value, TRUE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_vpn_connection_base_class_init (NMVpnConnectionBaseClass *vpn_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (vpn_class);

	g_type_class_add_private (vpn_class, sizeof (NMVpnConnectionBasePrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->dispose = dispose;

	/* properties */
    nm_active_connection_install_properties (object_class,
                                             PROP_CONNECTION,
                                             PROP_UUID,
                                             PROP_SPECIFIC_OBJECT,
                                             PROP_DEVICES,
                                             PROP_STATE,
                                             PROP_DEFAULT,
                                             PROP_DEFAULT6,
                                             PROP_VPN);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (vpn_class),
									 &dbus_glib_nm_vpn_connection_base_object_info);
}

