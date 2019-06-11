/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-vpn-connection.h"

#include "nm-dbus-interface.h"
#include "nm-utils.h"
#include "nm-object-private.h"
#include "nm-active-connection.h"
#include "nm-dbus-helpers.h"

#include "introspection/org.freedesktop.NetworkManager.VPN.Connection.h"

G_DEFINE_TYPE (NMVpnConnection, nm_vpn_connection, NM_TYPE_ACTIVE_CONNECTION)

#define NM_VPN_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_CONNECTION, NMVpnConnectionPrivate))

G_STATIC_ASSERT (sizeof (NMVpnConnectionStateReason) == sizeof (NMActiveConnectionStateReason));

typedef struct {
	char *banner;
	NMVpnConnectionState vpn_state;
} NMVpnConnectionPrivate;

enum {
	PROP_0,
	PROP_VPN_STATE,
	PROP_BANNER,

	LAST_PROP
};

enum {
	VPN_STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/**
 * nm_vpn_connection_get_banner:
 * @vpn: a #NMVpnConnection
 *
 * Gets the VPN login banner of the active #NMVpnConnection.
 *
 * Returns: the VPN login banner of the VPN connection. This is the internal
 * string used by the connection, and must not be modified.
 **/
const char *
nm_vpn_connection_get_banner (NMVpnConnection *vpn)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), NULL);

	return nm_str_not_empty (NM_VPN_CONNECTION_GET_PRIVATE (vpn)->banner);
}

/**
 * nm_vpn_connection_get_vpn_state:
 * @vpn: a #NMVpnConnection
 *
 * Gets the current #NMVpnConnection state.
 *
 * Returns: the VPN state of the active VPN connection.
 **/
NMVpnConnectionState
nm_vpn_connection_get_vpn_state (NMVpnConnection *vpn)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), NM_VPN_CONNECTION_STATE_UNKNOWN);

	return NM_VPN_CONNECTION_GET_PRIVATE (vpn)->vpn_state;
}

static void
vpn_state_changed_proxy (NMDBusVpnConnection *proxy,
                         guint vpn_state,
                         guint reason,
                         gpointer user_data)
{
	NMVpnConnection *connection = NM_VPN_CONNECTION (user_data);
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (priv->vpn_state != vpn_state) {
		priv->vpn_state = vpn_state;
		g_signal_emit (connection, signals[VPN_STATE_CHANGED], 0, vpn_state, reason);
		g_object_notify (G_OBJECT (connection), NM_VPN_CONNECTION_VPN_STATE);
	}
}

/*****************************************************************************/

static void
nm_vpn_connection_init (NMVpnConnection *connection)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	priv->vpn_state = NM_VPN_CONNECTION_STATE_UNKNOWN;
}

static void
init_dbus (NMObject *object)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_VPN_CONNECTION_BANNER,    &priv->banner },
		{ NM_VPN_CONNECTION_VPN_STATE, &priv->vpn_state },
		{ NULL },
	};
	GDBusProxy *proxy;

	NM_OBJECT_CLASS (nm_vpn_connection_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_VPN_CONNECTION,
	                                property_info);

	proxy = _nm_object_get_proxy (object, NM_DBUS_INTERFACE_VPN_CONNECTION);
	g_signal_connect_object (proxy, "vpn-state-changed",
	                         G_CALLBACK (vpn_state_changed_proxy), object, 0);
	g_object_unref (proxy);
}

static void
finalize (GObject *object)
{
	NMVpnConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	g_free (priv->banner);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMVpnConnection *self = NM_VPN_CONNECTION (object);

	switch (prop_id) {
	case PROP_VPN_STATE:
		g_value_set_enum (value, nm_vpn_connection_get_vpn_state (self));
		break;
	case PROP_BANNER:
		g_value_set_string (value, nm_vpn_connection_get_banner (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_vpn_connection_class_init (NMVpnConnectionClass *connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (connection_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (connection_class);

	g_type_class_add_private (connection_class, sizeof (NMVpnConnectionPrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	/* properties */

	/**
	 * NMVpnConnection:vpn-state:
	 *
	 * The VPN state of the active VPN connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_VPN_STATE,
		 g_param_spec_enum (NM_VPN_CONNECTION_VPN_STATE, "", "",
		                    NM_TYPE_VPN_CONNECTION_STATE,
		                    NM_VPN_CONNECTION_STATE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMVpnConnection:banner:
	 *
	 * The VPN login banner of the active VPN connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_BANNER,
		 g_param_spec_string (NM_VPN_CONNECTION_BANNER, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/* signals */
	G_GNUC_BEGIN_IGNORE_DEPRECATIONS
	signals[VPN_STATE_CHANGED] =
		g_signal_new ("vpn-state-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVpnConnectionClass, vpn_state_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2,
		              G_TYPE_UINT, G_TYPE_UINT);
	G_GNUC_END_IGNORE_DEPRECATIONS
}
