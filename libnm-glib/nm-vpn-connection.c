/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#include <string.h>

#include "nm-vpn-connection.h"
#include "NetworkManager.h"
#include "nm-utils.h"
#include "nm-object-private.h"
#include "nm-active-connection.h"

G_DEFINE_TYPE (NMVPNConnection, nm_vpn_connection, NM_TYPE_ACTIVE_CONNECTION)

#define NM_VPN_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_CONNECTION, NMVPNConnectionPrivate))

typedef struct {
	DBusGProxy *proxy;
	char *banner;
	NMVPNConnectionState vpn_state;
} NMVPNConnectionPrivate;

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
 * nm_vpn_connection_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the new connection
 *
 * Creates a new #NMVPNConnection.
 *
 * Returns: (transfer full): a new connection object
 **/
GObject *
nm_vpn_connection_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_object_new (NM_TYPE_VPN_CONNECTION,
	                     NM_OBJECT_DBUS_CONNECTION, connection,
	                     NM_OBJECT_DBUS_PATH, path,
	                     NULL);
}

/**
 * nm_vpn_connection_get_banner:
 * @vpn: a #NMVPNConnection
 *
 * Gets the VPN login banner of the active #NMVPNConnection.
 *
 * Returns: the VPN login banner of the VPN connection. This is the internal
 * string used by the connection, and must not be modified.
 **/
const char *
nm_vpn_connection_get_banner (NMVPNConnection *vpn)
{
	NMVPNConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), NULL);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn);

	/* We need to update vpn_state first in case it's unknown. */
	_nm_object_ensure_inited (NM_OBJECT (vpn));

	if (priv->vpn_state != NM_VPN_CONNECTION_STATE_ACTIVATED)
		return NULL;

	return priv->banner;
}

/**
 * nm_vpn_connection_get_vpn_state:
 * @vpn: a #NMVPNConnection
 *
 * Gets the current #NMVPNConnection state.
 *
 * Returns: the VPN state of the active VPN connection.
 **/
NMVPNConnectionState
nm_vpn_connection_get_vpn_state (NMVPNConnection *vpn)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), NM_VPN_CONNECTION_STATE_UNKNOWN);

	_nm_object_ensure_inited (NM_OBJECT (vpn));
	return NM_VPN_CONNECTION_GET_PRIVATE (vpn)->vpn_state;
}

static void
vpn_state_changed_proxy (DBusGProxy *proxy,
                         NMVPNConnectionState vpn_state,
                         NMVPNConnectionStateReason reason,
                         gpointer user_data)
{
	NMVPNConnection *connection = NM_VPN_CONNECTION (user_data);
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (priv->vpn_state != vpn_state) {
		priv->vpn_state = vpn_state;
		g_signal_emit (connection, signals[VPN_STATE_CHANGED], 0, vpn_state, reason);
		g_object_notify (G_OBJECT (connection), NM_VPN_CONNECTION_VPN_STATE);
	}
}

/*****************************************************************************/

static void
nm_vpn_connection_init (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	priv->vpn_state = NM_VPN_CONNECTION_STATE_UNKNOWN;
}

static void
register_properties (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);
	const NMPropertiesInfo property_info[] = {
		{ NM_VPN_CONNECTION_BANNER,    &priv->banner },
		{ NM_VPN_CONNECTION_VPN_STATE, &priv->vpn_state },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (connection),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_VPN_CONNECTION);

	dbus_g_object_register_marshaller (g_cclosure_marshal_generic,
	                                   G_TYPE_NONE,
	                                   G_TYPE_UINT, G_TYPE_UINT,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->proxy, "VpnStateChanged", G_TYPE_UINT, G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy,
	                             "VpnStateChanged",
	                             G_CALLBACK (vpn_state_changed_proxy),
	                             object,
	                             NULL);

	register_properties (NM_VPN_CONNECTION (object));
}

static void
finalize (GObject *object)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	g_free (priv->banner);
	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMVPNConnection *self = NM_VPN_CONNECTION (object);

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_VPN_STATE:
		g_value_set_uint (value, nm_vpn_connection_get_vpn_state (self));
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
nm_vpn_connection_class_init (NMVPNConnectionClass *connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (connection_class);

	g_type_class_add_private (connection_class, sizeof (NMVPNConnectionPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMVPNConnection:vpn-state:
	 *
	 * The VPN state of the active VPN connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_VPN_STATE,
		 g_param_spec_uint (NM_VPN_CONNECTION_VPN_STATE, "", "",
		                    NM_VPN_CONNECTION_STATE_UNKNOWN,
		                    NM_VPN_CONNECTION_STATE_DISCONNECTED,
		                    NM_VPN_CONNECTION_STATE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMVPNConnection:banner:
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
	signals[VPN_STATE_CHANGED] =
		g_signal_new ("vpn-state-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMVPNConnectionClass, vpn_state_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2,
		              G_TYPE_UINT, G_TYPE_UINT);
}
