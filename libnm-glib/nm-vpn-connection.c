/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
 *
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2008 Red Hat, Inc.
 */

#include <string.h>
#include "nm-vpn-connection.h"
#include "NetworkManager.h"
#include "nm-utils.h"
#include "nm-vpn-connection-bindings.h"
#include "nm-marshal.h"
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
	VPN_STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


GObject *
nm_vpn_connection_new (DBusGConnection *dbus_connection, const char *path)
{
	g_return_val_if_fail (dbus_connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_object_new (NM_TYPE_VPN_CONNECTION, 
	                     NM_OBJECT_DBUS_CONNECTION, dbus_connection,
	                     NM_OBJECT_DBUS_PATH, path,
	                     NULL);
}

const char *
nm_vpn_connection_get_banner (NMVPNConnection *vpn)
{
	NMVPNConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), NULL);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn);
	if (priv->vpn_state != NM_VPN_CONNECTION_STATE_ACTIVATED)
		return NULL;

	if (!priv->banner) {
		priv->banner = nm_object_get_string_property (NM_OBJECT (vpn),
		                                              NM_DBUS_INTERFACE_VPN_CONNECTION,
		                                              "Banner");
		if (priv->banner && !strlen (priv->banner)) {
			g_free (priv->banner);
			priv->banner = NULL;
		}
	}
	return priv->banner;
}

NMVPNConnectionState
nm_vpn_connection_get_vpn_state (NMVPNConnection *vpn)
{
	NMVPNConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), NM_VPN_CONNECTION_STATE_UNKNOWN);

	priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn);
	if (priv->vpn_state == NM_VPN_CONNECTION_STATE_UNKNOWN) {
		priv->vpn_state = nm_object_get_uint_property (NM_OBJECT (vpn),
		                                           NM_DBUS_INTERFACE_VPN_CONNECTION,
		                                           "VpnState");
	}
	return priv->vpn_state;
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
	}
}

/*****************************************************************************/

static void
nm_vpn_connection_init (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	priv->vpn_state = NM_VPN_CONNECTION_STATE_UNKNOWN;
}

static GObject*
constructor (GType type,
		   guint n_construct_params,
		   GObjectConstructParam *construct_params)
{
	NMObject *object;
	NMVPNConnectionPrivate *priv;

	object = (NMObject *) G_OBJECT_CLASS (nm_vpn_connection_parent_class)->constructor (type,
																	    n_construct_params,
																	    construct_params);
	if (!object)
		return NULL;

	priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (object),
									 NM_DBUS_SERVICE,
									 nm_object_get_path (object),
									 NM_DBUS_INTERFACE_VPN_CONNECTION);

	dbus_g_object_register_marshaller (nm_marshal_VOID__UINT_UINT,
	                                   G_TYPE_NONE,
	                                   G_TYPE_UINT, G_TYPE_UINT,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->proxy, "VpnStateChanged", G_TYPE_UINT, G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy,
						    "VpnStateChanged",
						    G_CALLBACK (vpn_state_changed_proxy),
						    object,
						    NULL);
	return G_OBJECT (object);
}

static void
finalize (GObject *object)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	if (priv->banner)
		g_free (priv->banner);

	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_vpn_connection_parent_class)->finalize (object);
}

static void
nm_vpn_connection_class_init (NMVPNConnectionClass *connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (connection_class);

	g_type_class_add_private (connection_class, sizeof (NMVPNConnectionPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->finalize = finalize;

	/* signals */
	signals[VPN_STATE_CHANGED] =
		g_signal_new ("vpn-state-changed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMVPNConnectionClass, vpn_state_changed),
				    NULL, NULL,
				    nm_marshal_VOID__UINT_UINT,
				    G_TYPE_NONE, 2,
				    G_TYPE_UINT, G_TYPE_UINT);
}
