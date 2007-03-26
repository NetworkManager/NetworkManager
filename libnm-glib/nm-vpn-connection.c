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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2004 Red Hat, Inc.
 */

#include <string.h>
#include "nm-vpn-connection.h"

G_DEFINE_TYPE (NMVPNConnection, nm_vpn_connection, G_TYPE_OBJECT)

#define NM_VPN_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPN_CONNECTION, NMVPNConnectionPrivate))

typedef struct {
	DBusGProxy *proxy;
	char *name;
	char *user_name;
	char *service;
	NMVPNActStage state;
} NMVPNConnectionPrivate;

enum {
	UPDATED,
	STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
nm_vpn_connection_init (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	priv->state = NM_VPN_ACT_STAGE_UNKNOWN;
}

static void
finalize (GObject *object)
{
	NMVPNConnectionPrivate *priv = NM_VPN_CONNECTION_GET_PRIVATE (object);

	g_free (priv->name);
	g_free (priv->user_name);
	g_free (priv->service);
}

static void
nm_vpn_connection_class_init (NMVPNConnectionClass *connection_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (connection_class);

	g_type_class_add_private (connection_class, sizeof (NMVPNConnectionPrivate));

	/* virtual methods */
	object_class->finalize = finalize;

	/* signals */
	signals[UPDATED] =
		g_signal_new ("updated",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMVPNConnectionClass, updated),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0);
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMVPNConnectionClass, state_changed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1,
					  G_TYPE_UINT);

}

static gboolean
update_properties (NMVPNConnection *connection)
{
	NMVPNConnectionPrivate *priv;
	char *name = NULL;
	char *user_name = NULL;
	char *service = NULL;
	NMVPNActStage state;
	GError *err = NULL;

	priv = NM_VPN_CONNECTION_GET_PRIVATE (connection);

	if (!dbus_g_proxy_call (priv->proxy, "getVPNConnectionProperties", &err,
							G_TYPE_STRING, priv->name,
							G_TYPE_INVALID,
							G_TYPE_STRING, &name,
							G_TYPE_STRING, &user_name,
							G_TYPE_STRING, &service,
							G_TYPE_UINT, &state,
							G_TYPE_INVALID)) {
		g_warning ("Error while updating VPN connection: %s", err->message);
		g_error_free (err);
		return FALSE;
	}

	g_free (priv->name);
	g_free (priv->user_name);
	g_free (priv->service);

	priv->name = name;
	priv->user_name = user_name;
	priv->service = service;
	
	nm_vpn_connection_set_state (connection, (NMVPNActStage) state);

	return TRUE;
}

NMVPNConnection *
nm_vpn_connection_new (DBusGProxy *proxy, const char *name)
{
	GObject *object;
	NMVPNConnectionPrivate *priv;

	g_return_val_if_fail (DBUS_IS_G_PROXY (proxy), NULL);
	g_return_val_if_fail (name != NULL, NULL);

	object = g_object_new (NM_TYPE_VPN_CONNECTION, NULL);
	if (!object)
		return NULL;

	priv = NM_VPN_CONNECTION_GET_PRIVATE (object);
	priv->proxy = proxy;
	priv->name = g_strdup (name);

	if (!update_properties ((NMVPNConnection *) object)) {
		g_object_unref (object);
		return NULL;
	}

	return (NMVPNConnection *) object;
}

gboolean
nm_vpn_connection_update (NMVPNConnection *vpn)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), FALSE);

	if (update_properties (vpn)) {
		g_signal_emit (vpn, signals[UPDATED], 0);
		return TRUE;
	}

	return FALSE;
}

const char *
nm_vpn_connection_get_name (NMVPNConnection *vpn)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (vpn)->name;
}

const char *
nm_vpn_connection_get_user_name (NMVPNConnection *vpn)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (vpn)->user_name;
}

const char *
nm_vpn_connection_get_service (NMVPNConnection *vpn)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), NULL);

	return NM_VPN_CONNECTION_GET_PRIVATE (vpn)->service;
}

NMVPNActStage
nm_vpn_connection_get_state (NMVPNConnection *vpn)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), NM_VPN_ACT_STAGE_UNKNOWN);

	return NM_VPN_CONNECTION_GET_PRIVATE (vpn)->state;
}

void
nm_vpn_connection_set_state (NMVPNConnection *vpn, NMVPNActStage state)
{
	NMVPNConnectionPrivate *priv;

	g_return_if_fail (NM_IS_VPN_CONNECTION (vpn));

	priv = NM_VPN_CONNECTION_GET_PRIVATE (vpn);
	if (priv->state != state) {
		priv->state = state;
		g_signal_emit (vpn, signals[STATE_CHANGED], 0, state);
	}
}

gboolean
nm_vpn_connection_is_activating (NMVPNConnection *vpn)
{
	NMVPNActStage state;

	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), FALSE);

	state = nm_vpn_connection_get_state (vpn);
	if (state == NM_VPN_ACT_STAGE_PREPARE ||
		state == NM_VPN_ACT_STAGE_CONNECT ||
		state == NM_VPN_ACT_STAGE_IP_CONFIG_GET)
		return TRUE;

	return FALSE;
}

gboolean
nm_vpn_connection_activate (NMVPNConnection *vpn, GSList *passwords)
{
	char **password_strings;
	GSList *iter;
	int i;

	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), FALSE);
	g_return_val_if_fail (passwords != NULL, FALSE);

	if (nm_vpn_connection_get_state (vpn) != NM_VPN_ACT_STAGE_DISCONNECTED) {
		g_warning ("VPN connection is already connected or connecting");
		return FALSE;
	}

	i = 0;
	password_strings = g_new (char *, g_slist_length (passwords) + 1);
	for (iter = passwords; iter; iter = iter->next)
		password_strings[i++] = iter->data;
	password_strings[i] = NULL;

	/* FIXME: This has to be ASYNC for now since NM will call back to get routes.
	   We should just pass the routes along with this call */
	dbus_g_proxy_call_no_reply (NM_VPN_CONNECTION_GET_PRIVATE (vpn)->proxy,
								"activateVPNConnection",
								G_TYPE_STRING, nm_vpn_connection_get_name (vpn),
								G_TYPE_STRV, password_strings,
								G_TYPE_INVALID,
								G_TYPE_INVALID);
	g_free (password_strings);

	return TRUE;
}

gboolean
nm_vpn_connection_deactivate (NMVPNConnection *vpn)
{
	g_return_val_if_fail (NM_IS_VPN_CONNECTION (vpn), FALSE);

	if (nm_vpn_connection_get_state (vpn) != NM_VPN_ACT_STAGE_ACTIVATED &&
		!nm_vpn_connection_is_activating (vpn)) {
		g_warning ("VPN connection isn't activated");
		return FALSE;
	}
	
	dbus_g_proxy_call_no_reply (NM_VPN_CONNECTION_GET_PRIVATE (vpn)->proxy,
								"deactivateVPNConnection",
								G_TYPE_INVALID, G_TYPE_INVALID);
	return TRUE;
}
