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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2004-2005 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n.h>
#include <stdio.h>
#include <string.h>
#include <dbus/dbus.h>
#include "applet-dbus-vpn.h"
#include "applet-dbus.h"
#include "applet.h"
#include "vpn-connection.h"
#include "nm-utils.h"

static void nma_free_vpn_connections (NMApplet *applet);


void
nma_dbus_vpn_set_last_attempt_status (NMApplet *applet, const char *vpn_name, gboolean last_attempt_success)
{
	char *gconf_key;
	char *escaped_name;
	VPNConnection *vpn;
	
	if ((vpn = nma_vpn_connection_find_by_name (applet->vpn_connections, vpn_name)))
	{
		escaped_name = gconf_escape_key (vpn_name, strlen (vpn_name));

		gconf_key = g_strdup_printf ("%s/%s/last_attempt_success", GCONF_PATH_VPN_CONNECTIONS, escaped_name);
		gconf_client_set_bool (applet->gconf_client, gconf_key, last_attempt_success, NULL);

		g_free (gconf_key);
		g_free (escaped_name);
	}
}


/*
 * nma_dbus_vpn_update_vpn_connection_stage
 *
 * Sets the activation stage for a dbus vpn connection.
 */
void nma_dbus_vpn_update_vpn_connection_stage (NMApplet *applet, const char *vpn_name, NMVPNActStage vpn_stage)
{
	VPNConnection	*vpn;

	g_return_if_fail (applet != NULL);

	if ((vpn = nma_vpn_connection_find_by_name (applet->vpn_connections, vpn_name)))
	{
		nma_vpn_connection_set_stage (vpn, vpn_stage);
		if (vpn_stage == NM_VPN_ACT_STAGE_ACTIVATED)
		{
			/* set the 'last_attempt_success' key in gconf so we DON'T prompt for password next time */
			nma_dbus_vpn_set_last_attempt_status (applet, vpn_name, TRUE);
		}
	}
}

typedef struct VpnPropsCBData
{
	NMApplet *	applet;	
	char *			name;
} VpnPropsCBData;

static void free_vpn_props_cb_data (VpnPropsCBData *data)
{
	if (data)
	{
		g_free (data->name);
		memset (data, 0, sizeof (VpnPropsCBData));
		g_free (data);
	}
}

static gint vpn_sorter (gconstpointer a,
				    gconstpointer b) {
	VPNConnection *va = (VPNConnection *)a;
	VPNConnection *vb = (VPNConnection *)b;

	return strcmp(nma_vpn_connection_get_name(va),
			    nma_vpn_connection_get_name(vb));
}

/*
 * nma_dbus_vpn_properties_cb
 *
 * Callback for each VPN connection we called "getVPNConnectionProperties" on.
 *
 */
static void nma_dbus_vpn_properties_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	VpnPropsCBData *	cb_data = user_data;
	NMApplet *	applet;
	const char *		name;
	const char *        user_name;
	const char *        service;
	NMVPNActStage		stage;
	dbus_uint32_t		stage_int;
	
	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->applet != NULL);
	g_return_if_fail (cb_data->name != NULL);

	applet = cb_data->applet;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL,	DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &user_name,
				DBUS_TYPE_STRING, &service, DBUS_TYPE_UINT32, &stage_int, DBUS_TYPE_INVALID))
	{
		VPNConnection *	vpn;

		stage = (NMVPNActStage) stage_int;

		/* If its already there, update the service, otherwise add it to the list */
		if ((vpn = nma_vpn_connection_find_by_name (applet->vpn_connections, name)))
		{
			nma_vpn_connection_set_service (vpn, service);
			nma_vpn_connection_set_stage (vpn, stage);
		}
		else
		{
			vpn = nma_vpn_connection_new (name);
			nma_vpn_connection_set_service (vpn, service);
			nma_vpn_connection_set_stage (vpn, stage);
			applet->vpn_connections = g_slist_insert_sorted (applet->vpn_connections, vpn, vpn_sorter);
		}
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nma_dbus_vpn_update_one_vpn_connection
 *
 * Get properties on one VPN connection
 *
 */
void nma_dbus_vpn_update_one_vpn_connection (NMApplet *applet, const char *vpn_name)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall = NULL;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (vpn_name != NULL);

	nma_get_first_active_vpn_connection (applet);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "getVPNConnectionProperties")))
	{
		dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_INVALID);
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		dbus_message_unref (message);
		if (pcall)
		{
			VpnPropsCBData *	cb_data = g_malloc0 (sizeof (VpnPropsCBData));

			cb_data->applet = applet;
			cb_data->name = g_strdup (vpn_name);
			dbus_pending_call_set_notify (pcall, nma_dbus_vpn_properties_cb, cb_data, (DBusFreeFunction) free_vpn_props_cb_data);
		}
	}
}


/*
 * nma_dbus_vpn_update_vpn_connections_cb
 *
 * nma_dbus_vpn_update_vpn_connections callback.
 *
 */
static void nma_dbus_vpn_update_vpn_connections_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NMApplet *	applet = (NMApplet *) user_data;
	char **			vpn_names;
	int				num_vpn_names;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, NM_DBUS_NO_VPN_CONNECTIONS))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (message_is_error (reply))
	{
		DBusError err;

		dbus_error_init (&err);
		dbus_set_error_from_message (&err, reply);
		nm_warning ("dbus returned an error.\n  (%s) %s\n", err.name, err.message);
		dbus_error_free (&err);
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &vpn_names, &num_vpn_names, DBUS_TYPE_INVALID))
	{
		char ** item;

		/* For each connection, fire off a "getVPNConnectionProperties" call */
		for (item = vpn_names; *item; item++)
			nma_dbus_vpn_update_one_vpn_connection (applet, *item);

		dbus_free_string_array (vpn_names);
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nma_dbus_vpn_update_vpn_connections
 *
 * Do a full update of vpn connections from NetworkManager
 *
 */
void nma_dbus_vpn_update_vpn_connections (NMApplet *applet)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall;

	nma_free_vpn_connections (applet);

	nma_get_first_active_vpn_connection (applet);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "getVPNConnections")))
	{
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		dbus_message_unref (message);
		if (pcall)
			dbus_pending_call_set_notify (pcall, nma_dbus_vpn_update_vpn_connections_cb, applet, NULL);
	}
}


/*
 * nma_dbus_vpn_remove_one_vpn_connection
 *
 * Remove one vpn connection from the list
 *
 */
void nma_dbus_vpn_remove_one_vpn_connection (NMApplet *applet, const char *vpn_name)
{
	VPNConnection *	vpn;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (vpn_name != NULL);

	if ((vpn = nma_vpn_connection_find_by_name (applet->vpn_connections, vpn_name)))
	{
		applet->vpn_connections = g_slist_remove (applet->vpn_connections, vpn);
		nma_vpn_connection_unref (vpn);
	}
}

static void nma_free_vpn_connections (NMApplet *applet)
{
	g_return_if_fail (applet != NULL);

	if (applet->vpn_connections)
	{
		g_slist_foreach (applet->vpn_connections, (GFunc) nma_vpn_connection_unref, NULL);
		g_slist_free (applet->vpn_connections);
		applet->vpn_connections = NULL;
	}
}


/*
 * nma_dbus_vpn_activate_connection
 *
 * Tell NetworkManager to activate a particular VPN connection.
 *
 */
void nma_dbus_vpn_activate_connection (DBusConnection *connection, const char *name, GSList *passwords)
{
	DBusMessage	*message;
	DBusMessageIter	 iter;
	DBusMessageIter	 iter_array;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (name != NULL);
	g_return_if_fail (passwords != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "activateVPNConnection")))
	{
		GSList *i;

		nm_info ("Activating VPN connection '%s'.", name);
		dbus_message_iter_init_append (message, &iter);
		dbus_message_iter_append_basic (&iter, DBUS_TYPE_STRING, &name);
		dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &iter_array);

		for (i = passwords; i != NULL; i = g_slist_next (i)) {
			dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_STRING, &(i->data));
		}
		dbus_message_iter_close_container (&iter, &iter_array);
		dbus_connection_send (connection, message, NULL);
	}
	else
		nm_warning ("Couldn't allocate the dbus message");
}


/*
 * nma_dbus_deactivate_vpn_connection
 *
 * Tell NetworkManager to deactivate the currently active VPN connection.
 *
 */
void nma_dbus_vpn_deactivate_connection (DBusConnection *connection)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "deactivateVPNConnection")))
	{
		nm_info ("Deactivating the current VPN connection.");
		dbus_connection_send (connection, message, NULL);
	}
	else
		nm_warning ("Couldn't allocate the dbus message");
}


