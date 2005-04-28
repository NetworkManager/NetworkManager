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

static void nmwa_free_gui_vpn_connections (NMWirelessApplet *applet);
static void nmwa_free_dbus_vpn_connections (NMWirelessApplet *applet);
static void nmwa_dbus_vpn_schedule_copy (NMWirelessApplet *applet);

/*
 * nmwa_dbus_vpn_get_active_vpn_connection_cb
 *
 * Callback from nmwa_dbus_vpn_get_active_vpn_connection
 *
 */
void nmwa_dbus_vpn_get_active_vpn_connection_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NMWirelessApplet *	applet = (NMWirelessApplet *) user_data;
	const char *		act_vpn;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (    dbus_message_is_error (reply, NM_DBUS_NO_ACTIVE_VPN_CONNECTION)
		|| dbus_message_is_error (reply, NM_DBUS_NO_VPN_CONNECTIONS))
	{
		/* Remove the active VPN connection if one exists */
		if (applet->dbus_active_vpn_name)
		{
			g_free (applet->dbus_active_vpn_name);
			applet->dbus_active_vpn_name = NULL;
		}

		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &act_vpn, DBUS_TYPE_INVALID))
	{
		g_free (applet->dbus_active_vpn_name);
		if (strlen (act_vpn))
			applet->dbus_active_vpn_name = g_strdup (act_vpn);
		else
			applet->dbus_active_vpn_name = NULL;
	}
	dbus_message_unref (reply);

out:
	applet->vpn_pending_call_list = g_slist_remove (applet->vpn_pending_call_list, pcall);
	nmwa_dbus_vpn_schedule_copy (applet);

	dbus_pending_call_unref (pcall);
}


/*
 * nmwa_dbus_vpn_get_active_vpn_connection
 *
 * Get the active VPN connection from NetworkManager
 *
 */
void nmwa_dbus_vpn_get_active_vpn_connection (NMWirelessApplet *applet)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall = NULL;

	g_return_if_fail (applet != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "getActiveVPNConnection")))
	{
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		dbus_message_unref (message);
		if (pcall)
		{
			dbus_pending_call_set_notify (pcall, nmwa_dbus_vpn_get_active_vpn_connection_cb, applet, NULL);
			applet->vpn_pending_call_list = g_slist_append (applet->vpn_pending_call_list, pcall);
		}
	}
}


typedef struct VpnPropsCBData
{
	NMWirelessApplet *	applet;	
	char *			name;
} VpnPropsCBData;

void free_vpn_props_cb_data (VpnPropsCBData *data)
{
	if (data)
	{
		g_free (data->name);
		memset (data, 0, sizeof (VpnPropsCBData));
		g_free (data);
	}
}

/*
 * nmwa_dbus_vpn_properties_cb
 *
 * Callback for each VPN connection we called "getVPNConnectionProperties" on.
 *
 */
void nmwa_dbus_vpn_properties_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	VpnPropsCBData *	cb_data = user_data;
	NMWirelessApplet *	applet;
	const char *		name;
	const char *		user_name;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->applet != NULL);
	g_return_if_fail (cb_data->name != NULL);

	dbus_pending_call_ref (pcall);

	applet = cb_data->applet;

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_get_type (reply) == DBUS_MESSAGE_TYPE_ERROR)
	{
		if (dbus_message_is_error (reply, NM_DBUS_INVALID_VPN_CONNECTION))
		{
			VPNConnection * vpn;

			if (applet->dbus_active_vpn_name && cb_data->name && !strcmp (applet->dbus_active_vpn_name, cb_data->name))
			{
				g_free (applet->dbus_active_vpn_name);
				applet->dbus_active_vpn_name = NULL;
			}
		}

		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL,	DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &user_name, DBUS_TYPE_INVALID))
	{
		VPNConnection *	vpn;

		/* If its already there, update the user_name, otherwise add it to the list */
		if ((vpn = nmwa_vpn_connection_find_by_name (applet->dbus_vpn_connections, name)))
			nmwa_vpn_connection_set_user_name (vpn, user_name);
		else
		{
			vpn = nmwa_vpn_connection_new (name);
			nmwa_vpn_connection_set_user_name (vpn, user_name);
			applet->dbus_vpn_connections = g_slist_append (applet->dbus_vpn_connections, vpn);
		}
	}
	dbus_message_unref (reply);

out:
	applet->vpn_pending_call_list = g_slist_remove (applet->vpn_pending_call_list, pcall);
	nmwa_dbus_vpn_schedule_copy (applet);

	dbus_pending_call_unref (pcall);
}


/*
 * nmwa_dbus_vpn_update_one_vpn_connection
 *
 * Get properties on one VPN connection
 *
 */
void nmwa_dbus_vpn_update_one_vpn_connection (NMWirelessApplet *applet, const char *vpn_name)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall = NULL;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (vpn_name != NULL);

	nmwa_dbus_vpn_get_active_vpn_connection (applet);

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
			dbus_pending_call_set_notify (pcall, nmwa_dbus_vpn_properties_cb, cb_data, (DBusFreeFunction) free_vpn_props_cb_data);
			applet->vpn_pending_call_list = g_slist_append (applet->vpn_pending_call_list, pcall);
		}
	}
}


/*
 * nmwa_dbus_vpn_update_vpn_connections_cb
 *
 * nmwa_dbus_vpn_update_vpn_connections callback.
 *
 */
void nmwa_dbus_vpn_update_vpn_connections_cb (DBusPendingCall *pcall, void *user_data)
{
	DBusMessage *		reply;
	NMWirelessApplet *	applet = (NMWirelessApplet *) user_data;
	char **			vpn_names;
	int				num_vpn_names;

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (applet != NULL);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, NM_DBUS_NO_VPN_CONNECTIONS))
	{
		dbus_message_unref (reply);
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &vpn_names, &num_vpn_names, DBUS_TYPE_INVALID))
	{
		char ** item;

		/* For each connection, fire off a "getVPNConnectionProperties" call */
		for (item = vpn_names; *item; item++)
			nmwa_dbus_vpn_update_one_vpn_connection (applet, *item);

		dbus_free_string_array (vpn_names);
	}
	dbus_message_unref (reply);

out:
	applet->vpn_pending_call_list = g_slist_remove (applet->vpn_pending_call_list, pcall);
	nmwa_dbus_vpn_schedule_copy (applet);

	dbus_pending_call_unref (pcall);
}


/*
 * nmwa_dbus_vpn_update_vpn_connections
 *
 * Do a full update of vpn connections from NetworkManager
 *
 */
void nmwa_dbus_vpn_update_vpn_connections (NMWirelessApplet *applet)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall;

	nmwa_free_dbus_vpn_connections (applet);

	nmwa_dbus_vpn_get_active_vpn_connection (applet);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "getVPNConnections")))
	{
		dbus_connection_send_with_reply (applet->connection, message, &pcall, -1);
		dbus_message_unref (message);
		if (pcall)
		{
			dbus_pending_call_set_notify (pcall, nmwa_dbus_vpn_update_vpn_connections_cb, applet, NULL);
			applet->vpn_pending_call_list = g_slist_append (applet->vpn_pending_call_list, pcall);
		}
	}
}


/*
 * nmwa_dbus_vpn_remove_one_vpn_connection
 *
 * Remove one vpn connection from the list
 *
 */
void nmwa_dbus_vpn_remove_one_vpn_connection (NMWirelessApplet *applet, const char *vpn_name)
{
	VPNConnection *	vpn;

	g_return_if_fail (applet != NULL);
	g_return_if_fail (vpn_name != NULL);

	if ((vpn = nmwa_vpn_connection_find_by_name (applet->dbus_vpn_connections, vpn_name)))
	{
		applet->dbus_vpn_connections = g_slist_remove (applet->dbus_vpn_connections, vpn);
		if (!strcmp (applet->dbus_active_vpn_name, nmwa_vpn_connection_get_name (vpn)))
		{
			g_free (applet->dbus_active_vpn_name);
			applet->dbus_active_vpn_name = NULL;
		}
		nmwa_vpn_connection_unref (vpn);
		nmwa_dbus_vpn_schedule_copy (applet);
	}
}


static int vpn_copy_idle_id = 0;

/*
 * nmwa_dbus_vpn_connections_lock_and_copy
 *
 * Copy VPN connections over to gui side.
 *
 */
static gboolean nmwa_dbus_vpn_connections_lock_and_copy (NMWirelessApplet *applet)
{
	vpn_copy_idle_id = 0;

	g_return_val_if_fail (applet != NULL, FALSE);

	/* Only copy over if we have a complete data model */
	if (g_slist_length (applet->vpn_pending_call_list) == 0)
	{
		VPNConnection *	act_vpn = NULL;
		GSList *			elt;

		/* Match up the active vpn with a device in the list */
		if (applet->dbus_active_vpn_name)
			act_vpn = nmwa_vpn_connection_find_by_name (applet->dbus_vpn_connections, applet->dbus_active_vpn_name);

		/* Now copy the data over to the GUI side */
		g_mutex_lock (applet->data_mutex);

		nmwa_free_gui_vpn_connections (applet);

		/* Deep-copy VPN connections to GUI data model */
		for (elt = applet->dbus_vpn_connections; elt; elt = g_slist_next (elt))
		{
			VPNConnection	*src_vpn = elt->data;
			VPNConnection	*new_vpn;

			new_vpn = nmwa_vpn_connection_copy (src_vpn);
			if (new_vpn)
			{
				applet->gui_vpn_connections = g_slist_append (applet->gui_vpn_connections, new_vpn);
				if (src_vpn == act_vpn)
				{
					nmwa_vpn_connection_ref (new_vpn);
					applet->gui_active_vpn = new_vpn;
				}
			}
		}

		g_mutex_unlock (applet->data_mutex);
	}

	return FALSE;
}

/*
 * nmwa_dbus_vpn_schedule_copy
 *
 * Schedule a copy VPN connections over to gui side, batching requests.
 *
 */
static void nmwa_dbus_vpn_schedule_copy (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	if (vpn_copy_idle_id == 0)
	{
		GSource	*source = g_idle_source_new ();

		/* We want this idle source to run before any other idle source */
		g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
		g_source_set_callback (source, (GSourceFunc) nmwa_dbus_vpn_connections_lock_and_copy, applet, NULL);
		vpn_copy_idle_id = g_source_attach (source, applet->thread_context);
		g_source_unref (source);
	}
}


static void nmwa_free_gui_vpn_connections (NMWirelessApplet *applet)
{
	g_return_if_fail (applet != NULL);

	if (applet->gui_active_vpn)
		nmwa_vpn_connection_unref (applet->gui_active_vpn);
	applet->gui_active_vpn = NULL;

	if (applet->gui_vpn_connections)
	{
		g_slist_foreach (applet->gui_vpn_connections, (GFunc) nmwa_vpn_connection_unref, NULL);
		g_slist_free (applet->gui_vpn_connections);
		applet->gui_vpn_connections = NULL;
	}
}


static void nmwa_free_dbus_vpn_connections (NMWirelessApplet *applet)
{
	GSList	*elt;

	g_return_if_fail (applet != NULL);

	g_free (applet->dbus_active_vpn_name);
	applet->dbus_active_vpn_name = NULL;

	if (applet->dbus_vpn_connections)
	{
		g_slist_foreach (applet->dbus_vpn_connections, (GFunc) nmwa_vpn_connection_unref, NULL);
		g_slist_free (applet->dbus_vpn_connections);
		applet->dbus_vpn_connections = NULL;
	}
}


/*
 * nmwa_dbus_vpn_activate_connection
 *
 * Tell NetworkManager to activate a particular VPN connection.
 *
 */
void nmwa_dbus_vpn_activate_connection (DBusConnection *connection, const char *name, const char *password)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (name != NULL);
	g_return_if_fail (password != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "activateVPNConnection")))
	{
		nm_info ("Activating VPN connection '%s'.\n", name);

		dbus_message_append_args (message, DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &password, DBUS_TYPE_INVALID);
		dbus_connection_send (connection, message, NULL);
	}
	else
		nm_warning ("nmwa_dbus_activate_vpn_connection(): Couldn't allocate the dbus message\n");
}


/*
 * nmwa_dbus_deactivate_vpn_connection
 *
 * Tell NetworkManager to deactivate the currently active VPN connection.
 *
 */
void nmwa_dbus_vpn_deactivate_connection (DBusConnection *connection)
{
	DBusMessage	*message;

	g_return_if_fail (connection != NULL);

	if ((message = dbus_message_new_method_call (NM_DBUS_SERVICE, NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "deactivateVPNConnection")))
	{
		nm_info ("Deactivating the current VPN connection.\n");
		dbus_connection_send (connection, message, NULL);
	}
	else
		nm_warning ("nmwa_dbus_activate_vpn_connection(): Couldn't allocate the dbus message\n");
}


