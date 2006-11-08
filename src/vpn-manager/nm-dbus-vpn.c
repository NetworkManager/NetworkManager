/* NetworkManager -- Network link manager
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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <glib.h>
#include <dbus/dbus.h>
#include "NetworkManagerMain.h"
#include "nm-device.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerVPN.h"
#include "nm-dbus-vpn.h"
#include "nm-vpn-manager.h"
#include "nm-vpn-connection.h"
#include "nm-vpn-service.h"
#include "nm-vpn-act-request.h"
#include "nm-utils.h"


/*
 * nm_dbus_vpn_signal_vpn_connection_update
 *
 * Notifies the bus that a VPN connection's properties have changed.
 *
 */
void nm_dbus_vpn_signal_vpn_connection_update (DBusConnection *con, NMVPNConnection *vpn, const char *signal)
{
	DBusMessage	*message;
	const char	*vpn_name;

	g_return_if_fail (con != NULL);
	g_return_if_fail (vpn != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, signal)))
	{
		nm_warning ("Not enough memory for new dbus message!");
		return;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (con, message, NULL))
		nm_warning ("Could not raise the %s signal!", signal);

	dbus_message_unref (message);
}

/*
 * nm_dbus_vpn_signal_vpn_connection_state_change
 *
 * Notifies the bus that a VPN connection's state has changed.
 */
void nm_dbus_vpn_signal_vpn_connection_state_change (DBusConnection *con, NMVPNConnection *vpn, NMVPNActStage new_stage)
{
	DBusMessage *	message;
	const char *	vpn_name;
	dbus_uint32_t	int_stage = (dbus_uint32_t) new_stage;

	g_return_if_fail (con != NULL);
	g_return_if_fail (vpn != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "VPNConnectionStateChange")))
	{
		nm_warning ("Not enough memory for new dbus message!");
		return;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_UINT32, &int_stage, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (con, message, NULL))
		nm_warning ("Could not raise the VPNConnectionStateChange signal!");

	dbus_message_unref (message);
}


/*
 * nnm_dbus_vpn_signal_vpn_failure
 *
 * Proxy a VPN Failure message from the vpn daemon to the bus.
 *
 */
void nm_dbus_vpn_signal_vpn_failed (DBusConnection *con, const char *signal, NMVPNConnection *vpn, const char *error_msg)
{
	DBusMessage	*message;
	const char	*vpn_name;

	g_return_if_fail (con != NULL);
	g_return_if_fail (signal != NULL);
	g_return_if_fail (vpn != NULL);
	g_return_if_fail (error_msg != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, signal)))
	{
		nm_warning ("Not enough memory for new dbus message!");
		return;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_STRING, &error_msg, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (con, message, NULL))
		nm_warning ("Could not raise the %s signal!", signal);

	dbus_message_unref (message);
}


/*
 * nnm_dbus_vpn_signal_vpn_login_banner
 *
 * Pass the VPN's login banner message to the bus if anyone wants to use it.
 *
 */
void nm_dbus_vpn_signal_vpn_login_banner (DBusConnection *con, NMVPNConnection *vpn, const char *banner)
{
	DBusMessage	*message;
	const char	*vpn_name;

	g_return_if_fail (con != NULL);
	g_return_if_fail (vpn != NULL);
	g_return_if_fail (banner != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, NM_DBUS_VPN_SIGNAL_LOGIN_BANNER)))
	{
		nm_warning ("Not enough memory for new dbus message!");
		return;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_STRING, &banner, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (con, message, NULL))
		nm_warning ("Could not raise the VPNLoginBanner signal!");

	dbus_message_unref (message);
}


/*
 * nm_dbus_vpn_get_vpn_data
 *
 * Get VPN specific data from NMI for a vpn connection
 *
 * NOTE: caller MUST free returned value using g_strfreev()
 *
 */
static char ** nm_dbus_vpn_get_vpn_data (DBusConnection *connection, NMVPNConnection *vpn, int *num_items)
{
	DBusMessage		*message;
	DBusError			 error;
	DBusMessage		*reply;
	char			    **data_items = NULL;
	const char		*vpn_name;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (vpn != NULL, NULL);
	g_return_val_if_fail (num_items != NULL, NULL);

	*num_items = -1;

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getVPNConnectionVPNData")))
	{
		nm_warning ("nm_dbus_vpn_get_vpn_data(): Couldn't allocate the dbus message");
		return (NULL);
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_INVALID);

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
		nm_warning ("nm_dbus_vpn_get_vpn_data(): %s raised %s", error.name, error.message);
	else if (!reply)
		nm_info ("nm_dbus_vpn_get_vpn_data(): reply was NULL.");
	else
	{
		DBusMessageIter iter, array_iter;
		GArray *buffer;

		dbus_message_iter_init (reply, &iter);
		dbus_message_iter_recurse (&iter, &array_iter);

		buffer = g_array_new (TRUE, TRUE, sizeof (gchar *));

		if (buffer == NULL)
			return NULL;

		while (dbus_message_iter_get_arg_type (&array_iter) == DBUS_TYPE_STRING)
		{
			const char *value;
			char *str;
		
			dbus_message_iter_get_basic (&array_iter, &value);
			str = g_strdup (value);
			
			if (str == NULL)
			{
				g_array_free (buffer, TRUE);
				return NULL;
			}

			g_array_append_val (buffer, str);

			dbus_message_iter_next (&array_iter);
		}
		data_items = (gchar **)(buffer->data);
		*num_items = buffer->len;
		g_array_free (buffer, FALSE);
	}
	
	if (reply)
		dbus_message_unref (reply);

	return (data_items);
}


/*
 * nm_dbus_vpn_get_routes
 *
 * Get VPN routes from NMI for a vpn connection
 *
 * NOTE: caller MUST free returned value using g_strfreev()
 *
 */
char ** nm_dbus_vpn_get_routes (DBusConnection *connection, NMVPNConnection *vpn, int *num_items)
{
	DBusMessage		*message;
	DBusError			 error;
	DBusMessage		*reply;
	char			    **routes = NULL;
	const char		*vpn_name;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (vpn != NULL, NULL);
	g_return_val_if_fail (num_items != NULL, NULL);

	*num_items = -1;

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getVPNConnectionRoutes")))
	{
		nm_warning ("nm_dbus_vpn_get_routes(): Couldn't allocate the dbus message");
		return (NULL);
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_INVALID);

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
		nm_warning ("nm_dbus_vpn_get_routes(): %s raised %s", error.name, error.message);
	else if (!reply)
		nm_info ("nm_dbus_vpn_get_routes(): reply was NULL.");
	else
	{
		DBusMessageIter iter, array_iter;
		GArray *buffer;

		dbus_message_iter_init (reply, &iter);
		dbus_message_iter_recurse (&iter, &array_iter);

		buffer = g_array_new (TRUE, TRUE, sizeof (gchar *));

		if (buffer == NULL)
			return NULL;

		while (dbus_message_iter_get_arg_type (&array_iter) == DBUS_TYPE_STRING)
		{
			const char *value;
			char *str;
		
			dbus_message_iter_get_basic (&array_iter, &value);
			str = g_strdup (value);
			
			if (str == NULL)
			{
				g_array_free (buffer, TRUE);
				return NULL;
			}

			g_array_append_val (buffer, str);

			dbus_message_iter_next (&array_iter);
		}
		routes = (gchar **)(buffer->data);
		*num_items = buffer->len;
		g_array_free (buffer, FALSE);
	}
	
	if (reply)
		dbus_message_unref (reply);

	return (routes);
}


typedef struct UpdateOneVPNCBData
{
	NMData *	data;
	char *	vpn;
} UpdateOneVPNCBData;


static void free_update_one_vpn_cb_data (UpdateOneVPNCBData *data)
{
	if (data)
		g_free (data->vpn);
	g_free (data);
}

/*
 * nm_dbus_vpn_update_one_connection_cb
 *
 * Retrieve and add to our VPN Manager one VPN connection from NMI.
 *
 */
static void nm_dbus_vpn_update_one_connection_cb (DBusPendingCall *pcall, void *user_data)
{
	UpdateOneVPNCBData *	cb_data = (UpdateOneVPNCBData *) user_data;
	DBusMessage *			reply;
	const char *			con_name = NULL;
	const char *			service_name = NULL;
	const char *			user_name = NULL;
	
	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->data != NULL);
	g_return_if_fail (cb_data->data->vpn_manager != NULL);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, "BadVPNConnectionData"))
	{
		NMVPNConnection *vpn;

		/* Bad VPN, remove it from our VPN connection list */
		if ((vpn = nm_vpn_manager_find_connection_by_name (cb_data->data->vpn_manager, cb_data->vpn)))
		{
			nm_vpn_connection_ref (vpn);
			nm_vpn_manager_remove_connection (cb_data->data->vpn_manager, vpn);
			nm_dbus_vpn_signal_vpn_connection_update (cb_data->data->dbus_connection, vpn, "VPNConnectionRemoved");
			nm_vpn_connection_unref (vpn);
		}
		goto out;
	}

	if (dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &con_name, DBUS_TYPE_STRING, &service_name,
									DBUS_TYPE_STRING, &user_name, DBUS_TYPE_INVALID))
	{
		NMVPNConnection *	vpn;
		gboolean			new = TRUE;

		if ((vpn = nm_vpn_manager_find_connection_by_name (cb_data->data->vpn_manager, con_name)))
		{
			const char *vpn_service_name = nm_vpn_connection_get_service_name (vpn);

			/* If all attributes of the existing connection are the same as the one we get from NMI,
			 * don't do anything.
			 */
			if (strcmp (vpn_service_name, service_name) || strcmp (nm_vpn_connection_get_user_name (vpn), user_name))
				nm_vpn_manager_remove_connection (cb_data->data->vpn_manager, vpn);
			else
				new = FALSE;
		}

		if (new)
			vpn = nm_vpn_manager_add_connection (cb_data->data->vpn_manager, con_name, service_name, user_name);
		if (vpn)
			nm_dbus_vpn_signal_vpn_connection_update (cb_data->data->dbus_connection, vpn, new ? "VPNConnectionAdded" : "VPNConnectionUpdate");
	}
	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_vpn_connections_update_cb
 *
 * Async callback from nnm_dbus_vpn_connections_update
 *
 */
static void nm_dbus_vpn_connections_update_cb (DBusPendingCall *pcall, void *user_data)
{
	NMData *			data = (NMData *) user_data;
	DBusMessage *		reply;
	DBusMessageIter	iter, array_iter;
	GSList *			remove_list = NULL;
	GSList *			elt;

	g_return_if_fail (pcall);
	g_return_if_fail (data != NULL);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
		goto out;

	nm_info ("Updating VPN Connections...");

	remove_list = nm_vpn_manager_vpn_connection_list_copy (data->vpn_manager);

	dbus_message_iter_init (reply, &iter);
	dbus_message_iter_recurse (&iter, &array_iter);
	while (dbus_message_iter_get_arg_type (&array_iter) == DBUS_TYPE_STRING)
	{
		DBusMessage *		message;
		const char *		con_name;
		NMVPNConnection *	vpn;

		dbus_message_iter_get_basic (&array_iter, &con_name);

		/* If the connection already exists, remove it from the remove list */
		if ((vpn = nm_vpn_manager_find_connection_by_name (data->vpn_manager, con_name)))
			remove_list = g_slist_remove (remove_list, vpn);

		if ((message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getVPNConnectionProperties")))
		{
			DBusPendingCall *		vpn_pcall = NULL;

			dbus_message_append_args (message, DBUS_TYPE_STRING, &con_name, DBUS_TYPE_INVALID);
			dbus_connection_send_with_reply (data->dbus_connection, message, &vpn_pcall, -1);
			dbus_message_unref (message);
			if (vpn_pcall)
			{
				UpdateOneVPNCBData *	vpn_cb_data = g_malloc0 (sizeof (UpdateOneVPNCBData));

				vpn_cb_data->data = data;
				vpn_cb_data->vpn = g_strdup (con_name);
				dbus_pending_call_set_notify (vpn_pcall, nm_dbus_vpn_update_one_connection_cb, vpn_cb_data, (DBusFreeFunction) free_update_one_vpn_cb_data);
			}
		}
		dbus_message_iter_next (&array_iter);
	}
	dbus_message_unref (reply);

	/* VPN connections left in the remove list aren't known by NMI, therefore we delete them */
	for (elt = remove_list; elt; elt = g_slist_next (elt))
	{
		nm_vpn_manager_remove_connection (data->vpn_manager, elt->data);
		nm_vpn_connection_unref (elt->data);
	}

	g_slist_free (remove_list);

out:
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_vpn_update_one_vpn_connection
 *
 * Update one VPN connection
 *
 */
void nm_dbus_vpn_update_one_vpn_connection (DBusConnection *connection, const char *vpn, NMData *data)
{
	DBusMessage *			message;
	DBusPendingCall *		pcall = NULL;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (vpn != NULL);
	g_return_if_fail (data != NULL);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getVPNConnectionProperties")))
	{
		nm_warning ("nm_dbus_update_one_vpn_connection(): Couldn't allocate the dbus message");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn, DBUS_TYPE_INVALID);
	dbus_connection_send_with_reply (connection, message, &pcall, -1);
	dbus_message_unref (message);
	if (pcall)
	{
		UpdateOneVPNCBData *	cb_data = g_malloc0 (sizeof (UpdateOneVPNCBData));

		cb_data->data = data;
		cb_data->vpn = g_strdup (vpn);
		dbus_pending_call_set_notify (pcall, nm_dbus_vpn_update_one_connection_cb, cb_data, (DBusFreeFunction) free_update_one_vpn_cb_data);
	}
}


/*
 * nm_dbus_vpn_connections_update_from_nmi
 *
 * Update VPN connections from NetworkManagerInfo.
 *
 */
static gboolean nm_dbus_vpn_connections_update_from_nmi (NMData *data)
{
	DBusMessage *		message;
	DBusPendingCall *	pcall;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (data->dbus_connection != NULL, FALSE);
	g_return_val_if_fail (data->vpn_manager != NULL, FALSE);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getVPNConnections")))
	{
		nm_warning ("nm_dbus_vpn_connections_update (): Couldn't allocate the dbus message");
		return FALSE;
	}

	dbus_connection_send_with_reply (data->dbus_connection, message, &pcall, -1);
	dbus_message_unref (message);
	if (pcall)
		dbus_pending_call_set_notify (pcall, nm_dbus_vpn_connections_update_cb, data, NULL);

	return FALSE;
}


/*
 * nm_dbus_vpn_schedule_vpn_connections_update
 *
 * Schedule an update of VPN connections in the main thread
 *
 */
void nm_dbus_vpn_schedule_vpn_connections_update (NMData *app_data)
{
	GSource	*source = NULL;

	g_return_if_fail (app_data != NULL);
	g_return_if_fail (app_data->main_context != NULL);

	source = g_idle_source_new ();
	/* We want this idle source to run before any other idle source */
	g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	g_source_set_callback (source, (GSourceFunc) nm_dbus_vpn_connections_update_from_nmi, app_data, NULL);
	g_source_attach (source, app_data->main_context);
	g_source_unref (source);
}


/*
 * nm_dbus_vpn_get_vpn_connections
 *
 * Returns a string array of VPN connection names.
 *
 */
static DBusMessage *nm_dbus_vpn_get_vpn_connections (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage		*reply = NULL;
	char				**vpn_names = NULL;
	int				 num_names;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	if (!data->data->vpn_manager)
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPN, "NoVPNConnections", "There are no available VPN connections.");
		goto out;
	}

	vpn_names = nm_vpn_manager_get_connection_names (data->data->vpn_manager);
	num_names = vpn_names ? g_strv_length (vpn_names) : 0;
	if (num_names == 0)
	{
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPN, "NoVPNConnections", "There are no available VPN connections.");
		goto out;
	}

	if (!(reply = dbus_message_new_method_return (message)))
		goto out;

	dbus_message_append_args (reply, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &vpn_names, num_names, DBUS_TYPE_INVALID);

out:
	if (vpn_names)
		g_strfreev (vpn_names); 

	return (reply);
}


/*
 * nm_dbus_vpn_get_vpn_connection_properties
 *
 * Grab properties of a VPN connection
 *
 */
static DBusMessage *nm_dbus_vpn_get_vpn_connection_properties (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage *		reply = NULL;
	DBusError			error;
	const char *		name;
	gboolean			good = FALSE;
	NMVPNManager *		manager;
	NMVPNConnection *	vpn;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	/* Check for no VPN Manager */
	if (!(manager = data->data->vpn_manager))
		return nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPN, "NoVPNConnections", "There are no available VPN connections.");

	if (!(reply = dbus_message_new_method_return (message)))
		return NULL;

	dbus_error_init (&error);
	if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
	{
		if ((vpn = nm_vpn_manager_find_connection_by_name (manager, name)))
		{
			const char *	user_name;
			const char *	service_name;
			NMVPNService *	service;

			user_name = nm_vpn_connection_get_user_name (vpn);
			service_name = nm_vpn_connection_get_service_name (vpn);
			if ((service = nm_vpn_manager_find_service_by_name (data->data->vpn_manager, service_name)))
			{
				NMVPNActRequest *	req = nm_vpn_manager_get_vpn_act_request (manager);
				dbus_uint32_t		stage = (dbus_uint32_t) NM_VPN_ACT_STAGE_DISCONNECTED;

				if (req && (nm_vpn_act_request_get_connection (req) == vpn))
					stage = nm_vpn_act_request_get_stage (req);

				dbus_message_append_args (reply, DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &user_name,
								DBUS_TYPE_STRING, &service_name, DBUS_TYPE_UINT32, &stage, DBUS_TYPE_INVALID);
				good = TRUE;
			}
		}
	}

	if (!good)
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPN, "InvalidVPNConnection", "No VPN connection with that name was found.");

	return reply;
}


/*
 * nm_dbus_vpn_activate_connection
 *
 * Activate a specific VPN connection.
 *
 */
static DBusMessage *nm_dbus_vpn_activate_connection (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusError			error;
	const char *		name;
	char **			passwords;
	int				num_passwords;
	NMVPNConnection *	vpn;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);

	if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &name, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &passwords, &num_passwords, DBUS_TYPE_INVALID))
	{
		if ((vpn = nm_vpn_manager_find_connection_by_name (data->data->vpn_manager, name)))
		{
			int	item_count = -1;
			char **items;
			int routes_count = -1;
			char **routes;
			routes = nm_dbus_vpn_get_routes (connection, vpn, &routes_count);
			if ((items = nm_dbus_vpn_get_vpn_data (connection, vpn, &item_count)))
			{
				char *	joined_string = g_strjoinv (" / ", items);
				char *  routes_string = g_strjoinv (" / ", routes);
				nm_info ("Will activate VPN connection '%s', service '%s', user_name '%s', vpn_data '%s', route '%s'.",
				name, nm_vpn_connection_get_service_name (vpn), nm_vpn_connection_get_user_name (vpn), joined_string, routes_string);
				nm_vpn_manager_activate_vpn_connection (data->data->vpn_manager, vpn, passwords, num_passwords, items, item_count, 
									routes, routes_count);

				g_free (joined_string);
				g_free (routes_string);
				g_strfreev (items);
			}
		} else {
			nm_warning ("nm_dbus_vpn_activate_connection(): cannot find VPN connection '%s'", name);
		}
	} else {
		nm_warning ("nm_dbus_vpn_activate_connection(): syntax error in method arguments");
	}

	return NULL;
}


/*
 * nm_dbus_vpn_deactivate_connection
 *
 * Deactivate the active VPN connection, if any.
 *
 */
static DBusMessage *nm_dbus_vpn_deactivate_connection (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	NMVPNActRequest *req;
	NMVPNConnection *vpn;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	if (!(req = nm_vpn_manager_get_vpn_act_request (data->data->vpn_manager)))
		return NULL;

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_info ("Will deactivate the VPN connection '%s', service '%s'.", nm_vpn_connection_get_name (vpn),
						nm_vpn_connection_get_service_name (vpn));
	nm_vpn_manager_deactivate_vpn_connection (data->data->vpn_manager, nm_vpn_act_request_get_parent_dev (req));

	return NULL;
}


/*
 * nm_dbus_vpn_methods_setup
 *
 * Register handlers for dbus methods on the
 * org.freedesktop.NetworkManager.VPNConnections object.
 *
 */
NMDbusMethodList *nm_dbus_vpn_methods_setup (void)
{
	NMDbusMethodList	*list = nm_dbus_method_list_new (NULL);

	nm_dbus_method_list_add_method (list, "getVPNConnections",			nm_dbus_vpn_get_vpn_connections);
	nm_dbus_method_list_add_method (list, "getVPNConnectionProperties",	nm_dbus_vpn_get_vpn_connection_properties);
	nm_dbus_method_list_add_method (list, "activateVPNConnection",		nm_dbus_vpn_activate_connection);
	nm_dbus_method_list_add_method (list, "deactivateVPNConnection",		nm_dbus_vpn_deactivate_connection);

	return (list);
}
