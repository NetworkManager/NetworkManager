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
#include "nm-dbus-manager.h"


static DBusMessage *
new_invalid_vpn_connection_error (DBusMessage *replyto)
{
	return nm_dbus_create_error_message (replyto, NM_DBUS_INTERFACE_VPN,
		                                 "InvalidVPNConnection",
		                                 "No VPN connection with that name"
		                                 " was found.");
}

/*
 * nm_dbus_vpn_signal_vpn_connection_update
 *
 * Notifies the bus that a VPN connection's properties have changed.
 *
 */
void
nm_dbus_vpn_signal_vpn_connection_update (DBusConnection *connection,
                                          NMVPNConnection *vpn,
                                          const char *signal)
{
	DBusMessage	*message;
	const char	*vpn_name;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (vpn != NULL);

	message = dbus_message_new_signal (NM_DBUS_PATH_VPN,
	                                   NM_DBUS_INTERFACE_VPN,
	                                   signal);
	if (!message) {
		nm_warning ("could not allocate the dbus message.");
		return;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message,
	                          DBUS_TYPE_STRING, &vpn_name,
	                          DBUS_TYPE_INVALID);
	dbus_connection_send (connection, message, NULL);
	dbus_message_unref (message);
}

/*
 * nm_dbus_vpn_signal_vpn_connection_state_change
 *
 * Notifies the bus that a VPN connection's state has changed.
 */
void
nm_dbus_vpn_signal_vpn_connection_state_change (DBusConnection *connection,
                                                NMVPNConnection *vpn,
                                                NMVPNConnectionState new_state)
{
	DBusMessage *	message;
	const char *	vpn_name;
	dbus_uint32_t	int_state = (dbus_uint32_t) new_state;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (vpn != NULL);

	message = dbus_message_new_signal (NM_DBUS_PATH_VPN,
	                                   NM_DBUS_INTERFACE_VPN,
	                                   "VPNConnectionStateChange");
	if (!message) {
		nm_warning ("could not allocate dbus connection.");
		return;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message,
	                          DBUS_TYPE_STRING, &vpn_name,
	                          DBUS_TYPE_UINT32, &int_state,
	                          DBUS_TYPE_INVALID);
	dbus_connection_send (connection, message, NULL);
	dbus_message_unref (message);
}


/*
 * nnm_dbus_vpn_signal_vpn_failure
 *
 * Proxy a VPN Failure message from the vpn daemon to the bus.
 *
 */
void
nm_dbus_vpn_signal_vpn_failed (DBusConnection *connection,
                               const char *signal,
                               NMVPNConnection *vpn,
                               const char *error_msg)
{
	DBusMessage	*message;
	const char	*vpn_name;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (signal != NULL);
	g_return_if_fail (vpn != NULL);
	g_return_if_fail (error_msg != NULL);

	message = dbus_message_new_signal (NM_DBUS_PATH_VPN,
	                                   NM_DBUS_INTERFACE_VPN,
	                                   signal);
	if (!message) {
		nm_warning ("could not allocate the dbus message.");
		return;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message,
	                          DBUS_TYPE_STRING, &vpn_name,
	                          DBUS_TYPE_STRING, &error_msg,
	                          DBUS_TYPE_INVALID);
	dbus_connection_send (connection, message, NULL);
	dbus_message_unref (message);
}


/*
 * nnm_dbus_vpn_signal_vpn_login_banner
 *
 * Pass the VPN's login banner message to the bus if anyone wants to use it.
 *
 */
void
nm_dbus_vpn_signal_vpn_login_banner (DBusConnection *connection,
                                     NMVPNConnection *vpn,
                                     const char *banner)
{
	DBusMessage	*message;
	const char	*vpn_name;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (vpn != NULL);
	g_return_if_fail (banner != NULL);

	message = dbus_message_new_signal (NM_DBUS_PATH_VPN,
	                                   NM_DBUS_INTERFACE_VPN,
	                                   NM_DBUS_VPN_SIGNAL_LOGIN_BANNER);
	if (!message) {
		nm_warning ("could not allocate the dbus message.");
		return;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message,
	                          DBUS_TYPE_STRING, &vpn_name,
	                          DBUS_TYPE_STRING, &banner,
	                          DBUS_TYPE_INVALID);
	dbus_connection_send (connection, message, NULL);
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
static char **
nm_dbus_vpn_get_vpn_data (DBusConnection *connection,
                          NMVPNConnection *vpn,
                          int *num_items)
{
	DBusMessage		*message;
	DBusError			 error;
	DBusMessage		*reply = NULL;
	char			    **data_items = NULL;
	const char		*vpn_name;
	DBusMessageIter iter, array_iter;
	GArray *		buffer;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (vpn != NULL, NULL);
	g_return_val_if_fail (num_items != NULL, NULL);

	*num_items = -1;

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE,
	                                        NMI_DBUS_PATH,
	                                        NMI_DBUS_INTERFACE,
	                                        "getVPNConnectionVPNData");
	if (!message) {
		nm_warning ("couldn't allocate the dbus message.");
		return NULL;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message,
	                          DBUS_TYPE_STRING, &vpn_name,
	                          DBUS_TYPE_INVALID);

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error)) {
		nm_warning ("%s raised %s", error.name, error.message);
		dbus_error_free (&error);
		goto out;
	}

	if (!reply) {
		nm_warning ("did not receive a reply.");
		goto out;
	}

	dbus_message_iter_init (reply, &iter);
	dbus_message_iter_recurse (&iter, &array_iter);

	buffer = g_array_new (TRUE, TRUE, sizeof (gchar *));
	if (buffer == NULL) {
		nm_warning ("could not allocate buffer for VPN connection data.");
		goto out;
	}

	while (dbus_message_iter_get_arg_type (&array_iter) == DBUS_TYPE_STRING) {
		const char *value;
		char *str;
	
		dbus_message_iter_get_basic (&array_iter, &value);
		str = g_strdup (value);
		if (!str) {
			nm_warning ("could not allocate string.");
			g_array_free (buffer, TRUE);
			goto out;
		}
		g_array_append_val (buffer, str);
		dbus_message_iter_next (&array_iter);
	}
	data_items = (gchar **)(buffer->data);
	*num_items = buffer->len;
	g_array_free (buffer, FALSE);

out:
	if (reply)
		dbus_message_unref (reply);

	return data_items;
}


/*
 * nm_dbus_vpn_get_routes
 *
 * Get VPN routes from NMI for a vpn connection
 *
 * NOTE: caller MUST free returned value using g_strfreev()
 *
 */
char **
nm_dbus_vpn_get_routes (DBusConnection *connection,
                        NMVPNConnection *vpn,
                        int *num_items)
{
	DBusMessage		*message;
	DBusError			 error;
	DBusMessage		*reply;
	char			    **routes = NULL;
	const char		*vpn_name;
	DBusMessageIter iter, array_iter;
	GArray *		buffer;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (vpn != NULL, NULL);
	g_return_val_if_fail (num_items != NULL, NULL);

	*num_items = -1;

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE,
	                                        NMI_DBUS_PATH,
	                                        NMI_DBUS_INTERFACE,
	                                        "getVPNConnectionRoutes");
	if (!message) {
		nm_warning ("couldn't allocate the dbus message.");
		return NULL;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message,
	                          DBUS_TYPE_STRING, &vpn_name,
	                          DBUS_TYPE_INVALID);

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error)) {
		nm_warning ("%s raised %s", error.name, error.message);
		dbus_error_free (&error);
		goto out;
	}

	if (!reply) {
		nm_warning ("did not receive a reply.");
		goto out;
	}

	dbus_message_iter_init (reply, &iter);
	dbus_message_iter_recurse (&iter, &array_iter);

	buffer = g_array_new (TRUE, TRUE, sizeof (gchar *));
	if (!buffer) {
		nm_warning ("could not allocate buffer for VPN routes.");
		goto out;
	}

	while (dbus_message_iter_get_arg_type (&array_iter) == DBUS_TYPE_STRING) {
		const char *value;
		char *str;
	
		dbus_message_iter_get_basic (&array_iter, &value);
		str = g_strdup (value);
		if (!str) {
			nm_warning ("could not allocate string.");
			g_array_free (buffer, TRUE);
			goto out;
		}
		g_array_append_val (buffer, str);
		dbus_message_iter_next (&array_iter);
	}
	routes = (gchar **)(buffer->data);
	*num_items = buffer->len;
	g_array_free (buffer, FALSE);

out:	
	if (reply)
		dbus_message_unref (reply);

	return routes;
}


typedef struct UpdateOneVPNCBData {
	NMVPNManager *manager;
	char *	vpn;
} UpdateOneVPNCBData;


static void
free_update_one_vpn_cb_data (UpdateOneVPNCBData *data)
{
	if (data)
		g_free (data->vpn);
	g_slice_free (UpdateOneVPNCBData, data);
}

/*
 * nm_dbus_vpn_update_one_connection_cb
 *
 * Retrieve and add to our VPN Manager one VPN connection from NMI.
 *
 */
static void
nm_dbus_vpn_update_one_connection_cb (DBusPendingCall *pcall,
                                      void *user_data)
{
	UpdateOneVPNCBData *	cb_data = (UpdateOneVPNCBData *) user_data;
	NMDBusManager *			dbus_mgr = NULL;
	DBusConnection *		dbus_connection;
	DBusMessage *			reply = NULL;
	const char *			con_name = NULL;
	const char *			service_name = NULL;
	const char *			user_name = NULL;
	const char *			vpn_service_name;
	NMVPNConnection *		vpn;
	gboolean				new = TRUE;
	
	g_return_if_fail (pcall != NULL);
	g_return_if_fail (cb_data != NULL);
	g_return_if_fail (cb_data->manager != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("couldn't get the dbus connection.");
		goto out;
	}

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (dbus_message_is_error (reply, "BadVPNConnectionData")) {
		/* Bad VPN, remove it from our VPN connection list */
		if ((vpn = nm_vpn_manager_find_connection_by_name (cb_data->manager,
		                                                   cb_data->vpn))) {
			nm_vpn_connection_ref (vpn);
			nm_vpn_manager_remove_connection (cb_data->manager, vpn);
			nm_dbus_vpn_signal_vpn_connection_update (dbus_connection,
			                                          vpn,
			                                          "VPNConnectionRemoved");
			nm_vpn_connection_unref (vpn);
		}
		goto unref_reply;
	}

	if (!dbus_message_get_args (reply,
	                            NULL,
	                            DBUS_TYPE_STRING, &con_name,
	                            DBUS_TYPE_STRING, &service_name,
	                            DBUS_TYPE_STRING, &user_name,
	                            DBUS_TYPE_INVALID)) {
		goto unref_reply;
	}

	vpn = nm_vpn_manager_find_connection_by_name (cb_data->manager,
	                                              con_name);
	if (vpn) {
		/* If all attributes of the existing connection are the same as
		 * the one we get from NMI, don't do anything.
		 */
		vpn_service_name = nm_vpn_connection_get_service_name (vpn);
		if (    (strcmp (vpn_service_name, service_name) != 0)
		     || (strcmp (nm_vpn_connection_get_user_name (vpn), user_name) != 0)) {
			nm_vpn_manager_remove_connection (cb_data->manager, vpn);
		} else {
			new = FALSE;
		}
	}

	if (new) {
		vpn = nm_vpn_manager_add_connection (cb_data->manager,
		                                     con_name,
		                                     service_name,
		                                     user_name);
	}

	if (vpn) {
		const char * signal = new ? "VPNConnectionAdded" : "VPNConnectionUpdate";
		nm_dbus_vpn_signal_vpn_connection_update (dbus_connection, vpn, signal);
	}

unref_reply:
	dbus_message_unref (reply);

out:
	if (dbus_mgr)
		g_object_unref (dbus_mgr);
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_vpn_connections_update_cb
 *
 * Async callback from nnm_dbus_vpn_connections_update
 *
 */
static void
nm_dbus_vpn_connections_update_cb (DBusPendingCall *pcall,
                                   void *user_data)
{
	NMVPNManager *manager = (NMVPNManager *) user_data;
	DBusMessage *		reply;
	DBusMessageIter	iter, array_iter;
	GSList *			remove_list = NULL;
	GSList *			elt;
	NMDBusManager *		dbus_mgr = NULL;
	DBusConnection *	dbus_connection;

	g_return_if_fail (pcall);
	g_return_if_fail (manager != NULL);

	nm_dbus_send_with_callback_replied (pcall, __func__);

	dbus_pending_call_ref (pcall);

	if (!dbus_pending_call_get_completed (pcall))
		goto out;

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("couldn't get the dbus connection.");
		goto out;
	}

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
		goto out;

	if (message_is_error (reply))
		goto unref_reply;

	nm_info ("Updating VPN Connections...");

	remove_list = nm_vpn_manager_vpn_connection_list_copy (manager);

	dbus_message_iter_init (reply, &iter);
	dbus_message_iter_recurse (&iter, &array_iter);
	while (dbus_message_iter_get_arg_type (&array_iter) == DBUS_TYPE_STRING) {
		DBusMessage *		message;
		const char *		con_name;
		NMVPNConnection *	vpn;

		dbus_message_iter_get_basic (&array_iter, &con_name);

		/* If the connection already exists, remove it from the remove list */
		if ((vpn = nm_vpn_manager_find_connection_by_name (manager, con_name)))
			remove_list = g_slist_remove (remove_list, vpn);

		message = dbus_message_new_method_call (NMI_DBUS_SERVICE,
		                                        NMI_DBUS_PATH,
		                                        NMI_DBUS_INTERFACE,
		                                        "getVPNConnectionProperties");
		if (message) {
			UpdateOneVPNCBData * vpn_cb_data = g_slice_new0 (UpdateOneVPNCBData);

			dbus_message_append_args (message,
			                          DBUS_TYPE_STRING, &con_name,
			                          DBUS_TYPE_INVALID);

			vpn_cb_data->manager = manager;
			vpn_cb_data->vpn = g_strdup (con_name);
			nm_dbus_send_with_callback (dbus_connection,
			                            message,
			                            (DBusPendingCallNotifyFunction) nm_dbus_vpn_update_one_connection_cb,
			                            vpn_cb_data,
			                            (DBusFreeFunction) free_update_one_vpn_cb_data,
			                            __func__);
			dbus_message_unref (message);
		}
		dbus_message_iter_next (&array_iter);
	}

	/* VPN connections left in the remove list aren't known by NMI, therefore we delete them */
	for (elt = remove_list; elt; elt = g_slist_next (elt)) {
		nm_vpn_manager_remove_connection (manager, elt->data);
		nm_vpn_connection_unref (elt->data);
	}

	g_slist_free (remove_list);

unref_reply:
	dbus_message_unref (reply);

out:
	if (dbus_mgr)
		g_object_unref (dbus_mgr);
	dbus_pending_call_unref (pcall);
}


/*
 * nm_dbus_vpn_update_one_vpn_connection
 *
 * Update one VPN connection
 *
 */
void
nm_dbus_vpn_update_one_vpn_connection (DBusConnection *connection,
									   NMVPNManager *manager,
                                       const char *vpn)
{
	DBusMessage *		message;
	UpdateOneVPNCBData *cb_data;

	g_return_if_fail (connection != NULL);
	g_return_if_fail (manager != NULL);
	g_return_if_fail (vpn != NULL);

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE,
	                                        NMI_DBUS_PATH,
	                                        NMI_DBUS_INTERFACE,
	                                        "getVPNConnectionProperties");
	if (!message) {
		nm_warning ("Couldn't allocate the dbus message.");
		return;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn, DBUS_TYPE_INVALID);

	cb_data = g_slice_new0 (UpdateOneVPNCBData);
	cb_data->manager = manager;
	cb_data->vpn = g_strdup (vpn);
	nm_dbus_send_with_callback (connection,
	                            message,
	                            (DBusPendingCallNotifyFunction) nm_dbus_vpn_update_one_connection_cb,
	                            cb_data,
	                            (DBusFreeFunction) free_update_one_vpn_cb_data,
	                            __func__);
	dbus_message_unref (message);
}


/*
 * nm_dbus_vpn_connections_update_from_nmi
 *
 * Update VPN connections from NetworkManagerInfo.
 *
 */
static gboolean
nm_dbus_vpn_connections_update_from_nmi (NMVPNManager *manager)
{
	DBusMessage *		message;
	NMDBusManager *		dbus_mgr;
	DBusConnection *	dbus_connection;

	g_return_val_if_fail (manager != NULL, FALSE);

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("couldn't get the dbus connection.");
		goto out;
	}

	message = dbus_message_new_method_call (NMI_DBUS_SERVICE,
	                                        NMI_DBUS_PATH,
	                                        NMI_DBUS_INTERFACE,
	                                        "getVPNConnections");
	if (!message) {
		nm_warning ("Couldn't allocate the dbus message.");
		goto out;
	}

	nm_dbus_send_with_callback (dbus_connection,
	                            message,
	                            (DBusPendingCallNotifyFunction) nm_dbus_vpn_connections_update_cb,
	                            manager,
	                            NULL,
	                            __func__);
	dbus_message_unref (message);

out:
	g_object_unref (dbus_mgr);
	return FALSE;
}


/*
 * nm_dbus_vpn_schedule_vpn_connections_update
 *
 * Schedule an update of VPN connections in the main thread
 *
 */
void nm_dbus_vpn_schedule_vpn_connections_update (NMVPNManager *manager)
{
	g_return_if_fail (manager != NULL);

	g_idle_add_full (G_PRIORITY_HIGH_IDLE,
					 (GSourceFunc) nm_dbus_vpn_connections_update_from_nmi,
					 manager,
					 NULL);
}


/*
 * nm_dbus_vpn_get_vpn_connections
 *
 * Returns a string array of VPN connection names.
 *
 */
static DBusMessage *
nm_dbus_vpn_get_vpn_connections (DBusConnection *connection,
                                 DBusMessage *message,
                                 gpointer user_data)
{
	NMVPNManager *	vpn_mgr = (NMVPNManager *) user_data;
	DBusMessage *	reply = NULL;
	char **			vpn_names = NULL;
	int				num_names;

	g_return_val_if_fail (vpn_mgr != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	vpn_names = nm_vpn_manager_get_connection_names (vpn_mgr);
	num_names = vpn_names ? g_strv_length (vpn_names) : 0;
	if (num_names == 0) {
		reply = nm_dbus_create_error_message (message,
		                                      NM_DBUS_INTERFACE_VPN,
		                                      "NoVPNConnections",
		                                      "There are no available VPN "
		                                      "connections.");
		goto out;
	}

	if (!(reply = dbus_message_new_method_return (message)))
		goto out;

	dbus_message_append_args (reply,
	                          DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &vpn_names, num_names,
	                          DBUS_TYPE_INVALID);

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
static DBusMessage *
nm_dbus_vpn_get_vpn_connection_properties (DBusConnection *connection,
                                           DBusMessage *message,
                                           gpointer user_data)
{
	DBusMessage *		reply = NULL;
	DBusError			error;
	const char *		name;
	gboolean			success = FALSE;
	NMVPNManager *		vpn_mgr = (NMVPNManager *) user_data;
	NMVPNConnection *	vpn;
	const char *		user_name;
	const char *		service_name;
	NMVPNService *		service;
	NMVPNActRequest *	req;
	dbus_uint32_t		state;

	g_return_val_if_fail (vpn_mgr != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	if (!(reply = dbus_message_new_method_return (message)))
		return NULL;

	dbus_error_init (&error);
	if (!dbus_message_get_args (message, &error,
	                            DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID)) {
		if (dbus_error_is_set (&error))
			dbus_error_free (&error);
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE_VPN);
		goto out;
	}

	if (!(vpn = nm_vpn_manager_find_connection_by_name (vpn_mgr, name)))
		goto out;

	user_name = nm_vpn_connection_get_user_name (vpn);
	service_name = nm_vpn_connection_get_service_name (vpn);
	if (!(service = nm_vpn_manager_find_service_by_name (vpn_mgr, service_name)))
		goto out;

	req = nm_vpn_manager_get_vpn_act_request (vpn_mgr);
	state = (dbus_uint32_t) NM_VPN_CONNECTION_STATE_DISCONNECTED;
	if (req && (nm_vpn_act_request_get_connection (req) == vpn))
		state = nm_vpn_act_request_get_state (req);

	dbus_message_append_args (reply, DBUS_TYPE_STRING, &name,
	                                 DBUS_TYPE_STRING, &user_name,
	                                 DBUS_TYPE_STRING, &service_name,
	                                 DBUS_TYPE_UINT32, &state,
	                                 DBUS_TYPE_INVALID);
	success = TRUE;

out:
	if (!success)
		reply = new_invalid_vpn_connection_error (message);

	return reply;
}


/*
 * nm_dbus_vpn_activate_connection
 *
 * Activate a specific VPN connection.
 *
 */
static DBusMessage *
nm_dbus_vpn_activate_connection (DBusConnection *connection,
                                 DBusMessage *message,
                                 gpointer user_data)
{
	NMVPNManager *		vpn_mgr = (NMVPNManager *) user_data;
	DBusMessage *		reply = NULL;
	DBusError			error;
	const char *		name;
	char **			passwords;
	int				num_passwords;
	NMVPNConnection *	vpn;
	int	item_count = -1;
	char **items;
	int routes_count = -1;
	char **routes;

	g_return_val_if_fail (vpn_mgr != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (!dbus_message_get_args (message, &error,
	                           DBUS_TYPE_STRING, &name,
	                           DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &passwords, &num_passwords,
	                           DBUS_TYPE_INVALID)) {
		reply = nm_dbus_new_invalid_args_error (message, NM_DBUS_INTERFACE_VPN);
		goto out;
	}

	if (!(vpn = nm_vpn_manager_find_connection_by_name (vpn_mgr, name))) {
		reply = new_invalid_vpn_connection_error (message);
		goto out;
	}

	routes = nm_dbus_vpn_get_routes (connection, vpn, &routes_count);
	if ((items = nm_dbus_vpn_get_vpn_data (connection, vpn, &item_count)))
	{
		char *	joined_string = g_strjoinv (" / ", items);
		char *  routes_string = g_strjoinv (" / ", routes);
		nm_info ("Will activate VPN connection '%s', service '%s', user_name "
		         "'%s', vpn_data '%s', route '%s'.",
		         name,
		         nm_vpn_connection_get_service_name (vpn),
		         nm_vpn_connection_get_user_name (vpn),
		         joined_string,
		         routes_string);
		nm_vpn_manager_activate_vpn_connection (vpn_mgr, vpn, passwords,
		                                        num_passwords, items, item_count, 
		                                        routes, routes_count);

		g_free (joined_string);
		g_free (routes_string);
		g_strfreev (items);
	}

out:
	return reply;
}


/*
 * nm_dbus_vpn_deactivate_connection
 *
 * Deactivate the active VPN connection, if any.
 *
 */
static DBusMessage *
nm_dbus_vpn_deactivate_connection (DBusConnection *connection,
                                   DBusMessage *message,
                                   gpointer user_data)
{
	NMVPNManager *		vpn_mgr = (NMVPNManager *) user_data;
	NMVPNActRequest *	req;
	NMVPNConnection *	vpn;

	g_return_val_if_fail (vpn_mgr != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	if (!(req = nm_vpn_manager_get_vpn_act_request (vpn_mgr)))
		return NULL;

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_info ("Will deactivate the VPN connection '%s', service '%s'.",
	         nm_vpn_connection_get_name (vpn),
	         nm_vpn_connection_get_service_name (vpn));
	nm_vpn_manager_deactivate_vpn_connection (vpn_mgr,
	                                          nm_vpn_act_request_get_parent_dev (req));

	return NULL;
}


static DBusHandlerResult
dbus_message_handler (DBusConnection *con, DBusMessage *message, void *user_data)
{
	DBusMessage *reply = NULL;
	DBusHandlerResult result = DBUS_HANDLER_RESULT_HANDLED;

	if (dbus_message_has_member (message, "getVPNConnections"))
		reply = nm_dbus_vpn_get_vpn_connections (con, message, user_data);
	else if (dbus_message_has_member (message, "getVPNConnectionProperties"))
		reply = nm_dbus_vpn_get_vpn_connection_properties (con, message, user_data);
	else if (dbus_message_has_member (message, "activateVPNConnection"))
		reply = nm_dbus_vpn_activate_connection (con, message, user_data);
	else if (dbus_message_has_member (message, "deactivateVPNConnection"))
		reply = nm_dbus_vpn_deactivate_connection (con, message, user_data);
	else
		result = DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

	if (reply) {
		dbus_connection_send (con, reply, NULL);
		dbus_message_unref (reply);
	}

	return result;
}


/*
 * nm_dbus_vpn_methods_setup
 *
 * Register handlers for dbus methods on the
 * org.freedesktop.NetworkManager.VPNConnections object.
 *
 */
gboolean
nm_dbus_vpn_methods_setup (NMVPNManager *mgr)
{
	NMDBusManager *dbus_mgr;
	gboolean success;
	DBusObjectPathVTable vtable = { NULL, &dbus_message_handler, NULL, NULL, NULL, NULL };

	dbus_mgr = nm_dbus_manager_get ();
	success = dbus_connection_register_object_path (nm_dbus_manager_get_dbus_connection (dbus_mgr),
													NM_DBUS_PATH_VPN, &vtable, mgr);
	if (!success)
		nm_warning ("Could not register a dbus handler for VPN. Not enough memory?");

	g_object_unref (dbus_mgr);

	return success;
}
