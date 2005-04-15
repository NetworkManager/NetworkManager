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
#include "NetworkManagerDevice.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerUtils.h"
#include "nm-dbus-vpn.h"
#include "nm-vpn-manager.h"
#include "nm-vpn-connection.h"
#include "nm-utils.h"


/*
 * nm_dbus_vpn_signal_vpn_connection_update
 *
 * Notifies the bus that a VPN connection has been added, deleted, or
 * changed properties.
 *
 */
void nm_dbus_vpn_signal_vpn_connection_update (DBusConnection *con, NMVPNConnection *vpn)
{
	DBusMessage	*message;
	const char	*vpn_name;

	g_return_if_fail (con != NULL);
	g_return_if_fail (vpn != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "VPNConnectionUpdate")))
	{
		nm_warning ("Not enough memory for new dbus message!");
		return;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (con, message, NULL))
		nm_warning ("Could not raise the VPNConnectionUpdate signal!");

	dbus_message_unref (message);
}


/*
 * nm_dbus_vpn_signal_vpn_connection_change
 *
 * Notifies the bus that the current VPN connection, if any, has changed.
 *
 */
void nm_dbus_vpn_signal_vpn_connection_change (DBusConnection *con, NMVPNConnection *vpn)
{
	DBusMessage	*message;
	const char	*vpn_name;

	g_return_if_fail (con != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "VPNConnectionChange")))
	{
		nm_warning ("Not enough memory for new dbus message!");
		return;
	}

	if (vpn)
		vpn_name = nm_vpn_connection_get_name (vpn);
	else
		vpn_name = "";
	dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (con, message, NULL))
		nm_warning ("Could not raise the VPNConnectionChange signal!");

	dbus_message_unref (message);
}


/*
 * nnm_dbus_vpn_signal_vpn_login_failed
 *
 * Pass the VPN Login Failure message from the daemon to the bus.
 *
 */
void nm_dbus_vpn_signal_vpn_login_failed (DBusConnection *con, NMVPNConnection *vpn, const char *error_msg)
{
	DBusMessage	*message;
	const char	*vpn_name;

	g_return_if_fail (con != NULL);
	g_return_if_fail (vpn != NULL);
	g_return_if_fail (error_msg != NULL);

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "VPNLoginFailed")))
	{
		nm_warning ("Not enough memory for new dbus message!");
		return;
	}

	vpn_name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (message, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_STRING, &error_msg, DBUS_TYPE_INVALID);
	if (!dbus_connection_send (con, message, NULL))
		nm_warning ("Could not raise the VPNLoginFailed signal!");

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

	if (!(message = dbus_message_new_signal (NM_DBUS_PATH_VPN, NM_DBUS_INTERFACE_VPN, "VPNLoginBanner")))
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
 * nm_dbus_vpn_add_one_connection
 *
 * Retrieve and add to our VPN Manager one VPN connection from NMI.
 *
 */
NMVPNConnection *nm_dbus_vpn_add_one_connection (DBusConnection *con, const char *name, NMVPNManager *vpn_manager)
{
	DBusMessage		*message;
	DBusError			 error;
	DBusMessage		*reply;
	const char		*con_name = NULL;
	const char		*service_name = NULL;
	const char		*user_name = NULL;
	DBusMessageIter 	 iter;
	NMVPNConnection	*vpn = NULL;
	
	g_return_val_if_fail (con != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (vpn_manager != NULL, NULL);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getVPNConnectionProperties")))
	{
		nm_warning ("Couldn't allocate the dbus message");
		return NULL;
	}

	dbus_message_append_args (message, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);

	/* Send message and get properties back from NetworkManagerInfo */
	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (con, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		nm_warning ("nm_dbus_add_one_vpn_connections(): %s raised %s", error.name, error.message);
		goto out;
	}
	if (!reply)
		goto out;

	dbus_error_init (&error);
	if (dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &con_name, DBUS_TYPE_STRING, &service_name,
									DBUS_TYPE_STRING, &user_name, DBUS_TYPE_INVALID))
	{
		vpn = nm_vpn_manager_add_connection (vpn_manager, con_name, service_name, user_name);
	}
	dbus_message_unref (reply);

out:
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	return vpn;
}


/*
 * nm_dbus_vpn_connections_update
 *
 * Update VPN connections from NetworkManagerInfo.
 *
 */
gboolean nm_dbus_vpn_connections_update (NMData *data)
{
	DBusMessage		*message;
	DBusError			 error;
	DBusMessage		*reply;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (data->dbus_connection != NULL, FALSE);
	g_return_val_if_fail (data->vpn_manager != NULL, FALSE);

	/* Clear all existing connections in preparation for new ones */
	nm_vpn_manager_clear_connections (data->vpn_manager);

	if (!(message = dbus_message_new_method_call (NMI_DBUS_SERVICE, NMI_DBUS_PATH, NMI_DBUS_INTERFACE, "getVPNConnections")))
	{
		nm_warning ("nm_dbus_vpn_connections_update (): Couldn't allocate the dbus message");
		return FALSE;
	}

	/* Send message and get essid back from NetworkManagerInfo */
	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (data->dbus_connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
		nm_warning ("nm_dbus_vpn_connections_update(): %s raised %s", error.name, error.message);
	else if (!reply)
		nm_info ("nm_dbus_vpn_connections_update(): reply was NULL.");
	else
	{
		DBusMessageIter iter, array_iter;

		dbus_message_iter_init (reply, &iter);
		dbus_message_iter_recurse (&iter, &array_iter);
		while (dbus_message_iter_get_arg_type (&array_iter) == DBUS_TYPE_STRING)
		{
			const char *value;
			NMVPNConnection *vpn;

			dbus_message_iter_get_basic (&array_iter, &value);
			if ((vpn = nm_dbus_vpn_add_one_connection (data->dbus_connection, value, data->vpn_manager)))
				nm_dbus_vpn_signal_vpn_connection_update (data->dbus_connection, vpn);
			dbus_message_iter_next(&array_iter);
		}
	}
	
	if (reply)
		dbus_message_unref (reply);

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
	g_source_set_callback (source, (GSourceFunc) nm_dbus_vpn_connections_update, app_data, NULL);
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
	DBusMessageIter	 iter;
	DBusMessageIter	 iter_array;
	char				**vpn_names = NULL;
	int				 num_names;
	int				 i;

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

	dbus_message_iter_init_append (reply, &iter);
	dbus_message_iter_open_container (&iter, DBUS_TYPE_ARRAY, DBUS_TYPE_STRING_AS_STRING, &iter_array);
	
	for (i = 0; i < num_names; i++)
	{
		dbus_message_iter_append_basic (&iter_array, DBUS_TYPE_STRING, &vpn_names[i]);
	}

	dbus_message_iter_close_container (&iter, &iter_array);

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
	DBusMessage		*reply = NULL;
	DBusError			 error;
	const char		*name;
	const char		*user_name;
	gboolean			 good = FALSE;
	NMVPNConnection	*vpn_con;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	/* Check for no VPN Manager */
	if (!data->data->vpn_manager)
		return nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPN, "NoVPNConnections", "There are no available VPN connections.");

	if (!(reply = dbus_message_new_method_return (message)))
		return NULL;

	dbus_error_init (&error);
	if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
	{
		if ((vpn_con = nm_vpn_manager_find_connection_by_name (data->data->vpn_manager, name)))
		{
			const char *user_name = nm_vpn_connection_get_user_name (vpn_con);

			dbus_message_append_args (reply, DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &user_name, DBUS_TYPE_INVALID);
			good = TRUE;
		}
	}

	if (!good)
		reply = nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPN, "InvalidVPNConnections", "No VPN connection with that name was found.");

	return reply;
}


/*
 * nm_dbus_vpn_get_active_vpn_connection
 *
 * Return the name of the currently active VPN connection.
 *
 */
static DBusMessage *nm_dbus_vpn_get_active_vpn_connection (DBusConnection *connection, DBusMessage *message, NMDbusCBData *data)
{
	DBusMessage		*reply = NULL;
	const char		*name;
	NMVPNConnection	*vpn = NULL;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	/* Check for no VPN Manager */
	if (!data->data->vpn_manager)
		return nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPN, "NoVPNConnections", "There are no available VPN connections.");

	if (!(vpn = nm_vpn_manager_get_active_vpn_connection (data->data->vpn_manager)))
		return nm_dbus_create_error_message (message, NM_DBUS_INTERFACE_VPN, "NoActiveVPNConnection", "There is no active VPN connection.");

	if (!(reply = dbus_message_new_method_return (message)))
		return NULL;

	name = nm_vpn_connection_get_name (vpn);
	dbus_message_append_args (reply, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID);

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
	DBusMessage		*reply = NULL;
	DBusError			 error;
	const char		*name;
	const char		*password;
	NMVPNConnection	*vpn;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	dbus_error_init (&error);
	if (dbus_message_get_args (message, &error, DBUS_TYPE_STRING, &name, DBUS_TYPE_STRING, &password, DBUS_TYPE_INVALID))
	{
		if ((vpn = nm_vpn_manager_find_connection_by_name (data->data->vpn_manager, name)))
		{
			int	item_count = -1;
			char **items;

			if ((items = nm_dbus_vpn_get_vpn_data (connection, vpn, &item_count)))
			{
				char				*joined_string = g_strjoinv (" / ", items);
				NMVPNService		*service = nm_vpn_connection_get_service (vpn);;

				nm_info ("Will activate VPN connection '%s', service '%s', user_name '%s', vpn_data '%s'.",
					name, nm_vpn_service_get_name (service), nm_vpn_connection_get_user_name (vpn), joined_string);
				nm_vpn_manager_activate_vpn_connection (data->data->vpn_manager, vpn, password, items, item_count);

				g_free (joined_string);
				g_strfreev (items);
			}
		}
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
	NMVPNConnection	*vpn_con;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->data != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (message != NULL, NULL);

	nm_info ("Will deactivate the current VPN connection.");
	nm_vpn_manager_deactivate_vpn_connection (data->data->vpn_manager);

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
	nm_dbus_method_list_add_method (list, "getActiveVPNConnection",		nm_dbus_vpn_get_active_vpn_connection);
	nm_dbus_method_list_add_method (list, "activateVPNConnection",		nm_dbus_vpn_activate_connection);
	nm_dbus_method_list_add_method (list, "deactivateVPNConnection",		nm_dbus_vpn_deactivate_connection);

	return (list);
}
