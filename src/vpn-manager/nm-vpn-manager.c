/* nm-vpn-manager.c - handle VPN connections within NetworkManager's framework 
 *
 * Copyright (C) 2005 Dan Williams
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <glib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dbus/dbus.h>
#include "nm-vpn-manager.h"
#include "NetworkManager.h"
#include "NetworkManagerMain.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerSystem.h"
#include "nm-vpn-connection.h"
#include "nm-vpn-service.h"
#include "nm-dbus-vpn.h"
#include "nm-utils.h"

#define VPN_SERVICE_FILE_PATH		SYSCONFDIR"/NetworkManager/VPN"

struct NMVPNManager
{
	NMData *			app_data;
	GSList *			services;
	GSList *			connections;
	NMVPNConnection *	active;
	char *			active_device;
	NMIP4Config *		active_config;
};

static GSList *	nm_vpn_manager_load_services				(void);
static void		nm_vpn_manager_set_active_vpn_connection	(NMVPNManager *manager, NMVPNConnection *con);

/*
 * nm_vpn_manager_new
 *
 * Create a new VPN manager instance.
 *
 */
NMVPNManager *nm_vpn_manager_new (NMData *app_data)
{
	NMVPNManager	*manager;

	g_return_val_if_fail (app_data != NULL, NULL);

	manager = g_malloc0 (sizeof (NMVPNManager));
	manager->services = nm_vpn_manager_load_services ();
	manager->app_data = app_data;

	return manager;
}


/*
 * nm_vpn_manager_dispose
 *
 * Release the VPN manager and all its data.
 *
 */
void nm_vpn_manager_dispose (NMVPNManager *manager)
{
	g_return_if_fail (manager != NULL);

	nm_vpn_manager_set_active_vpn_connection (manager, NULL);
	if (manager->active_device)
		g_free (manager->active_device);

	if (manager->active_config)
	{
		nm_system_remove_ip4_config_nameservers (manager->app_data->named, manager->active_config);
		nm_system_remove_ip4_config_search_domains (manager->app_data->named, manager->active_config);
		nm_ip4_config_unref (manager->active_config);
	}

	g_slist_foreach (manager->connections, (GFunc) nm_vpn_connection_unref, NULL);
	g_slist_free (manager->connections);

	g_slist_foreach (manager->services, (GFunc) nm_vpn_service_unref, NULL);
	g_slist_free (manager->services);

	memset (manager, 0, sizeof (NMVPNManager));
	g_free (manager);
}


/*
 * nm_vpn_manager_clear_connections
 *
 * Dispose of all the VPN connections the manager knows about.
 *
 */
void nm_vpn_manager_clear_connections (NMVPNManager *manager)
{
	g_return_if_fail (manager != NULL);

	g_slist_foreach (manager->connections, (GFunc)nm_vpn_connection_unref, NULL);
}


/*
 * find_vpn_service
 *
 * Return the VPN Service for a given vpn service name.
 *
 */
static NMVPNService *find_service_by_name (NMVPNManager *manager, const char *service_name)
{
	NMVPNService	*service = NULL;
	GSList		*elt;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (service_name != NULL, NULL);

	for (elt = manager->services; elt; elt = g_slist_next (elt))
	{
		if ((service = (NMVPNService *)(elt->data)))
		{
			const char *search_name = nm_vpn_service_get_name (service);
			if (search_name && (strcmp (service_name, search_name) == 0))
				break;
		}
		service = NULL;
	}

	return service;
}


/*
 * nm_vpn_manager_find_connection_by_name
 *
 * Return the NMVPNConnection object associated with a particular name.
 *
 */
NMVPNConnection *nm_vpn_manager_find_connection_by_name (NMVPNManager *manager, const char *con_name)
{
	NMVPNConnection	*con = NULL;
	GSList			*elt;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (con_name != NULL, NULL);

	for (elt = manager->connections; elt; elt = g_slist_next (elt))
	{
		if ((con = (NMVPNConnection *)(elt->data)))
		{
			const char *search_name = nm_vpn_connection_get_name (con);
			if (search_name && (strcmp (con_name, search_name) == 0))
				break;
		}
		con = NULL;
	}

	return con;
}


/*
 * nm_vpn_manager_set_active_vpn_connection
 *
 * Sets the active connection and adds a dbus signal filter for that
 * connection's service name.
 *
 */
static void nm_vpn_manager_set_active_vpn_connection (NMVPNManager *manager, NMVPNConnection *con)
{
	char				*match_string = NULL;
	const char		*service_name = NULL;
	NMVPNConnection	*active;
	NMVPNService		*service;

	g_return_if_fail (manager != NULL);

	if ((active = nm_vpn_manager_get_active_vpn_connection (manager)))
	{
		service = nm_vpn_connection_get_service (active);
		if (service && (service_name = nm_vpn_service_get_name (service)))
		{
			/* Remove any previous watch on this VPN connection's service name */
			match_string = g_strdup_printf ("type='signal',"
									  "interface='%s',"
									  "sender='%s'", service_name, service_name);
			dbus_bus_remove_match (manager->app_data->dbus_connection, match_string, NULL);
			g_free (match_string);
		}
		nm_vpn_connection_unref (active);
	}
	manager->active = NULL;

	if (manager->active_config)
	{
		nm_system_remove_ip4_config_nameservers (manager->app_data->named, manager->active_config);
		nm_system_remove_ip4_config_search_domains (manager->app_data->named, manager->active_config);
		nm_ip4_config_unref (manager->active_config);
		manager->active_config = NULL;
	}

	if (manager->active_device)
	{
nm_info ("Clearing active VPN device '%s'.", manager->active_device);
		nm_system_device_set_up_down_with_iface (NULL, manager->active_device, FALSE);
		nm_system_device_flush_routes_with_iface (manager->active_device);
		nm_system_device_flush_addresses_with_iface (manager->active_device);
		g_free (manager->active_device);
		manager->active_device = NULL;
	}

	nm_dbus_vpn_signal_vpn_connection_change (manager->app_data->dbus_connection, con);

	/* If passed NULL (clear active connection) there's nothing more to do */
	if (!con)
		return;

	service = nm_vpn_connection_get_service (con);
	if (!service || !(service_name = nm_vpn_service_get_name (service)))
	{
		nm_warning ("VPN connection could not be set active because it didn't have a VPN service.");
		return;
	}

	nm_vpn_connection_ref (con);
	manager->active = con;

	/* Add a dbus filter for this connection's service name so its signals
	 * get delivered to us.
	 */
	match_string = g_strdup_printf ("type='signal',"
							  "interface='%s',"
							  "sender='%s'", service_name, service_name);
	dbus_bus_add_match (manager->app_data->dbus_connection, match_string, NULL);
	g_free (match_string);
}


/*
 * nm_vpn_manager_add_connection
 *
 * Add a new VPN connection if none already exits, otherwise update the existing one.
 *
 */
NMVPNConnection *nm_vpn_manager_add_connection (NMVPNManager *manager, const char *name, const char *service_name, const char *user_name)
{
	NMVPNConnection	*connection = NULL;
	NMVPNService		*service;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (service_name != NULL, NULL);
	g_return_val_if_fail (user_name != NULL, NULL);

	/* Verify that the service name we are adding is in our allowed list */
	service = find_service_by_name (manager, service_name);
	if (service && (connection = nm_vpn_connection_new (name, user_name, service)))
	{
		gboolean	 found = FALSE;
		GSList	*elt;

		/* Remove the existing connection if found */
		for (elt = manager->connections; elt; elt = g_slist_next (elt))
		{
			NMVPNConnection *con = (NMVPNConnection *)(elt->data);

			if (con && nm_vpn_connection_get_name (con) && (strcmp (nm_vpn_connection_get_name (con), name) == 0))
			{
				manager->connections = g_slist_remove_link (manager->connections, elt);
				nm_vpn_connection_unref (con);
				g_slist_free (elt);
			}
		}

		/* Add in the updated connection */
		manager->connections = g_slist_append (manager->connections, connection);
	}

	return connection;
}


/*
 *  Prints config returned from vpnc-helper
 */
static void print_vpn_config (guint32 ip4_vpn_gateway,
						const char *tundev,
						guint32 ip4_internal_address,
						gint32 ip4_internal_netmask,
						guint32 *ip4_internal_dns,
						guint32 ip4_internal_dns_len,
						guint32 *ip4_internal_nbns,
						guint32 ip4_internal_nbns_len,
						const char *dns_domain,
						const char *login_banner)
{
	struct in_addr	temp_addr;
	guint32 		i;

	temp_addr.s_addr = ip4_vpn_gateway;
	nm_info ("VPN Gateway: %s", inet_ntoa (temp_addr));
	nm_info ("Tunnel Device: %s", tundev);
	temp_addr.s_addr = ip4_internal_address;
	nm_info ("Internal IP4 Address: %s", inet_ntoa (temp_addr));
	temp_addr.s_addr = ip4_internal_netmask;
	nm_info ("Internal IP4 Netmask: %s", inet_ntoa (temp_addr));

	for (i = 0; i < ip4_internal_dns_len; i++)
	{
		if (ip4_internal_dns[i] != 0)
		{
			temp_addr.s_addr = ip4_internal_dns[i];
			nm_info ("Internal IP4 DNS: %s", inet_ntoa (temp_addr));
		}
	}

	for (i = 0; i < ip4_internal_nbns_len; i++)
	{
		if (ip4_internal_nbns[i] != 0)
		{
			temp_addr.s_addr = ip4_internal_nbns[i];
			nm_info ("Internal IP4 NBNS: %s", inet_ntoa (temp_addr));
		}
	}

	nm_info ("DNS Domain: '%s'", dns_domain);
	nm_info ("Login Banner:");
	nm_info ("-----------------------------------------");
	nm_info ("%s", login_banner);
	nm_info ("-----------------------------------------");
}

/*
 * nm_vpn_manager_handle_ip4_config_signal
 *
 * Configure a device with IPv4 config info in response the the VPN daemon.
 *
 */
void nm_vpn_manager_handle_ip4_config_signal (NMVPNManager *manager, DBusMessage *message, NMVPNService *service, NMVPNConnection *con)
{
	guint32		ip4_vpn_gateway;
	char *		tundev;
	guint32		ip4_internal_address;
	guint32		ip4_internal_netmask;
	guint32 *		ip4_internal_dns;
	guint32		ip4_internal_dns_len;
	guint32 *		ip4_internal_nbns;
	guint32		ip4_internal_nbns_len;
	char *		dns_domain;
	char *		login_banner;

	g_return_if_fail (manager != NULL);
	g_return_if_fail (message != NULL);
	g_return_if_fail (service != NULL);
	g_return_if_fail (con != NULL);

	if (dbus_message_get_args(message, NULL, DBUS_TYPE_UINT32, &ip4_vpn_gateway,
									 DBUS_TYPE_STRING, &tundev,
									 DBUS_TYPE_UINT32, &ip4_internal_address,
									 DBUS_TYPE_UINT32, &ip4_internal_netmask,
									 DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_internal_dns, &ip4_internal_dns_len,
									 DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32, &ip4_internal_nbns, &ip4_internal_nbns_len,
									 DBUS_TYPE_STRING, &dns_domain,
									 DBUS_TYPE_STRING, &login_banner, DBUS_TYPE_INVALID))
	{
		NMIP4Config *	config;
		NMDevice *	vpn_dev;
		guint32		i;
		guint32		broadcast;

#if 0
		print_vpn_config (ip4_vpn_gateway, tundev, ip4_internal_address, ip4_internal_netmask,
						ip4_internal_dns, ip4_internal_dns_len, ip4_internal_nbns, ip4_internal_nbns_len,
						dns_domain, login_banner);
#endif

		config = nm_ip4_config_new ();

		nm_ip4_config_set_address (config, ip4_internal_address);

		if (ip4_internal_netmask)
			nm_ip4_config_set_netmask (config, ip4_internal_netmask);
		else
			nm_ip4_config_set_netmask (config, 0x00FF); /* Class C */

		nm_ip4_config_set_gateway (config, ip4_vpn_gateway);

		if (strlen (dns_domain))
			nm_ip4_config_add_domain (config, dns_domain);

		for (i = 0; i < ip4_internal_dns_len; i++)
		{
			if (ip4_internal_dns[i] != 0)
				nm_ip4_config_add_nameserver (config, ip4_internal_dns[i]);
		}

		manager->active_device = g_strdup (tundev);
		manager->active_config = config;
		nm_system_vpn_device_set_from_ip4_config (manager->app_data->named, manager->app_data->active_device,
											manager->active_device, manager->active_config);
		if (login_banner && strlen (login_banner))
			nm_dbus_vpn_signal_vpn_login_banner (manager->app_data->dbus_connection, con, login_banner);
	}
}


/*
 * nm_vpn_manager_get_connection_names
 *
 * Return an array of strings of all the VPN Connection names
 * we know about.
 *
 */
char **nm_vpn_manager_get_connection_names (NMVPNManager *manager)
{
	char		**names = NULL;
	GSList	 *elt;
	int		  i;

	g_return_val_if_fail (manager != NULL, NULL);

	names = g_malloc0 ((g_slist_length (manager->connections) + 1) * sizeof (char *));
	for (elt = manager->connections, i = 0; elt; elt = g_slist_next (elt), i++)
	{
		NMVPNConnection *vpn_con = (NMVPNConnection *)(elt->data);
		if (vpn_con)
			names[i] = g_strdup (nm_vpn_connection_get_name (vpn_con));
	}

	return names;
}


/*
 * nm_vpn_manager_get_active_vpn_connection
 *
 * Return the active VPN connection, if any.
 *
 */
NMVPNConnection *nm_vpn_manager_get_active_vpn_connection (NMVPNManager *manager)
{
	g_return_val_if_fail (manager != NULL, NULL);

	return manager->active;
}


/*
 * construct_op_from_service_name
 *
 * Construct an object path from a dbus service name by replacing
 * all "." in the service with "/" and prepending a "/" to the
 * object path.
 *
 */
static char *construct_op_from_service_name (const char *service_name)
{
	char **split = NULL;
	char *temp1;
	char *temp2;

	g_return_val_if_fail (service_name != NULL, NULL);

	if (!(split = g_strsplit (service_name, ".", 0)))
		return NULL;

	temp1 = g_strjoinv ("/", split);
	g_strfreev (split);
	temp2 = g_strdup_printf ("/%s", temp1);
	g_free (temp1);

	if (!temp2 || !strlen (temp2))
	{
		g_free (temp2);
		temp2 = NULL;
	}

	return temp2;
}


/*
 * nm_vpn_manager_process_signal
 *
 * Possibly process a signal from the bus, if it comes from the currently
 * active VPN daemon, if any.  Return TRUE if processed, FALSE if not.
 *
 */
gboolean nm_vpn_manager_process_signal (NMVPNManager *manager, DBusMessage *message)
{
	const char		*object_path;
	const char		*temp_op;
	NMVPNConnection	*active;
	NMVPNService		*service;
	const char		*service_name;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	if (!(object_path = dbus_message_get_path (message)))
		return FALSE;

	if (!(active = nm_vpn_manager_get_active_vpn_connection (manager)))
		return FALSE;

	service = nm_vpn_connection_get_service (active);
	if (!service || !(service_name = nm_vpn_service_get_name (service)))
		return FALSE;

	temp_op = construct_op_from_service_name (service_name);
	if (!temp_op || (strcmp (object_path, temp_op) != 0))
		return FALSE;

	if (dbus_message_is_signal (message, service_name, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED))
	{
		char *error_msg;
		char *blank_msg = "";

		if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &error_msg, DBUS_TYPE_INVALID))
			error_msg = blank_msg;
		nm_warning ("VPN Login failed for service '%s' with message '%s'.", service_name, error_msg);
		nm_dbus_vpn_signal_vpn_login_failed (manager->app_data->dbus_connection, active, error_msg);
	}
	else if (dbus_message_is_signal (message, service_name, NM_DBUS_VPN_SIGNAL_STATE_CHANGE))
	{
		NMVPNState	old_state;
		NMVPNState	new_state;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_UINT32, &old_state, DBUS_TYPE_UINT32, &new_state, DBUS_TYPE_INVALID))
		{
			nm_info ("VPN service '%s' signaled new state %d, old state %d.", service_name, new_state, old_state);
			nm_vpn_service_set_state (service, new_state);

			/* If the VPN daemon state is now stopped and it was starting, clear the active connection */
			if (((new_state == NM_VPN_STATE_STOPPED) || (new_state == NM_VPN_STATE_SHUTDOWN) || (new_state == NM_VPN_STATE_STOPPING))
				&& ((old_state == NM_VPN_STATE_STARTED) || (old_state == NM_VPN_STATE_STARTING)))
			{
				nm_vpn_manager_set_active_vpn_connection (manager, NULL);
			}
		}
	}
	else if (dbus_message_is_signal (message, service_name, NM_DBUS_VPN_SIGNAL_IP4_CONFIG))
		nm_vpn_manager_handle_ip4_config_signal (manager, message, service, active);

	return TRUE;
}


/*
 * nm_vpn_manager_process_name_owner_changed
 *
 * Respond to "service created"/"service deleted" signals from dbus for our active VPN daemon.
 *
 */
gboolean nm_vpn_manager_process_name_owner_changed (NMVPNManager *manager, const char *changed_service_name, const char *old_owner, const char *new_owner)
{
	NMVPNService		*service;
	NMVPNConnection	*active;
	gboolean			 old_owner_good = (old_owner && strlen (old_owner));
	gboolean			 new_owner_good = (new_owner && strlen (new_owner));

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (changed_service_name != NULL, FALSE);

	if (!(active = nm_vpn_manager_get_active_vpn_connection (manager)))
		return FALSE;
	nm_vpn_connection_ref (active);

	if (!(service = nm_vpn_connection_get_service (active)))
	{
		nm_vpn_connection_unref (active);
		return FALSE;
	}

	/* Can't handle the signal if its not from our active VPN service */
	if (strcmp (nm_vpn_service_get_name (service), changed_service_name) != 0)
	{
		nm_vpn_connection_unref (active);
		return FALSE;
	}

	if (!old_owner_good && new_owner_good)
	{
		/* VPN service got created. */
	}
	else if (old_owner_good && !new_owner_good)
	{
		/* VPN service went away. */
		nm_vpn_service_set_state (service, NM_VPN_STATE_SHUTDOWN);
		nm_vpn_manager_set_active_vpn_connection (manager, NULL);
		nm_dbus_vpn_signal_vpn_connection_change (manager->app_data->dbus_connection, active);
	}

	nm_vpn_connection_unref (active);
	return TRUE;
}


/*
 * nm_vpn_manager_activate_vpn_connection
 *
 * Signal the VPN service daemon to activate a particular VPN connection,
 * launching that daemon if necessary.
 *
 */
void nm_vpn_manager_activate_vpn_connection (NMVPNManager *manager, NMVPNConnection *vpn, const char *password, char **data_items, int count)
{
	DBusMessage		*message;
	DBusMessage		*reply;
	char				*op;
	NMVPNService		*service;
	const char		*service_name;
	const char		*name;
	const char		*user_name;
	DBusMessageIter	 iter, array_iter;
	int				 i, len;
	DBusError			 error;

	g_return_if_fail (manager != NULL);
	g_return_if_fail (manager->app_data != NULL);
	g_return_if_fail (manager->app_data->dbus_connection != NULL);
	g_return_if_fail (vpn != NULL);
	g_return_if_fail (password != NULL);
	g_return_if_fail (data_items != NULL);

	nm_vpn_manager_set_active_vpn_connection (manager, NULL);

	/* Construct a new method call with the correct service and object path */
	if (!(service = nm_vpn_connection_get_service (vpn)) || !(service_name = nm_vpn_service_get_name (service)))
		return;

	nm_vpn_manager_set_active_vpn_connection (manager, vpn);

	/* Start the daemon if its not already running */
	if (!dbus_bus_name_has_owner (manager->app_data->dbus_connection, service_name, NULL))
	{
		if (!nm_vpn_service_exec_daemon (service))
		{
			nm_vpn_manager_set_active_vpn_connection (manager, NULL);
			return;
		}
	}

	/* Send the activate request to the daemon */
	op = construct_op_from_service_name (service_name);
	message = dbus_message_new_method_call (service_name, op, service_name, "startConnection");
	g_free (op);
	if (!message)
	{
		nm_warning ("Couldn't allocate dbus message.");
		nm_vpn_manager_set_active_vpn_connection (manager, NULL);
		return;
	}

	name = nm_vpn_connection_get_name (vpn);
	user_name = nm_vpn_connection_get_user_name (vpn);

	dbus_message_append_args (message, DBUS_TYPE_STRING, &name,
								DBUS_TYPE_STRING, &user_name,
								DBUS_TYPE_STRING, &password,
								DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &data_items, count,
								DBUS_TYPE_INVALID);

	/* Send the message to the daemon again, now that its running. */
	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (manager->app_data->dbus_connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		nm_warning ("Could not activate the VPN service.  dbus says: '%s'  '%s'.", error.name, error.message);
		dbus_error_free (&error);
		nm_vpn_manager_set_active_vpn_connection (manager, NULL);
		return;
	}

	if (reply)
		dbus_message_unref (reply);
}


/*
 * nm_vpn_manager_deactivate_vpn_connection
 *
 * Signal the VPN service daemon to deactivate a particular VPN connection.
 *
 */
void nm_vpn_manager_deactivate_vpn_connection (NMVPNManager *manager)
{
	DBusMessage		*message;
	char				*op;
	NMVPNService		*service;
	const char		*service_name;
	NMVPNConnection	*active;
	NMIP4Config		*config;

	g_return_if_fail (manager != NULL);

	if (!(active = nm_vpn_manager_get_active_vpn_connection (manager)))
		return;
	nm_vpn_connection_ref (active);

	/* Construct a new method call with the correct service and object path */
	service = nm_vpn_connection_get_service (active);
	service_name = nm_vpn_service_get_name (service);
	op = construct_op_from_service_name (service_name);
	message = dbus_message_new_method_call (service_name, op, service_name, "stopConnection");
	g_free (op);
	if (!message)
	{
		nm_warning ("Couldn't allocate dbus message.");
		goto out;
	}

	/* Call the specific VPN service, let dbus activate it if needed */
	dbus_connection_send (manager->app_data->dbus_connection, message, NULL);
	dbus_message_unref (message);

out:
	nm_vpn_manager_set_active_vpn_connection (manager, NULL);
	nm_dbus_vpn_signal_vpn_connection_change (manager->app_data->dbus_connection, NULL);
	nm_vpn_connection_unref (active);

	if (manager->app_data->active_device)
		nm_system_device_set_from_ip4_config (manager->app_data->active_device);
}


/*********************************************************************/

static GSList *nm_vpn_manager_load_services (void)
{
	GSList		*list = NULL;
	GDir			*vpn_dir;

	/* Load allowed service names */
	if ((vpn_dir = g_dir_open (VPN_SERVICE_FILE_PATH, 0, NULL)))
	{
		const char *file_name;

		while ((file_name = g_dir_read_name (vpn_dir)))
		{
			char		*file_path = g_strdup_printf (VPN_SERVICE_FILE_PATH"/%s", file_name);
			char		*contents;

			if (g_file_get_contents (file_path, &contents, NULL, NULL) && (contents != NULL))
			{
				char	**split_contents = g_strsplit (contents, "\n", 0);

				if (split_contents)
				{
					int			 i, len;
					NMVPNService	*service = nm_vpn_service_new ();
					gboolean		 have_name = FALSE;
					gboolean		 have_program = FALSE;

					len = g_strv_length (split_contents);
					for (i = 0; i < len; i++)
					{
						char *line = split_contents[i];

						#define SERVICE_TAG "service="
						#define PROGRAM_TAG "program="

						if (!line || !strlen (line)) continue; 

						/* Comment lines begin with # */
						if (line[0] == '#') continue;

						if (strlen (line) > 8)
						{
							if ((strncmp (line, SERVICE_TAG, strlen (SERVICE_TAG)) == 0) && !have_name)
							{
								char *service_name = g_strdup (line+strlen (SERVICE_TAG));

								/* Deny the load if the service name is NetworkManager or NetworkManagerInfo. */
								if (strcmp (service_name, NM_DBUS_SERVICE) && strcmp (service_name, NM_DBUS_SERVICE))
									nm_vpn_service_set_name (service, (const char *)service_name);
								else
									nm_warning ("VPN service name matched NetworkManager or NetworkManagerInfo service names, "
												"which is not allowed and might be malicious.");
								g_free (service_name);
								have_name = TRUE;
							}
							else if ((strncmp (line, PROGRAM_TAG, strlen (PROGRAM_TAG)) == 0) && !have_program)
							{
								gboolean	program_ok = FALSE;
								if ((strlen (line) >= strlen (PROGRAM_TAG) + 1))
								{
									if ((*(line+strlen (PROGRAM_TAG)) == '/') && (*(line+strlen (line)-1) != '/'))
									{
										nm_vpn_service_set_program (service, (const char *)(line+strlen (PROGRAM_TAG)));
										program_ok = TRUE;
									}
								}
								if (!program_ok)
									nm_warning ("WARNING: VPN program '%s' invalid in file '%s'", line, file_path);
								have_program = TRUE;
							}
						}
					}
					g_strfreev (split_contents);

					if (nm_vpn_service_get_name (service) && nm_vpn_service_get_program (service))
					{
						nm_info ("Adding VPN service '%s' with program '%s'", nm_vpn_service_get_name (service),
									nm_vpn_service_get_program (service));
						list = g_slist_append (list, service);
					}
					else
						nm_vpn_service_unref (service);
				}
				g_free (contents);
			}
			g_free (file_path);
		}

		g_dir_close (vpn_dir);
	}

	return list;
}

