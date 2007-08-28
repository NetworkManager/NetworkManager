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
#include <dbus/dbus.h>
#include "nm-vpn-manager.h"
#include "nm-named-manager.h"
#include "NetworkManager.h"
#include "NetworkManagerMain.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerSystem.h"
#include "nm-vpn-act-request.h"
#include "nm-vpn-connection.h"
#include "nm-vpn-service.h"
#include "nm-dbus-vpn.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"

#define VPN_SERVICE_FILE_PATH		SYSCONFDIR"/NetworkManager/VPN"

struct NMVPNManager
{
	NMManager *         nm_manager;
	NMData *			app_data;
	GHashTable *		service_table;
	GSList *			connections;

	NMVPNActRequest *	act_req;
	gulong				device_signal_id;
};

static void load_services (NMVPNManager *manager, GHashTable *table);

static void
nm_name_owner_changed_handler (NMDBusManager *mgr,
                               const char *name,
                               const char *old,
                               const char *new,
                               gpointer user_data)
{
	NMVPNManager *vpn_manager = (NMVPNManager *) user_data;
	gboolean old_owner_good = (old && (strlen (old) > 0));
	gboolean new_owner_good = (new && (strlen (new) > 0));

	if (strcmp (name, NMI_DBUS_SERVICE) == 0 && (!old_owner_good && new_owner_good))
		/* NMI appeared, update stuff */
		nm_dbus_vpn_schedule_vpn_connections_update (vpn_manager);
}

static gboolean
nm_dbus_nmi_vpn_signal_handler (DBusConnection *connection,
								DBusMessage *message,
								gpointer user_data)
{
	NMVPNManager *manager = (NMVPNManager *) user_data;
	const char * object_path;
	gboolean	handled = FALSE;

	if (!(object_path = dbus_message_get_path (message)))
		return FALSE;

	if (strcmp (object_path, NMI_DBUS_PATH) != 0)
		return FALSE;

	if (dbus_message_is_signal (message, NMI_DBUS_INTERFACE, "VPNConnectionUpdate")) {
		char *name = NULL;

		if (dbus_message_get_args (message,
		                           NULL,
		                           DBUS_TYPE_STRING, &name,
		                           DBUS_TYPE_INVALID)) {
			nm_debug ("NetworkManagerInfo triggered update of VPN connection '%s'", name);
			nm_dbus_vpn_update_one_vpn_connection (connection, manager, name);
			handled = TRUE;
		}
	}

	return handled;
}

/*
 * nm_vpn_manager_new
 *
 * Create a new VPN manager instance.
 *
 */
NMVPNManager *nm_vpn_manager_new (NMManager *nm_manager, NMData *app_data)
{
	NMVPNManager *	manager;
	NMDBusManager *	dbus_mgr;

	g_return_val_if_fail (NM_IS_MANAGER (nm_manager), NULL);
	g_return_val_if_fail (app_data != NULL, NULL);

	manager = g_slice_new0 (NMVPNManager);
	manager->nm_manager = g_object_ref (nm_manager);
	manager->app_data = app_data;

	manager->service_table = g_hash_table_new_full (g_str_hash,
	                                                g_str_equal,
	                                                NULL,
	                                                (GDestroyNotify) nm_vpn_service_unref);
	load_services (manager, manager->service_table);

	if (!nm_dbus_vpn_methods_setup (manager)) {
		nm_vpn_manager_dispose (manager);
		return NULL;
	}

	dbus_mgr = nm_dbus_manager_get ();

	g_signal_connect (dbus_mgr,
					  "name-owner-changed",
	                  G_CALLBACK (nm_name_owner_changed_handler),
					  manager);

	nm_dbus_manager_register_signal_handler (dbus_mgr,
											 NMI_DBUS_INTERFACE,
											 NULL,
											 nm_dbus_nmi_vpn_signal_handler,
											 manager);

	if (nm_dbus_manager_name_has_owner (dbus_mgr, NMI_DBUS_SERVICE))
		nm_dbus_vpn_schedule_vpn_connections_update (manager);

	g_object_unref (dbus_mgr);

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

	if (manager->act_req)
		nm_vpn_manager_deactivate_vpn_connection (manager, nm_vpn_act_request_get_parent_dev (manager->act_req));

	g_slist_foreach (manager->connections, (GFunc) nm_vpn_connection_unref, NULL);
	g_slist_free (manager->connections);

	g_hash_table_destroy (manager->service_table);

	g_object_unref (manager->nm_manager);

	memset (manager, 0, sizeof (NMVPNManager));
	g_slice_free (NMVPNManager, manager);
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


NMVPNService *nm_vpn_manager_find_service_by_name (NMVPNManager *manager, const char *service_name)
{
	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (service_name != NULL, NULL);

	return (NMVPNService *) g_hash_table_lookup (manager->service_table, service_name);
}


/*
 * nm_vpn_manager_vpn_connection_list_copy
 *
 * Make a shallow copy of the VPN connection list, should
 * only be used by nm-dbus-vpn.c
 *
 */
GSList *nm_vpn_manager_vpn_connection_list_copy (NMVPNManager *manager)
{
	GSList *	list;
	GSList *	elt;

	g_return_val_if_fail (manager != NULL, NULL);

	list = g_slist_copy (manager->connections);
	for (elt = list; elt; elt = g_slist_next (elt))
		nm_vpn_connection_ref (elt->data);

	return list;
}


/*
 * nm_vpn_manager_add_connection
 *
 * Add a new VPN connection if none already exits, otherwise update the existing one.
 *
 */
NMVPNConnection *
nm_vpn_manager_add_connection (NMVPNManager *manager,
                               const char *name,
                               const char *service_name,
                               const char *user_name)
{
	NMVPNConnection *	connection = NULL;
	NMVPNService *		service;
	DBusConnection *	dbus_connection;
	NMDBusManager *		dbus_mgr = NULL;
	NMNamedManager *	named_mgr = NULL;
	GSList	*			elt;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (service_name != NULL, NULL);
	g_return_val_if_fail (user_name != NULL, NULL);

	/* Verify that the service name we are adding is in our allowed list */
	if (!(service = nm_vpn_manager_find_service_by_name (manager, service_name)))
		return NULL;

	dbus_mgr = nm_dbus_manager_get ();
	dbus_connection = nm_dbus_manager_get_dbus_connection (dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("couldn't get dbus connection.");
		goto out;
	}

	named_mgr = nm_named_manager_get ();
	connection = nm_vpn_connection_new (name,
	                                    user_name,
	                                    service_name,
	                                    named_mgr);
	g_object_unref (named_mgr);
	if (!connection) {
		nm_warning ("couldn't create VPN connecton for '%s (%s).",
		            name,
		            service_name);
		goto out;
	}

	/* Remove the existing connection if found */
	for (elt = manager->connections; elt; elt = g_slist_next (elt)) {
		NMVPNConnection *con = (NMVPNConnection *)(elt->data);

		
		if (!con || !nm_vpn_connection_get_name (con))
			continue;
		if (strcmp (nm_vpn_connection_get_name (con), name) != 0)
			continue;

		manager->connections = g_slist_remove_link (manager->connections, elt);
		nm_vpn_connection_unref (con);
		g_slist_free (elt);
	}

	/* Add in the updated connection */
	manager->connections = g_slist_append (manager->connections, connection);

out:
	g_object_unref (dbus_mgr);
	return connection;
}


/*
 * nm_vpn_manager_remove_connection
 *
 * Remove a VPN connection.
 *
 */
void nm_vpn_manager_remove_connection (NMVPNManager *manager, NMVPNConnection *vpn)
{
	g_return_if_fail (manager != NULL);
	g_return_if_fail (vpn != NULL);

	/* If this VPN is currently active, kill it */
	if (manager->act_req && (nm_vpn_act_request_get_connection (manager->act_req) == vpn))
	{
		NMVPNService *		service = nm_vpn_act_request_get_service (manager->act_req);
		NMVPNConnection *	v = nm_vpn_act_request_get_connection (manager->act_req);

		nm_vpn_connection_deactivate (v);
		nm_vpn_service_stop_connection (service, manager->act_req);

		nm_vpn_act_request_unref (manager->act_req);
		manager->act_req = NULL;
	}

	manager->connections = g_slist_remove (manager->connections, vpn);
	nm_vpn_connection_unref (vpn);
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
 * nm_vpn_manager_get_vpn_act_request
 *
 * Return the VPN activation request, if any.
 *
 */
NMVPNActRequest *nm_vpn_manager_get_vpn_act_request (NMVPNManager *manager)
{
	g_return_val_if_fail (manager != NULL, NULL);

	return manager->act_req;
}


static void
device_state_changed (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	NMVPNManager *manager = (NMVPNManager *) user_data;

	if (state == NM_DEVICE_STATE_DISCONNECTED)
		nm_vpn_manager_deactivate_vpn_connection (manager, device);
}


/*
 * nm_vpn_manager_activate_vpn_connection
 *
 * Signal the VPN service daemon to activate a particular VPN connection,
 * launching that daemon if necessary.
 *
 */
void nm_vpn_manager_activate_vpn_connection (NMVPNManager *manager, NMVPNConnection *vpn,
				char **password_items, int password_count, char **data_items, int data_count, char **user_routes, int user_routes_count)
{
	NMDevice *		parent_dev;
	NMVPNActRequest *	req;
	NMVPNService *		service;
	const char *		service_name;

	g_return_if_fail (manager != NULL);
	g_return_if_fail (vpn != NULL);
	g_return_if_fail (password_items != NULL);
	g_return_if_fail (data_items != NULL);

	if (nm_vpn_manager_get_vpn_act_request (manager))
		nm_vpn_manager_deactivate_vpn_connection (manager, nm_vpn_act_request_get_parent_dev (manager->act_req));

	service_name = nm_vpn_connection_get_service_name (vpn);
	if (!(service = nm_vpn_manager_find_service_by_name (manager, service_name)))
		return;

	if (!(parent_dev = nm_manager_get_active_device (manager->nm_manager)))
	{
		nm_warning ("nm_vpn_manager_activate_vpn_connection(): no currently active network device, won't activate VPN.");
		return;
	}

	req = nm_vpn_act_request_new (manager, service, vpn, parent_dev, password_items, password_count, data_items, data_count,
					 user_routes, user_routes_count);
	manager->act_req = req;

	manager->device_signal_id = g_signal_connect (parent_dev, "state-changed",
												  G_CALLBACK (device_state_changed),
												  manager);

	nm_vpn_service_start_connection (service, req);
}


/*
 * nm_vpn_manager_deactivate_vpn_connection
 *
 * Signal the VPN service daemon to deactivate a particular VPN connection.
 *
 */
void nm_vpn_manager_deactivate_vpn_connection (NMVPNManager *manager, NMDevice *dev)
{
	NMVPNService *		service;
	NMVPNConnection *	vpn;

	g_return_if_fail (manager != NULL);

	if (!manager->act_req || (dev != nm_vpn_act_request_get_parent_dev (manager->act_req)))
		return;

	if (manager->device_signal_id) {
		g_signal_handler_disconnect (dev, manager->device_signal_id);
		manager->device_signal_id = 0;
	}

	if (nm_vpn_act_request_is_activating (manager->act_req)
		|| nm_vpn_act_request_is_activated (manager->act_req)
		|| nm_vpn_act_request_is_failed (manager->act_req))
	{
		if (nm_vpn_act_request_is_activated (manager->act_req))
		{
			vpn = nm_vpn_act_request_get_connection (manager->act_req);
			g_assert (vpn);
			nm_vpn_connection_deactivate (vpn);
		}

		service = nm_vpn_act_request_get_service (manager->act_req);
		g_assert (service);
		nm_vpn_service_stop_connection (service, manager->act_req);
	}

	nm_vpn_act_request_unref (manager->act_req);
	manager->act_req = NULL;
}


static gboolean nm_vpn_manager_vpn_activation_failed (gpointer user_data)
{
	NMVPNActRequest *	req = (NMVPNActRequest *) user_data;
	NMVPNManager *		manager;

	g_assert (req);

	manager = nm_vpn_act_request_get_manager (req);
	g_assert (manager);

	if (manager->act_req == req)
		nm_vpn_manager_deactivate_vpn_connection (manager, nm_vpn_act_request_get_parent_dev (req));

	return FALSE;
}


void nm_vpn_manager_schedule_vpn_activation_failed (NMVPNManager *manager, NMVPNActRequest *req)
{
	g_return_if_fail (manager != NULL);
	g_return_if_fail (req != NULL);

	g_idle_add (nm_vpn_manager_vpn_activation_failed, req);
}


static gboolean nm_vpn_manager_vpn_connection_died (gpointer user_data)
{
	NMVPNActRequest *	req = (NMVPNActRequest *) user_data;
	NMVPNManager *		manager;

	g_assert (req);

	manager = nm_vpn_act_request_get_manager (req);
	g_assert (manager);

	if (manager->act_req == req)
		nm_vpn_manager_deactivate_vpn_connection (manager, nm_vpn_act_request_get_parent_dev (req));

	return FALSE;
}


void nm_vpn_manager_schedule_vpn_connection_died (NMVPNManager *manager, NMVPNActRequest *req)
{
	g_return_if_fail (manager != NULL);
	g_return_if_fail (req != NULL);

	g_idle_add (nm_vpn_manager_vpn_connection_died, req);
}


/*********************************************************************/

#define NAME_TAG "name="
#define SERVICE_TAG "service="
#define PROGRAM_TAG "program="

static gboolean
set_service_from_contents (char ** lines, NMVPNService * service, char **err)
{
	int			i;
	guint32		len = g_strv_length (lines);
	gboolean	have_name = FALSE;
	gboolean	have_service = FALSE;
	gboolean	have_program = FALSE;

	g_return_val_if_fail (err != NULL, FALSE);
	g_return_val_if_fail (*err == NULL, FALSE);

	for (i = 0; i < len; i++) {
		char * line = lines[i];

		/* Blank lines, or comment lines */
		if (!line || !strlen (line) || (line[0] == '#'))
			continue;

		if ((strncmp (line, NAME_TAG, strlen (NAME_TAG)) == 0)) {
			const char * name = line+strlen (NAME_TAG);

			if (have_name) {
				*err = "already parsed 'name' tag";
				return FALSE;
			}

			nm_vpn_service_set_name (service, name);
			have_name = TRUE;
			continue;
		}

		if ((strncmp (line, SERVICE_TAG, strlen (SERVICE_TAG)) == 0)) {
			const char * serv_name = line+strlen (SERVICE_TAG);

			/* Minimal service name sanity checking */
			if (have_service) {
				*err = "already parsed 'service' tag";
				return FALSE;
			}

			if (   !strcmp (serv_name, NM_DBUS_SERVICE)
			    || !strcmp (serv_name, NMI_DBUS_SERVICE)) {
				*err = "service name is invalid";
				return FALSE;
			}

			nm_vpn_service_set_service_name (service, serv_name);
			have_service = TRUE;
			continue;
		}

		if ((strncmp (line, PROGRAM_TAG, strlen (PROGRAM_TAG)) == 0)) {
			const char * program = line+strlen (PROGRAM_TAG);

			if (have_program) {
				*err = "already parsed 'program' tag";
				return FALSE;
			}
			
			if (!g_path_is_absolute (program)) {
				*err = "path to program was not absolute";
				return FALSE;
			}

			if (!g_file_test (program,   G_FILE_TEST_EXISTS
			                           | G_FILE_TEST_IS_EXECUTABLE
			                           | G_FILE_TEST_IS_REGULAR )) {
				*err = "program does not exist, or is not executable";
				return FALSE;
			}

			nm_vpn_service_set_program (service, (const char *)(line+strlen (PROGRAM_TAG)));
			have_program = TRUE;
			continue;
		}
	}

	if (!have_name || !have_service || !have_program) {
		*err = "didn't contain all required tags";
		return FALSE;
	}

	return TRUE;
}


struct dup_search_data {
	const char * name;
	const char * serv_name;
	gboolean found;
};

static void
find_dup_name (gpointer key, gpointer value, gpointer user_data)
{
	struct dup_search_data * data = (struct dup_search_data *) user_data;
	NMVPNService * service = (NMVPNService *) value;
	const char * serv_name = nm_vpn_service_get_service_name (service);
	const char * name = nm_vpn_service_get_name (service);

	/* already found a dupe, do nothing */
	if (data->found)
		return;

	if (strcmp (serv_name, data->serv_name) == 0)
		data->found = TRUE;
	else if (strcmp (name, data->name) == 0)
		data->found = TRUE;
}


static void
load_services (NMVPNManager *manager, GHashTable *table)
{
	GDir *		vpn_dir;
	const char *file_name;

	g_return_if_fail (manager != NULL);
	g_return_if_fail (table != NULL);

	/* Load allowed service names */
	if (!(vpn_dir = g_dir_open (VPN_SERVICE_FILE_PATH, 0, NULL)))
		return;

	while ((file_name = g_dir_read_name (vpn_dir))) {
		char *			file_path;
		char *			contents;
		char **			lines;
		NMVPNService *	service;
		char *			err = NULL;
		gboolean		success;

		file_path = g_strdup_printf (VPN_SERVICE_FILE_PATH"/%s", file_name);

		/* Check for the .name extension */
		if (strcmp (file_name + strlen (file_name) - 5, ".name") != 0) {
			nm_warning ("Error loading VPN service file '%s': doesn't "
			            "end with .name", file_path);
			goto free_file_path;
		}

		if (!g_file_get_contents (file_path, &contents, NULL, NULL))
			goto free_file_path;

		lines = g_strsplit (contents, "\n", 0);
		g_free (contents);
		if (!lines)
			goto free_file_path;
 
		service = nm_vpn_service_new (manager, manager->app_data);
		success = set_service_from_contents (lines, service, &err);
		g_strfreev (lines);

		if (!success) {
			nm_warning ("Error loading VPN service file '%s': %s.",
			            file_path, err);
			nm_vpn_service_unref (service);
		} else {
			const char * serv_name = nm_vpn_service_get_service_name (service);
			const char * name = nm_vpn_service_get_name (service);
			struct dup_search_data dup_data = { name, serv_name, FALSE };

			/* Check for duplicates */
			g_hash_table_foreach (table, find_dup_name, &dup_data);
			if (dup_data.found) {
				nm_warning ("Ignoring duplicate VPN service '%s' (%s) from %s.",
				            name, serv_name, file_path);
			} else {
				/* All good, add it */
				nm_info ("New VPN service '%s' (%s).", name, serv_name);
				g_hash_table_insert (table, (char *) serv_name, service);
			}
		}

	free_file_path:
		g_free (file_path);
	}

	g_dir_close (vpn_dir);
}

