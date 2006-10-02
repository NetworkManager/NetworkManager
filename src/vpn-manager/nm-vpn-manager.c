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
#include "NetworkManager.h"
#include "NetworkManagerMain.h"
#include "NetworkManagerDbus.h"
#include "NetworkManagerSystem.h"
#include "nm-vpn-act-request.h"
#include "nm-vpn-connection.h"
#include "nm-vpn-service.h"
#include "nm-dbus-vpn.h"
#include "nm-utils.h"

#define VPN_SERVICE_FILE_PATH		SYSCONFDIR"/NetworkManager/VPN"

struct NMVPNManager
{
	NMData *			app_data;
	GHashTable *		service_table;
	GSList *			connections;

	NMVPNActRequest *	act_req;
};

static void load_services (NMVPNManager *manager, GHashTable *table);

/*
 * nm_vpn_manager_new
 *
 * Create a new VPN manager instance.
 *
 */
NMVPNManager *nm_vpn_manager_new (NMData *app_data)
{
	NMVPNManager *	manager;

	g_return_val_if_fail (app_data != NULL, NULL);

	manager = g_malloc0 (sizeof (NMVPNManager));
	manager->app_data = app_data;

	manager->service_table = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, (GDestroyNotify) nm_vpn_service_unref);
	load_services (manager, manager->service_table);

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

	memset (manager, 0, sizeof (NMVPNManager));
	g_free (manager);
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
NMVPNConnection *nm_vpn_manager_add_connection (NMVPNManager *manager, const char *name, const char *service_name, const char *user_name)
{
	NMVPNConnection *	connection = NULL;
	NMVPNService *		service;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (service_name != NULL, NULL);
	g_return_val_if_fail (user_name != NULL, NULL);

	/* Verify that the service name we are adding is in our allowed list */
	if (!(service = nm_vpn_manager_find_service_by_name (manager, service_name)))
		return NULL;

	if ((connection = nm_vpn_connection_new (name, user_name, service_name, manager->app_data->named_manager,
												manager->app_data->dbus_connection)))
	{
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


static inline gboolean same_service_name (NMVPNService *service, NMVPNConnection *vpn)
{
	g_return_val_if_fail (service != NULL, FALSE);
	g_return_val_if_fail (vpn != NULL, FALSE);

	return (!strcmp (nm_vpn_service_get_service_name (service), nm_vpn_connection_get_service_name (vpn)));
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
	const char *		service_name;
	NMVPNService *		service;
	gboolean			handled = FALSE;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	service_name = dbus_message_get_interface (message);
	if ((service = nm_vpn_manager_find_service_by_name (manager, service_name)))
	{
		nm_vpn_service_process_signal (service, manager->act_req, message);
		handled = TRUE;
	}

	return handled;
}


/*
 * nm_vpn_manager_process_name_owner_changed
 *
 * Respond to "service created"/"service deleted" signals from dbus for our active VPN daemon.
 *
 */
gboolean nm_vpn_manager_process_name_owner_changed (NMVPNManager *manager, const char *changed_service_name, const char *old_owner, const char *new_owner)
{
	NMVPNService *		service;
	gboolean			handled = FALSE;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (changed_service_name != NULL, FALSE);

	if ((service = nm_vpn_manager_find_service_by_name (manager, changed_service_name)))
	{
		nm_vpn_service_name_owner_changed (service, manager->act_req, old_owner, new_owner);
		handled = TRUE;
	}

	return handled;
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

	if (!(parent_dev = nm_get_active_device (manager->app_data)))
	{
		nm_warning ("nm_vpn_manager_activate_vpn_connection(): no currently active network device, won't activate VPN.");
		return;
	}

	req = nm_vpn_act_request_new (manager, service, vpn, parent_dev, password_items, password_count, data_items, data_count,
					 user_routes, user_routes_count);
	manager->act_req = req;

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
	GSource *			source = NULL;

	g_return_if_fail (manager != NULL);
	g_return_if_fail (req != NULL);

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) nm_vpn_manager_vpn_activation_failed, req, NULL);
	g_source_attach (source, manager->app_data->main_context);
	g_source_unref (source);
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
	GSource *			source = NULL;

	g_return_if_fail (manager != NULL);
	g_return_if_fail (req != NULL);

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) nm_vpn_manager_vpn_connection_died, req, NULL);
	g_source_attach (source, manager->app_data->main_context);
	g_source_unref (source);
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

