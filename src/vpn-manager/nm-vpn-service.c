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
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dbus/dbus.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

#include "NetworkManagerDbus.h"
#include "nm-dbus-vpn.h"
#include "nm-vpn-service.h"
#include "nm-vpn-act-request.h"
#include "nm-utils.h"
#include "dbus-dict-helpers.h"
#include "nm-dbus-manager.h"

/* define this for getting VPN debug messages */
#undef NM_DEBUG_VPN_CONFIG

struct NMVPNService
{
	int				refcount;
	NMVPNManager *	manager;
	NMData *		app_data;
	GPid			pid;
	guint32         sig_handler_id;
	gulong			watch_id;
	gulong			dbus_con_watch_id;
	NMDBusManager *	dbus_mgr;

	char *			name;
	char *			service;
	char *			program;
	NMVPNServiceState	state;
};


static void nm_vpn_service_add_watch (NMVPNService *service);
static void nm_vpn_service_remove_watch (NMVPNService *service);
static void nm_vpn_service_stop_connection_internal (NMVPNService *service);

static void nm_vpn_service_schedule_stage1_daemon_exec (NMVPNService *service, NMVPNActRequest *req);
static void nm_vpn_service_schedule_stage3_connect (NMVPNService *service, NMVPNActRequest *req);
static void nm_vpn_service_schedule_stage2_daemon_wait (NMVPNService *service, NMVPNActRequest *req);
static void nm_vpn_service_schedule_stage4_ip_config_get_timeout (NMVPNService *service, NMVPNActRequest *req);
static void nm_vpn_service_cancel_callback (NMVPNService *service, NMVPNActRequest *req);

static gboolean nm_vpn_service_process_signal (DBusConnection *connection,
                                               DBusMessage *message,
                                               gpointer user_data);

static void nm_vpn_service_name_owner_changed (NMDBusManager *mgr,
                                               const char *name,
                                               const char *old,
                                               const char *new,
                                               gpointer user_data);

static void nm_vpn_service_dbus_connection_changed (NMDBusManager *mgr,
                                                    DBusConnection *connection,
                                                    gpointer user_data);

#ifdef NM_DEBUG_VPN_CONFIG
static void print_vpn_config (NMIP4Config *config,
						const char *tundev,
						const char *login_banner);
#endif


/*
 * nm_vpn_service_new
 *
 * Create a new VPNService object
 *
 */
NMVPNService *nm_vpn_service_new (NMVPNManager *manager, NMData *app_data)
{
	NMVPNService *service = g_malloc0 (sizeof (NMVPNService));

	service->refcount = 1;
	service->state = NM_VPN_SERVICE_STATE_SHUTDOWN;
	service->app_data = app_data;
	service->manager = manager;
	service->dbus_mgr = nm_dbus_manager_get ();

	return service;
}

void nm_vpn_service_ref (NMVPNService *service)
{
	g_return_if_fail (service != NULL);

	service->refcount++;
}


void nm_vpn_service_unref (NMVPNService *service)
{
	g_return_if_fail (service != NULL);

	service->refcount--;
	if (service->refcount <= 0)
	{
		nm_vpn_service_remove_watch (service);
		g_free (service->name);
		g_free (service->service);
		g_free (service->program);
		g_object_unref (service->dbus_mgr);
		memset (service, 0, sizeof (NMVPNService));
		g_free (service);
	}
}


const char *nm_vpn_service_get_name (NMVPNService *service)
{
	g_return_val_if_fail (service != NULL, NULL);

	return service->name;
}


void nm_vpn_service_set_name (NMVPNService *service, const char *name)
{
	g_return_if_fail (service != NULL);

	if (service->name)
		g_free (service->name);
	service->name = g_strdup (name);
}


const char *nm_vpn_service_get_service_name (NMVPNService *service)
{
	g_return_val_if_fail (service != NULL, NULL);

	return service->service;
}


void nm_vpn_service_set_service_name (NMVPNService *service, const char *name)
{
	g_return_if_fail (service != NULL);

	if (service->service)
		g_free (service->service);
	service->service = g_strdup (name);

	/* If the VPN daemon is currently running, tell it to stop */
	if (nm_dbus_manager_name_has_owner (service->dbus_mgr, service->service))
		nm_vpn_service_stop_connection_internal (service);
}


const char *nm_vpn_service_get_program (NMVPNService *service)
{
	g_return_val_if_fail (service != NULL, NULL);

	return service->program;
}


void nm_vpn_service_set_program (NMVPNService *service, const char *program)
{
	g_return_if_fail (service != NULL);

	if (service->program)
		g_free (service->program);
	service->program = g_strdup (program);
}


NMVPNServiceState
nm_vpn_service_get_state (NMVPNService *service)
{
	g_return_val_if_fail (service != NULL, NM_VPN_SERVICE_STATE_UNKNOWN);

	return service->state;
}


static void
nm_vpn_service_set_state (NMVPNService *service,
                          const NMVPNServiceState state)
{
	g_return_if_fail (service != NULL);

	service->state = state;
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

	return temp2;
}


/*
 * nm_vpn_service_act_request_failed
 *
 * Clean up after an activation request and tell the VPN manager that it
 * has failed.
 *
 */
static void
nm_vpn_service_act_request_failed (NMVPNService *service,
                                   NMVPNActRequest *req)
{
	NMVPNConnection *vpn;

	g_return_if_fail (service != NULL);
	g_return_if_fail (req != NULL);

	/* Sanity checks */
	if (nm_vpn_act_request_get_service (req) != service)
		return;

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_service_cancel_callback (service, req);

	nm_vpn_act_request_set_state (req, NM_VPN_CONNECTION_STATE_FAILED);
	nm_info ("VPN Activation (%s) failed.", nm_vpn_connection_get_name (vpn));

	nm_vpn_act_request_unref (req);
	nm_vpn_manager_schedule_vpn_activation_failed (service->manager, req);	
}


static void
nm_vpn_service_activation_success (NMVPNService *service,
                                   NMVPNActRequest *req)
{
	NMVPNConnection *	vpn = NULL;

	g_assert (service != NULL);
	g_assert (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_service_cancel_callback (service, req);

	nm_vpn_act_request_set_state (req, NM_VPN_CONNECTION_STATE_ACTIVATED);
	nm_info ("VPN Activation (%s) successful.", nm_vpn_connection_get_name (vpn));
}


/*
 * nm_vpn_service_start_connection
 *
 * Kick off the VPN connection process.
 *
 */
void
nm_vpn_service_start_connection (NMVPNService *service,
                                 NMVPNActRequest *req)
{
	g_return_if_fail (service != NULL);
	g_return_if_fail (req != NULL);

	nm_vpn_act_request_set_state (req, NM_VPN_CONNECTION_STATE_PREPARE);
	nm_vpn_service_add_watch (service);

	/* Start the daemon if it's not already running */
	nm_vpn_act_request_ref (req);
	if (!nm_dbus_manager_name_has_owner (service->dbus_mgr, service->service))
		nm_vpn_service_schedule_stage1_daemon_exec (service, req);
	else
		nm_vpn_service_schedule_stage2_daemon_wait (service, req);
}


/*
 * nm_vpn_service_child_setup
 *
 * Set the process group ID of the newly forked process
 *
 */
static void
nm_vpn_service_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);
}


/*
 * nm_vpn_service_stage_1_daemon_exec
 *
 * Execute the VPN service daemon.
 *
 */
static gboolean nm_vpn_service_stage1_daemon_exec (gpointer user_data)
{
	NMVPNActRequest *	req = (NMVPNActRequest *) user_data;
	NMVPNService *		service;
	NMVPNConnection *	vpn = NULL;
	GPtrArray *		vpn_argv;
	GError *			error = NULL;
	gboolean		launched = FALSE;

	g_assert (req != NULL);

	service = nm_vpn_act_request_get_service (req);
	g_assert (service != NULL);
	g_assert (service->program != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_act_request_set_callback_id (req, 0);

	vpn_argv = g_ptr_array_new ();
	g_ptr_array_add (vpn_argv, service->program);
	g_ptr_array_add (vpn_argv, NULL);

	launched = g_spawn_async (NULL,
	                          (char **) vpn_argv->pdata,
	                          NULL,
	                          0,
	                          &nm_vpn_service_child_setup,
	                          NULL,
	                          &service->pid,
	                          &error);
	if (!launched) {
		g_ptr_array_free (vpn_argv, TRUE);
		nm_warning ("(VPN Service %s): could not launch the VPN service.  "
		            "error: '%s'.",
		            service->service,
		            error->message);
		g_error_free (error);
		nm_vpn_service_act_request_failed (service, req);
		goto out;
	}
	g_ptr_array_free (vpn_argv, TRUE);
	nm_info ("VPN Activation (%s) Stage 1 of 4 (Connection Prepare) ran VPN "
	         "service daemon %s (PID %d)",
	         nm_vpn_connection_get_name (vpn),
	         service->service,
	         service->pid);
	nm_info ("VPN Activation (%s) Stage 1 of 4 (Connection Prepare) complete.",
	         nm_vpn_connection_get_name (vpn));

	nm_vpn_service_schedule_stage2_daemon_wait (service, req);

out:
	return FALSE;
}


static void
nm_vpn_service_schedule_stage1_daemon_exec (NMVPNService *service,
                                            NMVPNActRequest *req)
{
	NMVPNConnection * vpn = NULL;
	guint             id;

	g_assert (service != NULL);
	g_assert (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_act_request_set_state (req, NM_VPN_CONNECTION_STATE_PREPARE);
	nm_vpn_service_set_state (service, NM_VPN_SERVICE_STATE_SHUTDOWN);

	id = g_idle_add (nm_vpn_service_stage1_daemon_exec, req);
	nm_vpn_act_request_set_callback_id (req, id);
	nm_info ("VPN Activation (%s) Stage 1 of 4 (Connection Prepare) scheduled...",
	         nm_vpn_connection_get_name (vpn));
}


/*
 * nm_vpn_service_stage2_daemon_wait
 *
 * Wait until the VPN daemon has become active.
 *
 */
static gboolean
nm_vpn_service_stage2_daemon_wait (gpointer user_data)
{
	NMVPNActRequest *	req = (NMVPNActRequest *) user_data;
	NMVPNService *		service;
	NMVPNConnection *	vpn = NULL;
	gboolean			service_exists = FALSE;

	g_assert (req != NULL);

	service = nm_vpn_act_request_get_service (req);
	g_assert (service != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_act_request_set_callback_id (req, 0);

	nm_info ("VPN Activation (%s) Stage 2 of 4 (Connection Prepare Wait) "
				"waiting...", nm_vpn_connection_get_name (vpn));

	service_exists = nm_dbus_manager_name_has_owner (service->dbus_mgr,
	                                                 service->service);
	if (service_exists && (service->state == NM_VPN_SERVICE_STATE_STOPPED)) {
		nm_info ("VPN Activation (%s) Stage 2 of 4 (Connection Prepare Wait) "
				"complete.", nm_vpn_connection_get_name (vpn));
		nm_vpn_service_schedule_stage3_connect (service, req);
	} else if (nm_vpn_act_request_get_daemon_wait_count (req) > 10) {
		/* We only wait 2s (10 * 200 milliseconds) for the service to
		 * become available.
		 */
		nm_vpn_service_act_request_failed (service, req);
	} else {
		nm_vpn_service_schedule_stage2_daemon_wait (service, req);
	}

	return FALSE;
}


static void
nm_vpn_service_schedule_stage2_daemon_wait (NMVPNService *service,
                                            NMVPNActRequest *req)
{
	NMVPNConnection * vpn = NULL;
	guint             id;

	g_assert (service != NULL);
	g_assert (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_act_request_set_state (req, NM_VPN_CONNECTION_STATE_PREPARE);

	nm_vpn_act_request_set_daemon_wait_count (req, nm_vpn_act_request_get_daemon_wait_count (req) + 1);

	id = g_timeout_add (200, nm_vpn_service_stage2_daemon_wait, req);
	nm_vpn_act_request_set_callback_id (req, id);
	nm_info ("VPN Activation (%s) Stage 2 of 4 (Connection Prepare Wait) "
	         "scheduled...",
	         nm_vpn_connection_get_name (vpn));
}


static void
nm_vpn_service_stage3_connect_cb (DBusPendingCall *pcall,
                                  void *user_data)
{
	DBusMessage *		reply;
	NMVPNActRequest *	req = (NMVPNActRequest *) user_data;
	NMVPNService *		service;
	NMVPNConnection *	vpn;

	g_assert (pcall != NULL);
	g_assert (req != NULL);

	service = nm_vpn_act_request_get_service (req);
	g_assert (service != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_info ("VPN Activation (%s) Stage 3 of 4 (Connect) reply received.",
			nm_vpn_connection_get_name (vpn));

	if (!(reply = dbus_pending_call_steal_reply (pcall))) {
		nm_warning ("(VPN Service %s): could not obtain VPN service's reply.",
				service->service);
		nm_vpn_service_act_request_failed (service, req);
		goto out;
	}

	if (message_is_error (reply)) {
		const char *member = dbus_message_get_member (reply);
		char *message;

		if (!dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &message, NULL))
			message = (char *) "";

		nm_warning ("(VPN Service %s): could not start the VPN '%s'.  dbus says: '%s'  '%s'.", 
					service->service, nm_vpn_connection_get_name (vpn), member, message);
		nm_vpn_service_act_request_failed (service, req);
	} else {
		nm_vpn_act_request_set_state (req, NM_VPN_CONNECTION_STATE_IP_CONFIG_GET);
		nm_vpn_service_schedule_stage4_ip_config_get_timeout (service, req);
		nm_info ("VPN Activation (%s) Stage 3 of 4 (Connect) complete, "
				"waiting for IP configuration...", nm_vpn_connection_get_name (vpn));
	}

	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
}


static char **
sanitize_dbus_string_array (char **in_array, dbus_uint32_t *in_num)
{
	char ** out_array;

	g_return_val_if_fail (in_num != NULL, NULL);

	if (in_array)
		return in_array;

	out_array = g_malloc0 (sizeof (char *));
	out_array[0] = g_strdup ("");
	*in_num = 1;
	return out_array;
}


static gboolean nm_vpn_service_stage3_connect (gpointer user_data)
{
	NMVPNActRequest *	req = (NMVPNActRequest *) user_data;
	NMVPNService *		service;
	NMVPNConnection *	vpn;
	char *			op;
	const char *		name;
	const char *		user_name;
	char **			password_items;
	dbus_uint32_t		password_count;
	char **			data_items;
	dbus_uint32_t		data_count;
	char **			user_routes;
	dbus_uint32_t		user_routes_count = 0;
	DBusMessage *		message;
	DBusPendingCall *	pcall = NULL;
	DBusConnection *	dbus_connection;
	gboolean			success = FALSE;

	g_assert (req != NULL);

	service = nm_vpn_act_request_get_service (req);
	g_assert (service != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn != NULL);

	dbus_connection = nm_dbus_manager_get_dbus_connection (service->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("VPN Activation (%s) Stage 3 of 4 (Connect) could not get "
		            "the DBus connection.",
		            nm_vpn_connection_get_name (vpn));
		goto out;
	}

	nm_vpn_act_request_set_callback_id (req, 0);

	/* Send the start vpn request to the daemon */
	op = construct_op_from_service_name (service->service);
	message = dbus_message_new_method_call (service->service,
	                                        op,
	                                        service->service,
	                                        "startConnection");
	g_free (op);
	if (!message) {
		nm_warning ("VPN Activation (%s) Stage 3 of 4 (Connect): couldn't "
		            " allocate dbus message.",
		            service->service);
		goto out;
	}

	name = nm_vpn_connection_get_name (vpn);
	user_name = nm_vpn_connection_get_user_name (vpn);
	password_items = (char **) nm_vpn_act_request_get_password_items (req, &password_count);
	data_items = (char **) nm_vpn_act_request_get_data_items (req, &data_count);
	user_routes = (char **) nm_vpn_act_request_get_user_routes(req, &user_routes_count);

	/* Ensure that data_items and user_routes are safe to put through dbus */
	data_items = sanitize_dbus_string_array (data_items, &data_count);
	user_routes = sanitize_dbus_string_array (user_routes, &user_routes_count);

	nm_info ("VPN Activation (%s) Stage 3 of 4 (Connect) sending connect request.",
			nm_vpn_connection_get_name (vpn));
	dbus_message_append_args (message, DBUS_TYPE_STRING, &name,
				  DBUS_TYPE_STRING, &user_name,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &password_items, password_count,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &data_items, data_count,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &user_routes, user_routes_count,
				  DBUS_TYPE_INVALID);

	dbus_connection_send_with_reply (dbus_connection, message, &pcall, -1);
	if (pcall) {
		dbus_pending_call_set_notify (pcall,
		                              nm_vpn_service_stage3_connect_cb,
		                              req,
		                              NULL);
		nm_info ("VPN Activation (%s) Stage 3 of 4 (Connect) request sent,"
		         " waiting for reply...",
		         nm_vpn_connection_get_name (vpn));
		success = TRUE;
	}
	dbus_message_unref (message);

out:
	if (!success)
		nm_vpn_service_act_request_failed (service, req);

	return FALSE;
}


static void
nm_vpn_service_schedule_stage3_connect (NMVPNService *service,
                                        NMVPNActRequest *req)
{
	NMVPNConnection * vpn = NULL;
	guint             id;

	g_assert (service != NULL);
	g_assert (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_act_request_set_state (req, NM_VPN_CONNECTION_STATE_CONNECT);

	id = g_idle_add (nm_vpn_service_stage3_connect, req);
	nm_vpn_act_request_set_callback_id (req, id);
	nm_info ("VPN Activation (%s) Stage 3 of 4 (Connect) scheduled...",
	         nm_vpn_connection_get_name (vpn));
}


static gboolean
nm_vpn_service_stage4_ip_config_get_timeout (gpointer user_data)
{
	NMVPNActRequest *	req = (NMVPNActRequest *) user_data;
	NMVPNService *		service;
	NMVPNConnection *	vpn;

	g_assert (req != NULL);

	service = nm_vpn_act_request_get_service (req);
	g_assert (service != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn != NULL);

	nm_vpn_act_request_set_callback_id (req, 0);

	/* If the activation request's state is still IP_CONFIG_GET and we're
	 * in this timeout, cancel activation because it's taken too long.
	 */
	if (nm_vpn_act_request_get_state (req) == NM_VPN_CONNECTION_STATE_IP_CONFIG_GET) {
		nm_info ("VPN Activation (%s) Stage 4 of 4 (IP Config Get) timeout "
		         "exceeded.",
		         nm_vpn_connection_get_name (vpn));
		nm_vpn_service_act_request_failed (service, req);
	}

	return FALSE;
}


static void
nm_vpn_service_schedule_stage4_ip_config_get_timeout (NMVPNService *service,
                                                      NMVPNActRequest *req)
{
	NMVPNConnection * vpn = NULL;
	guint             id;

	g_assert (service != NULL);
	g_assert (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_act_request_set_state (req, NM_VPN_CONNECTION_STATE_IP_CONFIG_GET);

	/* 20 second timeout waiting for IP config signal from VPN service */
	id = g_timeout_add (20000, nm_vpn_service_stage4_ip_config_get_timeout, req);
	nm_vpn_act_request_set_callback_id (req, id);
	nm_info ("VPN Activation (%s) Stage 4 of 4 (IP Config Get) timeout "
	         " scheduled...",
	         nm_vpn_connection_get_name (vpn));
}


static void nm_vpn_service_cancel_callback (NMVPNService *service, NMVPNActRequest *req)
{
	guint     id;

	g_return_if_fail (service != NULL);
	g_return_if_fail (req != NULL);

	if ((id = nm_vpn_act_request_get_callback_id (req)) == 0)
		return;

	g_source_destroy (g_main_context_find_source_by_id (NULL, id));
	nm_vpn_act_request_set_callback_id (req, 0);
}


static gboolean
get_dbus_guint32_helper (DBusMessageIter *iter,
                         guint32 *num,
					char *desc)
{
	if (!dbus_message_iter_next (iter)
	    || (dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_UINT32))
	{
		nm_warning ("Error: couldn't get %s from VPN IP Config message.", desc);
		return FALSE;
	}
	dbus_message_iter_get_basic (iter, num);
	return TRUE;
}

static gboolean
get_dbus_string_helper (DBusMessageIter *iter,
                        char **str,
                        char *desc)
{
	if (!dbus_message_iter_next (iter)
	    || (dbus_message_iter_get_arg_type (iter) != DBUS_TYPE_STRING))
	{
		nm_warning ("Error: couldn't get %s from VPN IP Config message.", desc);
		return FALSE;
	}
	dbus_message_iter_get_basic (iter, str);
	return TRUE;
}


/*
 * nm_vpn_service_stage4_ip4_config_get_old
 *
 * Configure a device with IPv4 config info in response the the VPN daemon.
 *
 */
static void
nm_vpn_service_stage4_ip4_config_get_old (NMVPNService *service,
                                          NMVPNActRequest *req,
                                          DBusConnection *dbus_connection,
                                          DBusMessage *message)
{
	NMVPNConnection *	vpn;
	guint32			num;
	char *			str;
	char *			tundev;
	char *			login_banner;
	gboolean			success = FALSE;
	DBusMessageIter	iter;
	DBusMessageIter	subiter;
	NMIP4Config *		config = NULL;
	NMDevice *		parent_dev;

	g_return_if_fail (service != NULL);
	g_return_if_fail (message != NULL);
	g_return_if_fail (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_info ("VPN Activation (%s) Stage 4 of 4 (IP Config Get) reply received.",
		nm_vpn_connection_get_name (vpn));

	config = nm_ip4_config_new ();
	nm_ip4_config_set_secondary (config, TRUE);

	dbus_message_iter_init (message, &iter);

	/* First arg: IP4 VPN Gateway address (UINT32) */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_UINT32) {
		nm_warning ("Error: couldn't get IP4 VPN Gateway Address"
		          " from VPN IP Config message.");
		goto out;
	}
	dbus_message_iter_get_basic (&iter, &num);
	nm_ip4_config_set_gateway (config, num);

	/* Second arg: Tunnel device, if any (STRING) */
	if (!get_dbus_string_helper (&iter, &tundev, "Tunnel Device"))
		goto out;

	/* Third arg: IP4 VPN Local Address (UINT32) */
	if (!get_dbus_guint32_helper (&iter, &num, "IP4 VPN Local Address"))
		goto out;
	nm_ip4_config_set_address (config, num);

	/* Fourth arg: IP4 VPN Point-to-Point Address (UINT32) */
	if (!get_dbus_guint32_helper (&iter, &num, "IP4 VPN PtP Address"))
		goto out;
	nm_ip4_config_set_ptp_address (config, num);

	/* Fifth arg: IP4 VPN Local Netmask (UINT32) */
	if (!get_dbus_guint32_helper (&iter, &num, "IP4 VPN Local Netmask"))
		goto out;
	/* If no netmask, default to Class C address */
	nm_ip4_config_set_netmask (config, num ? num : 0x00FF);

	/* Sixth arg: IP4 DNS Server Addresses (ARRAY, UINT32) */
	if (   !dbus_message_iter_next (&iter)
	    || (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_ARRAY)) {
		nm_warning ("Error: couldn't get IP4 DNS Server Addresses"
		          " from VPN IP Config message.");
		goto out;
	}
	dbus_message_iter_recurse (&iter, &subiter);
	while (dbus_message_iter_get_arg_type (&subiter) == DBUS_TYPE_UINT32) {
		dbus_message_iter_get_basic (&subiter, &num);
		if (num)
			nm_ip4_config_add_nameserver (config, num);
		dbus_message_iter_next (&subiter);
	}

	/* Seventh arg: IP4 NBNS Server Addresses (ARRAY, UINT32) */
	if (   !dbus_message_iter_next (&iter)
	    || (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_ARRAY)) {
		nm_warning ("Error: couldn't get IP4 NBNS Server Addresses"
		          " from VPN IP Config message.");
		goto out;
	}
	dbus_message_iter_recurse (&iter, &subiter);
	while (dbus_message_iter_get_arg_type (&subiter) == DBUS_TYPE_UINT32) {
		dbus_message_iter_get_basic (&subiter, &num);
		/* We don't do anything with these yet */
		dbus_message_iter_next (&subiter);
	}

	/* Eighth arg: MSS (UINT32) */
	if (!get_dbus_guint32_helper (&iter, &num, "MSS"))
		goto out;
	nm_ip4_config_set_mss (config, num);
	
	/* Ninth arg: DNS Domain (STRING) */
	if (!get_dbus_string_helper (&iter, &str, "DNS Domain"))
		goto out;
	if (strlen (str))
		nm_ip4_config_add_domain (config, str);

	/* Tenth arg: VPN Login Banner (STRING) */
	if (!get_dbus_string_helper (&iter, &login_banner, "Login Banner"))
		goto out;

#ifdef NM_DEBUG_VPN_CONFIG
	print_vpn_config (config, tundev, login_banner);
#endif

	if (!(parent_dev = nm_vpn_act_request_get_parent_dev (req)))
		goto out;

	if (nm_vpn_connection_set_config (vpn, tundev, parent_dev, config)) {
		nm_info ("VPN Activation (%s) Stage 4 of 4 (IP Config Get) complete.",
				nm_vpn_connection_get_name (vpn));
		if (login_banner && strlen (login_banner)) {
			nm_dbus_vpn_signal_vpn_login_banner (dbus_connection,
			                                     vpn,
			                                     login_banner);
		}
		success = TRUE;
		nm_vpn_service_activation_success (service, req);
	}

out:
	if (!success) {
		g_object_unref (config);
		nm_warning ("(VPN Service %s): did not receive valid IP config "
		            "information.",
		            service->service);
		nm_vpn_service_act_request_failed (service, req);
	}
}


#define HANDLE_DICT_ITEM(in_key, in_type, in_ary_type, op) \
	if (!strcmp (entry.key, in_key)) { \
		if (entry.type != in_type) { \
			nm_warning (in_key "had invalid type in VPN IP Config message."); \
		} else { \
			if (in_type == DBUS_TYPE_ARRAY && entry.array_type != in_ary_type) { \
				nm_warning (in_key "had invalid type in VPN IP Config message."); \
			} else { \
				op \
			} \
		} \
		goto next; \
	}


/*
 * nm_vpn_service_stage4_ip4_config_get
 *
 * Configure a device with IPv4 config info in response the the VPN daemon.
 *
 */
static void
nm_vpn_service_stage4_ip4_config_get (NMVPNService *service,
                                     NMVPNActRequest *req,
                                     DBusMessage *message)
{
	NMVPNConnection *	vpn;
	char *			tundev = NULL;
	char *			login_banner = NULL;
	gboolean			success = FALSE;
	DBusMessageIter	iter;
	DBusMessageIter	iter_dict;
	NMIP4Config *		config = NULL;
	NMDevice *		parent_dev;
	NMUDictEntry		entry = { .type = DBUS_TYPE_STRING };
	DBusConnection *dbus_connection;

	g_return_if_fail (service != NULL);
	g_return_if_fail (message != NULL);
	g_return_if_fail (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_info ("VPN Activation (%s) Stage 4 of 4 (IP Config Get) reply received.",
		nm_vpn_connection_get_name (vpn));

	dbus_connection = nm_dbus_manager_get_dbus_connection (service->dbus_mgr);
	if (!dbus_connection) {
		nm_info ("VPN Activation (%s) Stage 4 of 4 (IP Config Get) could not "
		         "get the DBus connection.",
		         nm_vpn_connection_get_name (vpn));
		goto out;
	}

	dbus_message_iter_init (message, &iter);

	/* If first arg is (UINT32) then this is an old type message */
	if (dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_UINT32) {
		nm_warning ("Warning: VPN plugin is using the old IP4Config message type");
		nm_vpn_service_stage4_ip4_config_get_old (service,
		                                          req,
		                                          dbus_connection,
		                                          message);
		return;
	}

	if (!nmu_dbus_dict_open_read (&iter, &iter_dict)) {
		nm_warning ("Warning: couldn't get config dictionary"
		            " from VPN IP Config message.");
		goto out;
	}

	config = nm_ip4_config_new ();
	nm_ip4_config_set_secondary (config, TRUE);

	/* First arg: Dict Type */
	if (dbus_message_iter_get_arg_type (&iter) != DBUS_TYPE_ARRAY) {
		nm_warning ("Error: couldn't get configuration dict"
		          " from VPN IP Config message.");
		goto out;
	}

	while (nmu_dbus_dict_has_dict_entry (&iter_dict)) {
		int i;

		if (!nmu_dbus_dict_get_entry (&iter_dict, &entry)) {
			nm_warning ("Error: couldn't read dict entry"
			            " from VPN IP Config message.");
			goto out;
		}

		/* IP specific options */
		HANDLE_DICT_ITEM("gateway", DBUS_TYPE_UINT32, 0,
			{ nm_ip4_config_set_gateway (config, entry.uint32_value); });
		HANDLE_DICT_ITEM("local_addr", DBUS_TYPE_UINT32, 0,
			{ nm_ip4_config_set_address (config, entry.uint32_value); });
		HANDLE_DICT_ITEM("ptp_addr", DBUS_TYPE_UINT32, 0,
			{ nm_ip4_config_set_ptp_address (config, entry.uint32_value); });
		/* If no netmask, default to Class C address */
		HANDLE_DICT_ITEM("local_netmask", DBUS_TYPE_UINT32, 0,
			{ nm_ip4_config_set_netmask (config,  entry.uint32_value ? entry.uint32_value : 0x00FF); });
		/* Multiple DNS servers are allowed */
		HANDLE_DICT_ITEM("dns_server", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
			{
				for (i = 0; i < entry.array_len; i++)
					nm_ip4_config_add_nameserver (config, entry.uint32array_value[i]);
			});
		/* Multiple NBNS servers are allowed */
		HANDLE_DICT_ITEM("nbns_server", DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
			{
				for (i = 0; i < entry.array_len; i++) {
					/* We don't do anything with these yet */
				}
			});
		/* Generic options */
		HANDLE_DICT_ITEM("mss", DBUS_TYPE_UINT32, 0,
			{ nm_ip4_config_set_mss (config, entry.uint32_value); });
		HANDLE_DICT_ITEM("mtu", DBUS_TYPE_UINT32, 0,
			{ nm_ip4_config_set_mtu (config, entry.uint32_value); });
		HANDLE_DICT_ITEM("tundev", DBUS_TYPE_STRING, 0,
			{ if (strlen (entry.str_value)) tundev = g_strdup (entry.str_value); });
		HANDLE_DICT_ITEM("dns_domain", DBUS_TYPE_STRING, 0,
			{ if (strlen (entry.str_value)) nm_ip4_config_add_domain (config, entry.str_value); });
		HANDLE_DICT_ITEM("login_banner", DBUS_TYPE_STRING, 0,
			{ if (strlen (entry.str_value)) login_banner = g_strdup (entry.str_value); });

	next:
		nmu_dbus_dict_entry_clear (&entry);
	};

#ifdef NM_DEBUG_VPN_CONFIG
	print_vpn_config (config, tundev, login_banner);
#endif

	if (!(parent_dev = nm_vpn_act_request_get_parent_dev (req)))
		goto out;

	if (nm_vpn_connection_set_config (vpn, tundev, parent_dev, config)) {
		nm_info ("VPN Activation (%s) Stage 4 of 4 (IP Config Get) complete.",
				nm_vpn_connection_get_name (vpn));
		if (login_banner && strlen (login_banner)) {
			nm_dbus_vpn_signal_vpn_login_banner (dbus_connection,
			                                     vpn,
			                                     login_banner);
		}
		success = TRUE;
		nm_vpn_service_activation_success (service, req);
	}

out:
	if (tundev) g_free (tundev);
	if (login_banner) g_free (login_banner);
	if (!success) {
		if (config)
			g_object_unref (config);
		nm_warning ("(VPN Service %s): did not receive valid IP config "
		            "information.",
		            service->service);
		nm_vpn_service_act_request_failed (service, req);
	}
}


static void
nm_vpn_service_stop_connection_internal (NMVPNService *service)
{
	DBusConnection *	dbus_connection;

	g_return_if_fail (service != NULL);

	dbus_connection = nm_dbus_manager_get_dbus_connection (service->dbus_mgr);
	if (dbus_connection) {
		DBusMessage *	message;
		char *			op;

		/* Construct a new method call with the correct service and object path */
		op = construct_op_from_service_name (service->service);
		message = dbus_message_new_method_call (service->service,
		                                        op,
		                                        service->service,
		                                        "stopConnection");
		g_free (op);
		if (!message) {
			nm_warning ("(VPN Service %s): couldn't allocate dbus message.",
			            service->service);
		} else {
			dbus_connection_send (dbus_connection, message, NULL);
			dbus_message_unref (message);
		}
	} else {
		/* If we have the PID of the VPN service daemon, send it a TERM */
		if (service->pid) {
			kill (service->pid, SIGTERM);
			service->pid = 0;
		} else {
			nm_warning ("(VPN Service %s): stop called, but did not have PID "
			            "for VPN service daemon.",
			            service->service);
		}
	}
}


void
nm_vpn_service_stop_connection (NMVPNService *service,
                                NMVPNActRequest *req)
{
	NMVPNConnection *vpn;

	g_return_if_fail (service != NULL);
	g_return_if_fail (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_service_cancel_callback (service, req);
	nm_vpn_act_request_set_state (req, NM_VPN_CONNECTION_STATE_DISCONNECTED);

	/* Ensure we can stop the connection in this state */
	if (   (service->state != NM_VPN_SERVICE_STATE_STARTED)
	    && (service->state != NM_VPN_SERVICE_STATE_STARTING)) {
		nm_warning ("(VPN Service %s): could not stop connection '%s' because "
		            " service was %d.", 
		            service->service,
					nm_vpn_connection_get_name (vpn),
					service->state);
		return;
	}

	nm_vpn_service_stop_connection_internal (service);
	nm_vpn_service_set_state (service, NM_VPN_SERVICE_STATE_STOPPED);
}


static void
nm_vpn_service_add_watch (NMVPNService *service)
{
	guint32 id;

	g_return_if_fail (service != NULL);

	if (service->watch_id)
		return;

	/* Add a dbus filter for this connection's service name so its signals
	 * get delivered to us.
	 */
	id = nm_dbus_manager_register_signal_handler (service->dbus_mgr,
	                                              service->service,
	                                              NULL,
	                                              nm_vpn_service_process_signal,
	                                              service);
	service->sig_handler_id = id;
	service->watch_id = g_signal_connect (service->dbus_mgr,
	                                      "name-owner-changed",
	                                      G_CALLBACK (nm_vpn_service_name_owner_changed),
	                                      service);
	service->dbus_con_watch_id = g_signal_connect (service->dbus_mgr,
	                                               "dbus-connection-changed",
	                                               G_CALLBACK (nm_vpn_service_dbus_connection_changed),
	                                               service);
}


static void
nm_vpn_service_remove_watch (NMVPNService *service)
{
	g_return_if_fail (service != NULL);

	if (!service->watch_id)
		return;

	nm_dbus_manager_remove_signal_handler (service->dbus_mgr, service->sig_handler_id);
	g_signal_handler_disconnect (service->dbus_mgr, service->watch_id);
	service->watch_id = 0;
	g_signal_handler_disconnect (service->dbus_mgr, service->dbus_con_watch_id);
	service->dbus_con_watch_id = 0;
}


static inline gboolean same_service_name (NMVPNService *service, NMVPNConnection *vpn)
{
	g_return_val_if_fail (service != NULL, FALSE);
	g_return_val_if_fail (vpn != NULL, FALSE);

	return (!strcmp (nm_vpn_service_get_service_name (service), nm_vpn_connection_get_service_name (vpn)));
}

static void
nm_vpn_service_dbus_connection_changed (NMDBusManager *mgr,
                                        DBusConnection *dbus_connection,
                                        gpointer user_data)
{
	NMVPNService *	service = (NMVPNService *) user_data;

	g_return_if_fail (service != NULL);

	if (!dbus_connection) {
		NMVPNActRequest *	req;
		NMVPNConnection *	vpn;
		gboolean			valid_vpn = FALSE;

		/* Kill the VPN service since we can't talk to it anymore anyway */
		nm_vpn_service_set_state (service, NM_VPN_SERVICE_STATE_SHUTDOWN);
		nm_vpn_service_remove_watch (service);

		req = nm_vpn_manager_get_vpn_act_request (service->manager);
		if (req && (vpn = nm_vpn_act_request_get_connection (req)))
			valid_vpn = same_service_name (service, vpn);

		if (valid_vpn) {
			nm_vpn_act_request_unref (req);
			nm_vpn_manager_schedule_vpn_connection_died (service->manager, req);
		}
	}
}

static void
nm_vpn_service_name_owner_changed (NMDBusManager *mgr,
                                   const char *name,
                                   const char *old,
                                   const char *new,
                                   gpointer user_data)
{
	NMVPNService *		service = (NMVPNService *) user_data;
	NMVPNActRequest *	req;
	NMVPNConnection *	vpn;
	gboolean			valid_vpn = FALSE;
	gboolean			old_owner_good = (old && strlen (old));
	gboolean			new_owner_good = (new && strlen (new));

	g_return_if_fail (service != NULL);

	if (strcmp (name, service->service) != 0)
		return;

	req = nm_vpn_manager_get_vpn_act_request (service->manager);
	if (req && (vpn = nm_vpn_act_request_get_connection (req)))
		valid_vpn = same_service_name (service, vpn);

	if (!old_owner_good && new_owner_good) {
		/* VPN service started. */
		nm_vpn_service_add_watch (service);
		nm_vpn_service_set_state (service, NM_VPN_SERVICE_STATE_INIT);
	} else if (old_owner_good && !new_owner_good) {
		/* VPN service went away. */
		nm_vpn_service_set_state (service, NM_VPN_SERVICE_STATE_SHUTDOWN);
		nm_vpn_service_remove_watch (service);

		if (valid_vpn) {
			nm_vpn_act_request_unref (req);
			nm_vpn_manager_schedule_vpn_connection_died (service->manager, req);
		}
	}
}


static gboolean
nm_vpn_service_process_signal (DBusConnection *connection,
                               DBusMessage *message,
                               gpointer user_data)
{
	NMVPNService *		service = (NMVPNService *) user_data;
	NMVPNConnection *	vpn = NULL;
	NMVPNActRequest *	req;
	gboolean			valid_vpn = FALSE;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);
	g_return_val_if_fail (service != NULL, FALSE);

	req = nm_vpn_manager_get_vpn_act_request (service->manager);
	if (req && (vpn = nm_vpn_act_request_get_connection (req)))
		valid_vpn = same_service_name (service, vpn);

	if (   dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED)
	    || dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_LAUNCH_FAILED)
	    || dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_CONNECT_FAILED)
	    || dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD)
	    || dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_IP_CONFIG_BAD))
	{
		const char *	member = dbus_message_get_member (message);
		char *		error_msg;

		if (valid_vpn) {
			if (!dbus_message_get_args (message,
			                            NULL,
			                            DBUS_TYPE_STRING, &error_msg,
			                            DBUS_TYPE_INVALID)) {
				error_msg = (char *) "";
			}
			nm_warning ("VPN failed for service '%s', signal '%s', with "
			            " message '%s'.",
			            service->service,
			            member,
			            error_msg);
			nm_dbus_vpn_signal_vpn_failed (connection, member, vpn, error_msg);

			/* Don't deal with VPN Connection stopping here, we'll do that
			 * when we get the STOPPED or STOPPING signal below.
			 */
		}
	} else if (dbus_message_is_signal (message, service->service,
	                                   NM_DBUS_VPN_SIGNAL_STATE_CHANGE)) {
		dbus_uint32_t old_state_int;
		dbus_uint32_t new_state_int;

		if (dbus_message_get_args (message,
		                           NULL,
		                           DBUS_TYPE_UINT32, &old_state_int,
		                           DBUS_TYPE_UINT32, &new_state_int,
		                           DBUS_TYPE_INVALID)) {
			NMVPNServiceState old_state = (NMVPNServiceState) old_state_int;
			NMVPNServiceState new_state = (NMVPNServiceState) new_state_int;

			nm_info ("VPN service '%s' signaled state change %d -> %d.",
			         service->service,
			         old_state,
			         new_state);
			nm_vpn_service_set_state (service, new_state);

			/* If the VPN daemon state is now stopped and it was starting, 
			 * clear the active connection.
			 */
			if (   (   (new_state == NM_VPN_SERVICE_STATE_STOPPED)
			        || (new_state == NM_VPN_SERVICE_STATE_SHUTDOWN)
			        || (new_state == NM_VPN_SERVICE_STATE_STOPPING))
			    && (   (old_state == NM_VPN_SERVICE_STATE_STARTED)
			        || (old_state == NM_VPN_SERVICE_STATE_STARTING))
				&& valid_vpn) {
				nm_vpn_act_request_unref (req);
				nm_vpn_manager_schedule_vpn_connection_died (service->manager, req);
			}
		}
	} else if (   valid_vpn
	           && dbus_message_is_signal (message, service->service,
	                                      NM_DBUS_VPN_SIGNAL_IP4_CONFIG)) {
		nm_vpn_service_stage4_ip4_config_get (service, req, message);
	}

	return TRUE;
}

#ifdef NM_DEBUG_VPN_CONFIG
/*
 *  Prints config returned from the service daemo
 */
static void print_vpn_config (NMIP4Config *config,
                              const char *tundev,
						const char *login_banner)
{
	struct in_addr	temp_addr;
	char *		dns_domain = NULL;
	guint32		num;
	guint32 		i;

	g_return_if_fail (config != NULL);

	temp_addr.s_addr = nm_ip4_config_get_gateway (config);
	nm_info ("VPN Gateway: %s", inet_ntoa (temp_addr));
	nm_info ("Tunnel Device: %s", tundev);
	temp_addr.s_addr = nm_ip4_config_get_address (config);
	nm_info ("Internal IP4 Address: %s", inet_ntoa (temp_addr));
	temp_addr.s_addr = nm_ip4_config_get_netmask (config);
	nm_info ("Internal IP4 Netmask: %s", inet_ntoa (temp_addr));
	temp_addr.s_addr = nm_ip4_config_get_ptp_address (config);
	nm_info ("Internal IP4 Point-to-Point Address: %s", inet_ntoa (temp_addr));
	nm_info ("Maximum Segment Size (MSS): %d", nm_ip4_config_get_mss (config));

	num = nm_ip4_config_get_num_nameservers (config);
	for (i = 1; i <= num; i++)
	{
		temp_addr.s_addr = nm_ip4_config_get_nameserver (config, i);
		nm_info ("Internal IP4 DNS: %s", inet_ntoa (temp_addr));
	}

	if (nm_ip4_config_get_num_domains (config) > 0)
		dns_domain = (char *) nm_ip4_config_get_domain (config, 1);
	nm_info ("DNS Domain: '%s'", dns_domain ? dns_domain : "(none)");
	nm_info ("Login Banner:");
	nm_info ("-----------------------------------------");
	nm_info ("%s", login_banner);
	nm_info ("-----------------------------------------");
}

#endif
