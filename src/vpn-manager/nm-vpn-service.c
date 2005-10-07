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
#include "NetworkManagerDbus.h"
#include "nm-dbus-vpn.h"
#include "nm-vpn-service.h"
#include "nm-vpn-act-request.h"
#include "nm-utils.h"

/* define this for getting VPN debug messages */
#undef NM_DEBUG_VPN_CONFIG

struct NMVPNService
{
	int				refcount;
	NMVPNManager *		manager;
	NMData *			app_data;
	gboolean			watch_active;

	char *			name;
	char *			service;
	char *			program;
	NMVPNState		state;
};


static void nm_vpn_service_add_watch (NMVPNService *service);
static void nm_vpn_service_remove_watch (NMVPNService *service);
static void nm_vpn_service_stop_connection_internal (NMVPNService *service);
#ifdef NM_DEBUG_VPN_CONFIG
static void print_vpn_config (guint32 ip4_vpn_gateway,
						const char *tundev,
						guint32 ip4_internal_address,
						gint32 ip4_internal_netmask,
						guint32 *ip4_internal_dns,
						guint32 ip4_internal_dns_len,
						guint32 *ip4_internal_nbns,
						guint32 ip4_internal_nbns_len,
						const char *dns_domain,
						const char *login_banner);
#endif

static void nm_vpn_service_schedule_stage1_daemon_exec (NMVPNService *service, NMVPNActRequest *req);
static void nm_vpn_service_schedule_stage3_connect (NMVPNService *service, NMVPNActRequest *req);
static void nm_vpn_service_schedule_stage2_daemon_wait (NMVPNService *service, NMVPNActRequest *req);
static void nm_vpn_service_schedule_stage4_ip_config_get_timeout (NMVPNService *service, NMVPNActRequest *req);
static void nm_vpn_service_cancel_callback (NMVPNService *service, NMVPNActRequest *req);


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
	service->state = NM_VPN_STATE_SHUTDOWN;
	service->app_data = app_data;
	service->manager = manager;

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
		g_free (service->name);
		g_free (service->service);
		g_free (service->program);
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
	if (!dbus_bus_name_has_owner (service->app_data->dbus_connection, service->service, NULL))
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


NMVPNState nm_vpn_service_get_state (NMVPNService *service)
{
	g_return_val_if_fail (service != NULL, NM_VPN_STATE_UNKNOWN);

	return service->state;
}


static void nm_vpn_service_set_state (NMVPNService *service, const NMVPNState state)
{
	g_return_if_fail (service != NULL);

	service->state = state;
}


DBusConnection *nm_vpn_service_get_dbus_connection (NMVPNService *service)
{
	g_return_val_if_fail (service != NULL, NULL);

	return service->app_data->dbus_connection;
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
static void nm_vpn_service_act_request_failed (NMVPNService *service,
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

	nm_vpn_act_request_set_stage (req, NM_VPN_ACT_STAGE_FAILED);
	nm_info ("VPN Activation (%s) failed.", nm_vpn_connection_get_name (vpn));

	nm_vpn_act_request_unref (req);
	nm_vpn_manager_schedule_vpn_activation_failed (service->manager, req);	
}


static void nm_vpn_service_activation_success (NMVPNService *service, NMVPNActRequest *req)
{
	NMVPNConnection *	vpn = NULL;

	g_assert (service != NULL);
	g_assert (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_service_cancel_callback (service, req);

	nm_vpn_act_request_set_stage (req, NM_VPN_ACT_STAGE_ACTIVATED);
	nm_info ("VPN Activation (%s) successful.", nm_vpn_connection_get_name (vpn));
}


/*
 * nm_vpn_service_start_connection
 *
 * Kick off the VPN connection process.
 *
 */
void nm_vpn_service_start_connection (NMVPNService *service, NMVPNActRequest *req)
{
	g_return_if_fail (service != NULL);
	g_return_if_fail (req != NULL);

	nm_vpn_act_request_set_stage (req, NM_VPN_ACT_STAGE_PREPARE);
	nm_vpn_service_add_watch (service);

	/* Start the daemon if it's not already running */
	nm_vpn_act_request_ref (req);
	if (!dbus_bus_name_has_owner (service->app_data->dbus_connection, service->service, NULL))
		nm_vpn_service_schedule_stage1_daemon_exec (service, req);
	else
		nm_vpn_service_schedule_stage3_connect (service, req);
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
	GPtrArray *		vpn_argv;
	GError *			error = NULL;
	GPid				pid;

	g_assert (req != NULL);

	service = nm_vpn_act_request_get_service (req);
	g_assert (service != NULL);
	g_assert (service->program != NULL);

	nm_vpn_act_request_set_callback_id (req, 0);

	vpn_argv = g_ptr_array_new ();
	g_ptr_array_add (vpn_argv, service->program);
	g_ptr_array_add (vpn_argv, NULL);

	if (!g_spawn_async (NULL, (char **) vpn_argv->pdata, NULL, 0, NULL, NULL, &pid, &error))
	{
		g_ptr_array_free (vpn_argv, TRUE);
		nm_warning ("nm_vpn_service_stage1_daemon_exec(%s): could not launch the VPN service.  error: '%s'.", service->service, error->message);
		g_error_free (error);
		nm_vpn_service_act_request_failed (service, req);
		goto out;
	}
	g_ptr_array_free (vpn_argv, TRUE);
	nm_info ("nm_vpn_service_stage1_daemon_exec(%s): execed the VPN service, PID is %d.", service->service, pid);

	nm_vpn_service_schedule_stage2_daemon_wait (service, req);

out:
	return FALSE;
}


static void nm_vpn_service_schedule_stage1_daemon_exec (NMVPNService *service, NMVPNActRequest *req)
{
	GSource *			source = NULL;
	NMVPNConnection *	vpn = NULL;
	guint			id;

	g_assert (service != NULL);
	g_assert (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_act_request_set_stage (req, NM_VPN_ACT_STAGE_PREPARE);
	nm_vpn_service_set_state (service, NM_VPN_STATE_SHUTDOWN);

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) nm_vpn_service_stage1_daemon_exec, req, NULL);
	id = g_source_attach (source, service->app_data->main_context);
	nm_vpn_act_request_set_callback_id (req, id);
	g_source_unref (source);
	nm_info ("VPN Activation (%s) Stage 1 (Connection Prepare) scheduled...", nm_vpn_connection_get_name (vpn));
}


/*
 * nm_vpn_service_stage2_daemon_wait
 *
 * Wait until the VPN daemon has become active.
 *
 */
static gboolean nm_vpn_service_stage2_daemon_wait (gpointer user_data)
{
	NMVPNActRequest *	req = (NMVPNActRequest *) user_data;
	NMVPNService *		service;

	g_assert (req != NULL);

	service = nm_vpn_act_request_get_service (req);
	g_assert (service != NULL);

	nm_vpn_act_request_set_callback_id (req, 0);

	if (service->state == NM_VPN_STATE_STOPPED)
		nm_vpn_service_schedule_stage3_connect (service, req);
	else if (nm_vpn_act_request_get_daemon_wait_count (req) >= 4)
	{
		/* We only wait 2s (4 * 500 milliseconds) for the service to start up */
		nm_vpn_service_act_request_failed (service, req);
	}
	else
		nm_vpn_service_schedule_stage2_daemon_wait (service, req);

	return FALSE;
}


static void nm_vpn_service_schedule_stage2_daemon_wait (NMVPNService *service, NMVPNActRequest *req)
{
	GSource *			source = NULL;
	NMVPNConnection *	vpn = NULL;
	guint			id;

	g_assert (service != NULL);
	g_assert (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_act_request_set_stage (req, NM_VPN_ACT_STAGE_PREPARE);

	nm_vpn_act_request_set_daemon_wait_count (req, nm_vpn_act_request_get_daemon_wait_count (req) + 1);

	source = g_timeout_source_new (500);
	g_source_set_callback (source, (GSourceFunc) nm_vpn_service_stage2_daemon_wait, req, NULL);
	id = g_source_attach (source, service->app_data->main_context);
	nm_vpn_act_request_set_callback_id (req, id);
	g_source_unref (source);
	nm_info ("VPN Activation (%s) Stage 2 (Connection Prepare Wait) scheduled...", nm_vpn_connection_get_name (vpn));
}


static void nm_vpn_service_stage3_connect_cb (DBusPendingCall *pcall, void *user_data)
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

	nm_info ("VPN Activation (%s) Stage 3 (Connect) reply received.", nm_vpn_connection_get_name (vpn));

	if (!(reply = dbus_pending_call_steal_reply (pcall)))
	{
		nm_warning ("nm_vpn_service_stage3_connect_cb(%s): could not obtain VPN service's reply.", service->service);
		nm_vpn_service_act_request_failed (service, req);
		goto out;
	}

	if (message_is_error (reply))
	{
		const char *member = dbus_message_get_member (reply);
		char *message;

		if (!dbus_message_get_args (reply, NULL, DBUS_TYPE_STRING, &message, NULL))
			message = (char *) "";

		nm_warning ("nm_vpn_service_stage3_connect_cb(%s): could not start the VPN '%s'.  dbus says: '%s'  '%s'.", 
					service->service, nm_vpn_connection_get_name (vpn), member, message);
		nm_vpn_service_act_request_failed (service, req);
	}
	else
	{
		nm_vpn_act_request_set_stage (req, NM_VPN_ACT_STAGE_IP_CONFIG_GET);
		nm_vpn_service_schedule_stage4_ip_config_get_timeout (service, req);
		nm_info ("VPN Activation (%s) Stage 4 (IP Config Get) reply expected soon...", nm_vpn_connection_get_name (vpn));
	}

	dbus_message_unref (reply);

out:
	dbus_pending_call_unref (pcall);
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
	DBusMessage *		message;
	DBusPendingCall *	pcall = NULL;

	g_assert (req != NULL);

	service = nm_vpn_act_request_get_service (req);
	g_assert (service != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn != NULL);

	nm_vpn_act_request_set_callback_id (req, 0);

	/* Send the start vpn request to the daemon */
	op = construct_op_from_service_name (service->service);
	message = dbus_message_new_method_call (service->service, op, service->service, "startConnection");
	g_free (op);
	if (!message)
	{
		nm_warning ("nm_vpn_service_stage3_connect(%s): couldn't allocate dbus message.", service->service);
		nm_vpn_service_act_request_failed (service, req);
		return FALSE;
	}

	name = nm_vpn_connection_get_name (vpn);
	user_name = nm_vpn_connection_get_user_name (vpn);
	password_items = (char **) nm_vpn_act_request_get_password_items (req, &password_count);
	data_items = (char **) nm_vpn_act_request_get_data_items (req, &data_count);
	dbus_message_append_args (message, DBUS_TYPE_STRING, &name,
				  DBUS_TYPE_STRING, &user_name,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &password_items, password_count,
				  DBUS_TYPE_ARRAY, DBUS_TYPE_STRING, &data_items, data_count,
				  DBUS_TYPE_INVALID);

	dbus_connection_send_with_reply (service->app_data->dbus_connection, message, &pcall, -1);
	if (pcall)
	{
		dbus_pending_call_set_notify (pcall, nm_vpn_service_stage3_connect_cb, req, NULL);
		nm_info ("VPN Activation (%s) Stage 3 (Connect) reply expected soon...", nm_vpn_connection_get_name (vpn));
	}
	else
		nm_vpn_service_act_request_failed (service, req);
	dbus_message_unref (message);

	return FALSE;
}


static void nm_vpn_service_schedule_stage3_connect (NMVPNService *service, NMVPNActRequest *req)
{
	GSource *			source = NULL;
	NMVPNConnection *	vpn = NULL;
	guint			id;

	g_assert (service != NULL);
	g_assert (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_act_request_set_stage (req, NM_VPN_ACT_STAGE_CONNECT);

	source = g_idle_source_new ();
	g_source_set_callback (source, (GSourceFunc) nm_vpn_service_stage3_connect, req, NULL);
	id = g_source_attach (source, service->app_data->main_context);
	nm_vpn_act_request_set_callback_id (req, id);
	g_source_unref (source);
	nm_info ("VPN Activation (%s) Stage 3 (Connect) scheduled...", nm_vpn_connection_get_name (vpn));
}


static gboolean nm_vpn_service_stage4_ip_config_get_timeout (gpointer *user_data)
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
	if (nm_vpn_act_request_get_stage (req) == NM_VPN_ACT_STAGE_IP_CONFIG_GET)
	{
		nm_info ("VPN Activation (%s) Stage 4 (IP Config Get) timeout exceeded.", nm_vpn_connection_get_name (vpn));
		nm_vpn_service_act_request_failed (service, req);
	}

	return FALSE;
}


static void nm_vpn_service_schedule_stage4_ip_config_get_timeout (NMVPNService *service, NMVPNActRequest *req)
{
	GSource *			source = NULL;
	NMVPNConnection *	vpn = NULL;
	guint			id;

	g_assert (service != NULL);
	g_assert (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_act_request_set_stage (req, NM_VPN_ACT_STAGE_IP_CONFIG_GET);

	/* 20 second timeout waiting for IP config signal from VPN service */
	source = g_timeout_source_new (20000);
	g_source_set_callback (source, (GSourceFunc) nm_vpn_service_stage4_ip_config_get_timeout, req, NULL);
	id = g_source_attach (source, service->app_data->main_context);
	nm_vpn_act_request_set_callback_id (req, id);
	g_source_unref (source);
	nm_info ("VPN Activation (%s) Stage 4 (IP Config Get) timeout scheduled...", nm_vpn_connection_get_name (vpn));
}


static void nm_vpn_service_cancel_callback (NMVPNService *service, NMVPNActRequest *req)
{
	guint	id;

	g_return_if_fail (service != NULL);
	g_return_if_fail (req != NULL);

	if ((id = nm_vpn_act_request_get_callback_id (req)) != 0)
	{
		g_source_destroy (g_main_context_find_source_by_id (service->app_data->main_context, id));
		nm_vpn_act_request_set_callback_id (req, 0);
	}
}


/*
 * nm_vpn_service_stage4_ip_config_get
 *
 * Configure a device with IPv4 config info in response the the VPN daemon.
 *
 */
static void nm_vpn_service_stage4_ip_config_get (NMVPNService *service, NMVPNActRequest *req, DBusMessage *message)
{
	NMVPNConnection *	vpn;
	guint32			ip4_vpn_gateway;
	char *			tundev;
	guint32			ip4_internal_address;
	guint32			ip4_internal_netmask;
	guint32 *			ip4_internal_dns;
	guint32			ip4_internal_dns_len;
	guint32 *			ip4_internal_nbns;
	guint32			ip4_internal_nbns_len;
	char *			dns_domain;
	char *			login_banner;
	gboolean			success = FALSE;

	g_return_if_fail (service != NULL);
	g_return_if_fail (message != NULL);
	g_return_if_fail (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_info ("VPN Activation (%s) Stage 4 (IP Config Get) reply received.", nm_vpn_connection_get_name (vpn));

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
		NMDevice *	parent_dev;
		guint32		i;

#ifdef NM_DEBUG_VPN_CONFIG
		print_vpn_config (ip4_vpn_gateway, tundev, ip4_internal_address, ip4_internal_netmask,
						ip4_internal_dns, ip4_internal_dns_len, ip4_internal_nbns, ip4_internal_nbns_len,
						dns_domain, login_banner);
#endif

		config = nm_ip4_config_new ();

		nm_ip4_config_set_secondary (config, TRUE);

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

		parent_dev = nm_vpn_act_request_get_parent_dev (req);
		g_assert (parent_dev);

		if (nm_vpn_connection_set_config (vpn, tundev, parent_dev, config))
		{
			if (login_banner && strlen (login_banner))
				nm_dbus_vpn_signal_vpn_login_banner (service->app_data->dbus_connection, vpn, login_banner);
			success = TRUE;
		}
	}

	if (!success)
	{
		nm_warning ("nm_vpn_service_stage4_ip_config_get(%s): did not receive valid IP config information.", service->service);
		nm_vpn_service_act_request_failed (service, req);
	}
	else
		nm_vpn_service_activation_success (service, req);
}


static void nm_vpn_service_stop_connection_internal (NMVPNService *service)
{
	DBusMessage *		message;
	char *			op;

	g_return_if_fail (service != NULL);

	/* Construct a new method call with the correct service and object path */
	op = construct_op_from_service_name (service->service);
	if ((message = dbus_message_new_method_call (service->service, op, service->service, "stopConnection")))
	{
		dbus_connection_send (service->app_data->dbus_connection, message, NULL);
		dbus_message_unref (message);
	}
	else
		nm_warning ("nm_vpn_service_stop_connection(): error, couldn't allocate dbus message.");

	g_free (op);
}


void nm_vpn_service_stop_connection (NMVPNService *service, NMVPNActRequest *req)
{
	NMVPNConnection *vpn;

	g_return_if_fail (service != NULL);
	g_return_if_fail (req != NULL);

	vpn = nm_vpn_act_request_get_connection (req);
	g_assert (vpn);

	nm_vpn_service_cancel_callback (service, req);
	nm_vpn_act_request_set_stage (req, NM_VPN_ACT_STAGE_DISCONNECTED);

	/* Ensure we can stop the connection in this state */
	if ((service->state != NM_VPN_STATE_STARTED) && (service->state != NM_VPN_STATE_STARTING))
	{
		nm_info ("nm_vpn_service_start_connection(%s): could not stop connection '%s' because service was not STARTED.", 
					service->service, nm_vpn_connection_get_name (vpn));
		return;
	}

	nm_vpn_service_stop_connection_internal (service);
	nm_vpn_service_set_state (service, NM_VPN_STATE_STOPPED);
}


static void nm_vpn_service_add_watch (NMVPNService *service)
{
	char *	match_string = NULL;

	g_return_if_fail (service != NULL);

	if (service->watch_active)
		return;

	/* Add a dbus filter for this connection's service name so its signals
	 * get delivered to us.
	 */
	match_string = g_strdup_printf ("type='signal',"
							  "interface='%s',"
							  "sender='%s'", service->service, service->service);
	dbus_bus_add_match (service->app_data->dbus_connection, match_string, NULL);
	g_free (match_string);
	service->watch_active = TRUE;
}


static void nm_vpn_service_remove_watch (NMVPNService *service)
{
	char *	match_string = NULL;

	g_return_if_fail (service != NULL);

	if (!service->watch_active)
		return;

	match_string = g_strdup_printf ("type='signal',"
							  "interface='%s',"
							  "sender='%s'", service->service, service->service);
	dbus_bus_remove_match (service->app_data->dbus_connection, match_string, NULL);
	g_free (match_string);
	service->watch_active = FALSE;
}


static inline gboolean same_service_name (NMVPNService *service, NMVPNConnection *vpn)
{
	g_return_val_if_fail (service != NULL, FALSE);
	g_return_val_if_fail (vpn != NULL, FALSE);

	return (!strcmp (nm_vpn_service_get_service_name (service), nm_vpn_connection_get_service_name (vpn)));
}


gboolean nm_vpn_service_name_owner_changed (NMVPNService *service, NMVPNActRequest *req, const char *old, const char *new)
{
	NMVPNConnection *	vpn;
	gboolean			valid_vpn = FALSE;
	gboolean			old_owner_good = (old && strlen (old));
	gboolean			new_owner_good = (new && strlen (new));

	g_return_val_if_fail (service != NULL, FALSE);

	if (req && (vpn = nm_vpn_act_request_get_connection (req)))
		valid_vpn = same_service_name (service, vpn);

	if (!old_owner_good && new_owner_good)
	{
		/* VPN service started. */
		nm_vpn_service_add_watch (service);
		nm_vpn_service_set_state (service, NM_VPN_STATE_INIT);
	}
	else if (old_owner_good && !new_owner_good)
	{
		/* VPN service went away. */
		nm_vpn_service_set_state (service, NM_VPN_STATE_SHUTDOWN);
		nm_vpn_service_remove_watch (service);

		if (valid_vpn)
		{
			nm_vpn_act_request_unref (req);
			nm_vpn_manager_schedule_vpn_connection_died (service->manager, req);
		}
	}

	return TRUE;
}


gboolean nm_vpn_service_process_signal (NMVPNService *service, NMVPNActRequest *req, DBusMessage *message)
{
	NMVPNConnection *	vpn = NULL;
	gboolean			valid_vpn = FALSE;

	g_return_val_if_fail (service != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	if (req && (vpn = nm_vpn_act_request_get_connection (req)))
		valid_vpn = same_service_name (service, vpn);

	if (    dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED)
		|| dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_LAUNCH_FAILED)
		|| dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_CONNECT_FAILED)
		|| dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD)
		|| dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_IP_CONFIG_BAD))
	{
		const char *	member = dbus_message_get_member (message);
		char *		error_msg;

		if (valid_vpn)
		{
			if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &error_msg, DBUS_TYPE_INVALID))
				error_msg = (char *) "";
			nm_warning ("VPN failed for service '%s', signal '%s', with message '%s'.", service->service, member, error_msg);
			nm_dbus_vpn_signal_vpn_failed (service->app_data->dbus_connection, member, vpn, error_msg);
			/* Don't deal with VPN Connection stopping here, we'll do that when we get the STOPPED or STOPPING signal below */
		}
	}
	else if (dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_STATE_CHANGE))
	{
		dbus_uint32_t old_state_int;
		dbus_uint32_t new_state_int;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_UINT32, &old_state_int, DBUS_TYPE_UINT32, &new_state_int, DBUS_TYPE_INVALID))
		{
			NMVPNState	old_state = (NMVPNState) old_state_int;
			NMVPNState	new_state = (NMVPNState) new_state_int;

			nm_info ("VPN service '%s' signaled new state %d, old state %d.", service->service, new_state, old_state);
			nm_vpn_service_set_state (service, new_state);

			/* If the VPN daemon state is now stopped and it was starting, clear the active connection */
			if (((new_state == NM_VPN_STATE_STOPPED) || (new_state == NM_VPN_STATE_SHUTDOWN) || (new_state == NM_VPN_STATE_STOPPING))
				&& ((old_state == NM_VPN_STATE_STARTED) || (old_state == NM_VPN_STATE_STARTING))
				&& valid_vpn)
			{
				nm_vpn_act_request_unref (req);
				nm_vpn_manager_schedule_vpn_connection_died (service->manager, req);
			}
		}
	}
	else if (valid_vpn && dbus_message_is_signal (message, service->service, NM_DBUS_VPN_SIGNAL_IP4_CONFIG))
		nm_vpn_service_stage4_ip_config_get (service, req, message);

	return TRUE;
}

#ifdef NM_DEBUG_VPN_CONFIG
/*
 *  Prints config returned from the service daemo
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

#endif
