/* nm-dhcp-manager.c - Handle the DHCP daemon for NetworkManager
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
#include <dbus/dbus.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nm-dhcp-manager.h"
#include "nm-device.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerSystem.h"
#include "nm-activation-request.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"


#define NM_DHCP_TIMEOUT		45	/* DHCP timeout, in seconds */

static gboolean nm_dhcp_manager_process_signal (DBusConnection *connection,
                                                DBusMessage *message,
                                                gpointer user_data);

static void nm_dhcp_manager_name_owner_changed (NMDBusManager *dbus_mgr,
                                                DBusConnection *connection,
                                                const char *name,
                                                const char *old,
                                                const char *new,
                                                gpointer user_data);

static void nm_dhcp_manager_dbus_connection_changed (NMDBusManager *dbus_mgr,
                                                     DBusConnection *dbus_connection,
                                                     gpointer user_data);

struct NMDHCPManager {
	NMData *	data;
	GMainContext *	main_ctx;
	gboolean	running;
	size_t		dhcp_sn_len;
	NMDBusManager *	dbus_mgr;
	guint32     sig_handler_id;
};


static gboolean state_is_bound (guint8 state)
{
	if (   (state == DHCDBD_BOUND)
	    || (state == DHCDBD_RENEW)
	    || (state == DHCDBD_REBOOT)
	    || (state == DHCDBD_REBIND))
		return TRUE;

	return FALSE;
}


static gboolean state_is_down (guint8 state)
{
	if (   (state == DHCDBD_NBI)
	    || (state == DHCDBD_RELEASE)
	    || (state == DHCDBD_ABEND)
	    || (state == DHCDBD_END))
		return TRUE;

	return FALSE;
}


NMDHCPManager *
nm_dhcp_manager_new (NMData *data,
                     GMainContext *main_ctx)
{
	NMDHCPManager *	manager;
	guint32         id;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (main_ctx != NULL, NULL);

	manager = g_slice_new0 (NMDHCPManager);
	manager->data = data;
	manager->main_ctx = main_ctx;
	manager->dbus_mgr = nm_dbus_manager_get (NULL);
	manager->running = nm_dbus_manager_name_has_owner (manager->dbus_mgr,
	                                                   DHCP_SERVICE_NAME);
	manager->dhcp_sn_len = strlen (DHCP_SERVICE_NAME);

	id = nm_dbus_manager_register_signal_handler (manager->dbus_mgr,
	                                              DHCP_SERVICE_NAME ".state",
	                                              DHCP_SERVICE_NAME,
	                                              nm_dhcp_manager_process_signal,
	                                              manager);
	manager->sig_handler_id = id;
	g_signal_connect (G_OBJECT (manager->dbus_mgr),
	                  "name-owner-changed",
	                  G_CALLBACK (nm_dhcp_manager_name_owner_changed),
	                  manager);
	g_signal_connect (G_OBJECT (manager->dbus_mgr),
	                  "dbus-connection-changed",
	                  G_CALLBACK (nm_dhcp_manager_dbus_connection_changed),
	                  manager);

	return manager;
}


void nm_dhcp_manager_dispose (NMDHCPManager *manager)
{
	g_return_if_fail (manager != NULL);

	nm_dbus_manager_remove_signal_handler (manager->dbus_mgr,
	                                       manager->sig_handler_id);

	g_object_unref (manager->dbus_mgr);
	memset (manager, 0, sizeof (NMDHCPManager));
	g_slice_free (NMDHCPManager, manager);
}


guint32
nm_dhcp_manager_get_state_for_device (NMDHCPManager *manager,
                                      NMDevice *dev)
{
	DBusMessage *	message;
	DBusMessage *	reply;
	char *		path;
	guint32		state = 0;
	DBusError		error;
	DBusConnection *dbus_connection;

	g_return_val_if_fail (manager != NULL, 0);
	g_return_val_if_fail (dev != NULL, 0);

	if (!manager->running) {
		nm_warning ("dhcdbd not running!");
		return 0;
	}

	dbus_connection = nm_dbus_manager_get_dbus_connection (manager->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get dbus connection.");
		goto out;
	}

	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", nm_device_get_iface (dev));
	message = dbus_message_new_method_call (DHCP_SERVICE_NAME,
	                                        path,
	                                        DHCP_SERVICE_NAME ".dbus.get",
	                                        "reason");
	g_free (path);
	if (message == NULL) {
		nm_warning ("couldn't allocate the dbus message.");
		goto out;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (dbus_connection,
	                                                   message,
	                                                   -1,
	                                                   &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error)) {
		if (strcmp (error.name, "org.freedesktop.DBus.Error.UnknownMethod") != 0) {
			nm_info ("Error from dhcdbd on 'reason' request because: name '%s',"
			         " message '%s'.",
			         error.name,
			         error.message);
		}
		dbus_error_free (&error);
	}

	if (reply) {
		if (!dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID))
			state = 0;
		dbus_message_unref (reply);
	}

out:
	return state;
}


/*
 * nm_dhcp_manager_handle_timeout
 *
 * Called after timeout of a DHCP transaction to notify device of the failure.
 *
 */
static gboolean
nm_dhcp_manager_handle_timeout (NMActRequest *req)
{
	NMData *		data;
	NMDevice *	dev;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	nm_info ("Device '%s' DHCP transaction took too long (>%ds), stopping"
	         " it.",
	         nm_device_get_iface (dev),
	         NM_DHCP_TIMEOUT);

	if (nm_act_request_get_stage (req) == NM_ACT_STAGE_IP_CONFIG_START) {
		nm_act_request_set_dhcp_timeout (req, 0);
		nm_dhcp_manager_cancel_transaction (data->dhcp_manager, req);
		nm_device_activate_schedule_stage4_ip_config_timeout (req);
	}

	return FALSE;
}


gboolean
nm_dhcp_manager_begin_transaction (NMDHCPManager *manager,
                                   NMActRequest *req)
{
	DBusError		error;
	DBusMessage *		message;
	DBusMessage *		reply;
	NMDevice *		dev;
	char *			path;
	const guint32		opt1 = 31;  /* turns off ALL actions and dhclient-script just writes options to dhcdbd */
	const guint32		opt2 = 2;   /* dhclient is run in ONE SHOT mode and releases existing leases when brought down */
	GSource *		source;
	DBusConnection *	dbus_connection;
	gboolean		success = FALSE;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (req != NULL, FALSE);

	if (!manager->running) {
		nm_warning ("dhcdbd not running!");
		return FALSE;
	}

	dbus_connection = nm_dbus_manager_get_dbus_connection (manager->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get dbus connection.");
		goto out;
	}

	/* Cancel any DHCP transaction already in progress */
	nm_dhcp_manager_cancel_transaction (manager, req);
	/* FIXME don't sleep */
	sleep (1);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	nm_info ("Activation (%s) Beginning DHCP transaction.",
	         nm_device_get_iface (dev));

	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", nm_device_get_iface (dev));
	message = dbus_message_new_method_call (DHCP_SERVICE_NAME,
	                                        path,
	                                        DHCP_SERVICE_NAME,
	                                        "up");
	g_free (path);
	if (message == NULL) {
		nm_warning ("couldn't allocate dbus message");
		goto out;
	}

	dbus_message_append_args (message,
	                          DBUS_TYPE_UINT32, &opt1,
	                          DBUS_TYPE_UINT32, &opt2,
	                          DBUS_TYPE_INVALID);

	dbus_error_init (&error);
	if ((reply = dbus_connection_send_with_reply_and_block (dbus_connection, message, -1, &error)))
		dbus_message_unref (reply);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error)) {
		nm_info ("Couldn't send DHCP 'up' message because: name '%s', "
		         "message '%s'.",
		         error.name,
		         error.message);
		dbus_error_free (&error);
		goto out;
	}

	/* Set up a timeout on the transaction to kill it after NM_DHCP_TIMEOUT seconds */
	source = g_timeout_source_new (NM_DHCP_TIMEOUT * 1000);
	g_source_set_callback (source,
	                       (GSourceFunc) nm_dhcp_manager_handle_timeout,
	                       req,
	                       NULL);
	nm_act_request_set_dhcp_timeout (req, g_source_attach (source, manager->main_ctx));
	g_source_unref (source);
	success = TRUE;

out:
	return TRUE;
}


static void
remove_timeout (NMDHCPManager *manager, NMActRequest *req)
{
	guint id;

	g_return_if_fail (manager != NULL);
	g_return_if_fail (req != NULL);

	/* Remove any pending timeouts on the request */
	if ((id = nm_act_request_get_dhcp_timeout (req)) > 0) {
		GSource * source = g_main_context_find_source_by_id (manager->main_ctx, id);
		nm_act_request_set_dhcp_timeout (req, 0);
		g_source_destroy (source);
	}
}

/*
 * nm_dhcp_manager_cancel_transaction
 *
 * Stop any in-progress DHCP transaction on a particular device.
 *
 */
void
nm_dhcp_manager_cancel_transaction (NMDHCPManager *manager,
                                    NMActRequest *req)
{
	NMDevice *dev;
	DBusMessage *message = NULL;
	char *path;
	DBusConnection *dbus_connection;

	g_return_if_fail (manager != NULL);
	g_return_if_fail (req != NULL);

	if (!manager->running || state_is_down (nm_act_request_get_dhcp_state (req)))
		return;

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	dbus_connection = nm_dbus_manager_get_dbus_connection (manager->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get dbus connection.");
		goto out;
	}

	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", nm_device_get_iface (dev));
	message = dbus_message_new_method_call (DHCP_SERVICE_NAME,
	                                        path,
	                                        DHCP_SERVICE_NAME,
	                                        "down");
	g_free (path);
	if (!message) {
		nm_warning ("could not allocate dbus message.");
		goto out;
	}

	dbus_connection_send (dbus_connection, message, NULL);
	dbus_message_unref (message);

	/* Give dhcdbd/dhclient some time to send out a RELEASE if they like */
	/* FIXME: we should really monitor the interface's DHCP state by waiting
	 * for dhcdbd to tell us the device is "down" rather than sleeping here.
	 */
	if (!manager->data->asleep)
		sleep (1);

	remove_timeout (manager, req);

out:
	return;
}


static gboolean
get_ip4_uint32s (DBusConnection *dbus_connection,
                 const char *path,
                 const char *item,
                 guint32 **ip4_uint32,
                 guint32 *num_items,
                 gboolean ignore_error)
{
	DBusMessage *	message = NULL;
	DBusMessage *	reply = NULL;
	gboolean	success = FALSE;
	DBusError	error;
	GArray *	buffer;
	DBusMessageIter	iter;

	g_return_val_if_fail (dbus_connection != NULL, FALSE);
	g_return_val_if_fail (path != NULL, FALSE);
	g_return_val_if_fail (ip4_uint32 != NULL, FALSE);
	g_return_val_if_fail (num_items != NULL, FALSE);

	*ip4_uint32 = NULL;
	*num_items = 0;
	message = dbus_message_new_method_call (DHCP_SERVICE_NAME,
	                                        path,
	                                        DHCP_SERVICE_NAME".dbus.get",
	                                        item);
	if (!message) {
		nm_warning ("could not allocate dbus message.");
		goto out;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (dbus_connection,
	                                                   message,
	                                                   -1,
	                                                   &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error)) {
		if (!ignore_error) {
			nm_warning ("error calling '%s', DHCP daemon returned "
			            "error '%s', message '%s'.",
			            item,
			            error.name,
			            error.message);
		}
		dbus_error_free (&error);
		goto out;
	}

	if (!reply) {
		nm_warning ("error calling '%s', DHCP daemon did not respond.",
		            item);
		goto out;
	}

	dbus_message_iter_init (reply, &iter);

	buffer = g_array_new (TRUE, TRUE, sizeof (guint32));
	while (dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_UINT32) {
		guint32 uint32_value;
	
		dbus_message_iter_get_basic (&iter, &uint32_value);
		g_array_append_val (buffer, uint32_value);
		dbus_message_iter_next (&iter);
		success = TRUE;
	}

	if (success) {
		*ip4_uint32 = (guint32 *)(buffer->data);
		*num_items = buffer->len;
	}
	g_array_free (buffer, FALSE);
	dbus_message_unref (reply);

out:
	return success;
}


static gboolean
get_ip4_string (DBusConnection *dbus_connection,
                const char *path,
                const char *item,
                char **string,
                gboolean ignore_error)
{
	DBusMessage *	message = NULL;
	DBusMessage *	reply = NULL;
	gboolean	success = FALSE;
	DBusError	error;
	DBusMessageIter	iter;

	g_return_val_if_fail (dbus_connection != NULL, FALSE);
	g_return_val_if_fail (path != NULL, FALSE);
	g_return_val_if_fail (string != NULL, FALSE);

	*string = NULL;
	message = dbus_message_new_method_call (DHCP_SERVICE_NAME,
	                                        path,
	                                        DHCP_SERVICE_NAME".dbus.get",
	                                        item);
	if (!message) {
		nm_warning ("could not allocate dbus message.");
		goto out;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (dbus_connection,
	                                                   message,
	                                                   -1,
	                                                   &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error)) {
		if (!ignore_error) {
			nm_warning ("error calling '%s', DHCP daemon returned "
			            "error '%s', message '%s'.",
			            item,
			            error.name,
			            error.message);
		}
		dbus_error_free (&error);
		*string = NULL;
		goto out;
	}

	if (!reply) {
		nm_warning ("error calling '%s', DHCP daemon did not respond.",
		            item);
		goto out;
	}

	dbus_message_iter_init (reply, &iter);
	if (dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_STRING) {
		char *dbus_string;

		dbus_error_init (&error);
		if (dbus_message_get_args (reply,
		                           &error,
		                           DBUS_TYPE_STRING, &dbus_string,
		                           DBUS_TYPE_INVALID)) {
			*string = g_strdup (dbus_string);
			success = TRUE;
		}
	} else if (dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_ARRAY) {
		char *byte_array = NULL;
		int   len = 0;

		dbus_error_init (&error);
		if (dbus_message_get_args (reply,
		                           &error,
		                           DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE, &byte_array, &len,
		                           DBUS_TYPE_INVALID)) {
			byte_array[len] = '\0';
			*string = g_strdup (byte_array);
			success = TRUE;
		}
	}

out:
	return success;
}


static gboolean
nm_completion_dhcp_bound_test (int tries,
                               nm_completion_args args)
{
	NMActRequest *	req = args[0];
	NMDevice *	dev = args[1];

	if (state_is_bound (nm_act_request_get_dhcp_state (req)))
		return TRUE;
	if (nm_device_activation_should_cancel (dev))
		return TRUE;
	return FALSE;
}

/*
 * nm_dhcp_manager_get_ip4_config
 *
 * Get IP4 configuration values from the DHCP daemon
 *
 */
NMIP4Config *
nm_dhcp_manager_get_ip4_config (NMDHCPManager *manager,
                                NMActRequest *req)
{
	NMDevice *		dev;
	NMIP4Config *		ip4_config = NULL;
	int			i;
	guint32			count = 0;
	guint32 *		ip4_address = NULL;
	guint32 *		ip4_netmask = NULL;
	guint32 *		ip4_broadcast = NULL;
	guint32 *		ip4_nameservers = NULL;
	guint32 *		ip4_gateway = NULL;
	guint32			num_ip4_nameservers = 0;
	guint32			num_ip4_nis_servers = 0;
	char *			hostname = NULL;
	char *			domain_names = NULL;
	char *			nis_domain = NULL;
	guint32 *		ip4_nis_servers = NULL;
	struct in_addr		temp_addr;
	nm_completion_args	args;
	DBusConnection *	dbus_connection;
	char *			path = NULL;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (req != NULL, NULL);

	if (!manager->running)
		return NULL;

	dbus_connection = nm_dbus_manager_get_dbus_connection (manager->dbus_mgr);
	if (!dbus_connection) {
		nm_warning ("could not get dbus connection.");
		return NULL;
	}

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	args[0] = req;
	args[1] = dev;
	nm_wait_for_completion (30, G_USEC_PER_SEC / 10,
			nm_completion_dhcp_bound_test, NULL, args);
	if (nm_device_activation_should_cancel (dev))
		return NULL;

	if (!state_is_bound (nm_act_request_get_dhcp_state (req))) {
		nm_warning ("Tried to get IP4 Config for a device when dhcdbd "
		            "wasn't in a BOUND state!");
		return NULL;
	}

	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", nm_device_get_iface (dev));
	if (!path) {
		nm_warning ("could not allocate device path.");
		goto out;
	}

	if (!get_ip4_uint32s (dbus_connection, path, "ip_address", &ip4_address, &count, FALSE) || !count)
		goto out;

	if (!get_ip4_uint32s (dbus_connection, path, "subnet_mask", &ip4_netmask, &count, FALSE) || !count)
		goto out;

	if (!get_ip4_uint32s (dbus_connection, path, "broadcast_address", &ip4_broadcast, &count, FALSE) || !count)
		goto out;

	if (!get_ip4_uint32s (dbus_connection, path, "routers", &ip4_gateway, &count, TRUE) || !count) {
		/* If DHCP doesn't have a 'routers', just use the DHCP server's address as our gateway for now */
		if (!get_ip4_uint32s (dbus_connection, path, "dhcp_server_identifier", &ip4_gateway, &count, FALSE) || !count)
			goto out;
	}

	get_ip4_string (dbus_connection, path, "host_name", &hostname, TRUE);
	get_ip4_uint32s (dbus_connection, path, "domain_name_servers", &ip4_nameservers, &num_ip4_nameservers, FALSE);
	get_ip4_string (dbus_connection, path, "domain_name", &domain_names, TRUE);
	get_ip4_string (dbus_connection, path, "nis_domain", &nis_domain, TRUE);
	get_ip4_uint32s (dbus_connection, path, "nis_servers", &ip4_nis_servers, &num_ip4_nis_servers, TRUE);

	nm_info ("Retrieved the following IP4 configuration from the DHCP daemon:");

	ip4_config = nm_ip4_config_new ();
	nm_ip4_config_set_address (ip4_config, ip4_address[0]);
	temp_addr.s_addr = ip4_address[0];
	nm_info ("  address %s", inet_ntoa (temp_addr));

	nm_ip4_config_set_netmask (ip4_config, ip4_netmask[0]);
	temp_addr.s_addr = ip4_netmask[0];
	nm_info ("  netmask %s", inet_ntoa (temp_addr));

	nm_ip4_config_set_broadcast (ip4_config, ip4_broadcast[0]);
	temp_addr.s_addr = ip4_broadcast[0];
	nm_info ("  broadcast %s", inet_ntoa (temp_addr));

	nm_ip4_config_set_gateway (ip4_config, ip4_gateway[0]);
	temp_addr.s_addr = ip4_gateway[0];
	nm_info ("  gateway %s", inet_ntoa (temp_addr));

	for (i = 0; i < num_ip4_nameservers; i++) {
		nm_ip4_config_add_nameserver (ip4_config, ip4_nameservers[i]);
		temp_addr.s_addr = ip4_nameservers[i];
		nm_info ("  nameserver %s", inet_ntoa (temp_addr));
	}

	if (hostname) {
		nm_ip4_config_set_hostname (ip4_config, hostname);
		nm_info ("  hostname '%s'", hostname);
	}

	if (domain_names) {
		char **searches = g_strsplit (domain_names, " ", 0);
		char **s;

		for (s = searches; *s; s++) {
			nm_info ("  domain name '%s'", *s);
			nm_ip4_config_add_domain (ip4_config, *s);
		}
		g_strfreev (searches);
	}

	if (nis_domain) {
		nm_ip4_config_set_nis_domain (ip4_config, nis_domain);
		nm_info ("  nis domain '%s'", nis_domain);
	}

	for (i = 0; i < num_ip4_nis_servers; i++) {
		nm_ip4_config_add_nis_server (ip4_config, ip4_nis_servers[i]);
		temp_addr.s_addr = ip4_nis_servers[i];
		nm_info ("  nis server %s", inet_ntoa (temp_addr));
	}

	/*
	 * Grab the MTU from the backend.  If DHCP servers can send recommended
	 * MTU's, should set that here if the backend returns zero.
	 */
	nm_ip4_config_set_mtu (ip4_config, nm_system_get_mtu (dev));

out:
	g_free (path);
	return ip4_config;
}

static inline const char * state_to_string (guint8 state)
{
	switch (state)
	{
		case DHCDBD_PREINIT:
			return "starting";
		case DHCDBD_BOUND:
			return "bound";
		case DHCDBD_RENEW:
			return "renew";
		case DHCDBD_REBOOT:
			return "reboot";
		case DHCDBD_REBIND:
			return "rebind";
		case DHCDBD_TIMEOUT:
			return "timeout";
		case DHCDBD_FAIL:
			return "fail";
		case DHCDBD_START:
			return "successfully started";
		case DHCDBD_ABEND:
			return "abnormal exit";
		case DHCDBD_END:
			return "normal exit";
		default:
			break;
	}
	return NULL;
}


/*
 * nm_dhcp_manager_process_signal
 *
 * Possibly process a signal from the bus, if it comes from the currently
 * active DHCP daemon, if any.  Return TRUE if processed, FALSE if not.
 *
 */
static gboolean
nm_dhcp_manager_process_signal (DBusConnection *connection,
                                DBusMessage *message,
                                gpointer user_data)
{
	NMDHCPManager *	manager = (NMDHCPManager *) user_data;
	const char *		object_path;
	const char *		member;
	const char *		interface;
	gboolean			handled = FALSE;
	NMDevice *		dev;
	NMActRequest *		req = NULL;
	const char *		iface = NULL;
	guint8			state;
	const char *		desc;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	if (!(object_path = dbus_message_get_path (message)))
		return FALSE;
	if (!(member = dbus_message_get_member (message)))
		return FALSE;
	if (!(interface = dbus_message_get_interface (message)))
		return FALSE;

	/* Ignore non-DHCP related messages */
	if (strncmp (interface, DHCP_SERVICE_NAME, manager->dhcp_sn_len))
		return FALSE;

#if 0
	{
		const char *signature = dbus_message_get_signature (message);
		nm_info ("nm_dhcp_manager_process_signal(): got signal op='%s' member='%s' interface='%s' sig='%s'", object_path, member, interface, signature);
	}
#endif

	if (!(dev = nm_get_device_by_iface (manager->data, member)))
		return FALSE;

	if (!(req = nm_device_get_act_request (dev)))
		return FALSE;

	iface = nm_device_get_iface (dev);
	g_assert (iface != NULL);

	if (!dbus_message_is_signal (message, DHCP_SERVICE_NAME".state", iface))
		return FALSE;

	handled = TRUE;
	if (!dbus_message_get_args (message, NULL, DBUS_TYPE_BYTE, &state, DBUS_TYPE_INVALID))
		goto out;

	desc = state_to_string (state);
	nm_info ("DHCP daemon state is now %d (%s) for interface %s",
			state, desc ? desc : "unknown", iface);

	switch (state)
	{
		case DHCDBD_BOUND:		/* lease obtained */
		case DHCDBD_RENEW:		/* lease renewed */
		case DHCDBD_REBOOT:		/* have valid lease, but now obtained a different one */
		case DHCDBD_REBIND:		/* new, different lease */
			if (nm_act_request_get_stage (req) == NM_ACT_STAGE_IP_CONFIG_START)
			{
				nm_device_activate_schedule_stage4_ip_config_get (req);
				remove_timeout (manager, req);
			}
			break;

		case DHCDBD_TIMEOUT:		/* timed out contacting DHCP server */
			if (nm_act_request_get_stage (req) == NM_ACT_STAGE_IP_CONFIG_START)
			{
				nm_device_activate_schedule_stage4_ip_config_timeout (req);
				remove_timeout (manager, req);
			}
			break;					

		case DHCDBD_FAIL:		/* all attempts to contact server timed out, sleeping */
		case DHCDBD_ABEND:		/* dhclient exited abnormally */
		case DHCDBD_END:		/* dhclient exited normally */
			if (nm_act_request_get_stage (req) == NM_ACT_STAGE_IP_CONFIG_START)
			{
				nm_policy_schedule_activation_failed (req);
				remove_timeout (manager, req);
			}
			break;

		default:
			break;
	}
	nm_act_request_set_dhcp_state (req, state);

out:
	return handled;
}


/*
 * nm_dhcp_manager_process_name_owner_changed
 *
 * Respond to "service created"/"service deleted" signals from dbus for the active DHCP daemon.
 *
 */
static void
nm_dhcp_manager_name_owner_changed (NMDBusManager *dbus_mgr,
                                    DBusConnection *connection,
                                    const char *name,
                                    const char *old,
                                    const char *new,
                                    gpointer user_data)
{
	NMDHCPManager *	self = (NMDHCPManager *) user_data;
	gboolean		old_owner_good = (old && strlen (old));
	gboolean		new_owner_good = (new && strlen (new));

	g_return_if_fail (self != NULL);
	g_return_if_fail (name != NULL);

	/* Can't handle the signal if its not from the DHCP service */
	if (strcmp (DHCP_SERVICE_NAME, name) != 0)
		return;

	if (!old_owner_good && new_owner_good) {
		self->running = TRUE;
	} else if (old_owner_good && !new_owner_good) {
		self->running = FALSE;
	}
}


static void
nm_dhcp_manager_dbus_connection_changed (NMDBusManager *dbus_mgr,
                                         DBusConnection *dbus_connection,
                                         gpointer user_data)
{
	NMDHCPManager *	self = (NMDHCPManager *) user_data;

	if (dbus_connection) {
		if (nm_dbus_manager_name_has_owner (dbus_mgr, DHCP_SERVICE_NAME))
			self->running = TRUE;
	} else {
		self->running = FALSE;
	}
}
