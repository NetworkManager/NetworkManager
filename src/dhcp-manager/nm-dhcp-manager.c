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
#include "nm-activation-request.h"
#include "nm-utils.h"


struct NMDHCPManager
{
	NMData *		data;
	gboolean		running;
};


char *get_dhcp_match_string (const char *owner)
{
	g_return_val_if_fail (owner != NULL, NULL);

	return g_strdup_printf ("type='signal',interface='" DHCP_SERVICE_NAME ".state',sender='%s'", owner);
}


static gboolean state_is_bound (guint8 state)
{
	if (	   (state == 2)	/* BOUND */
		|| (state == 3)	/* RENEW */
		|| (state == 4)	/* REBOOT */
		|| (state == 5))	/* REBIND */
		return TRUE;

	return FALSE;
}


static gboolean state_is_down (guint8 state)
{
	if (	   (state == 0)	/* NBI */
		|| (state == 11)	/* RELEASE */
		|| (state == 13)	/* ABEND */
		|| (state == 14))	/* END */
		return TRUE;

	return FALSE;
}


/*
 * nm_dhcp_manager_exec_daemon
 *
 * Launch the DHCP daemon.
 *
 */
static gboolean nm_dhcp_manager_exec_daemon (NMDHCPManager *manager)
{
	GPtrArray		*dhcp_argv;
	GError		*error = NULL;
	GPid			 pid;

	g_return_val_if_fail (manager != NULL, FALSE);

	dhcp_argv = g_ptr_array_new ();
	g_ptr_array_add (dhcp_argv, (gpointer) DHCDBD_BINARY_PATH);
	g_ptr_array_add (dhcp_argv, (gpointer) "--system");
	g_ptr_array_add (dhcp_argv, NULL);

	if (!g_spawn_async ("/", (char **) dhcp_argv->pdata, NULL, 0, NULL, NULL, &pid, &error))
	{
		g_ptr_array_free (dhcp_argv, TRUE);
		nm_warning ("Could not activate the DHCP daemon " DHCDBD_BINARY_PATH ".  error: '%s'.", error->message);
		g_error_free (error);
		return FALSE;
	}
	g_ptr_array_free (dhcp_argv, TRUE);
	nm_info ("Activated the DHCP daemon " DHCDBD_BINARY_PATH " with PID %d.", pid);

	return TRUE;
}


NMDHCPManager * nm_dhcp_manager_new (NMData *data)
{
	NMDHCPManager *	manager;
	char *			owner;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (data->dbus_connection != NULL, NULL);

	manager = g_malloc0 (sizeof (NMDHCPManager));
	manager->data = data;
	manager->running = dbus_bus_name_has_owner (manager->data->dbus_connection, DHCP_SERVICE_NAME, NULL);

	if (manager->running && (owner = get_name_owner (data->dbus_connection, DHCP_SERVICE_NAME)))
	{
		char *match = get_dhcp_match_string (owner);
		dbus_bus_add_match (data->dbus_connection, match, NULL);
		g_free (match);
		g_free (owner);
	}

	return manager;
}


void nm_dhcp_manager_dispose (NMDHCPManager *manager)
{
	g_return_if_fail (manager != NULL);

	memset (manager, 0, sizeof (NMDHCPManager));
	g_free (manager);
}


guint32 nm_dhcp_manager_get_state_for_device (NMDHCPManager *manager, NMDevice *dev)
{
	DBusMessage *	message;
	DBusMessage *	reply;
	char *		path;
	guint32		state = 0;
	DBusError		error;

	g_return_val_if_fail (manager != NULL, 0);
	g_return_val_if_fail (dev != NULL, 0);

	if (!manager->running)
	{
		if (nm_dhcp_manager_exec_daemon (manager) == FALSE)
			return 0;
		sleep (1);
	}

	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", nm_device_get_iface (dev));
	message = dbus_message_new_method_call (DHCP_SERVICE_NAME, path, DHCP_SERVICE_NAME".dbus.get", "reason");
	g_free (path);
	if (message == NULL)
	{
		nm_warning ("nm_dhcp_manager_get_state_for_device(): Couldn't allocate the dbus message");
		return 0;
	}

	dbus_error_init (&error);
	reply = dbus_connection_send_with_reply_and_block (manager->data->dbus_connection, message, -1, &error);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		if (strcmp (error.name, "org.freedesktop.DBus.Error.UnknownMethod") != 0)
			nm_info ("Error from dhcdbd on 'reason' request because: name '%s', message '%s'.", error.name, error.message);
		dbus_error_free (&error);
	}
	else if (reply)
	{
		if (!dbus_message_get_args (reply, NULL, DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID))
			state = 0;
		dbus_message_unref (reply);
	}

	return state;
}


/*
 * nm_dhcp_manager_handle_timeout
 *
 * Called after timeout of a DHCP transaction to notify device of the failure.
 *
 */
static gboolean nm_dhcp_manager_handle_timeout (NMActRequest *req)
{
	NMData *		data;
	NMDevice *	dev;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	nm_info ("Device '%s' DHCP transaction took too long (>25s), stopping it.", nm_device_get_iface (dev));

	if (nm_act_request_get_stage (req) == NM_ACT_STAGE_IP_CONFIG_START)
	{
		nm_act_request_set_dhcp_timeout (req, 0);
		nm_dhcp_manager_cancel_transaction (data->dhcp_manager, req);
		nm_device_activate_schedule_stage4_ip_config_timeout (req);
	}

	return FALSE;
}


gboolean nm_dhcp_manager_begin_transaction (NMDHCPManager *manager, NMActRequest *req)
{
	DBusError			error;
	DBusMessage *		message;
	DBusMessage *		reply;
	NMDevice *		dev;
	char *			path;
	const guint32		opt1 = 31;	/* turns off ALL actions and dhclient-script just writes options to dhcdbd */
	const guint32		opt2 = 2;		/* dhclient is run in ONE SHOT mode and releases existing leases when brought down */
	GSource *			source;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (req != NULL, FALSE);

	if (!manager->running)
	{
		if (nm_dhcp_manager_exec_daemon (manager) == FALSE)
			return FALSE;
		sleep (1);
	}
	else
	{
		/* Cancel any DHCP transaction already in progress */
		nm_dhcp_manager_cancel_transaction (manager, req);
		/* FIXME don't sleep */
		sleep (1);
	}

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	nm_info ("Activation (%s) Beginning DHCP transaction.", nm_device_get_iface (dev));

	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", nm_device_get_iface (dev));
	message = dbus_message_new_method_call (DHCP_SERVICE_NAME, path, DHCP_SERVICE_NAME, "up");
	g_free (path);
	if (message == NULL)
	{
		nm_warning ("nm_dhcp_manager_begin_transaction(): Couldn't allocate the dbus message");
		return FALSE;
	}

	dbus_message_append_args (message, DBUS_TYPE_UINT32, &opt1, DBUS_TYPE_UINT32, &opt2, DBUS_TYPE_INVALID);
	dbus_error_init (&error);
	if ((reply = dbus_connection_send_with_reply_and_block (manager->data->dbus_connection, message, -1, &error)))
		dbus_message_unref (reply);
	dbus_message_unref (message);
	if (dbus_error_is_set (&error))
	{
		nm_info ("Couldn't send DHCP 'up' message because: name '%s', message '%s'.", error.name, error.message);
		dbus_error_free (&error);
		return FALSE;
	}

	/* Set up a timeout on the transaction to kill it after 25s */
	source = g_timeout_source_new (25000);
	g_source_set_callback (source, (GSourceFunc) nm_dhcp_manager_handle_timeout, req, NULL);
	nm_act_request_set_dhcp_timeout (req, g_source_attach (source, manager->data->main_context));
	g_source_unref (source);

	return TRUE;
}


static void remove_timeout (NMDHCPManager *manager, NMActRequest *req)
{
	guint id;

	g_return_if_fail (manager != NULL);
	g_return_if_fail (req != NULL);

	/* Remove any pending timeouts on the request */
	if ((id = nm_act_request_get_dhcp_timeout (req)) > 0)
	{
		GSource *	source = g_main_context_find_source_by_id (manager->data->main_context, id);
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
void nm_dhcp_manager_cancel_transaction (NMDHCPManager *manager, NMActRequest *req)
{
	NMDevice *dev;

	g_return_if_fail (manager != NULL);
	g_return_if_fail (req != NULL);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	if (manager->running && !state_is_down (nm_act_request_get_dhcp_state (req)))
	{
		DBusMessage *	message;
		char *		path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", nm_device_get_iface (dev));

		if ((message = dbus_message_new_method_call (DHCP_SERVICE_NAME, path, DHCP_SERVICE_NAME, "down")))
		{
			dbus_connection_send (manager->data->dbus_connection, message, NULL);
			dbus_message_unref (message);

			/* Give dhcdbd/dhclient some time to send out a RELEASE if they like */
			/* FIXME: we should really monitor the interface's DHCP state by waiting
			 * for dhcdbd to tell us the device is "down" rather than sleeping here.
			 */
			if (!manager->data->asleep)
				sleep (1);
		}
		g_free (path);

		remove_timeout (manager, req);
	}
}


static gboolean get_ip4_uint32s (NMDHCPManager *manager, NMDevice *dev, const char *item,
			guint32 **ip4_uint32, guint32 *num_items, gboolean ignore_error)
{
	DBusMessage *	message = NULL;
	DBusMessage *	reply = NULL;
	char *		path;
	gboolean		success = FALSE;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (ip4_uint32 != NULL, FALSE);
	g_return_val_if_fail (num_items != NULL, FALSE);

	*ip4_uint32 = NULL;
	*num_items = 0;
	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", nm_device_get_iface (dev));
	if ((message = dbus_message_new_method_call (DHCP_SERVICE_NAME, path, DHCP_SERVICE_NAME".dbus.get", item)))
	{
		DBusError	error;

		dbus_error_init (&error);
		reply = dbus_connection_send_with_reply_and_block (manager->data->dbus_connection, message, -1, &error);
		if (reply)
		{
			GArray *buffer;
			DBusMessageIter iter;

			dbus_message_iter_init (reply, &iter);

			buffer = g_array_new (TRUE, TRUE, sizeof (guint32));
			while (dbus_message_iter_get_arg_type (&iter) == DBUS_TYPE_UINT32)
			{
				guint32 value;
			
				dbus_message_iter_get_basic (&iter, &value);
				g_array_append_val (buffer, value);
				dbus_message_iter_next (&iter);
				success = TRUE;
			}

			if (success)
			{
				*ip4_uint32 = (guint32 *)(buffer->data);
				*num_items = buffer->len;
			}
			g_array_free (buffer, FALSE);
			dbus_message_unref (reply);
		}

		if (dbus_error_is_set (&error))
		{
			if (!ignore_error)
				nm_warning ("get_ip4_uint32s(): error calling '%s', DHCP daemon returned error '%s', message '%s'.",
					item, error.name, error.message);
			dbus_error_free (&error);
		}
		dbus_message_unref (message);
	}
	g_free (path);

	return success;
}


static gboolean get_ip4_string (NMDHCPManager *manager, NMDevice *dev, const char *item,
			char **string, gboolean ignore_error)
{
	DBusMessage *	message = NULL;
	DBusMessage *	reply = NULL;
	char *		path;
	gboolean		success = FALSE;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (string != NULL, FALSE);

	*string = NULL;
	path = g_strdup_printf (DHCP_OBJECT_PATH"/%s", nm_device_get_iface (dev));
	if ((message = dbus_message_new_method_call (DHCP_SERVICE_NAME, path, DHCP_SERVICE_NAME".dbus.get", item)))
	{
		DBusError	error;

		dbus_error_init (&error);
		if ((reply = dbus_connection_send_with_reply_and_block (manager->data->dbus_connection, message, -1, &error)))
		{
			char *dbus_string;

			dbus_error_init (&error);
			if (dbus_message_get_args (reply, &error, DBUS_TYPE_STRING, &dbus_string, DBUS_TYPE_INVALID))
			{
				*string = g_strdup (dbus_string);
				success = TRUE;
			}
		}

		if (dbus_error_is_set (&error))
		{
			if (!ignore_error)
				nm_warning ("get_ip4_string(): error calling '%s', DHCP daemon returned error '%s', message '%s'.",
						item, error.name, error.message);
			dbus_error_free (&error);
			*string = NULL;
		}
		dbus_message_unref (message);
	}
	g_free (path);

	return success;
}


static gboolean nm_completion_dhcp_bound_test(int tries,
		nm_completion_args args)
{
	NMActRequest *req = args[0];

	if (state_is_bound (nm_act_request_get_dhcp_state (req)))
		return TRUE;
	return FALSE;
}

/*
 * nm_dhcp_manager_get_ip4_config
 *
 * Get IP4 configuration values from the DHCP daemon
 *
 */
NMIP4Config * nm_dhcp_manager_get_ip4_config (NMDHCPManager *manager, NMActRequest *req)
{
	NMDevice *	dev;
	NMIP4Config *	ip4_config = NULL;
	int			i;
	guint32		count = 0;
	guint32 *		ip4_address = NULL;
	guint32 *		ip4_netmask = NULL;
	guint32 *		ip4_broadcast = NULL;
	guint32 *		ip4_nameservers = NULL;
	guint32 *		ip4_gateway = NULL;
	guint32		num_ip4_nameservers = 0;
	guint32		num_ip4_nis_servers = 0;
	char *		domain_names = NULL;
	char *		nis_domain = NULL;
	guint32 *		ip4_nis_servers = NULL;
	struct in_addr	temp_addr;
	nm_completion_args	args;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (req != NULL, NULL);

	if (!manager->running)
		return NULL;

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	args[0] = req;
	nm_wait_for_completion (30, G_USEC_PER_SEC / 10,
			nm_completion_dhcp_bound_test, NULL, args);
	if (!state_is_bound (nm_act_request_get_dhcp_state (req)))
	{
		nm_warning ("Tried to get IP4 Config for a device when dhcdbd wasn't in a BOUND state!");
		return NULL;
	}

	if (!get_ip4_uint32s (manager, dev, "ip_address", &ip4_address, &count, FALSE) || !count)
		goto out;

	if (!get_ip4_uint32s (manager, dev, "subnet_mask", &ip4_netmask, &count, FALSE) || !count)
		goto out;

	if (!get_ip4_uint32s (manager, dev, "broadcast_address", &ip4_broadcast, &count, FALSE) || !count)
		goto out;

	if (!get_ip4_uint32s (manager, dev, "routers", &ip4_gateway, &count, TRUE) || !count)
	{
		/* If DHCP doesn't have a 'routers', just use the DHCP server's address as our gateway for now */
		if (!get_ip4_uint32s (manager, dev, "dhcp_server_identifier", &ip4_gateway, &count, FALSE) || !count)
			goto out;
	}

	get_ip4_uint32s (manager, dev, "domain_name_servers", &ip4_nameservers, &num_ip4_nameservers, FALSE);
	get_ip4_string (manager, dev, "domain_name", &domain_names, FALSE);
	get_ip4_string (manager, dev, "nis_domain", &nis_domain, TRUE);
	get_ip4_uint32s (manager, dev, "nis_servers", &ip4_nis_servers, &num_ip4_nis_servers, TRUE);

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

	for (i = 0; i < num_ip4_nameservers; i++)
	{
		nm_ip4_config_add_nameserver (ip4_config, ip4_nameservers[i]);
		temp_addr.s_addr = ip4_nameservers[i];
		nm_info ("  nameserver %s", inet_ntoa (temp_addr));
	}

	if (domain_names)
	{
		char **searches = g_strsplit (domain_names, " ", 0);
		char **s;

		for (s = searches; *s; s++)
		{
			nm_info ("  domain name '%s'", *s);
			nm_ip4_config_add_domain (ip4_config, *s);
		}
		g_strfreev (searches);
	}

	if (nis_domain)
	{
		nm_ip4_config_set_nis_domain (ip4_config, nis_domain);
		nm_info ("  nis domain '%s'", nis_domain);
	}

	for (i = 0; i < num_ip4_nis_servers; i++)
	{
		nm_ip4_config_add_nis_server (ip4_config, ip4_nis_servers[i]);
		temp_addr.s_addr = ip4_nis_servers[i];
		nm_info ("  nis server %s", inet_ntoa (temp_addr));
	}

out:
	return ip4_config;
}


/*
 * nm_dhcp_manager_process_signal
 *
 * Possibly process a signal from the bus, if it comes from the currently
 * active DHCP daemon, if any.  Return TRUE if processed, FALSE if not.
 *
 */
gboolean nm_dhcp_manager_process_signal (NMDHCPManager *manager, DBusMessage *message)
{
	const char *		object_path;
	const char *		member;
	const char *		interface;
	gboolean			handled = FALSE;
	NMDevice *		dev;
	NMActRequest *		req = NULL;

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (message != NULL, FALSE);

	if (!(object_path = dbus_message_get_path (message)))
		return FALSE;
	if (!(member = dbus_message_get_member (message)))
		return FALSE;
	if (!(interface = dbus_message_get_interface (message)))
		return FALSE;

	/* nm_info ("nm_dhcp_manager_process_signal(): got signal op='%s' member='%s' interface='%s'", object_path, member, interface); */

	dev = nm_get_device_by_iface (manager->data, member);
	if (dev && (req = nm_device_get_act_request (dev)))
	{
		if (dbus_message_is_signal (message, "com.redhat.dhcp.state", nm_device_get_iface (dev)))
		{
			guint8	state;

			if (dbus_message_get_args (message, NULL, DBUS_TYPE_BYTE, &state, DBUS_TYPE_INVALID))
			{
				nm_info ("DHCP daemon state now %d for interface %s", state, nm_device_get_iface (dev));
				switch (state)
				{
					case 2:		/* BOUND */
					case 3:		/* RENEW */
					case 4:		/* REBOOT */
					case 5:		/* REBIND */
						if (nm_act_request_get_stage (req) == NM_ACT_STAGE_IP_CONFIG_START)
						{
							nm_device_activate_schedule_stage4_ip_config_get (req);
							remove_timeout (manager, req);
						}
						break;

					case 8:		/* TIMEOUT - timed out trying to contact server */
						if (nm_act_request_get_stage (req) == NM_ACT_STAGE_IP_CONFIG_START)
						{
							nm_device_activate_schedule_stage4_ip_config_timeout (req);
							remove_timeout (manager, req);
						}
						break;					

					case 9:		/* FAIL */
					case 13:		/* ABEND */
//					case 14:		/* END */
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
			}

			handled = TRUE;
		}
	}

	return handled;
}


/*
 * nm_dhcp_manager_process_name_owner_changed
 *
 * Respond to "service created"/"service deleted" signals from dbus for the active DHCP daemon.
 *
 */
gboolean nm_dhcp_manager_process_name_owner_changed (NMDHCPManager *manager, const char *changed_service_name, const char *old_owner, const char *new_owner)
{
	gboolean	handled = FALSE;
	gboolean	old_owner_good = (old_owner && strlen (old_owner));
	gboolean	new_owner_good = (new_owner && strlen (new_owner));

	g_return_val_if_fail (manager != NULL, FALSE);
	g_return_val_if_fail (changed_service_name != NULL, FALSE);

	/* Can't handle the signal if its not from the DHCP service */
	if (strcmp (DHCP_SERVICE_NAME, changed_service_name) != 0)
		return FALSE;

	if (!old_owner_good && new_owner_good)
	{
		char *match = get_dhcp_match_string (new_owner);

		/* DHCP service got created */
		dbus_bus_add_match (manager->data->dbus_connection, match, NULL);
		g_free (match);

		manager->running = TRUE;
		handled = TRUE;
	}
	else if (old_owner_good && !new_owner_good)
	{
		char *match = get_dhcp_match_string (old_owner);

		/* DHCP service went away */
		dbus_bus_remove_match (manager->data->dbus_connection, match, NULL);
		g_free (match);

		manager->running = FALSE;
		handled = TRUE;
	}

	return handled;
}


