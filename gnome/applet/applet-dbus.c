/* NetworkManager Wireless Applet -- Display wireless access points and allow user control
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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <glib/gi18n.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <math.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include "applet.h"
#include "applet-dbus.h"
#include "applet-dbus-devices.h"
#include "applet-dbus-vpn.h"
#include "applet-dbus-info.h"
#include "vpn-connection.h"
#include "passphrase-dialog.h"
#include "nm-utils.h"

#define	DBUS_NO_SERVICE_ERROR			"org.freedesktop.DBus.Error.ServiceDoesNotExist"


#define DBUS_PENDING_CALL_DEBUG

typedef struct PCallInfo
{
	DBusPendingCall *	pcall;
	char *			caller;
	guint32			id;
	GTimeVal			start;
} PCallInfo;

static GStaticMutex pcall_mutex = G_STATIC_MUTEX_INIT;
static GHashTable *	pcall_table = NULL;
static guint32		pcall_gid = 0;
static guint32		pcall_pending = 0;


gboolean
nma_dbus_send_with_callback (DBusConnection *connection,
                             DBusMessage *msg, 
                             DBusPendingCallNotifyFunction func,
                             gpointer data,
                             DBusFreeFunction free_func,
                             const char *caller)
{
	PCallInfo * info;
	DBusPendingCall * pcall = NULL;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (msg != NULL, FALSE);
	g_return_val_if_fail (func != NULL, FALSE);
	g_return_val_if_fail (caller != NULL, FALSE);

	dbus_connection_send_with_reply (connection, msg, &pcall, -1);
	if (!pcall)
	{
		g_warning ("Error: '%s' couldn't send dbus message.", caller);
		if (free_func)
			(*free_func)(data);
		return FALSE;
	}
	dbus_pending_call_set_notify (pcall, func, data, free_func);

	if (!(info = g_malloc0 (sizeof (PCallInfo))))
		return FALSE;
	info->caller = g_strdup (caller);
	info->pcall = pcall;
	g_get_current_time (&info->start);
	dbus_pending_call_ref (pcall);

	g_static_mutex_lock (&pcall_mutex);
	info->id = pcall_gid++;
	pcall_pending++;

	if (!pcall_table)
		pcall_table = g_hash_table_new (g_direct_hash, g_direct_equal);
	g_hash_table_insert (pcall_table, pcall, info);

#ifdef DBUS_PENDING_CALL_DEBUG
	nm_info ("PCall Debug: registered ID %d (%p), initiated by '%s'.  Total "
		"pending: %d", info->id, pcall, info->caller, pcall_pending);
#endif

	g_static_mutex_unlock (&pcall_mutex);

	return TRUE;
}

void
nma_dbus_send_with_callback_replied (DBusPendingCall *pcall,
                                     const char *caller)
{
	PCallInfo *	info;
	GTimeVal		now;
#ifdef DBUS_PENDING_CALL_DEBUG
	long			elapsed_ms = 0;
#endif

	g_return_if_fail (pcall != NULL);
	g_return_if_fail (caller != NULL);

	g_static_mutex_lock (&pcall_mutex);
	if (!(info = g_hash_table_lookup (pcall_table, pcall)))
	{
		nm_warning ("Error: couldn't find pending call %p in tracking"
			" table.", pcall);
		goto out;
	}

	pcall_pending--;
#ifdef DBUS_PENDING_CALL_DEBUG
	g_get_current_time (&now);
	if (info->start.tv_usec > now.tv_usec)
	{
		now.tv_sec--;
		now.tv_usec = G_USEC_PER_SEC - (info->start.tv_usec - now.tv_usec);
	}
	else
		now.tv_usec -= info->start.tv_usec;
	now.tv_sec -= info->start.tv_sec;
	elapsed_ms = now.tv_sec * G_USEC_PER_SEC + now.tv_usec;
	elapsed_ms /= 1000;

	nm_info ("PCall Debug: unregistered ID %d (%p), %s -> %s,"
		" %lums elapsed.  Total pending: %d", info->id, info->pcall, info->caller,
		caller, elapsed_ms, pcall_pending);
#endif

	g_hash_table_remove (pcall_table, pcall);
	g_free (info->caller);
	dbus_pending_call_unref (info->pcall);
	g_free (info);

out:
	g_static_mutex_unlock (&pcall_mutex);
}


/*
 * nma_dbus_filter
 *
 */
static DBusHandlerResult nma_dbus_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMApplet	*applet = (NMApplet *)user_data;
	gboolean			 handled = TRUE;

	const char *		object_path;
	const char *		member;
	const char *		interface;

	g_return_val_if_fail (applet != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (connection != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
	g_return_val_if_fail (message != NULL, DBUS_HANDLER_RESULT_NOT_YET_HANDLED);

	if (!(object_path = dbus_message_get_path (message)))
		return FALSE;
	if (!(member = dbus_message_get_member (message)))
		return FALSE;
	if (!(interface = dbus_message_get_interface (message)))
		return FALSE;

	/* nm_info ("signal(): got signal op='%s' member='%s' interface='%s'", object_path, member, interface); */

	if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS, "NameOwnerChanged"))
	{
		char 	*service;
		char		*old_owner;
		char		*new_owner;

		if (dbus_message_get_args (message, NULL,
								DBUS_TYPE_STRING, &service,
								DBUS_TYPE_STRING, &old_owner,
								DBUS_TYPE_STRING, &new_owner,
								DBUS_TYPE_INVALID))
		{
			if (strcmp (service, NM_DBUS_SERVICE) == 0)
			{
				gboolean old_owner_good = (old_owner && (strlen (old_owner) > 0));
				gboolean new_owner_good = (new_owner && (strlen (new_owner) > 0));

				if (!old_owner_good && new_owner_good && !applet->nm_running)
				{
					/* NetworkManager started up */
					applet->nm_running = TRUE;
					nma_set_state (applet, NM_STATE_DISCONNECTED);
					nma_dbus_update_nm_state (applet);
					nma_dbus_update_devices (applet);
					nma_dbus_update_dialup (applet);
					nma_dbus_vpn_update_vpn_connections (applet);
				}
				else if (old_owner_good && !new_owner_good)
				{
					applet->nm_running = FALSE;
					nma_set_state (applet, NM_STATE_DISCONNECTED);
					nmi_passphrase_dialog_destroy (applet);
				}
			}
		}
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, NM_DBUS_SIGNAL_STATE_CHANGE))
	{
		NMState	state = NM_STATE_UNKNOWN;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID))
		{
			NetworkDevice *act_dev = nma_get_first_active_device (applet->device_list);

			/* If we've switched to connecting, update the active device to ensure that we have
			 * valid wireless network information for it.
			 */
			if (state == NM_STATE_CONNECTING && act_dev && network_device_is_wireless (act_dev))
			{
				nma_dbus_device_update_one_device (applet, network_device_get_nm_path (act_dev));
			}
			nma_set_state (applet, state);
		}
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceAdded")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivating")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceCarrierOn")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceCarrierOff"))
	{
		char *path = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
			nma_dbus_device_update_one_device (applet, path);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNowActive"))
	{
		char *path = NULL;
		char *essid = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_STRING, &essid, DBUS_TYPE_INVALID))
			nma_dbus_device_activated (applet, path, essid);
		else if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
			nma_dbus_device_activated (applet, path, NULL);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNoLongerActive"))
	{
		char *path = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
			nma_dbus_device_deactivated (applet, path);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceRemoved"))
	{
		char *path = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
			nma_dbus_device_remove_one_device (applet, path);
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, "VPNConnectionAdded")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, "VPNConnectionUpdate"))	/* VPN connection properties changed */
	{
		char *name = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
			nma_dbus_vpn_update_one_vpn_connection (applet, name);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, "VPNConnectionStateChange"))	/* Active VPN connection changed */
	{
		char *		name = NULL;
		NMVPNActStage	vpn_stage;
		dbus_uint32_t	vpn_stage_int;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_UINT32, &vpn_stage_int, DBUS_TYPE_INVALID))
		{
			vpn_stage = (NMVPNActStage) vpn_stage_int;
			nma_dbus_vpn_update_vpn_connection_stage (applet, name, vpn_stage);
		}
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, "VPNConnectionRemoved"))
	{
		char *name = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
			nma_dbus_vpn_remove_one_vpn_connection (applet, name);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkAppeared"))
	{
		char *dev_path = NULL;
		char *net_path = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_OBJECT_PATH, &net_path, DBUS_TYPE_INVALID))
			nma_dbus_device_update_one_network (applet, dev_path, net_path, NULL);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkDisappeared"))
	{
		char *dev_path = NULL;
		char *net_path = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_OBJECT_PATH, &net_path, DBUS_TYPE_INVALID))
			nma_dbus_device_remove_one_network (applet, dev_path, net_path);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkStrengthChanged"))
	{
		char *	dev_path = NULL;
		char *	net_path = NULL;
		int		strength = -1;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_OBJECT_PATH, &net_path, DBUS_TYPE_INT32, &strength, DBUS_TYPE_INVALID))
			nma_dbus_update_strength (applet, dev_path, net_path, strength);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceStrengthChanged"))
	{
		char *dev_path = NULL;
		int strength = -1;
		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_INT32, &strength, DBUS_TYPE_INVALID))
			nma_dbus_update_strength (applet, dev_path, NULL, strength);
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, NM_DBUS_VPN_SIGNAL_LOGIN_FAILED)
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, NM_DBUS_VPN_SIGNAL_LAUNCH_FAILED)
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, NM_DBUS_VPN_SIGNAL_CONNECT_FAILED)
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, NM_DBUS_VPN_SIGNAL_VPN_CONFIG_BAD)
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, NM_DBUS_VPN_SIGNAL_IP_CONFIG_BAD))
	{
		char *vpn_name;
		char *error_msg;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_STRING, &error_msg, DBUS_TYPE_INVALID)) {
			nma_show_vpn_failure_alert (applet, member, vpn_name, error_msg);
			/* clear the 'last_attempt_success' key in gconf so we prompt for password next time */
			nma_dbus_vpn_set_last_attempt_status (applet, vpn_name, FALSE);
		}
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, NM_DBUS_VPN_SIGNAL_LOGIN_BANNER))
	{
		char *vpn_name;
		char *banner;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_STRING, &banner, DBUS_TYPE_INVALID))
		{
			char *stripped = g_strstrip (g_strdup (banner));

			nma_show_vpn_login_banner (applet, vpn_name, stripped);
			g_free (stripped);

			/* set the 'last_attempt_success' key in gconf so we DON'T prompt for password next time */
			nma_dbus_vpn_set_last_attempt_status (applet, vpn_name, TRUE);
		}
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivationFailed"))
	{
		char		*dev = NULL;
		char		*net = NULL;

		if (!dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &dev, DBUS_TYPE_STRING, &net, DBUS_TYPE_INVALID))
			dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &dev, DBUS_TYPE_INVALID);

		if (dev && net)
		{
			char *string = g_strdup_printf (_("Connection to the wireless network '%s' failed."), net);
			nma_schedule_warning_dialog (applet, string);
			g_free (string);
		}
		else if (dev)
			nma_schedule_warning_dialog (applet, _("Connection to the wired network failed."));
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivationStage"))
	{
		char *		dev_path = NULL;
		NMActStage	stage;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_UINT32, &stage, DBUS_TYPE_INVALID))
		{
			NetworkDevice *dev;

			if ((dev = nma_get_device_for_nm_path (applet->device_list, dev_path)))
				network_device_set_act_stage (dev, stage);
		}
	}
	else
		handled = FALSE;

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nma_dbus_nm_is_running
 *
 * Ask dbus whether or not NetworkManager is running
 *
 */
static gboolean nma_dbus_nm_is_running (DBusConnection *connection)
{
	DBusError		error;
	gboolean		exists;

	g_return_val_if_fail (connection != NULL, FALSE);

	dbus_error_init (&error);
	exists = dbus_bus_name_has_owner (connection, NM_DBUS_SERVICE, &error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	return (exists);
}


/*
 * nma_dbus_init
 *
 * Initialize a connection to NetworkManager if we can get one
 *
 */
static DBusConnection * nma_dbus_init (NMApplet *applet)
{
	DBusConnection	*		connection = NULL;
	DBusError		 		error;
	DBusObjectPathVTable	vtable = { NULL, &nmi_dbus_info_message_handler, NULL, NULL, NULL, NULL };
	int					acquisition;

	g_return_val_if_fail (applet != NULL, NULL);

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (dbus_error_is_set (&error))
	{
		nm_warning ("%s raised:\n %s\n\n", error.name, error.message);
		dbus_error_free (&error);
		return NULL;
	}

	dbus_error_init (&error);
	acquisition = dbus_bus_request_name (connection, NMI_DBUS_SERVICE, DBUS_NAME_FLAG_REPLACE_EXISTING, &error);
	if (dbus_error_is_set (&error))
	{
		nm_warning ("nma_dbus_init() could not acquire its service.  dbus_bus_acquire_service() says: '%s'", error.message);
		dbus_error_free (&error);
		return NULL;
	}
	if (acquisition == DBUS_REQUEST_NAME_REPLY_EXISTS)
	     return NULL;

	if (!dbus_connection_register_object_path (connection, NMI_DBUS_PATH, &vtable, applet))
	{
		nm_warning ("nma_dbus_init() could not register a handler for NetworkManagerInfo.  Not enough memory?");
		return NULL;
	}

	if (!dbus_connection_add_filter (connection, nma_dbus_filter, applet, NULL))
		return NULL;

	dbus_connection_set_exit_on_disconnect (connection, FALSE);
	dbus_connection_setup_with_g_main (connection, NULL);

	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" DBUS_INTERFACE_DBUS "',"
				"sender='" DBUS_SERVICE_DBUS "'",
				&error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" NM_DBUS_INTERFACE "',"
				"path='" NM_DBUS_PATH "',"
				"sender='" NM_DBUS_SERVICE "'",
				&error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" NM_DBUS_INTERFACE_VPN "',"
				"path='" NM_DBUS_PATH_VPN "',"
				"sender='" NM_DBUS_SERVICE "'",
				&error);
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);

	return (connection);
}


/*
 * nma_dbus_connection_watcher
 *
 * Try to reconnect if we ever get disconnected from the bus
 *
 */
static gboolean nma_dbus_connection_watcher (gpointer user_data)
{
	NMApplet	*applet = (NMApplet *)user_data;

	g_return_val_if_fail (applet != NULL, TRUE);

	if (!applet->connection)
	{
		if ((applet->connection = nma_dbus_init (applet)))
		{
			applet->nm_running = nma_dbus_nm_is_running (applet->connection);
			nma_set_state (applet, NM_STATE_DISCONNECTED);
			nma_dbus_update_nm_state (applet);
			nma_dbus_update_devices (applet);
			nma_dbus_update_dialup (applet);
			nma_dbus_vpn_update_vpn_connections (applet);
		}
	}

	return (TRUE);
}


/*
 * nma_dbus_worker
 *
 * Thread worker function that periodically grabs the NetworkManager state
 * and updates our local applet state to reflect that.
 *
 */
void nma_dbus_init_helper (NMApplet *applet)
{
	GSource *			timeout_source;

	g_return_if_fail (applet != NULL);

	dbus_g_thread_init ();

	applet->connection = nma_dbus_init (applet);
	applet->nmi_methods = nmi_dbus_nmi_methods_setup ();

	timeout_source = g_timeout_source_new (2000);
	g_source_set_callback (timeout_source, nma_dbus_connection_watcher, applet, NULL);
	g_source_attach (timeout_source, NULL);

	if (applet->connection && nma_dbus_nm_is_running (applet->connection))
	{
		applet->nm_running = TRUE;
		nma_dbus_update_nm_state (applet);
		nma_dbus_update_devices (applet);
		nma_dbus_update_dialup (applet);
		nma_dbus_vpn_update_vpn_connections (applet);
	}

	g_source_unref (timeout_source);
}
