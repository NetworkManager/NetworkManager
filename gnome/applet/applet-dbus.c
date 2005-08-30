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


/*
 * nmi_dbus_create_error_message
 *
 * Convenience function to make a DBus error message
 *
 */
DBusMessage *nmwa_dbus_create_error_message (DBusMessage *message, const char *exception_namespace, const char *exception, const char *format, ...)
{
	char *		exception_text;
	DBusMessage *	reply_message;
	va_list		args;
	char			error_text[512];


	va_start (args, format);
	vsnprintf (error_text, 512, format, args);
	va_end (args);

	exception_text = g_strdup_printf ("%s.%s", exception_namespace, exception);
	reply_message = dbus_message_new_error (message, exception_text, error_text);
	g_free (exception_text);

	return (reply_message);
}


/*
 * deal_with_dbus_error
 *
 * Ignore some common dbus errors
 *
 */
static int deal_with_dbus_error (const char *function, const char *method, DBusError *error)
{
	int	ret = RETURN_FAILURE;

	if (!strcmp (error->name, DBUS_NO_SERVICE_ERROR))
		ret = RETURN_NO_NM;
	else if (!strcmp (error->name, NM_DBUS_NO_ACTIVE_NET_ERROR))
		ret = RETURN_SUCCESS;
	else if (!strcmp (error->name, NM_DBUS_NO_ACTIVE_DEVICE_ERROR))
		ret = RETURN_SUCCESS;
	else if (!strcmp (error->name, NM_DBUS_NO_NETWORKS_ERROR))
		ret = RETURN_SUCCESS;
	else if (!strcmp (error->name, NM_DBUS_NO_ACTIVE_VPN_CONNECTION))
		ret = RETURN_SUCCESS;
	else if (!strcmp (error->name, NM_DBUS_NO_VPN_CONNECTIONS))
		ret = RETURN_SUCCESS;

	if ((ret != RETURN_SUCCESS) && (ret != RETURN_NO_NM))
		nm_warning ("%s(): %s raised on method '%s':\n %s\n\n", function, error->name, method, error->message);

	return ret;
}



static void
set_vpn_last_attempt_status (NMWirelessApplet *applet, const char *vpn_name, gboolean last_attempt_success)
{
	char *gconf_key;
	char *escaped_name;

	escaped_name = gconf_escape_key (vpn_name, strlen (vpn_name));

	gconf_key = g_strdup_printf ("%s/%s/last_attempt_success", GCONF_PATH_VPN_CONNECTIONS, escaped_name);
	gconf_client_set_bool (applet->gconf_client, gconf_key, last_attempt_success, NULL);

	g_free (gconf_key);
	g_free (escaped_name);
}

/*
 * nmwa_dbus_filter
 *
 */
static DBusHandlerResult nmwa_dbus_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;
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
					applet->nm_state = NM_STATE_DISCONNECTED;
					nmwa_dbus_update_nm_state (applet);
					nmwa_dbus_update_devices (applet);
					nmwa_dbus_update_dialup (applet);
					nmwa_dbus_vpn_update_vpn_connections (applet);
				}
				else if (old_owner_good && !new_owner_good)
				{
					applet->nm_running = FALSE;
					nmi_passphrase_dialog_schedule_cancel (applet);
				}
			}
		}
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, NM_DBUS_SIGNAL_STATE_CHANGE))
	{
		NMState	state = NM_STATE_UNKNOWN;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_UINT32, &state, DBUS_TYPE_INVALID))
		{
			NetworkDevice *act_dev = nmwa_get_first_active_device (applet->device_list);

			/* If we've switched to connecting, update the active device to ensure that we have
			 * valid wireless network information for it.
			 */
			if (   (state == NM_STATE_CONNECTING)
				&& act_dev
				&& network_device_is_wireless (act_dev))
			{
				nmwa_dbus_device_update_one_device (applet, network_device_get_nm_path (act_dev));
			}
			applet->nm_state = state;
		}
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceAdded")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNowActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceNoLongerActive")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivating")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceCarrierOn")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceCarrierOff"))
	{
		char *path = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
			nmwa_dbus_device_update_one_device (applet, path);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceRemoved"))
	{
		char *path = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &path, DBUS_TYPE_INVALID))
			nmwa_dbus_device_remove_one_device (applet, path);
	}
	else if (    dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, "VPNConnectionAdded")
			|| dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, "VPNConnectionUpdate"))	/* VPN connection properties changed */
	{
		char *name = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
			nmwa_dbus_vpn_update_one_vpn_connection (applet, name);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, "VPNConnectionStateChange"))	/* Active VPN connection changed */
	{
		char *name = NULL;
		NMVPNState vpn_state;
		dbus_uint32_t vpn_state_int;
		if (dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_UINT32, &vpn_state_int, DBUS_TYPE_INVALID))
		{
			vpn_state = (NMVPNState) vpn_state_int;
			nmwa_dbus_vpn_update_vpn_connection_state (applet, name, vpn_state);
		}
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, "VPNConnectionRemoved"))
	{
		char *name = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &name, DBUS_TYPE_INVALID))
			nmwa_dbus_vpn_remove_one_vpn_connection (applet, name);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkAppeared"))
	{
		char *dev_path = NULL;
		char *net_path = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_OBJECT_PATH, &net_path, DBUS_TYPE_INVALID))
			nmwa_dbus_device_update_one_network (applet, dev_path, net_path, NULL);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkDisappeared"))
	{
		char *dev_path = NULL;
		char *net_path = NULL;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_OBJECT_PATH, &net_path, DBUS_TYPE_INVALID))
			nmwa_dbus_device_remove_one_network (applet, dev_path, net_path);
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "WirelessNetworkStrengthChanged"))
	{
		char *	dev_path = NULL;
		char *	net_path = NULL;
		int		strength = -1;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_OBJECT_PATH, &net_path, DBUS_TYPE_INT32, &strength, DBUS_TYPE_INVALID))
		{
			/* FIXME  actually use strength rather than querying all network properties */
			nmwa_dbus_device_update_one_network (applet, dev_path, net_path, NULL);
		}
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
			nmwa_schedule_vpn_failure_dialog (applet, member, vpn_name, error_msg);
			/* clear the 'last_attempt_success' key in gconf so we prompt for password next time */
			set_vpn_last_attempt_status (applet, vpn_name, FALSE);
		}
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE_VPN, NM_DBUS_VPN_SIGNAL_LOGIN_BANNER))
	{
		char *vpn_name;
		char *banner;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_STRING, &vpn_name, DBUS_TYPE_STRING, &banner, DBUS_TYPE_INVALID)) {
			nmwa_schedule_vpn_login_banner_dialog (applet, vpn_name, banner);
			/* set the 'last_attempt_success' key in gconf so we DON'T prompt for password next time */
			set_vpn_last_attempt_status (applet, vpn_name, TRUE);
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
			nmwa_schedule_warning_dialog (applet, string);
			g_free (string);
		}
		else if (dev)
			nmwa_schedule_warning_dialog (applet, _("Connection to the wired network failed."));
	}
	else if (dbus_message_is_signal (message, NM_DBUS_INTERFACE, "DeviceActivationStage"))
	{
		char *		dev_path = NULL;
		NMActStage	stage;

		if (dbus_message_get_args (message, NULL, DBUS_TYPE_OBJECT_PATH, &dev_path, DBUS_TYPE_UINT32, &stage, DBUS_TYPE_INVALID))
		{
			NetworkDevice *dev;

			if ((dev = nmwa_get_device_for_nm_path (applet->device_list, dev_path)))
				network_device_set_act_stage (dev, stage);
		}
	}
	else
		handled = FALSE;

	return (handled ? DBUS_HANDLER_RESULT_HANDLED : DBUS_HANDLER_RESULT_NOT_YET_HANDLED);
}


/*
 * nmwa_dbus_nm_is_running
 *
 * Ask dbus whether or not NetworkManager is running
 *
 */
static gboolean nmwa_dbus_nm_is_running (DBusConnection *connection)
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
 * nmwa_dbus_init
 *
 * Initialize a connection to NetworkManager if we can get one
 *
 */
static DBusConnection * nmwa_dbus_init (NMWirelessApplet *applet)
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
	acquisition = dbus_bus_request_name (connection, NMI_DBUS_SERVICE, DBUS_NAME_FLAG_PROHIBIT_REPLACEMENT, &error);
	if (dbus_error_is_set (&error))
	{
		nm_warning ("nmwa_dbus_init() could not acquire its service.  dbus_bus_acquire_service() says: '%s'", error.message);
		dbus_error_free (&error);
		return NULL;
	}
	if (acquisition == DBUS_REQUEST_NAME_REPLY_EXISTS)
	     return NULL;

	if (!dbus_connection_register_object_path (connection, NMI_DBUS_PATH, &vtable, applet))
	{
		nm_warning ("nmwa_dbus_init() could not register a handler for NetworkManagerInfo.  Not enough memory?");
		return NULL;
	}

	if (!dbus_connection_add_filter (connection, nmwa_dbus_filter, applet, NULL))
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
 * nmwa_dbus_connection_watcher
 *
 * Try to reconnect if we ever get disconnected from the bus
 *
 */
static gboolean nmwa_dbus_connection_watcher (gpointer user_data)
{
	NMWirelessApplet	*applet = (NMWirelessApplet *)user_data;

	g_return_val_if_fail (applet != NULL, TRUE);

	if (!applet->connection)
	{
		if ((applet->connection = nmwa_dbus_init (applet)))
		{
			applet->nm_running = nmwa_dbus_nm_is_running (applet->connection);
			applet->nm_state = NM_STATE_DISCONNECTED;
			nmwa_dbus_update_nm_state (applet);
			nmwa_dbus_update_devices (applet);
			nmwa_dbus_update_dialup (applet);
			nmwa_dbus_vpn_update_vpn_connections (applet);
		}
	}

	return (TRUE);
}


/*
 * nmwa_dbus_worker
 *
 * Thread worker function that periodically grabs the NetworkManager state
 * and updates our local applet state to reflect that.
 *
 */
void nmwa_dbus_init_helper (NMWirelessApplet *applet)
{
	GSource *			timeout_source;
	GSource *			strength_source;

	g_return_if_fail (applet != NULL);

	dbus_g_thread_init ();

	applet->connection = nmwa_dbus_init (applet);

	timeout_source = g_timeout_source_new (2000);
	g_source_set_callback (timeout_source, nmwa_dbus_connection_watcher, applet, NULL);
	g_source_attach (timeout_source, NULL);

	strength_source = g_timeout_source_new (2000);
	g_source_set_callback (strength_source, (GSourceFunc) nmwa_dbus_update_device_strength, applet, NULL);
	g_source_attach (strength_source, NULL);

	if (applet->connection && nmwa_dbus_nm_is_running (applet->connection))
	{
		applet->nm_running = TRUE;
		nmwa_dbus_update_nm_state (applet);
		nmwa_dbus_update_devices (applet);
		nmwa_dbus_update_dialup (applet);
		nmwa_dbus_vpn_update_vpn_connections (applet);
	}
}
