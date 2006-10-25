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


/*
 * nma_dbus_filter
 *
 */
static DBusHandlerResult nma_dbus_filter (DBusConnection *connection, DBusMessage *message, void *user_data)
{
	NMApplet *	applet = (NMApplet *)user_data;
	gboolean		handled = TRUE;
	const char *	object_path;
	const char *	member;
	const char *	interface;

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

	if (dbus_message_is_signal (message, DBUS_INTERFACE_LOCAL, "Disconnected"))
	{
		dbus_connection_unref (applet->connection);
		applet->connection = NULL;
		nma_set_running (applet, FALSE);
		if (!applet->connection_timeout_id)
			nma_start_dbus_connection_watch (applet);
	}
	else if (dbus_message_is_signal (message, DBUS_INTERFACE_DBUS, "NameOwnerChanged"))
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
					nma_set_running (applet, TRUE);
					nma_set_state (applet, NM_STATE_DISCONNECTED);

					nma_dbus_update_nm_state (applet);
					nma_dbus_update_devices (applet);
					nma_dbus_update_dialup (applet);
					nma_dbus_vpn_update_vpn_connections (applet);

					/* Immediate redraw */
					nma_update_state (applet);
				}
				else if (old_owner_good && !new_owner_good)
				{
					nma_set_state (applet, NM_STATE_DISCONNECTED);
					nma_set_running (applet, FALSE);
					nmi_passphrase_dialog_destroy (applet);

					/* One last redraw to capture new state before sleeping */
					nma_update_state (applet);
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
	dbus_bool_t			success = FALSE;

	g_return_val_if_fail (applet != NULL, NULL);

	dbus_error_init (&error);
	connection = dbus_bus_get (DBUS_BUS_SYSTEM, &error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("%s raised:\n %s\n\n", error.name, error.message);
		goto error;
	}

	dbus_error_init (&error);
	acquisition = dbus_bus_request_name (connection,
	                                     NMI_DBUS_SERVICE,
	                                     DBUS_NAME_FLAG_REPLACE_EXISTING,
	                                     &error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("could not acquire its service.  dbus_bus_acquire_service()"
		            " says: '%s'",
		            error.message);
		goto error;
	}
	if (acquisition == DBUS_REQUEST_NAME_REPLY_EXISTS)
		goto error;

	success = dbus_connection_register_object_path (connection,
	                                                NMI_DBUS_PATH,
	                                                &vtable,
	                                                applet);
	if (!success) {
		nm_warning ("could not register a messgae handler for the"
		            " NetworkManagerInfo service.  Not enough memory?");
		goto error;
	}

	success = dbus_connection_add_filter (connection, nma_dbus_filter, applet, NULL);
	if (!success)
		goto error;

	dbus_connection_set_exit_on_disconnect (connection, FALSE);
	dbus_connection_setup_with_g_main (connection, NULL);

	dbus_error_init (&error);
	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" DBUS_INTERFACE_DBUS "',"
				"sender='" DBUS_SERVICE_DBUS "'",
				&error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("Could not register signal handlers.  '%s'",
		            error.message);
		goto error;
	}

	dbus_error_init (&error);
	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" NM_DBUS_INTERFACE "',"
				"path='" NM_DBUS_PATH "',"
				"sender='" NM_DBUS_SERVICE "'",
				&error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("Could not register signal handlers.  '%s'",
		            error.message);
		goto error;
	}

	dbus_error_init (&error);
	dbus_bus_add_match(connection,
				"type='signal',"
				"interface='" NM_DBUS_INTERFACE_VPN "',"
				"path='" NM_DBUS_PATH_VPN "',"
				"sender='" NM_DBUS_SERVICE "'",
				&error);
	if (dbus_error_is_set (&error)) {
		nm_warning ("Could not register signal handlers.  '%s'",
		            error.message);
		goto error;
	}

	return connection;

error:
	if (dbus_error_is_set (&error))
		dbus_error_free (&error);
	if (connection)
		dbus_connection_unref (connection);
	return NULL;
}


/*
 * nma_dbus_connection_watcher
 *
 * Try to reconnect if we ever get disconnected from the bus
 *
 */
static gboolean
nma_dbus_connection_watcher (gpointer user_data)
{
	NMApplet * applet = (NMApplet *)user_data;

	g_return_val_if_fail (applet != NULL, TRUE);

	nma_dbus_init_helper (applet);
	if (applet->connection) {
		applet->connection_timeout_id = 0;
		return FALSE;  /* Remove timeout */
	}

	return TRUE;
}


void
nma_start_dbus_connection_watch (NMApplet *applet)
{
	if (applet->connection_timeout_id)
		g_source_remove (applet->connection_timeout_id);

	applet->connection_timeout_id = g_timeout_add (5000,
	                                               (GSourceFunc) nma_dbus_connection_watcher,
	                                               applet);
}


/*
 * nma_dbus_init_helper
 *
 * Set up the applet's NMI dbus methods and dbus connection
 *
 */
void
nma_dbus_init_helper (NMApplet *applet)
{
	g_return_if_fail (applet != NULL);

	applet->connection = nma_dbus_init (applet);
	if (applet->connection) {
		if (applet->connection_timeout_id) {
			g_source_remove (applet->connection_timeout_id);
			applet->connection_timeout_id = 0;
		}

		if (nma_dbus_nm_is_running (applet->connection)) {
			nma_set_running (applet, TRUE);
			nma_dbus_update_nm_state (applet);
			nma_dbus_update_devices (applet);
			nma_dbus_update_dialup (applet);
			nma_dbus_vpn_update_vpn_connections (applet);

			/* Immediate redraw */
			nma_update_state (applet);
		}
	}
}
