/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
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

#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/select.h>

#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerAP.h"
#include "nm-activation-request.h"
#include "nm-utils.h"
#include "nm-device-interface.h"
#include "nm-device-802-11-wireless.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-dbus-manager.h"
#include "nm-setting-connection.h"
#include "NetworkManagerSystem.h"

struct NMPolicy {
	NMManager *manager;
	guint device_state_changed_idle_id;
	GSList *signal_ids;
};

#define INVALID_TAG "invalid"

static void schedule_change_check (NMPolicy *policy);

static const char *
get_connection_id (NMConnection *connection)
{
	NMSettingConnection *s_con;

	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
	g_return_val_if_fail (s_con != NULL, NULL);

	return s_con->id;
}

/*
 * nm_policy_auto_get_best_device
 *
 * Find the best device to use, regardless of whether we are
 * "locked" on one device at this time.
 *
 */
static NMDevice *
nm_policy_auto_get_best_device (NMPolicy *policy,
                                NMConnection **connection,
                                char **specific_object)
{
	GSList *connections;
	GSList *				elt;
	NMDevice8023Ethernet *	best_wired_dev = NULL;
	guint				best_wired_prio = 0;
	NMConnection * best_wired_connection = NULL;
	char * best_wired_specific_object = NULL;
	NMDevice80211Wireless *	best_wireless_dev = NULL;
	guint				best_wireless_prio = 0;
	NMConnection * best_wireless_connection = NULL;
	char * best_wireless_specific_object = NULL;
	NMDevice *			highest_priority_dev = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (*connection == NULL, NULL);
	g_return_val_if_fail (specific_object != NULL, NULL);
	g_return_val_if_fail (*specific_object == NULL, NULL);

	if (nm_manager_get_state (policy->manager) == NM_STATE_ASLEEP)
		return NULL;

	/* System connections first, then user connections */
	connections = nm_manager_get_connections (policy->manager, NM_CONNECTION_SCOPE_SYSTEM);
	connections = g_slist_concat (connections, nm_manager_get_connections (policy->manager, NM_CONNECTION_SCOPE_USER));

	/* Remove connections that are in the invalid list. */
	elt = connections;
	while (elt) {
		NMConnection *iter_connection = NM_CONNECTION (elt->data);
		GSList *next = g_slist_next (elt);

		if (g_object_get_data (G_OBJECT (iter_connection), INVALID_TAG)) {
			connections = g_slist_remove_link (connections, elt);
			g_object_unref (iter_connection);
			g_slist_free (elt);
		}
		elt = next;
	}

	for (elt = nm_manager_get_devices (policy->manager); elt; elt = elt->next) {
		NMConnection *tmp_con = NULL;
		char *tmp_obj = NULL;
		gboolean link_active;
		guint prio = 0;
		NMDevice * dev = (NMDevice *)(elt->data);
		guint32 caps;

		link_active = nm_device_has_active_link (dev);
		caps = nm_device_get_capabilities (dev);

		tmp_con = nm_device_get_best_connection (dev, connections, &tmp_obj);
		if (tmp_con == NULL) {
			NMActRequest *req = nm_device_get_act_request (dev);

			/* If the device is activating, the NMConnection it's got is the
			 * best one.  In other words, follow activation of a particular
			 * NMConnection through to success/failure rather than cutting it
			 * off if it becomes invalid
			 */
			tmp_con = req ? nm_act_request_get_connection (req) : NULL;
			if (!tmp_con)
				continue;
		}

		if (NM_IS_DEVICE_802_3_ETHERNET (dev)) {
			if (link_active)
				prio += 1;

			if (nm_device_get_act_request (dev) && link_active)
				prio += 1;

			if (prio > best_wired_prio) {
				best_wired_dev = NM_DEVICE_802_3_ETHERNET (dev);
				best_wired_prio = prio;
				best_wired_connection = tmp_con;
				best_wired_specific_object = tmp_obj;
			}
		} else if (   NM_IS_DEVICE_802_11_WIRELESS (dev)
		           && nm_manager_wireless_enabled (policy->manager)) {
			/* Bump by 1 so that _something_ gets chosen every time */
			prio += 1;

			if (link_active)
				prio += 1;

			if (nm_device_get_act_request (dev) && link_active)
				prio += 3;

			if (prio > best_wireless_prio) {
				best_wireless_dev = NM_DEVICE_802_11_WIRELESS (dev);
				best_wireless_prio = prio;
				best_wireless_connection = tmp_con;
				best_wireless_specific_object = tmp_obj;
			}
		}
	}

	if (best_wired_dev) {
		highest_priority_dev = NM_DEVICE (best_wired_dev);
		*connection = g_object_ref (best_wired_connection);
		*specific_object = best_wired_specific_object;
	} else if (best_wireless_dev) {
		gboolean can_activate;

		can_activate = nm_device_802_11_wireless_can_activate (best_wireless_dev);
		if (can_activate) {
			highest_priority_dev = NM_DEVICE (best_wireless_dev);
			*connection = g_object_ref (best_wireless_connection);
			*specific_object = best_wireless_specific_object;
		}
	}

	g_slist_foreach (connections, (GFunc) g_object_unref, NULL);
	g_slist_free (connections);

	if (FALSE) {
		nm_info ("AUTO: Best wired device = %s, best wireless device = %s, best connection name = '%s'",
		         best_wired_dev ? nm_device_get_iface (NM_DEVICE (best_wired_dev)) : "(null)",
		         best_wireless_dev ? nm_device_get_iface (NM_DEVICE (best_wireless_dev)) : "(null)",
		         *connection ? get_connection_id (*connection) : "(none)");
	}

	return *connection ? highest_priority_dev : NULL;
}

/*
 * nm_policy_device_change_check
 *
 * Figures out which interface to switch the active
 * network connection to if our global network state has changed.
 * Global network state changes are triggered by:
 *    1) insertion/deletion of interfaces
 *    2) link state change of an interface
 *    3) wireless network topology changes
 *
 */
static gboolean
nm_policy_device_change_check (gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	GSList *iter;
	guint32 caps;
	NMConnection *connection = NULL;
	NMConnection *old_connection = NULL;
	NMActRequest *old_act_req = NULL;
	char * specific_object = NULL;
	NMDevice * new_dev = NULL;
	NMDevice * old_dev = NULL;
	gboolean do_switch = FALSE;

	policy->device_state_changed_idle_id = 0;

	switch (nm_manager_get_state (policy->manager)) {
	case NM_STATE_CONNECTED:
		old_dev = nm_manager_get_active_device (policy->manager);

		/* Don't touch devices that are not upped/downed automatically */
		if (!NM_IS_DEVICE_802_3_ETHERNET (old_dev) && !NM_IS_DEVICE_802_11_WIRELESS (old_dev))
			goto out;

		caps = nm_device_get_capabilities (old_dev);

		/* Don't interrupt semi-supported devices.  If the user chose
		 * one, they must explicitly choose to move to another device, we're not
		 * going to move for them.
		 */
		if ((NM_IS_DEVICE_802_3_ETHERNET (old_dev) && !(caps & NM_DEVICE_CAP_CARRIER_DETECT))) {
			nm_info ("Old device '%s' was semi-supported and user chosen, won't"
			         " change unless told to.",
			         nm_device_get_iface (old_dev));
			goto out;
		}
		break;
	case NM_STATE_CONNECTING:
		for (iter = nm_manager_get_devices (policy->manager); iter; iter = iter->next) {
			NMDevice *d = NM_DEVICE (iter->data);

			if (nm_device_is_activating (d)) {
				if (nm_device_can_interrupt_activation (d)) {
					old_dev = d;
					break;
				} else
					goto out;
			}
		}
		break;
	case NM_STATE_DISCONNECTED:
		if (nm_manager_activation_pending (policy->manager)) {
			nm_info ("There is a pending activation, won't change.");
			goto out;
		}
		break;
	default:
		break;
	}

	new_dev = nm_policy_auto_get_best_device (policy, &connection, &specific_object);

	if (old_dev) {
		old_act_req = nm_device_get_act_request (old_dev);
		if (old_act_req)
			old_connection = nm_act_request_get_connection (old_act_req);
 	}

	/* Four cases here:
	 *
	 * 1) old device is NULL, new device is NULL - we aren't currently connected to anything, and we
	 *		can't find anything to connect to.  Do nothing.
	 *
	 * 2) old device is NULL, new device is good - we aren't currently connected to anything, but
	 *		we have something we can connect to.  Connect to it.
	 *
	 * 3) old device is good, new device is NULL - have a current connection, but it's no good since
	 *		auto device picking didn't come up with the save device.  Terminate current connection.
	 *
	 * 4) old device is good, new device is good - have a current connection, and auto device picking
	 *		came up with a device too.  More considerations:
	 *		a) different devices?  activate new device
	 *		b) same device, different access points?  activate new device
	 *		c) same device, same access point?  do nothing
	 */

	if (!old_dev && !new_dev) {
		; /* Do nothing, wait for something like link-state to change, or an access point to be found */
	} else if (!old_dev && new_dev) {
		/* Activate new device */
		nm_info ("SWITCH: no current connection, found better connection '%s (%s)'.",
		         connection ? get_connection_id (connection) : "(none)",
		         nm_device_get_iface (new_dev));
		do_switch = TRUE;
	} else if (old_dev && !new_dev) {
		/* Terminate current connection */
		nm_info ("SWITCH: terminating current connection '%s (%s)' because it's"
		         " no longer valid.",
		         old_connection ? get_connection_id (old_connection) : "(none)",
		         nm_device_get_iface (old_dev));
		do_switch = TRUE;
	} else if (old_dev && new_dev) {
		gboolean old_user_requested = nm_act_request_get_user_requested (old_act_req);
		gboolean old_has_link = nm_device_has_active_link (old_dev);

		/* If an old device is active or being activated, and its connection is
		 * a system connection, and the best connection is a user connection,
		 * don't switch.
		 */
		if (   old_connection
		    && (nm_manager_get_connection_scope (old_connection) == NM_CONNECTION_SCOPE_SYSTEM)
		    && (nm_manager_get_connection_scope (connection) == NM_CONNECTION_SCOPE_USER))
			goto out;

		if (   (nm_manager_get_connection_scope (connection) == NM_CONNECTION_SCOPE_SYSTEM)
		    && (nm_manager_get_connection_scope (old_connection) == NM_CONNECTION_SCOPE_USER)) {
			do_switch = TRUE;
			nm_info ("SWITCH: found system connection '%s (%s)', overrides"
			         " current connection '%s (%s)'.",
			         connection ? get_connection_id (connection) : "(none)",
			         nm_device_get_iface (new_dev),
			         old_connection ? get_connection_id (old_connection) : "(none)",
			         nm_device_get_iface (old_dev));
			goto do_switch;
		}

		if (NM_IS_DEVICE_802_3_ETHERNET (old_dev)) {
			/* Only switch if the old device was not user requested, and we are switching to
			 * a new device.  Note that new_dev will never be wireless since automatic device picking
			 * above will prefer a wired device to a wireless device.
			 */
			if ((!old_user_requested || !old_has_link) && (new_dev != old_dev)) {
				nm_info ("SWITCH: found better connection '%s (%s)' than "
				         " current connection '%s (%s)'.",
				         connection ? get_connection_id (connection) : "(none)",
				         nm_device_get_iface (new_dev),
				         old_connection ? get_connection_id (old_connection) : "(none)",
				         nm_device_get_iface (old_dev));
				do_switch = TRUE;
			}
		} else if (NM_IS_DEVICE_802_11_WIRELESS (old_dev)) {
			/* Only switch if the old device's wireless config is invalid */
			if (NM_IS_DEVICE_802_11_WIRELESS (new_dev)) {
				NMAccessPoint *old_ap = nm_device_802_11_wireless_get_activation_ap (NM_DEVICE_802_11_WIRELESS (old_dev));
				int old_mode = nm_ap_get_mode (old_ap);
				gboolean same_activating = FALSE;

				/* Don't interrupt activation of a wireless device by
				 * trying to auto-activate any connection on that device.
				 */
				if (old_dev == new_dev && nm_device_is_activating (new_dev))
					same_activating = TRUE;

				if (!same_activating && !old_has_link && (old_mode != IW_MODE_ADHOC)) {
					NMSettingConnection * new_sc = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
					NMSettingConnection * old_sc = (NMSettingConnection *) nm_connection_get_setting (old_connection, NM_TYPE_SETTING_CONNECTION);

					nm_info ("SWITCH: found better connection '%s/%s'"
					         " than current connection '%s/%s'.  "
					         "have_link=%d",
					         nm_device_get_iface (new_dev),
					         new_sc->id,
					         nm_device_get_iface (old_dev),
					         old_sc->id,
					         old_has_link);
					do_switch = TRUE;
				}
			} else if (NM_IS_DEVICE_802_3_ETHERNET (new_dev)) {
				/* Always prefer Ethernet over wireless, unless the user explicitly switched away. */
 				if (!old_user_requested)
					do_switch = TRUE;
			}
		}
	}

do_switch:
	if (do_switch) {
		// FIXME: remove old_dev deactivation when multiple device support lands
		if (old_dev)
			nm_device_interface_deactivate (NM_DEVICE_INTERFACE (old_dev));

		if (new_dev) {
			GError *error = NULL;
			gboolean success;

			success = nm_manager_activate_device (policy->manager,
			                                      new_dev,
			                                      connection,
			                                      specific_object,
			                                      FALSE,
			                                      &error);
			if (!success) {
				nm_warning ("Failed to automatically activate device %s: (%d) %s",
				            nm_device_get_iface (new_dev),
				            error->code,
				            error->message);
				g_error_free (error);
			}
		}
	}

out:
	if (connection)
		g_object_unref (connection);
	return FALSE;
}


/*****************************************************************************/

static void
global_state_changed (NMManager *manager, NMState state, gpointer user_data)
{
	if (state == NM_STATE_CONNECTED)
		nm_system_restart_mdns_responder ();
}

static void
schedule_change_check (NMPolicy *policy)
{
	if (policy->device_state_changed_idle_id > 0)
		return;

	policy->device_state_changed_idle_id = g_idle_add (nm_policy_device_change_check,
	                                                   policy);
}

static NMConnection *
get_device_connection (NMDevice *device)
{
	NMActRequest *req;

	req = nm_device_get_act_request (device);
	if (!req)
		return NULL;

	return nm_act_request_get_connection (req);
}

static void
device_state_changed (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	NMConnection *connection = get_device_connection (device);

	if ((state == NM_DEVICE_STATE_FAILED) || (state == NM_DEVICE_STATE_CANCELLED)) {
		schedule_change_check (policy);

		/* Mark the connection invalid so it doesn't get automatically chosen */
		if (connection) {
			g_object_set_data (G_OBJECT (connection), INVALID_TAG, GUINT_TO_POINTER (TRUE));
			nm_info ("Marking connection '%s' invalid.", get_connection_id (connection));
		}
	} else if (state == NM_DEVICE_STATE_ACTIVATED) {
		/* Clear the invalid tag on the connection */
		if (connection)
			g_object_set_data (G_OBJECT (connection), INVALID_TAG, NULL);
	} else if (state == NM_DEVICE_STATE_DISCONNECTED) {
		schedule_change_check (policy);
	}
}

static void
device_carrier_changed (NMDevice *device, gboolean carrier_on, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	schedule_change_check (policy);
}

static void
wireless_networks_changed (NMDevice80211Wireless *device, NMAccessPoint *ap, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	schedule_change_check (policy);
}

static void
device_added (NMManager *manager, NMDevice *device, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	g_signal_connect (device, "state-changed",
					  G_CALLBACK (device_state_changed),
					  policy);

	g_signal_connect (device, "carrier-changed",
					  G_CALLBACK (device_carrier_changed),
					  policy);

	if (NM_IS_DEVICE_802_11_WIRELESS (device)) {
		g_signal_connect (device, "access-point-added",
						  G_CALLBACK (wireless_networks_changed),
						  policy);
		g_signal_connect (device, "access-point-removed",
						  G_CALLBACK (wireless_networks_changed),
						  policy);
	}

	schedule_change_check (policy);
}

static void
device_removed (NMManager *manager, NMDevice *device, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	schedule_change_check (policy);
}

static void
connections_added (NMManager *manager,
                   NMConnectionScope scope,
                   gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	schedule_change_check (policy);
}

static void
connection_added (NMManager *manager,
                  NMConnection *connection,
                  NMConnectionScope scope,
                  gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	schedule_change_check (policy);
}

static void
connection_updated (NMManager *manager,
                    NMConnection *connection,
                    NMConnectionScope scope,
                    gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	/* Clear the invalid tag on the connection if it got updated. */
	g_object_set_data (G_OBJECT (connection), INVALID_TAG, NULL);

	schedule_change_check (policy);
}

static void
connection_removed (NMManager *manager,
                    NMConnection *connection,
                    NMConnectionScope scope,
                    gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	GSList *iter;

	/* If the connection just removed was active, deactive it */
	for (iter = nm_manager_get_devices (manager); iter; iter = g_slist_next (iter)) {
		NMDevice *device = (NMDevice *) iter->data;
		NMActRequest *req = nm_device_get_act_request (device);
		NMConnection *dev_connection;

		if (!req)
			continue;

		dev_connection = nm_act_request_get_connection (req);
		if (dev_connection == connection)
			nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));
	}

	schedule_change_check (policy);
}

NMPolicy *
nm_policy_new (NMManager *manager)
{
	NMPolicy *policy;
	static gboolean initialized = FALSE;
	gulong id;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (initialized == FALSE, NULL);

	policy = g_malloc0 (sizeof (NMPolicy));
	policy->manager = g_object_ref (manager);
	policy->device_state_changed_idle_id = 0;

	id = g_signal_connect (manager, "state-change",
	                       G_CALLBACK (global_state_changed), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "device-added",
	                       G_CALLBACK (device_added), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "device-removed",
	                       G_CALLBACK (device_removed), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	/* Large batch of connections added, manager doesn't want us to
	 * process each one individually.
	 */
	id = g_signal_connect (manager, "connections-added",
	                       G_CALLBACK (connections_added), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	/* Single connection added */
	id = g_signal_connect (manager, "connection-added",
	                       G_CALLBACK (connection_added), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "connection-updated",
	                       G_CALLBACK (connection_updated), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	id = g_signal_connect (manager, "connection-removed",
	                       G_CALLBACK (connection_removed), policy);
	policy->signal_ids = g_slist_append (policy->signal_ids, (gpointer) id);

	return policy;
}

void
nm_policy_destroy (NMPolicy *policy)
{
	GSList *iter;

	g_return_if_fail (policy != NULL);

	if (policy->device_state_changed_idle_id) {
		g_source_remove (policy->device_state_changed_idle_id);
		policy->device_state_changed_idle_id = 0;
	}

	for (iter = policy->signal_ids; iter; iter = g_slist_next (iter))
		g_signal_handler_disconnect (policy->manager, (gulong) iter->data);
	g_slist_free (policy->signal_ids);

	g_object_unref (policy->manager);
	g_free (policy);
}

