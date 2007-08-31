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
#include "NetworkManagerAPList.h"
#include "nm-activation-request.h"
#include "nm-utils.h"
#include "nm-device-interface.h"
#include "nm-device-802-11-wireless.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-dbus-manager.h"
#include "nm-setting.h"

struct NMPolicy {
	NMManager *manager;
	guint device_state_changed_idle_id;
};

static void schedule_change_check (NMPolicy *policy);

/* NMPolicy is supposed to be one of the highest classes of the
   NM class hierarchy and the only public API it needs is:
   NMPolicy *nm_policy_new (NMManager *manager);
   void nm_policy_destroy (NMPolicy *policy);

   Until this hasn't fixed, keep the global policy around.
*/
static NMPolicy *global_policy;


/*
 * nm_policy_auto_get_best_device
 *
 * Find the best device to use, regardless of whether we are
 * "locked" on one device at this time.
 *
 */
static NMDevice * nm_policy_auto_get_best_device (NMPolicy *policy, NMAccessPoint **ap)
{
	GSList *				elt;
	NMDevice8023Ethernet *	best_wired_dev = NULL;
	guint				best_wired_prio = 0;
	NMDevice80211Wireless *	best_wireless_dev = NULL;
	guint				best_wireless_prio = 0;
	NMDevice *			highest_priority_dev = NULL;

	g_return_val_if_fail (ap != NULL, NULL);

	if (nm_manager_get_state (policy->manager) == NM_STATE_ASLEEP)
		return NULL;

	for (elt = nm_manager_get_devices (policy->manager); elt; elt = elt->next) {
		gboolean		link_active;
		guint		prio = 0;
		NMDevice *	dev = (NMDevice *)(elt->data);
		guint32		caps;

		link_active = nm_device_has_active_link (dev);
		caps = nm_device_get_capabilities (dev);

		/* Don't use devices that SUCK */
		if (!(caps & NM_DEVICE_CAP_NM_SUPPORTED))
			continue;

		if (NM_IS_DEVICE_802_3_ETHERNET (dev)) {
			/* We never automatically choose devices that don't support carrier detect */
			if (!(caps & NM_DEVICE_CAP_CARRIER_DETECT))
				continue;

			if (link_active)
				prio += 1;

			if (nm_device_get_act_request (dev) && link_active)
				prio += 1;

			if (prio > best_wired_prio)
			{
				best_wired_dev = NM_DEVICE_802_3_ETHERNET (dev);
				best_wired_prio = prio;
			}
		}
		else if (NM_IS_DEVICE_802_11_WIRELESS (dev) &&
				 nm_manager_wireless_enabled (policy->manager)) {
			/* Bump by 1 so that _something_ gets chosen every time */
			prio += 1;

			if (link_active)
				prio += 1;

			if (nm_device_get_act_request (dev) && link_active)
				prio += 3;

			if (prio > best_wireless_prio)
			{
				best_wireless_dev = NM_DEVICE_802_11_WIRELESS (dev);
				best_wireless_prio = prio;
			}
		}
	}

	if (best_wired_dev)
		highest_priority_dev = NM_DEVICE (best_wired_dev);
	else if (best_wireless_dev)
	{
		gboolean can_activate;

		can_activate = nm_device_802_11_wireless_can_activate (best_wireless_dev);

		*ap = nm_device_802_11_wireless_get_best_ap (best_wireless_dev);
		/* If the device doesn't have a "best" ap, then we can't use it */
		if (!*ap)
			highest_priority_dev = NULL;
		else if (can_activate == TRUE)
			highest_priority_dev = NM_DEVICE (best_wireless_dev);
	}

	if (FALSE) {
		const GByteArray * ssid = (best_wireless_dev && *ap) ? nm_ap_get_ssid (*ap) : NULL;

		nm_info ("AUTO: Best wired device = %s, best wireless device = %s (%s)",
		         best_wired_dev ? nm_device_get_iface (NM_DEVICE (best_wired_dev)) : "(null)",
		         best_wireless_dev ? nm_device_get_iface (NM_DEVICE (best_wireless_dev)) : "(null)",
		         ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "null" );
	}

	return highest_priority_dev;
}

static NMConnection *
create_connection (NMDevice *device, NMAccessPoint *ap)
{
	NMConnection *connection = NULL;
	NMSetting *setting = NULL;

	if (NM_IS_DEVICE_802_3_ETHERNET (device)) {
		nm_info ("Will activate connection '%s'.", nm_device_get_iface (device));
		setting = nm_setting_wired_new ();
	} else if (NM_IS_DEVICE_802_11_WIRELESS (device) && ap) {
		NMSettingWireless *wireless;
		const GByteArray * ssid = nm_ap_get_ssid (ap);

		nm_info ("Will activate connection '%s/%s'.",
				 nm_device_get_iface (device),
		         ssid ? nm_utils_escape_ssid (ssid->data, ssid->len) : "(none)");

		setting = nm_setting_wireless_new ();
		wireless = (NMSettingWireless *) setting;

		wireless->ssid = g_byte_array_sized_new (ssid->len);
		g_byte_array_append (wireless->ssid, ssid->data, ssid->len);

		wireless->mode = g_strdup ("infrastructure");
	} else {
		nm_warning ("Unhandled device type '%s'", G_OBJECT_CLASS_NAME (device));
	}

	if (setting) {
		NMSettingConnection *scon;

		connection = nm_connection_new ();
		nm_connection_add_setting (connection, setting);

		scon = (NMSettingConnection *) nm_setting_connection_new ();
		scon->name = g_strdup ("Auto");
		scon->devtype = g_strdup (setting->name);
		nm_connection_add_setting (connection, (NMSetting *) scon);
	}

	return connection;
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
	NMAccessPoint * ap = NULL;
	NMDevice *      new_dev = NULL;
	NMDevice *      old_dev = NULL;
	gboolean        do_switch = FALSE;

	switch (nm_manager_get_state (policy->manager)) {
	case NM_STATE_CONNECTED:
		old_dev = nm_manager_get_active_device (policy->manager);
		break;
	case NM_STATE_CONNECTING:
		for (iter = nm_manager_get_devices (policy->manager); iter; iter = iter->next) {
			if (nm_device_is_activating (NM_DEVICE (iter->data))) {
				old_dev = NM_DEVICE (iter->data);
				break;
			}
		}
		break;
	default:
		break;
	}

	if (old_dev) {
		guint32 caps = nm_device_get_capabilities (old_dev);

		/* Don't interrupt a currently activating device. */
		if (   nm_device_is_activating (old_dev)
		    && !nm_device_can_interrupt_activation (old_dev)) {
			nm_info ("Old device '%s' activating, won't change.", nm_device_get_iface (old_dev));
			goto out;
		}

		/* Don't interrupt semi-supported devices either.  If the user chose
		 * one, they must explicitly choose to move to another device, we're not
		 * going to move for them.
		 */
		if (    (NM_IS_DEVICE_802_3_ETHERNET (old_dev)
		    && !(caps & NM_DEVICE_CAP_CARRIER_DETECT))) {
			nm_info ("Old device '%s' was semi-supported and user chosen, won't"
			         " change unless told to.",
			         nm_device_get_iface (old_dev));
			goto out;
		}
	}

	new_dev = nm_policy_auto_get_best_device (policy, &ap);

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
		nm_info ("SWITCH: no current connection, found better connection '%s'.", nm_device_get_iface (new_dev));
		do_switch = TRUE;
	} else if (old_dev && !new_dev) {
		/* Terminate current connection */
		nm_info ("SWITCH: terminating current connection '%s' because it's no longer valid.", nm_device_get_iface (old_dev));
		do_switch = TRUE;
	} else if (old_dev && new_dev) {
		NMActRequest *	old_act_req = nm_device_get_act_request (old_dev);
		gboolean		old_user_requested = nm_act_request_get_user_requested (old_act_req);
		gboolean		old_has_link = nm_device_has_active_link (old_dev);

		if (NM_IS_DEVICE_802_3_ETHERNET (old_dev)) {
			/* Only switch if the old device was not user requested, and we are switching to
			 * a new device.  Note that new_dev will never be wireless since automatic device picking
			 * above will prefer a wired device to a wireless device.
			 */
			if ((!old_user_requested || !old_has_link) && (new_dev != old_dev)) {
				nm_info ("SWITCH: found better connection '%s' than current "
				         "connection '%s'.",
				         nm_device_get_iface (new_dev),
				         nm_device_get_iface (old_dev));
				do_switch = TRUE;
			}
		} else if (NM_IS_DEVICE_802_11_WIRELESS (old_dev)) {
			/* Only switch if the old device's wireless config is invalid */
			if (NM_IS_DEVICE_802_11_WIRELESS (new_dev)) {
				NMAccessPoint *old_ap = nm_device_802_11_wireless_get_activation_ap (NM_DEVICE_802_11_WIRELESS (old_dev));
				const GByteArray * old_ssid = nm_ap_get_ssid (old_ap);
				int			old_mode = nm_ap_get_mode (old_ap);
				const GByteArray * new_ssid = nm_ap_get_ssid (ap);
				gboolean		same_request = FALSE;

				/* Schedule new activation if the currently associated
				 * access point is not the "best" one or we've lost the
				 * link to the old access point.  We don't switch away
				 * from Ad-Hoc APs either.
				 */
				gboolean same_ssid = nm_utils_same_ssid (old_ssid, new_ssid, TRUE);

				/* If the "best" AP's SSID is the same as the current activation
				 * request's SSID, but the current activation request isn't
				 * done yet, don't switch.  This prevents multiple requests for the
				 * AP's password on startup.
				 */
				if ((old_dev == new_dev) && nm_device_is_activating (new_dev) && same_ssid)
					same_request = TRUE;

				if (!same_request && (!same_ssid || !old_has_link) && (old_mode != IW_MODE_ADHOC)) {
					char * new_esc_ssid;
					char * old_esc_ssid;

					new_esc_ssid = g_strdup (new_ssid ? nm_utils_escape_ssid (new_ssid->data, new_ssid->len) : "(none)");
					old_esc_ssid = g_strdup (old_ssid ? nm_utils_escape_ssid (old_ssid->data, old_ssid->len) : "(none)");
					nm_info ("SWITCH: found better connection '%s/%s'"
					         " than current connection '%s/%s'.  "
					         "same_ssid=%d, have_link=%d",
					         nm_device_get_iface (new_dev),
					         new_esc_ssid,
					         nm_device_get_iface (old_dev),
					         old_esc_ssid,
					         same_ssid, old_has_link);
					g_free (new_esc_ssid);
					g_free (old_esc_ssid);
					do_switch = TRUE;
				}
			} else if (NM_IS_DEVICE_802_3_ETHERNET (new_dev)) {
				/* Always prefer Ethernet over wireless, unless the user explicitly switched away. */
 				if (!old_user_requested)
					do_switch = TRUE;
			}
		}
	}

	if (do_switch) {
		if (old_dev) {
			nm_device_interface_deactivate (NM_DEVICE_INTERFACE (old_dev));
		}

		if (new_dev) {
	 		NMConnection *connection;

			connection = create_connection (new_dev, ap);
			if (connection)
				nm_device_interface_activate (NM_DEVICE_INTERFACE (new_dev),
											  connection, NULL, FALSE);
		}
	}

	if (ap)
		g_object_unref (ap);

out:
	return FALSE;
}


/*****************************************************************************/

static void
device_change_check_done (gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;
	policy->device_state_changed_idle_id = 0;
}

static void
schedule_change_check (NMPolicy *policy)
{
	if (policy->device_state_changed_idle_id > 0)
		return;

	policy->device_state_changed_idle_id = g_idle_add_full (G_PRIORITY_DEFAULT_IDLE,
															nm_policy_device_change_check,
															policy,
															device_change_check_done);
}

static void
device_state_changed (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	if (state == NM_DEVICE_STATE_FAILED || state == NM_DEVICE_STATE_CANCELLED)
		schedule_change_check (policy);
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
		g_signal_connect (device, "network-added",
						  G_CALLBACK (wireless_networks_changed),
						  policy);
		g_signal_connect (device, "network-removed",
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
state_changed (NMManager *manager, NMState state, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	if (state == NM_STATE_CONNECTING) {
		/* A device starts activation, bring all devices down
		 * Remove this when we support multiple active devices.
		 */

		NMDevice *old_dev;
		
		if ((old_dev = nm_manager_get_active_device (policy->manager)))
			nm_device_interface_deactivate (NM_DEVICE_INTERFACE (old_dev));
	}
}

static void
connection_added (NMManager *manager,
                  NMConnection *connection,
                  gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	nm_info ("connection %p added", connection);
}

static void
connection_removed (NMManager *manager,
                    NMConnection *connection,
                    gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	nm_info ("connection %p removed", connection);
}

NMPolicy *
nm_policy_new (NMManager *manager)
{
	NMPolicy *policy;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	g_assert (global_policy == NULL);

	policy = g_slice_new (NMPolicy);
	policy->manager = g_object_ref (manager);

	g_signal_connect (manager, "device-added",
					  G_CALLBACK (device_added), policy);

	g_signal_connect (manager, "device-removed",
					  G_CALLBACK (device_removed), policy);

	g_signal_connect (manager, "state-change",
					  G_CALLBACK (state_changed), policy);

	g_signal_connect (manager, "connection-added",
					  G_CALLBACK (connection_added), policy);

	g_signal_connect (manager, "connection-removed",
					  G_CALLBACK (connection_removed), policy);

	global_policy = policy;

	return policy;
}

void
nm_policy_destroy (NMPolicy *policy)
{
	if (policy) {
		g_object_unref (policy->manager);
		g_slice_free (NMPolicy, policy);
	}

	global_policy = NULL;
}

