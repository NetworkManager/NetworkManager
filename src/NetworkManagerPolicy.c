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
#include "NetworkManagerDbus.h"
#include "nm-activation-request.h"
#include "nm-utils.h"
#include "nm-dbus-nmi.h"
#include "nm-device-interface.h"
#include "nm-device-802-11-wireless.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-dbus-manager.h"

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
 * nm_policy_activation_finish
 *
 * Finishes up activation by sending out dbus signals, which has to happen
 * on the main thread.
 *
 */
static gboolean nm_policy_activation_finish (gpointer user_data)
{
	NMActRequest *  req = (NMActRequest *) user_data;
	NMDevice *      dev = NULL;
	NMData *        data = NULL;
	NMAccessPoint * ap = NULL;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

    if (NM_IS_DEVICE_802_11_WIRELESS (dev))
        ap = nm_act_request_get_ap (req);

	nm_dbus_schedule_device_status_change_signal (data, dev, ap, DEVICE_NOW_ACTIVE);
	nm_schedule_state_change_signal_broadcast (data);

	return FALSE;
}


/*
 * nm_policy_schedule_activation_finish
 *
 */
void nm_policy_schedule_activation_finish (NMActRequest *req)
{
	GSource *  source;
	NMDevice * dev;
	guint      id;

	g_return_if_fail (req != NULL);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	nm_act_request_set_stage (req, NM_ACT_STAGE_ACTIVATED);
	id = g_idle_add (nm_policy_activation_finish, req);
	source = g_main_context_find_source_by_id (NULL, id);
	if (source) {
		g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	}

	nm_info ("Activation (%s) Finish handler scheduled.",
	         nm_device_get_iface (dev));
}


/*
 * nm_policy_activation_failed
 *
 * Clean up a failed activation.
 *
 */
static gboolean nm_policy_activation_failed (gpointer user_data)
{
	NMActRequest *  req = (NMActRequest *) user_data;
	NMDevice *      dev = NULL;
	NMData *        data = NULL;
	NMAccessPoint * ap = NULL;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

    if (NM_IS_DEVICE_802_11_WIRELESS (dev))
        ap = nm_act_request_get_ap (req);

	nm_dbus_schedule_device_status_change_signal (data, dev, ap, DEVICE_ACTIVATION_FAILED);

	nm_device_interface_deactivate (NM_DEVICE_INTERFACE (dev));
	nm_schedule_state_change_signal_broadcast (data);
	schedule_change_check ((gpointer) global_policy);

	return FALSE;
}


/*
 * nm_policy_schedule_activation_failed
 *
 */
void nm_policy_schedule_activation_failed (NMActRequest *req)
{
	GSource *  source;
	NMDevice * dev;
	guint      id;

	g_return_if_fail (req != NULL);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	nm_act_request_set_stage (req, NM_ACT_STAGE_FAILED);
	id = g_idle_add (nm_policy_activation_failed, req);
	source = g_main_context_find_source_by_id (NULL, id);
	if (source) {
		g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	}

	nm_info ("Activation (%s) failure scheduled...", nm_device_get_iface (dev));
}


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
		guint		dev_type;
		gboolean		link_active;
		guint		prio = 0;
		NMDevice *	dev = (NMDevice *)(elt->data);
		guint32		caps;

		dev_type = nm_device_get_device_type (dev);
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
			/* Don't automatically choose a device that doesn't support wireless scanning */
			if (!(caps & NM_DEVICE_CAP_WIRELESS_SCAN))
				continue;

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

#if 0
	nm_info ("AUTO: Best wired device = %s, best wireless device = %s (%s)", best_wired_dev ? nm_device_get_iface (best_wired_dev) : "(null)",
			best_wireless_dev ? nm_device_get_iface (best_wireless_dev) : "(null)", (best_wireless_dev && *ap) ? nm_ap_get_essid (*ap) : "null" );
#endif

	return highest_priority_dev;
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
	NMAccessPoint * ap = NULL;
	NMDevice *      new_dev;
	NMDevice *      old_dev;
	gboolean        do_switch = FALSE;

	old_dev = nm_manager_get_active_device (policy->manager);

	if (old_dev) {
		guint32 caps = nm_device_get_capabilities (old_dev);

		/* Don't interrupt a currently activating device. */
		if (   nm_device_is_activating (old_dev)
		    && !nm_device_can_interrupt_activation (old_dev)) {
			nm_info ("Old device '%s' activating, won't change.", nm_device_get_iface (old_dev));
			goto out;
		}

		/* Don't interrupt semi-supported devices either.  If the user chose one, they must
		 * explicitly choose to move to another device, we're not going to move for them.
		 */
		if ((NM_IS_DEVICE_802_3_ETHERNET (old_dev) && !(caps & NM_DEVICE_CAP_CARRIER_DETECT))
			|| (NM_IS_DEVICE_802_11_WIRELESS (old_dev) && !(caps & NM_DEVICE_CAP_WIRELESS_SCAN))) {
			nm_info ("Old device '%s' was semi-supported and user chosen, won't change unless told to.",
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
		nm_device_interface_deactivate (NM_DEVICE_INTERFACE (old_dev));
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
				NMAccessPoint *old_ap = nm_act_request_get_ap (old_act_req);
				const char *	old_essid = nm_ap_get_essid (old_ap);
				int			old_mode = nm_ap_get_mode (old_ap);
				const char *	new_essid = nm_ap_get_essid (ap);
				gboolean		same_request = FALSE;

				/* Schedule new activation if the currently associated
				 * access point is not the "best" one or we've lost the
				 * link to the old access point.  We don't switch away
				 * from Ad-Hoc APs either.
				 */
				gboolean same_essid = (nm_null_safe_strcmp (old_essid, new_essid) == 0);

				/* If the "best" AP's essid is the same as the current activation
				 * request's essid, but the current activation request isn't
				 * done yet, don't switch.  This prevents multiple requests for the
				 * AP's password on startup.
				 */
				if ((old_dev == new_dev) && nm_device_is_activating (new_dev) && same_essid)
					same_request = TRUE;

				if (!same_request && (!same_essid || !old_has_link) && (old_mode != IW_MODE_ADHOC)) {
					nm_info ("SWITCH: found better connection '%s/%s'"
					         " than current connection '%s/%s'.  "
					         "same_ssid=%d, have_link=%d",
					         nm_device_get_iface (new_dev),	new_essid,
					         nm_device_get_iface (old_dev), old_essid,
					         same_essid, old_has_link);
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
		if (NM_IS_DEVICE_802_3_ETHERNET (new_dev)) {
			nm_info ("Will activate connection '%s'.",
					 nm_device_get_iface (new_dev));
			nm_device_802_3_ethernet_activate (NM_DEVICE_802_3_ETHERNET (new_dev), FALSE);
		} else if (NM_IS_DEVICE_802_11_WIRELESS (new_dev) && ap) {
			nm_info ("Will activate connection '%s/%s'.",
					 nm_device_get_iface (new_dev),
					 nm_ap_get_essid (ap));
			nm_device_802_11_wireless_activate (NM_DEVICE_802_11_WIRELESS (new_dev), ap, FALSE);
		} else
			nm_warning ("Unhandled device activation");
	}

	if (ap)
		g_object_unref (ap);

out:
	return FALSE;
}


static guint allowed_list_update_id = 0;

/*
 * nm_policy_allowed_ap_list_update
 *
 * Requery NetworkManagerInfo for a list of updated
 * allowed wireless networks.
 *
 */
static gboolean
nm_policy_allowed_ap_list_update (gpointer user_data)
{
	NMData * data = (NMData *)user_data;

	allowed_list_update_id = 0;

	g_return_val_if_fail (data != NULL, FALSE);

	nm_info ("Updating allowed wireless network lists.");

	/* Query info daemon for network lists if its now running */
	if (data->allowed_ap_list)
		nm_ap_list_unref (data->allowed_ap_list);
	if ((data->allowed_ap_list = nm_ap_list_new (NETWORK_TYPE_ALLOWED)))
		nm_dbus_update_allowed_networks (data->allowed_ap_list, data);
	return FALSE;
}


/*
 * nm_policy_schedule_allowed_ap_list_update
 *
 * Schedule an update of the allowed AP list in the main thread.
 *
 */
void nm_policy_schedule_allowed_ap_list_update (NMData *app_data)
{
	GSource * source;
	guint     id;

	g_return_if_fail (app_data != NULL);

	if (allowed_list_update_id > 0)
		return;

	id = g_idle_add (nm_policy_allowed_ap_list_update, app_data);
	allowed_list_update_id = id;
	source = g_main_context_find_source_by_id (NULL, id);
	if (source) {
		g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	}
}


static gboolean device_list_update_id = 0;

/*
 * nm_policy_device_list_update_from_allowed_list
 *
 * Requery NetworkManagerInfo for a list of updated
 * allowed wireless networks.
 *
 */
static gboolean
nm_policy_device_list_update_from_allowed_list (gpointer user_data)
{
	NMData * data = (NMData *) user_data;
	GSList * elt;

	device_list_update_id = 0;

	g_return_val_if_fail (data != NULL, FALSE);

	for (elt = nm_manager_get_devices (global_policy->manager); elt; elt = elt->next) {
		NMDevice	*dev = (NMDevice *)(elt->data);
		NMDevice80211Wireless *	wdev;

		if (!NM_IS_DEVICE_802_11_WIRELESS (dev))
			continue;

		wdev = NM_DEVICE_802_11_WIRELESS (dev);
		if (nm_device_get_capabilities (dev) & NM_DEVICE_CAP_WIRELESS_SCAN) {
			/* Once we have the list, copy in any relevant information from our
			 * Allowed list and fill in the ESSID of base stations that aren't
			 * broadcasting their ESSID, if we have their MAC address in our
			 * allowed list.
			 */
			nm_ap_list_copy_essids_by_address (nm_device_802_11_wireless_ap_list_get (wdev),
			                                   data->allowed_ap_list);
			nm_ap_list_copy_properties (nm_device_802_11_wireless_ap_list_get (wdev),
			                            data->allowed_ap_list);
		} else {
			nm_device_802_11_wireless_copy_allowed_to_dev_list (wdev, data->allowed_ap_list);
		}

		nm_ap_list_remove_duplicate_essids (nm_device_802_11_wireless_ap_list_get (wdev));
	}

	schedule_change_check ((gpointer) global_policy);
	
	return FALSE;
}


/*
 * nm_policy_schedule_device_ap_lists_update_from_allowed
 *
 * Schedule an update of each wireless device's AP list from
 * the allowed list, in the main thread.
 *
 */
void
nm_policy_schedule_device_ap_lists_update_from_allowed (NMData *app_data)
{
	GSource	* source;
	guint     id;

	g_return_if_fail (app_data != NULL);

	if (device_list_update_id > 0)
		return;

	id = g_idle_add (nm_policy_device_list_update_from_allowed_list, app_data);
	device_list_update_id = id;
	source = g_main_context_find_source_by_id (NULL, id);
	if (source) {
		g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	}
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

	/* FIXME: */
	{
		NMData *nm_data = nm_device_get_app_data (device);
		nm_data->dev_list = g_slist_append (nm_data->dev_list, device);
	}

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

	/* FIXME: */
	{
		NMData *nm_data = nm_device_get_app_data (device);
		nm_data->dev_list = g_slist_remove (nm_data->dev_list, device);
	}

	schedule_change_check (policy);
}

static void
state_changed (NMManager *manager, NMState state, gpointer user_data)
{
	NMPolicy *policy = (NMPolicy *) user_data;

	if (state == NM_ACT_STAGE_DEVICE_PREPARE) {
		/* A device starts activation, bring all devices down
		 * Remove this when we support multiple active devices.
		 */

		NMDevice *old_dev;
		
		if ((old_dev = nm_manager_get_active_device (policy->manager)))
			nm_device_interface_deactivate (NM_DEVICE_INTERFACE (old_dev));
	}
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
