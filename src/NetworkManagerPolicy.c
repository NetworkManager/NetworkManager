
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
 * (C) Copyright 2004 Red Hat, Inc.
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


/*
 * nm_policy_auto_get_best_device
 *
 * Find the best device to use, regardless of whether we are
 * "locked" on one device at this time.
 *
 */
static NMDevice * nm_policy_auto_get_best_device (NMData *data)
{
	GSList		*element;
	NMDevice		*best_wired_dev = NULL;
	guint		 best_wired_prio = 0;
	NMDevice		*best_wireless_dev = NULL;
	guint		 best_wireless_prio = 0;
	NMDevice		*highest_priority_dev = NULL;

	g_return_val_if_fail (data != NULL, NULL);
	element = data->dev_list;

	while (element)
	{
		guint	 dev_type;
		gboolean	 link_active;
		guint	 prio = 0;
		NMDevice	*dev = (NMDevice *)(element->data);

		/* Skip unsupported devices */
		if (nm_device_get_driver_support_level (dev) == NM_DRIVER_UNSUPPORTED)
		{
			element = g_slist_next (element);
			continue;
		}

		dev_type = nm_device_get_type (dev);
		link_active = nm_device_get_link_active (dev);

		if (dev_type == DEVICE_TYPE_WIRED_ETHERNET)
		{
			if (link_active)
				prio += 1;

			if (    data->active_device
				&& (dev == data->active_device)
				&& link_active)
				prio += 1;

			if (prio > best_wired_prio)
			{
				best_wired_dev = dev;
				best_wired_prio = prio;
			}
		}
		else if (dev_type == DEVICE_TYPE_WIRELESS_ETHERNET)
		{
			NMAccessPoint	*best_ap = nm_device_get_best_ap (dev);

			/* This deals with the case where the WEP key we have
			 * for an access point is wrong.  In that case, the
			 * MAC address of the associated AP will be invalid,
			 * so link_active will be FALSE.  However, we still want
			 * to use this card and AP, just need to get the correct
			 * WEP key from the user via NetworkManagerInfo.
			 */
			if (    !link_active
				&& !nm_device_need_ap_switch (dev)
				&& best_ap
				&& nm_ap_get_encrypted (best_ap))
				link_active = TRUE;

			if (link_active)
				prio += 1;

			if (nm_device_get_supports_wireless_scan (dev))
				prio += 2;
			else
				prio += 1;

			if (    data->active_device
				&& (dev == data->active_device)
				&& link_active)
				prio += 3;

			if (prio > best_wireless_prio)
			{
				best_wireless_dev = dev;
				best_wireless_prio = prio;
			}
			if (best_ap)
				nm_ap_unref (best_ap);
		}

		element = g_slist_next (element);
	}

	syslog (LOG_NOTICE, "AUTO: Best wired device = %s", best_wired_dev ? nm_device_get_iface (best_wired_dev) : "(null)");
	syslog (LOG_NOTICE, "AUTO: Best wireless device = %s  (%s)", best_wireless_dev ? nm_device_get_iface (best_wireless_dev) : "(null)",
			best_wireless_dev ? nm_device_get_essid (best_wireless_dev) : "null" );

	if (best_wireless_dev || best_wired_dev)
	{
		if (best_wired_dev)
			highest_priority_dev = best_wired_dev;
		else
			highest_priority_dev = best_wireless_dev;
	}

	return (highest_priority_dev);
}


/*
 * nm_policy_get_best_device
 *
 * Find the best device to use, taking into account if we are
 * "locked" on one device or not.  That lock may also be cleared
 * under certain conditions.
 *
 */
static NMDevice * nm_policy_get_best_device (NMData *data, gboolean *should_lock_on_activate)
{
	NMDevice		*best_dev = NULL;

	g_return_val_if_fail (data != NULL, NULL);

	/* Can't lock the active device if you don't have one */
	if (!data->active_device)
		data->active_device_locked = FALSE;

	if (should_lock_on_activate)
		*should_lock_on_activate = FALSE;

	/* If the user told us to switch to a particular device, do it now */
	if (nm_try_acquire_mutex (data->user_device_mutex, __FUNCTION__))
	{
		if (data->user_device)
		{
			best_dev = data->user_device;

			nm_device_unref (data->user_device);
			data->user_device = NULL;
			*should_lock_on_activate = TRUE;
		}
		nm_unlock_mutex (data->user_device_mutex, __FUNCTION__);
	}

	/* Determine whether we need to clear the active device and unlock it.
	 * This occurs if the best device is removed, for example.
	 */
	if (!best_dev && data->active_device_locked)
	{
		switch (nm_device_get_type (data->active_device))
		{
			/* If the active device was a wired device, and it no
			 * longer has a link, switch to auto mode.
			 */
			case (DEVICE_TYPE_WIRED_ETHERNET):
				if (nm_device_get_link_active (data->active_device))
					best_dev = data->active_device;
				break;

			/* For wireless devices, we only "unlock" them if they are
			 * removed from the system or a different device is "locked"
			 * by the user.
			 */
			case (DEVICE_TYPE_WIRELESS_ETHERNET):
				best_dev = data->active_device;
				break;

			default:
				break;
		}
	}

	/* Fall back to automatic device picking */
	if (!best_dev)
	{
		data->active_device_locked = FALSE;
		best_dev = nm_policy_auto_get_best_device (data);
	}

	/* Ensure we support this driver */
	if (best_dev && (nm_device_get_driver_support_level (best_dev) == NM_DRIVER_UNSUPPORTED))
	{
		syslog (LOG_ERR, "nm_policy_get_best_device(): tried to switch to unsupported device '%s'!\n", nm_device_get_iface (best_dev));
		best_dev == NULL;
	}

	return (best_dev);
}


/*
 * nm_state_modification_monitor
 *
 * Called every 2s and figures out which interface to switch the active
 * network connection to if our global network state has changed.
 * Global network state changes are triggered by:
 *    1) insertion/deletion of interfaces
 *    2) link state change of an interface
 *    3) appearance/disappearance of an allowed wireless access point
 *
 */
gboolean nm_state_modification_monitor (gpointer user_data)
{
	NMData	*data = (NMData *)user_data;
	gboolean	 modified = FALSE;

	g_return_val_if_fail (data != NULL, TRUE);

	/* If the info daemon is now running, get our trusted/preferred ap lists from it */
	if (data->info_daemon_avail)
	{
		if (data->update_ap_lists)
		{
			/* Query info daemon for network lists if its now running */
			if (data->allowed_ap_list)
				nm_ap_list_unref (data->allowed_ap_list);
			data->allowed_ap_list = nm_ap_list_new (NETWORK_TYPE_ALLOWED);
			if (data->allowed_ap_list)
				nm_ap_list_populate (data->allowed_ap_list, data);
	
			data->update_ap_lists = FALSE;
		}

		if (data->notify_device_support)
		{
			data->notify_device_support = FALSE;
		}
	}

	/* Check global state modified variable, and reset it with
	 * appropriate locking.
	 */
	g_mutex_lock (data->state_modified_mutex);
	modified = data->state_modified;
	if (data->state_modified)
		data->state_modified = FALSE;
	g_mutex_unlock (data->state_modified_mutex);

	/* If any modifications to the data model were made, update
	 * network state based on policy applied to the data model.
	 */
	if (modified)
	{
		if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
		{
			gboolean		 should_lock_on_activate = FALSE;
			gboolean		 do_switch = FALSE;
			NMDevice		*best_dev = NULL;

			if ((best_dev = nm_policy_get_best_device (data, &should_lock_on_activate)))
				nm_device_ref (best_dev);

			/* Figure out if we need to change devices or wireless networks */
			if (best_dev != data->active_device)
			{
				syslog (LOG_INFO, "    SWITCH: best device changed");
				do_switch = TRUE;	/* Device changed */
			}
			else if (best_dev && nm_device_is_wireless (best_dev))
			{
				if (!nm_device_is_activating (best_dev) && nm_device_need_ap_switch (best_dev))
				{
					syslog (LOG_INFO, "    SWITCH: need to associate with new access point");
					do_switch = TRUE;
				}
				else if (!nm_device_is_activating (best_dev) && !nm_device_get_ip4_address (best_dev))
				{
					syslog (LOG_INFO, "    SWITCH: need to get an IP address");
					do_switch = TRUE;
				}
			}

			if (do_switch)
			{
				/* Deactivate the old device */
				if (data->active_device)
				{
					nm_device_deactivate (data->active_device, FALSE);
					nm_device_unref (data->active_device);
					data->active_device = NULL;
				}

				if (best_dev)
				{
					/* Begin activation on the new device */
					syslog (LOG_INFO, "nm_state_modification_monitor(): beginning activation for device '%s'", nm_device_get_iface (best_dev));
					nm_device_ref (best_dev);
					data->active_device = best_dev;
					nm_device_activation_begin (data->active_device);

					/* nm_policy_get_best_device() signals us that the user forced
					 * a device upon us and that we should lock the active device.
					 */
					if (should_lock_on_activate)
						data->active_device_locked = TRUE;
				}
			}

			if (best_dev)
				nm_device_unref (best_dev);

			nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
		}
		else
			syslog (LOG_ERR, "nm_state_modification_monitor() could not get device list mutex");
	}
	else if (data->active_device && nm_device_is_just_activated (data->active_device))
	{
		nm_dbus_signal_device_status_change (data->dbus_connection, data->active_device, DEVICE_NOW_ACTIVE);
		syslog (LOG_INFO, "nm_state_modification_monitor() activated device %s", nm_device_get_iface (data->active_device));
	}
	else if (data->active_device && nm_device_did_activation_fail (data->active_device))
	{
		nm_device_clear_activation_fail (data->active_device);
		nm_dbus_signal_device_status_change (data->dbus_connection, data->active_device, DEVICE_ACTIVATION_FAILED);
		if (nm_device_is_wireless (data->active_device))
		{
			NMAccessPoint *ap = nm_device_get_best_ap (data->active_device);
			if (ap)
			{
				/* Add the AP to the invalid list and force a best ap update */
				nm_ap_list_append_ap (data->invalid_ap_list, ap);
				nm_device_update_best_ap (data->active_device);

				/* Unref once because the list takes ownership, and unref a second time because
				 * nm_device_get_best_ap() refs it before returning.
				 */
				nm_ap_unref (ap);
				nm_ap_unref (ap);
			}
			syslog (LOG_INFO, "nm_state_modification_monitor() failed to activate device %s (%s)", nm_device_get_iface (data->active_device), ap ? nm_ap_get_essid (ap) : "(none)");
		}
		else
			syslog (LOG_INFO, "nm_state_modification_monitor() failed to activate device %s", nm_device_get_iface (data->active_device));
		nm_data_mark_state_changed (data);
	}

	/* Clear the starting up flag, so we will now take over and have our way with
	 * any device we find out about.
	 */
	if (data->starting_up)
		data->starting_up = FALSE;

	return (TRUE);
}
