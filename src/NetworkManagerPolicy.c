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
	GSList		*elt;
	NMDevice		*best_wired_dev = NULL;
	guint		 best_wired_prio = 0;
	NMDevice		*best_wireless_dev = NULL;
	guint		 best_wireless_prio = 0;
	NMDevice		*highest_priority_dev = NULL;

	g_return_val_if_fail (data != NULL, NULL);

	for (elt = data->dev_list; elt != NULL; elt = g_slist_next (elt))
	{
		guint	 dev_type;
		gboolean	 link_active;
		guint	 prio = 0;
		NMDevice	*dev = (NMDevice *)(elt->data);

		/* Skip unsupported devices */
		if (nm_device_get_driver_support_level (dev) == NM_DRIVER_UNSUPPORTED)
			continue;

		dev_type = nm_device_get_type (dev);
		link_active = nm_device_get_link_active (dev);

		if (dev_type == DEVICE_TYPE_WIRED_ETHERNET)
		{
			/* We never automatically choose devices that don't support carrier detect */
			if (!nm_device_get_supports_carrier_detect (dev))
				continue;

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
		else if ((dev_type == DEVICE_TYPE_WIRELESS_ETHERNET) && data->wireless_enabled)
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
				&& best_ap
				&& nm_ap_get_encrypted (best_ap)
				&& !nm_device_need_ap_switch (dev))
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
	}

#if 0
	syslog (LOG_NOTICE, "AUTO: Best wired device = %s, best wireless device = %s (%s)", best_wired_dev ? nm_device_get_iface (best_wired_dev) : "(null)",
			best_wireless_dev ? nm_device_get_iface (best_wireless_dev) : "(null)", best_wireless_dev ? nm_device_get_essid (best_wireless_dev) : "null" );
#endif

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
static NMDevice * nm_policy_get_best_device (NMDevice *switch_to_dev, NMData *data, gboolean *should_lock_on_activate)
{
	NMDevice		*best_dev = NULL;

	g_return_val_if_fail (data != NULL, NULL);

	/* Can't lock the active device if you don't have one */
	if (!data->active_device)
		data->active_device_locked = FALSE;

	if (should_lock_on_activate)
		*should_lock_on_activate = FALSE;

	/* Prefer a device forced on us by the user */
	if (switch_to_dev && !nm_device_get_removed (switch_to_dev))
	{
		best_dev = switch_to_dev;
		*should_lock_on_activate = TRUE;
	}

	/* Determine whether we need to clear the active device and unlock it.
	 * This occurs if the best device is removed, for example.
	 */
	if (!best_dev && data->active_device_locked)
	{
		switch (nm_device_get_type (data->active_device))
		{
			/* Wired devices get unlocked only if they have lost their link */
			case (DEVICE_TYPE_WIRED_ETHERNET):
				if (nm_device_get_link_active (data->active_device))
					best_dev = data->active_device;
				break;

			/* Wireless devices get unlocked if the user removes the card
			 * or turns wireless off.
			 */
			case (DEVICE_TYPE_WIRELESS_ETHERNET):
				if (data->wireless_enabled == TRUE)
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
		best_dev = NULL;
	}

	return (best_dev);
}


/*
 * nm_policy_activation_finish
 *
 * Finishes up activation by sending out dbus signals, which has to happen
 * on the main thread.
 *
 */
gboolean nm_policy_activation_finish (gpointer user_data)
{
	NMActivationResult	*result = (NMActivationResult *)user_data;
	NMDevice			*dev = NULL;
	NMData			*data = NULL;

	g_return_val_if_fail (result != NULL, FALSE);

	if (!(dev = result->dev))
		goto out;

	if (!(data = nm_device_get_app_data (dev)))
		goto out;

	switch (result->result)
	{
		case DEVICE_NOW_ACTIVE:
			nm_dbus_signal_device_status_change (data->dbus_connection, dev, result->result);
			/* Tell NetworkManagerInfo to store the MAC address of the active device's AP */
			if (nm_device_is_wireless (dev))
			{
				NMAccessPoint		*ap = NULL;

				if ((ap = nm_device_get_best_ap (dev)))
				{
					struct ether_addr	 addr;

					nm_device_get_ap_address (dev, &addr);
					if (!nm_ethernet_address_is_valid (nm_ap_get_address (ap)))
						nm_ap_set_address (ap, &addr);

					/* Don't store MAC addresses for non-infrastructure networks */
					if ((nm_ap_get_mode (ap) == NETWORK_MODE_INFRA) && nm_ethernet_address_is_valid (&addr))
						nm_dbus_add_network_address (data->dbus_connection, NETWORK_TYPE_ALLOWED, nm_ap_get_essid (ap), &addr);

					nm_ap_unref (ap);
				}
			}
			syslog (LOG_INFO, "Activation (%s) successful, device activated.", nm_device_get_iface (data->active_device));
			break;

		case DEVICE_ACTIVATION_FAILED:
			nm_dbus_signal_device_status_change (data->dbus_connection, dev, result->result);
			if (nm_device_is_wireless (dev))
			{
				NMAccessPoint *ap = nm_device_get_best_ap (dev);
				if (ap)
				{
					/* Add the AP to the invalid list and force a best ap update */
					nm_ap_list_append_ap (data->invalid_ap_list, ap);
					nm_device_update_best_ap (dev);

					/* Unref because nm_device_get_best_ap() refs it before returning. */
					nm_ap_unref (ap);
				}
				syslog (LOG_INFO, "Activation (%s) failed for access point (%s)", nm_device_get_iface (dev), ap ? nm_ap_get_essid (ap) : "(none)");
			}
			else
				syslog (LOG_INFO, "Activation (%s) failed.", nm_device_get_iface (dev));
			if (data->active_device == dev)
				data->active_device = NULL;
			nm_device_deactivate (dev, FALSE);
			break;

		case DEVICE_ACTIVATION_CANCELED:
		default:
			break;
	}

	nm_policy_schedule_state_update (data);

out:
	nm_device_unref (dev);
	g_free (result);
	return FALSE;
}

typedef struct NMStateUpdateData
{
	NMDevice	*switch_to_dev;
	NMData	*app_data;
} NMStateUpdateData;


/*
 * nm_state_modification_monitor
 *
 * Figures out which interface to switch the active
 * network connection to if our global network state has changed.
 * Global network state changes are triggered by:
 *    1) insertion/deletion of interfaces
 *    2) link state change of an interface
 *
 */
static gboolean nm_policy_state_update (gpointer user_data)
{
	NMStateUpdateData	*cb_data = (NMStateUpdateData *)user_data;
	NMData			*app_data;

	g_return_val_if_fail (cb_data != NULL, FALSE);

	app_data = cb_data->app_data;
	if (!app_data)
		goto out;

	app_data->state_modified_idle_id = 0;

	/* If we're currently waiting for a force-device operation to complete, don't try
	 * to change devices.  We'll be notified of what device to switch to explicitly
	 * when the force-device operation completes.
	 */
	if (!cb_data->switch_to_dev && app_data->forcing_device)
		goto out;

	app_data->forcing_device = FALSE;

	if (nm_try_acquire_mutex (app_data->dev_list_mutex, __FUNCTION__))
	{
		gboolean		 should_lock_on_activate = FALSE;
		gboolean		 do_switch = FALSE;
		NMDevice		*best_dev = NULL;

		if ((best_dev = nm_policy_get_best_device (cb_data->switch_to_dev, app_data, &should_lock_on_activate)))
			nm_device_ref (best_dev);

		/* Figure out if we need to change devices or wireless networks */
		if (best_dev != app_data->active_device)
		{
			if (best_dev)
				syslog (LOG_INFO, "    SWITCH: best device changed");
			else
				syslog (LOG_INFO, "    SWITCH: old device no longer good, but no better device was available");
			do_switch = TRUE;	/* Device changed */
		}
		else if (best_dev)
		{
			if (nm_device_is_wireless (best_dev) && !nm_device_is_activating (best_dev) && nm_device_need_ap_switch (best_dev))
			{
				syslog (LOG_INFO, "    SWITCH: need to associate with new access point or create a wireless network.");
				do_switch = TRUE;
			}
			else if (!nm_device_is_activating (best_dev) && !nm_device_get_ip4_address (best_dev))
			{
				syslog (LOG_INFO, "    SWITCH: need to get an IP address.");
				do_switch = TRUE;
			}
		}

		if (do_switch)
		{
			/* Deactivate the old device */
			if (app_data->active_device)
			{
				nm_device_deactivate (app_data->active_device, FALSE);
				nm_device_unref (app_data->active_device);
				app_data->active_device = NULL;
			}

			if (best_dev)
			{
				/* Begin activation on the new device */
				nm_device_ref (best_dev);
				app_data->active_device = best_dev;
				nm_device_activation_schedule_start (app_data->active_device);

				/* nm_policy_get_best_device() signals us that the user forced
				 * a device upon us and that we should lock the active device.
				 */
				if (should_lock_on_activate)
					app_data->active_device_locked = TRUE;
			}
		}

		if (best_dev)
			nm_device_unref (best_dev);

		nm_unlock_mutex (app_data->dev_list_mutex, __FUNCTION__);
	}

out:
	g_free (cb_data);
	return (FALSE);
}


/*
 * nm_policy_schedule_state_update
 *
 * Queue up an idle handler to deal with state changes.
 *
 */
void nm_policy_schedule_state_update (NMData *app_data)
{
	g_return_if_fail (app_data != NULL);

	nm_policy_schedule_device_switch (NULL, app_data);
}


/*
 * nm_policy_schedule_state_update
 *
 * Queue up an idle handler to deal with state changes when we want
 * to force a particular device to be the active device.
 *
 */
void nm_policy_schedule_device_switch (NMDevice *switch_to_dev, NMData *app_data)
{
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

	g_return_if_fail (app_data != NULL);

	g_static_mutex_lock (&mutex);

	/* Don't queue the idle handler if switch_to_dev is NULL and there's already
	 * an idle handler queued.  Always queue the idle handler if we were passed
	 * a switch_to_dev.
	 */
	if (switch_to_dev || (app_data->state_modified_idle_id == 0))
	{
		GSource			*source = g_idle_source_new ();
		NMStateUpdateData	*cb_data = g_malloc0 (sizeof (NMStateUpdateData));

		cb_data->switch_to_dev = switch_to_dev;
		cb_data->app_data = app_data;

		g_source_set_callback (source, nm_policy_state_update, cb_data, NULL);
		app_data->state_modified_idle_id = g_source_attach (source, app_data->main_context);
		g_source_unref (source);
	}

	g_static_mutex_unlock (&mutex);
}



/*
 * nm_policy_allowed_ap_list_update
 *
 * Requery NetworkManagerInfo for a list of updated
 * allowed wireless networks.
 *
 */
static gboolean nm_policy_allowed_ap_list_update (gpointer user_data)
{
	NMData	*data = (NMData *)user_data;
	GSList	*elt;

	g_return_val_if_fail (data != NULL, FALSE);

	syslog (LOG_INFO, "Updating allowed wireless network lists.");

	/* Query info daemon for network lists if its now running */
	if (data->allowed_ap_list)
		nm_ap_list_unref (data->allowed_ap_list);
	data->allowed_ap_list = nm_ap_list_new (NETWORK_TYPE_ALLOWED);
	if (data->allowed_ap_list)
		nm_ap_list_populate_from_nmi (data->allowed_ap_list, data);

	for (elt = data->dev_list; elt != NULL; elt = g_slist_next (elt))
	{
		NMDevice	*dev = (NMDevice *)(elt->data);
		if (nm_device_is_wireless (dev))
		{
			/* Once we have the list, copy in any relevant information from our Allowed list and fill
			 * in the ESSID of base stations that aren't broadcasting their ESSID, if we have their
			 * MAC address in our allowed list.
			 */
			nm_ap_list_copy_essids_by_address (nm_device_ap_list_get (dev), data->allowed_ap_list);
			nm_ap_list_copy_properties (nm_device_ap_list_get (dev), data->allowed_ap_list);
		}
	}	

	/* If the active device doesn't have a best_ap already, make it update to
	 * get the new data.
	 */
	if (    data->active_device
		&& nm_device_is_activating (data->active_device)
		&& nm_device_is_wireless (data->active_device))
	{
		NMAccessPoint	*best_ap;

		best_ap = nm_device_get_best_ap (data->active_device);
		if (!best_ap)
			nm_device_update_best_ap (data->active_device);
		else
			nm_ap_unref (best_ap);
	}

	return (FALSE);
}


/*
 * nm_policy_schedule_allowed_ap_list_update
 *
 * Schedule an update of the allowed AP list in the main thread.
 *
 */
void nm_policy_schedule_allowed_ap_list_update (NMData *app_data)
{
	GSource	*source = NULL;

	g_return_if_fail (app_data != NULL);
	g_return_if_fail (app_data->main_context != NULL);

	source = g_idle_source_new ();
	/* We want this idle source to run before any other idle source */
	g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	g_source_set_callback (source, nm_policy_allowed_ap_list_update, app_data, NULL);
	g_source_attach (source, app_data->main_context);
	g_source_unref (source);
}
