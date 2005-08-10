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
#include "nm-activation-request.h"
#include "nm-utils.h"


/*
 * nm_policy_activation_finish
 *
 * Finishes up activation by sending out dbus signals, which has to happen
 * on the main thread.
 *
 */
static gboolean nm_policy_activation_finish (NMActRequest *req)
{
	NMDevice			*dev = NULL;
	NMAccessPoint		*ap = NULL;
	NMData			*data = NULL;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	/* Tell NetworkManagerInfo to store the MAC address of the active device's AP */
	if (nm_device_is_wireless (dev))
	{
		struct ether_addr	addr;
		NMAccessPoint *	ap = nm_act_request_get_ap (req);
		NMAccessPoint *tmp_ap;

		/* Cache details in the info-daemon since the connect was successful */
		nm_dbus_update_network_info (data->dbus_connection, ap);

		/* Cache the correct auth method in our AP list too */
		if ((tmp_ap = nm_ap_list_get_ap_by_essid (data->allowed_ap_list, nm_ap_get_essid (ap))))
			nm_ap_set_auth_method (tmp_ap, nm_ap_get_auth_method (ap));

		nm_device_get_ap_address (dev, &addr);
		if (!nm_ap_get_address (ap) || !nm_ethernet_address_is_valid (nm_ap_get_address (ap)))
			nm_ap_set_address (ap, &addr);

		/* Don't store MAC addresses for non-infrastructure networks */
		if ((nm_ap_get_mode (ap) == NETWORK_MODE_INFRA) && nm_ethernet_address_is_valid (&addr))
			nm_dbus_add_network_address (data->dbus_connection, NETWORK_TYPE_ALLOWED, nm_ap_get_essid (ap), &addr);
	}

	nm_info ("Activation (%s) successful, device activated.", nm_device_get_iface (dev));
	nm_dbus_schedule_device_status_change_signal (data, dev, NULL, DEVICE_NOW_ACTIVE);
	nm_schedule_state_change_signal_broadcast (data);

out:
	return FALSE;
}


/*
 * nm_policy_schedule_activation_finish
 *
 */
void nm_policy_schedule_activation_finish (NMActRequest *req)
{
	GSource *		source;
	NMData *		data;
	NMDevice *	dev;

	g_return_if_fail (req != NULL);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	nm_act_request_set_stage (req, NM_ACT_STAGE_ACTIVATED);

	source = g_idle_source_new ();
	g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	g_source_set_callback (source, (GSourceFunc) nm_policy_activation_finish, req, NULL);
	g_source_attach (source, data->main_context);
	g_source_unref (source);
	nm_info ("Activation (%s) Finish handler scheduled.", nm_device_get_iface (dev));
}


/*
 * nm_policy_activation_failed
 *
 * Clean up a failed activation.
 *
 */
static gboolean nm_policy_activation_failed (NMActRequest *req)
{
	NMDevice			*dev = NULL;
	NMAccessPoint		*ap = NULL;
	NMData			*data = NULL;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	if (nm_device_is_wireless (dev))
	{
		if ((ap = nm_act_request_get_ap (req)))
		{
			/* Only pop up the Network Not Found dialog when its a user-requested access point
			 * that failed, not one that we've automatically found and connected to.
			 */
			if (nm_act_request_get_user_requested (req))
				nm_dbus_schedule_device_status_change_signal	(data, dev, ap, DEVICE_ACTIVATION_FAILED);

			/* Add the AP to the invalid list and force a best ap update */
			nm_ap_set_invalid (ap, TRUE);
			nm_ap_list_append_ap (data->invalid_ap_list, ap);
		}

		nm_info ("Activation (%s) failed for access point (%s)", nm_device_get_iface (dev),
				ap ? nm_ap_get_essid (ap) : "(none)");
	}
	else
	{
		nm_info ("Activation (%s) failed.", nm_device_get_iface (dev));
		nm_dbus_schedule_device_status_change_signal	(data, dev, NULL, DEVICE_ACTIVATION_FAILED);
	}

	nm_device_deactivate (dev);
	nm_schedule_state_change_signal_broadcast (data);
	nm_policy_schedule_device_change_check (data);

out:
	return FALSE;
}


/*
 * nm_policy_schedule_activation_failed
 *
 */
void nm_policy_schedule_activation_failed (NMActRequest *req)
{
	GSource *		source;
	NMData *		data;
	NMDevice *	dev;

	g_return_if_fail (req != NULL);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	nm_act_request_set_stage (req, NM_ACT_STAGE_FAILED);

	source = g_idle_source_new ();
	g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	g_source_set_callback (source, (GSourceFunc) nm_policy_activation_failed, req, NULL);
	g_source_attach (source, data->main_context);
	g_source_unref (source);
	nm_info ("Activation (%s) failure scheduled...", nm_device_get_iface (dev));
}


/*
 * nm_policy_auto_get_best_device
 *
 * Find the best device to use, regardless of whether we are
 * "locked" on one device at this time.
 *
 */
static NMDevice * nm_policy_auto_get_best_device (NMData *data, NMAccessPoint **ap)
{
	GSList		*elt;
	NMDevice		*best_wired_dev = NULL;
	guint		 best_wired_prio = 0;
	NMDevice		*best_wireless_dev = NULL;
	guint		 best_wireless_prio = 0;
	NMDevice		*highest_priority_dev = NULL;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (ap != NULL, NULL);

	if (data->asleep)
		return NULL;

	for (elt = data->dev_list; elt != NULL; elt = g_slist_next (elt))
	{
		guint	 dev_type;
		gboolean	 link_active;
		guint	 prio = 0;
		NMDevice	*dev = (NMDevice *)(elt->data);

		/* Skip devices that can't do carrier detect or can't do wireless scanning */
		if (nm_device_get_driver_support_level (dev) != NM_DRIVER_FULLY_SUPPORTED)
			continue;

		dev_type = nm_device_get_type (dev);
		link_active = nm_device_has_active_link (dev);

		if (nm_device_is_wired (dev))
		{
			/* We never automatically choose devices that don't support carrier detect */
			if (!nm_device_get_supports_carrier_detect (dev))
				continue;

			if (link_active)
				prio += 1;

			if (nm_device_get_act_request (dev) && link_active)
				prio += 1;

			if (prio > best_wired_prio)
			{
				best_wired_dev = dev;
				best_wired_prio = prio;
			}
		}
		else if (nm_device_is_wireless (dev) && data->wireless_enabled)
		{
			if (link_active)
				prio += 1;

			if (nm_device_get_supports_wireless_scan (dev))
				prio += 2;
			else
				prio += 1;

			if (nm_device_get_act_request (dev) && link_active)
				prio += 3;

			/* Stick with an already active non-scanning device if the user chose one */
			if (!nm_device_get_supports_wireless_scan (dev) && nm_device_get_act_request (dev))
				prio += 2;

			if (prio > best_wireless_prio)
			{
				best_wireless_dev = dev;
				best_wireless_prio = prio;
			}
		}
	}

	if (best_wired_dev)
		highest_priority_dev = best_wired_dev;
	else if (best_wireless_dev)
	{
		highest_priority_dev = best_wireless_dev;
		*ap = nm_device_get_best_ap (highest_priority_dev);
		/* If the device doesn't have a "best" ap, then we can't use it */
		if (!*ap)
			highest_priority_dev = NULL;
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
static gboolean nm_policy_device_change_check (NMData *data)
{
	NMAccessPoint *	ap = NULL;
	NMDevice *		new_dev = NULL;
	NMDevice *		old_dev = NULL;
	gboolean			do_switch = FALSE;

	g_return_val_if_fail (data != NULL, FALSE);

	data->dev_change_check_idle_id = 0;

	old_dev = nm_get_active_device (data);

	if (!nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
		return FALSE;

	if (old_dev)
	{
		/* Don't interrupt a currently activating device. */
		if (nm_device_is_activating (old_dev))
		{
			nm_info ("Old device '%s' activating, won't change.", nm_device_get_iface (old_dev));
			goto out;
		}

		/* Don't interrupt semi-supported devices either.  If the user chose one, they must
		 * explicitly choose to move to another device, we're not going to move for them.
		 */
		if (nm_device_get_driver_support_level (old_dev) != NM_DRIVER_FULLY_SUPPORTED)
		{
			nm_info ("Old device '%s' was semi-supported and user chosen, won't change unless told to.",
				nm_device_get_iface (old_dev));
			goto out;
		}
	}

	new_dev = nm_policy_auto_get_best_device (data, &ap);

	/* Four cases here:
	 *
	 * 1) old device is NULL, new device is NULL - we aren't currently connected to anything, and we
	 *		can't find anything to connect to.  Do nothing.
	 *
	 * 2) old device is NULL, new device is good - we aren't currenlty connected to anything, but
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

	if (!old_dev && !new_dev)
	{
		/* Do nothing, wait for something like link-state to change, or an access point to be found */
	}
	else if (!old_dev && new_dev)
	{
		/* Activate new device */
		nm_info ("SWITCH: no current connection, found better connection '%s'.", nm_device_get_iface (new_dev));
		do_switch = TRUE;
	}
	else if (old_dev && !new_dev)
	{
		/* Terminate current connection */
		nm_info ("SWITCH: terminating current connection '%s' because it's no longer valid.", nm_device_get_iface (old_dev));
		nm_device_deactivate (old_dev);
		do_switch = TRUE;
	}
	else if (old_dev && new_dev)
	{
		if (old_dev != new_dev)
		{
			nm_info ("SWITCH: found better connection '%s' than current connection '%s'.", nm_device_get_iface (new_dev), nm_device_get_iface (old_dev));
			do_switch = TRUE;
		}
		else if ((old_dev == new_dev) && nm_device_is_wireless (new_dev))
		{
			NMAccessPoint *old_ap = nm_act_request_get_ap (nm_device_get_act_request (old_dev));

			/* Stick with the current access point unless we don't have a link to it anymore */

			/* Schedule new activation if the currently associated access point is not the "best" one */
			if (strcmp (nm_ap_get_essid (old_ap), nm_ap_get_essid (ap)) != 0)
			{
				nm_info ("SWITCH: found better connection '%s/%s' than current connection '%s/%s'.", nm_device_get_iface (new_dev), nm_ap_get_essid (ap),
							nm_device_get_iface (old_dev), nm_ap_get_essid (old_ap));
				do_switch = TRUE;
			}
		}
	}

	if (do_switch && (nm_device_is_wired (new_dev) || (nm_device_is_wireless (new_dev) && ap)))
	{
		NMActRequest *	act_req = NULL;

		if ((act_req = nm_act_request_new (data, new_dev, ap, FALSE)))

		{
			nm_info ("Will activate connection '%s%s%s'.", nm_device_get_iface (new_dev), ap ? "/" : "", ap ? nm_ap_get_essid (ap) : "");
			nm_policy_schedule_device_activation (act_req);
		}
	}

	if (ap)
		nm_ap_unref (ap);

out:
	nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	return FALSE;
}


/*
 * nm_policy_schedule_device_change_check
 *
 * Queue up an idle handler to deal with state changes that could
 * cause us to activate a different device or wireless network.
 *
 */
void nm_policy_schedule_device_change_check (NMData *data)
{
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

	g_return_if_fail (data != NULL);

	g_static_mutex_lock (&mutex);

	if (data->dev_change_check_idle_id == 0)
	{
		GSource *	source = g_idle_source_new ();

		g_source_set_callback (source, (GSourceFunc) nm_policy_device_change_check, data, NULL);
		data->dev_change_check_idle_id = g_source_attach (source, data->main_context);
		g_source_unref (source);
	}

	g_static_mutex_unlock (&mutex);
}


/*
 * nm_policy_device_activation
 *
 * Handle device activation, shutting down all other devices and starting
 * activation on the requested device.
 *
 */
static gboolean nm_policy_device_activation (NMActRequest *req)
{
	NMData *		data;
	NMDevice *	new_dev = NULL;
	NMDevice *	old_dev = NULL;

	g_return_val_if_fail (req != NULL, FALSE);

	data = nm_act_request_get_data (req);
	g_assert (data);

	if ((old_dev = nm_get_active_device (data)))
		nm_device_deactivate (old_dev);

	new_dev = nm_act_request_get_dev (req);
	if (nm_device_is_activating (new_dev))
		return FALSE;

	nm_device_activation_start (req);

	return FALSE;
}


/*
 * nm_policy_schedule_device_activation
 *
 * Activate a particular device (and possibly access point)
 *
 */
void nm_policy_schedule_device_activation (NMActRequest *req)
{
	GSource *		source;
	NMData *		data;
	NMDevice *	dev;

	g_return_if_fail (req != NULL);

	data = nm_act_request_get_data (req);
	g_assert (data);

	dev = nm_act_request_get_dev (req);
	g_assert (dev);

	source = g_idle_source_new ();
	g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
	g_source_set_callback (source, (GSourceFunc) nm_policy_device_activation, req, NULL);
	g_source_attach (source, data->main_context);
	g_source_unref (source);
	nm_info ("Device %s activation scheduled...", nm_device_get_iface (dev));
}


static gboolean allowed_list_update_pending = FALSE;

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

	allowed_list_update_pending = FALSE;

	g_return_val_if_fail (data != NULL, FALSE);

	nm_info ("Updating allowed wireless network lists.");

	/* Query info daemon for network lists if its now running */
	if (data->allowed_ap_list)
		nm_ap_list_unref (data->allowed_ap_list);
	if ((data->allowed_ap_list = nm_ap_list_new (NETWORK_TYPE_ALLOWED)))
		nm_dbus_update_allowed_networks (data->dbus_connection, data->allowed_ap_list, data);

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
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

	g_return_if_fail (app_data != NULL);
	g_return_if_fail (app_data->main_context != NULL);

	g_static_mutex_lock (&mutex);

	if (allowed_list_update_pending == FALSE)
	{
		GSource *source = g_idle_source_new ();
		/* We want this idle source to run before any other idle source */
		g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
		g_source_set_callback (source, nm_policy_allowed_ap_list_update, app_data, NULL);
		g_source_attach (source, app_data->main_context);
		g_source_unref (source);

		allowed_list_update_pending = TRUE;
	}

	g_static_mutex_unlock (&mutex);
}


static gboolean device_list_update_pending = FALSE;

/*
 * nm_policy_device_list_update_from_allowed_list
 *
 * Requery NetworkManagerInfo for a list of updated
 * allowed wireless networks.
 *
 */
static gboolean nm_policy_device_list_update_from_allowed_list (NMData *data)
{
	GSList *	elt;

	device_list_update_pending = FALSE;

	g_return_val_if_fail (data != NULL, FALSE);

	for (elt = data->dev_list; elt != NULL; elt = g_slist_next (elt))
	{
		NMDevice	*dev = (NMDevice *)(elt->data);
		if (nm_device_is_wireless (dev))
		{
			NMAccessPoint	*best_ap;

			if (nm_device_get_supports_wireless_scan (dev))
			{
				/* Once we have the list, copy in any relevant information from our Allowed list and fill
				 * in the ESSID of base stations that aren't broadcasting their ESSID, if we have their
				 * MAC address in our allowed list.
				 */
				nm_ap_list_copy_essids_by_address (nm_device_ap_list_get (dev), data->allowed_ap_list);
				nm_ap_list_copy_properties (nm_device_ap_list_get (dev), data->allowed_ap_list);
			}
			else
				nm_device_copy_allowed_to_dev_list (dev, data->allowed_ap_list);

			nm_ap_list_remove_duplicate_essids (nm_device_ap_list_get (dev));
		}
	}

	nm_policy_schedule_device_change_check (data);
	
	return FALSE;
}


/*
 * nm_policy_schedule_device_ap_lists_update_from_allowed
 *
 * Schedule an update of each wireless device's AP list from
 * the allowed list, in the main thread.
 *
 */
void nm_policy_schedule_device_ap_lists_update_from_allowed (NMData *app_data)
{
	static GStaticMutex mutex = G_STATIC_MUTEX_INIT;

	g_return_if_fail (app_data != NULL);
	g_return_if_fail (app_data->main_context != NULL);

	g_static_mutex_lock (&mutex);

	if (device_list_update_pending == FALSE)
	{
		GSource	*source = g_idle_source_new ();

		/* We want this idle source to run before any other idle source */
		g_source_set_priority (source, G_PRIORITY_HIGH_IDLE);
		g_source_set_callback (source, (GSourceFunc) nm_policy_device_list_update_from_allowed_list, app_data, NULL);
		g_source_attach (source, app_data->main_context);
		g_source_unref (source);

		device_list_update_pending = TRUE;
	}

	g_static_mutex_unlock (&mutex);
}
