
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

gboolean			allowed_ap_worker_exit = FALSE;
extern gboolean	debug;


/*
 * nm_policy_get_best_device
 *
 * Filter all the devices and find the best device to use as the
 * link.  NOTE: caller must lock the device list if needed.
 *
 */
NMDevice * nm_policy_get_best_device (NMData *data)
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
		NMDevice	*dev = NULL;
		guint	 dev_type;
		gboolean	 link_active;
		guint	 prio = 0;

		dev = (NMDevice *)(element->data);

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
		}

		element = g_slist_next (element);
	}

	syslog (LOG_NOTICE, "Best wired device = %s", best_wired_dev ? nm_device_get_iface (best_wired_dev) : "(null)");
	syslog (LOG_NOTICE, "Best wireless device = %s  (%s)", best_wireless_dev ? nm_device_get_iface (best_wireless_dev) : "(null)",
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
	if (data->info_daemon_avail && data->update_ap_lists)
	{
		/* Query info daemon for network lists if its now running */
		if (data->trusted_ap_list)
			nm_ap_list_unref (data->trusted_ap_list);
		data->trusted_ap_list = nm_ap_list_new (NETWORK_TYPE_TRUSTED);
		if (data->trusted_ap_list)
			nm_ap_list_populate (data->trusted_ap_list, data);

		if (data->preferred_ap_list)
			nm_ap_list_unref (data->preferred_ap_list);
		data->preferred_ap_list = nm_ap_list_new (NETWORK_TYPE_PREFERRED);
		if (data->preferred_ap_list)
			nm_ap_list_populate (data->preferred_ap_list, data);

		data->update_ap_lists = FALSE;
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
			NMDevice		*best_dev = NULL;

			if ((best_dev = nm_policy_get_best_device (data)))
				nm_device_ref (best_dev);

			/* Only do a switch when:
			 * 1) the best_dev is different from data->active_device, OR
			 * 2) best_dev is wireless and its access point is not the "best" ap, OR
			 * 3) best_dev is wireless and its access point is the best, but it doesn't have an IP address
			 */
			if (    best_dev != data->active_device
				|| (    best_dev && nm_device_is_wireless (best_dev) && !nm_device_activating (best_dev)
					&& (nm_device_need_ap_switch (best_dev) || (nm_device_get_ip4_address (best_dev) == 0))))
			{
				syslog (LOG_INFO, "nm_state_modification_monitor(): beginning activation for device '%s'", best_dev ? nm_device_get_iface (best_dev) : "(null)");

				/* Deactivate the old device */
				if (data->active_device)
				{
					nm_device_deactivate (data->active_device, FALSE);
					nm_device_unref (data->active_device);
					data->active_device = NULL;
				}

				/* Begin activation on the new device */
				nm_device_ref (best_dev);
				data->active_device = best_dev;
				nm_device_activation_begin (data->active_device);
			}

			nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
		}
		else
			syslog( LOG_ERR, "nm_state_modification_monitor() could not get device list mutex");
	}
	else if (data->active_device && nm_device_just_activated (data->active_device))
	{
		nm_dbus_signal_device_now_active (data->dbus_connection, data->active_device);
		syslog (LOG_INFO, "nm_state_modification_monitor() activated device %s", nm_device_get_iface (data->active_device));
	}

	return (TRUE);
}

#if 0
/*
 * nm_policy_allowed_ap_refresh_worker
 *
 * Worker thread function to periodically refresh the allowed
 * access point list with updated data.
 *
 */
gpointer nm_policy_allowed_ap_refresh_worker (gpointer user_data)
{
	NMData		*data = (NMData *)(user_data);
	struct timeval	 timeout;
	
	g_return_val_if_fail (data != NULL, NULL);
	
	/* Simply loop and every 20s update the available allowed ap data */
	while (!allowed_ap_worker_exit)
	{
		int	err;

		timeout.tv_sec = 20;
		timeout.tv_usec = 0;
		
		/* Wait, but don't execute the update if select () returned an error,
		 * since it may have immediately returned, so that we don't hammer
		 * GConf (or the hard drive).
		 */
		err = select (0, NULL, NULL, NULL, &timeout);
		if (err >= 0)
			nm_policy_update_allowed_access_points (data);
	}

	g_thread_exit (0);

	return (NULL);
}


/*
 * nm_policy_update_allowed_access_points
 *
 * Grabs a list of allowed access points from the user's preferences
 *
 */
void nm_policy_update_allowed_access_points	(NMData *data)
{
#define	NM_ALLOWED_AP_FILE		"/etc/sysconfig/networking/allowed_access_points"

	FILE		*ap_file;

	g_return_if_fail (data != NULL);

	if (nm_try_acquire_mutex (data->allowed_ap_list_mutex, __FUNCTION__))
	{
		ap_file = fopen (NM_ALLOWED_AP_FILE, "r");
		if (ap_file)
		{
			gchar	line[ 500 ];
			gchar	prio[ 20 ];
			gchar	essid[ 50 ];
			gchar	wep_key[ 50 ];
			
			/* Free the old list of allowed access points */
//			nm_data_allowed_ap_list_free (data);

			while (fgets (line, 499, ap_file))
			{
				guint	 len = strnlen (line, 499);
				gchar	*p = &line[0];
				gchar	*end = strchr (line, '\n');
				guint	 op = 0;

				strcpy (prio, "\0");
				strcpy (essid, "\0");
				strcpy (wep_key, "\0");

				if (end)
					*end = '\0';
				else
					end = p + len - 1;

				while ((end-p > 0) && (*p=='\t'))
					p++;

				while (end-p > 0)
				{
					switch (op)
					{
						case 0:
							strncat (prio, p, 1);
							break;
						case 1:
							strncat (essid, p, 1);
							break;
						case 2:
							strncat (wep_key, p, 1);
							break;
						default:
							break;
					}
					p++;

					if ((end-p > 0) && (*p=='\t'))
					{
						op++;
						while ((end-p > 0) && (*p=='\t'))
							p++;
					}
				}

				/* Create a new entry for this essid */
				if (strlen (essid) > 0)
				{
					NMAccessPoint		*ap;
					guint			 prio_num = atoi (prio);

					if (prio_num < 1)
						prio_num = NM_AP_PRIORITY_WORST;
					else if (prio_num > NM_AP_PRIORITY_WORST)
						prio_num = NM_AP_PRIORITY_WORST;

					ap = nm_ap_new ();
					nm_ap_set_priority (ap, prio_num);
					nm_ap_set_essid (ap, essid);
					if (strlen (wep_key) > 0)
						nm_ap_set_wep_key (ap, wep_key);

					data->allowed_ap_list = g_slist_append (data->allowed_ap_list, ap);
					/*
					syslog( LOG_DEBUG, "FOUND: allowed ap, prio=%d  essid=%s  wep_key=%s", prio_num, essid, wep_key );
					*/
				}
			}

			fclose (ap_file);
		}
		else
			syslog( LOG_WARNING, "nm_policy_update_allowed_access_points() could not open allowed ap list file %s.  errno %d", NM_ALLOWED_AP_FILE, errno );
	
		nm_unlock_mutex (data->allowed_ap_list_mutex, __FUNCTION__);
	}
	else
		syslog( LOG_ERR, "nm_policy_update_allowed_access_points() could not lock allowed ap list mutex" );
}
#endif
