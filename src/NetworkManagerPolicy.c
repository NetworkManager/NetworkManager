
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

gboolean			allowed_ap_worker_exit = FALSE;
extern gboolean	debug;


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
			GSList		*element = data->dev_list;
			NMDevice		*best_wired_dev = NULL;
			guint		 best_wired_prio = 0;
			NMDevice		*best_wireless_dev = NULL;
			guint		 best_wireless_prio = 0;
			guint		 highest_priority = 0;
			NMDevice		*highest_priority_dev = NULL;
			gboolean		 essid_change_needed = FALSE;

			while (element)
			{
				NMDevice	*dev = NULL;
				guint	 iface_type;
				gboolean	 link_active;
				guint	 prio = 0;

				dev = (NMDevice *)(element->data);

				iface_type = nm_device_get_iface_type (dev);
				link_active = nm_device_get_link_active (dev);

				if (iface_type == NM_IFACE_TYPE_WIRED_ETHERNET)
				{
					if (link_active)
						prio += 1;

					if (data->active_device
						&& (dev == data->active_device)
						&& link_active)
						prio += 1;

					if (prio > best_wired_prio)
					{
						best_wired_dev = dev;
						best_wired_prio = prio;
					}
				}
				else if (iface_type == NM_IFACE_TYPE_WIRELESS_ETHERNET)
				{
					if (link_active)
						prio += 1;

					if (nm_device_get_supports_wireless_scan (dev))
						prio += 2;

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

			NM_DEBUG_PRINT_1 ("Best wired device = %s\n", best_wired_dev ? nm_device_get_iface (best_wired_dev) : "(null)");
			NM_DEBUG_PRINT_2 ("Best wireless device = %s  (%s)\n", best_wireless_dev ? nm_device_get_iface (best_wireless_dev) : "(null)",
						best_wireless_dev ? nm_device_get_essid (best_wireless_dev) : "null" );

			if (best_wireless_dev || best_wired_dev)
			{
				if (best_wired_dev)
					highest_priority_dev = best_wired_dev;
				else
					highest_priority_dev = best_wireless_dev;
			}
			else
			{
				/* No devices at all, wait for them to change status */
				nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
				return (TRUE);
			}

			/* If the current essid of the wireless card and the desired ap's essid are different,
			 * trigger an interface switch.  We switch to the same interface, but we still need to bring
			 * the device up again to get a new DHCP address.  However, don't switch if there is no
			 * desired ap.
			 */
			if (nm_device_get_iface_type (highest_priority_dev) == NM_IFACE_TYPE_WIRELESS_ETHERNET)
			{
				NMAccessPoint	*ap = nm_device_get_best_ap (highest_priority_dev);

				if (    ap
					&& (nm_null_safe_strcmp (nm_device_get_essid (highest_priority_dev), nm_ap_get_essid (ap)) != 0)
					&& (strlen (nm_ap_get_essid (ap)) > 0))
						essid_change_needed = TRUE;
			}

			/* If the highest priority device is different than data->active_device, switch the connection. */
			if (    essid_change_needed
				|| (!data->active_device || (highest_priority_dev != data->active_device)))
			{
				NM_DEBUG_PRINT_2 ("**** Switching active interface from '%s' to '%s'\n",
						data->active_device ? nm_device_get_iface (data->active_device) : "(null)",
						nm_device_get_iface (highest_priority_dev));

				/* FIXME
				 * We should probably wait a bit before forcibly changing connections
				 * after we send the signal.  However, dbus delivers its messages in the
				 * glib main loop.  If we call g_main_context_iteration(), we can deadlock
				 * but if we split this function into two steps and execute the second half,
				 * after a main loop iteration, we make a much more complicated state machine.
				 */
				if (data->active_device)
					nm_device_deactivate (data->active_device);

				if (data->active_device)
					nm_device_unref (data->active_device);

				data->active_device = highest_priority_dev;
				nm_device_ref (data->active_device);

				nm_device_activate (data->active_device);

				NM_DEBUG_PRINT ("**** Switched.\n");
			}

			nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
		}
		else
			NM_DEBUG_PRINT("nm_state_modification_monitor() could not get device list mutex\n");
	}

	return (TRUE);
}


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
	
	g_return_if_fail (data != NULL);
	
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
			nm_data_allowed_ap_list_free (data);

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
					NM_DEBUG_PRINT_3( "FOUND: allowed ap, prio=%d  essid=%s  wep_key=%s\n", prio_num, essid, wep_key );
					*/
				}
			}

			fclose (ap_file);
		}
		else
			NM_DEBUG_PRINT_2( "nm_policy_update_allowed_access_points() could not open allowed ap list file %s.  errno %d\n", NM_ALLOWED_AP_FILE, errno );
	
		nm_unlock_mutex (data->allowed_ap_list_mutex, __FUNCTION__);
	}
	else
		NM_DEBUG_PRINT( "nm_policy_update_allowed_access_points() could not lock allowed ap list mutex\n" );
}


/*
 * nm_policy_essid_is_allowed
 *
 * Searches for a specific essid in the list of allowed access points.
 */
gboolean nm_policy_essid_is_allowed (NMData *data, const unsigned char *essid)
{
	gboolean	allowed = FALSE;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (essid != NULL, FALSE);

	if (strlen (essid) <= 0)
		return FALSE;

	/* Acquire allowed AP list mutex, silently fail if we cannot */
	if (nm_try_acquire_mutex (data->allowed_ap_list_mutex, __FUNCTION__))
	{
		GSList	*element = data->allowed_ap_list;
		
		while (element)
		{
			NMAccessPoint		*ap = (NMAccessPoint *)(element->data);

			if (ap && (nm_null_safe_strcmp (nm_ap_get_essid (ap), essid) == 0))
			{
				allowed = TRUE;
				break;
			}
			element = g_slist_next (element);
		}

		nm_unlock_mutex (data->allowed_ap_list_mutex, __FUNCTION__);
	}

	return (allowed);
}
