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
#include <iwlib.h>
#include "NetworkManager.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerWireless.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"

extern gboolean	debug;


/*
 * nm_wireless_is_most_prefered_ap
 *
 * For a given AP, filter it through the allowed list and return TRUE if its
 * both allowed _and_ has a better priority than highest_priority.
 *
 */
static gboolean nm_wireless_is_most_prefered_ap (NMAccessPoint *ap, int *highest_priority)
{
	NMData		*data = nm_get_global_data ();
	GSList		*element;
	gboolean		 is_most_preferred = FALSE;

	g_return_val_if_fail (ap != NULL, FALSE);

	/* Attempt to acquire mutex for device list iteration.
	 * If the acquire fails, just ignore the scan completely.
	 */
	if (nm_try_acquire_mutex (data->allowed_ap_list_mutex, __FUNCTION__))
	{
		element = data->allowed_ap_list;
		while (element)
		{
			NMAccessPoint	*allowed_ap = (NMAccessPoint *)(element->data);

			/* If the essid of the scanned ap matches one in our allowed list, and this AP is
			 * a higher priority than one we may possibly have already found.
			 */
			if (    allowed_ap
				&& (nm_null_safe_strcmp (nm_ap_get_essid (allowed_ap), nm_ap_get_essid (ap)) == 0)
				&& (nm_ap_get_priority (allowed_ap) < *highest_priority))
			{
				is_most_preferred = TRUE;
				break;
			}

			element = g_slist_next (element);
		}
		nm_unlock_mutex (data->allowed_ap_list_mutex, __FUNCTION__);
	}
	else
		NM_DEBUG_PRINT( "nm_wireless_is_most_prefered_ap() could not acquire allowed access point mutex.\n" );
	
	return (is_most_preferred);
}


/*
 * nm_wireless_do_scan
 *
 * Runs the actual scan fore access points.
 *
 */
void nm_wireless_do_scan (NMData *data, NMDevice *dev)
{
	int		iwlib_socket;

	g_return_if_fail (data != NULL);
	g_return_if_fail (dev  != NULL);

	if (nm_device_get_iface_type (dev) != NM_IFACE_TYPE_WIRELESS_ETHERNET)
		return;

	if (nm_device_get_supports_wireless_scan (dev) == FALSE)
		return;

	/* Device must be up before we can scan */
	if (!nm_device_is_up (dev))
		nm_device_bring_up (dev);

	iwlib_socket = iw_sockets_open ();
	if (iwlib_socket >= 0)
	{
		wireless_scan_head	 scan_results = { NULL, 0 };
		wireless_scan		*tmp_ap;
		int				 err;
		NMAccessPoint		*highest_priority_ap = NULL;
		int				 highest_priority = NM_AP_PRIORITY_WORST;

		/* Clear out the device's ap list */
		nm_device_ap_list_clear (dev);

		err = iw_scan (iwlib_socket, nm_device_get_iface (dev), WIRELESS_EXT, &scan_results);

		/* Iterate over scan results and pick a "most" preferred access point. */
		tmp_ap = scan_results.result;
		while (tmp_ap)
		{
			/* Blank essids usually indicate an AP that is not broadcasting its essid,
			 * but since its not broadcasting the essid, we cannot use that ap yet.
			 */
			if (tmp_ap->b.has_essid && tmp_ap->b.essid_on && (strlen (tmp_ap->b.essid) > 0))
			{
				NMAccessPoint		*nm_ap  = nm_ap_new ();

				/* Copy over info from scan to local structure */
				nm_ap_set_essid (nm_ap, tmp_ap->b.essid);

				if (tmp_ap->has_ap_addr)
				{
					char		buf[20];

					memset (&buf[0], 0, 20);
					iw_ether_ntop((const struct ether_addr *) (tmp_ap->ap_addr.sa_data), &buf[0]);
					nm_ap_set_address (nm_ap, buf);
				}

				nm_ap_set_quality (nm_ap, tmp_ap->stats.qual.qual);

				if (tmp_ap->b.has_freq)
					nm_ap_set_freq (nm_ap, tmp_ap->b.freq);

				/* Add the AP to the device's AP list, no matter if its allowed or not */
				nm_device_ap_list_add (dev, nm_ap);

				if (nm_wireless_is_most_prefered_ap (nm_ap, &highest_priority))
				{
					if (highest_priority_ap)
						nm_ap_unref (highest_priority_ap);

					highest_priority_ap = nm_ap_new_from_ap (nm_ap);
				}
				nm_ap_unref (nm_ap);
			}
			tmp_ap = tmp_ap->next;
		}
		nm_dispose_scan_results (scan_results.result);

		/* If we have the "most" preferred access point, and its different than the current
		 * access point, switch to it during the next cycle.
		 */
		if (    highest_priority_ap
			&& (!data->desired_ap || (nm_null_safe_strcmp (nm_device_get_essid (dev), nm_ap_get_essid (highest_priority_ap)) != 0)))
		{
			if (data->desired_ap)
				nm_ap_unref (data->desired_ap);

			data->desired_ap = nm_ap_new_from_ap (highest_priority_ap);
			data->state_modified = TRUE;

			nm_ap_unref (highest_priority_ap);
		}
		close (iwlib_socket);
	}
	else
		NM_DEBUG_PRINT ("nm_wireless_do_scan() could not get a control socket for the wireless card.\n" );
}


/*
 * nm_wireless_scan_monitor
 *
 * Called every 10s to get a list of access points.
 *
 */
gboolean nm_wireless_scan_monitor (gpointer user_data)
{
	NMData	*data = (NMData *)user_data;
	GSList	*element;
	NMDevice	*dev;

	g_return_val_if_fail (data != NULL, TRUE);
	if (!data->active_device)
		return (TRUE);

	/* Grab a current list of allowed access points */
	nm_policy_update_allowed_access_points (data);

	/* Attempt to acquire mutex for device list iteration.
	 * If the acquire fails, just ignore the scan completely.
	 */
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		if (data->active_device && (nm_device_get_iface_type (data->active_device) == NM_IFACE_TYPE_WIRELESS_ETHERNET))
			nm_wireless_do_scan (data, data->active_device);

		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}
	else
		NM_DEBUG_PRINT( "nm_wireless_scan_monitor() could not acquire device list mutex.\n" );
	
	return (TRUE);
}
