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

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <netinet/ether.h>
#include "NetworkManagerAP.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerDbus.h"
#include "nm-utils.h"


struct NMAccessPointList
{
	guint		 refcount;
	NMNetworkType	 type;
	GSList		*ap_list;
	GMutex		*mutex;
};


/*
 * nm_ap_list_new
 *
 * Creates a new empty access point list
 *
 */
NMAccessPointList *nm_ap_list_new (NMNetworkType type)
{
	NMAccessPointList *list = g_new0 (NMAccessPointList, 1);

	g_return_val_if_fail (list != NULL, NULL);

	nm_ap_list_ref (list);
	list->type = type;
	list->mutex = g_mutex_new ();
	if (!list->mutex)
	{
		g_free (list);
		nm_warning ("nm_ap_list_new() could not create list mutex");
		return (NULL);
	}
	nm_register_mutex_desc (list->mutex, "AP List Mutex");

	return (list);
}


/*
 * nm_ap_list_ref
 *
 * Increases the refcount of the ap list
 *
 */
void nm_ap_list_ref (NMAccessPointList *list)
{
	g_return_if_fail (list != NULL);

	list->refcount++;
}


/*
 * nm_ap_list_element_free
 *
 * Frees each member of an access point list before the list is
 * disposed of. 
 *
 */
static void nm_ap_list_element_free (void *element, void *user_data)
{
	nm_ap_unref (element);
}


/*
 * nm_ap_list_unref
 *
 * Decreases the refcount of the ap list, and if it reaches
 * 0 frees the structure.
 *
 */
void nm_ap_list_unref (NMAccessPointList *list)
{
	if (!list)
		return;

	list->refcount--;
	if (list->refcount <= 0)
	{
		gboolean	acquired = nm_try_acquire_mutex (list->mutex, __FUNCTION__);

		g_slist_foreach (list->ap_list, nm_ap_list_element_free, NULL);
		g_slist_free (list->ap_list);

		if (acquired)
			nm_unlock_mutex (list->mutex, __FUNCTION__);

		g_mutex_free (list->mutex);
		g_free(list);
	}
}


/*
 * nm_ap_list_size
 *
 * Return size of the access point list
 *
 */
guint nm_ap_list_size (NMAccessPointList *list)
{
	guint size;

	g_return_val_if_fail (list != NULL, 0);

	if (!nm_ap_list_lock (list))
	{
		nm_warning ("nm_ap_list_size() could not acquire AP list mutex." );
		return 0;
	}

	size = g_slist_length (list->ap_list);
	nm_ap_list_unlock (list);

	return size;
}


/*
 * nm_ap_list_is_empty
 *
 * Returns whether or not the access point list has any access points
 * in it.
 *
 */
gboolean nm_ap_list_is_empty (NMAccessPointList *list)
{
	return ((list->ap_list == NULL));
}


/*
 * nm_ap_list_append_ap
 *
 * Helper to append an AP to an ap list of a certain type.
 *
 */
void nm_ap_list_append_ap (NMAccessPointList *list, NMAccessPoint *ap)
{
	g_return_if_fail (list != NULL);
	g_return_if_fail (ap != NULL);

	if (!nm_ap_list_lock (list))
	{
		nm_warning ("nm_ap_list_append_ap() could not acquire AP list mutex." );
		return;
	}

	nm_ap_ref (ap);
	list->ap_list = g_slist_append (list->ap_list, ap);

	nm_ap_list_unlock (list);
}


/*
 * nm_ap_list_remove_ap
 *
 * Helper to remove an AP to an ap list of a certain type.
 *
 */
void nm_ap_list_remove_ap (NMAccessPointList *list, NMAccessPoint *ap)
{
	GSList		*elt = NULL;

	g_return_if_fail (list != NULL);
	g_return_if_fail (ap != NULL);

	if (!nm_ap_list_lock (list))
	{
		nm_warning ("nm_ap_list_remove_ap() could not acquire AP list mutex." );
		return;
	}

	for (elt = list->ap_list; elt; elt = g_slist_next (elt))
	{
		NMAccessPoint	*list_ap = (NMAccessPoint *)(elt->data);

		if (list_ap == ap)
		{
			list->ap_list = g_slist_remove_link (list->ap_list, elt);
			nm_ap_unref (list_ap);
			g_slist_free (elt);
			break;
		}
	}
	nm_ap_list_unlock (list);
}


/*
 * nm_ap_list_remove_ap_by_essid
 *
 * Helper to remove an AP from an AP list by the AP's ESSID.
 *
 */
void nm_ap_list_remove_ap_by_essid (NMAccessPointList *list, const char *network)
{
	GSList		*elt = NULL;

	g_return_if_fail (list != NULL);
	g_return_if_fail (network != NULL);

	if (!nm_ap_list_lock (list))
	{
		nm_warning ("nm_ap_list_remove_ap_by_essid() could not acquire AP list mutex." );
		return;
	}

	for (elt = list->ap_list; elt; elt = g_slist_next (elt))
	{
		NMAccessPoint	*list_ap = (NMAccessPoint *)(elt->data);

		if (nm_null_safe_strcmp (nm_ap_get_essid (list_ap), network) == 0)
		{
			list->ap_list = g_slist_remove_link (list->ap_list, elt);
			nm_ap_unref (list_ap);
			g_slist_free (elt);
			break;
		}
	}
	nm_ap_list_unlock (list);
}

/* nm_ap_list_remove_duplicate_essids
 *
 */
void    nm_ap_list_remove_duplicate_essids (NMAccessPointList *list)
{
	NMAccessPoint   *removal_ap;
	NMAccessPoint   *list_ap_max;
	GSList          *elt_i = NULL;	
	GSList          *elt_j = NULL;
	GSList          *elt_max = NULL;
	GSList          *removal_list = NULL;
	GSList          *elt;
	gint8            max_strength = 0;
	gint8            strengthj = 0;

	g_return_if_fail (list != NULL);

	if (!nm_ap_list_lock (list))
	{
		nm_warning ("nm_ap_list_append_ap() could not acquire AP list mutex." );
		return;
	}

	for (elt_i = list->ap_list; elt_i; elt_i = g_slist_next (elt_i))
	{
		NMAccessPoint   *list_ap_i = (NMAccessPoint *)(elt_i->data);
		gboolean         found = FALSE;

		for (elt_j = list->ap_list; elt_j < elt_i; elt_j = g_slist_next (elt_j))
		{
			NMAccessPoint   *list_ap_j = (NMAccessPoint *)(elt_j->data);

			if ((found = (nm_null_safe_strcmp (nm_ap_get_essid (list_ap_i), nm_ap_get_essid (list_ap_j)) == 0)))
				break;
		}

		if (found)
			continue;

		elt_max = elt_i;
		list_ap_max = (NMAccessPoint *)(elt_i->data);
		max_strength = nm_ap_get_strength (list_ap_i);

		for (elt_j = g_slist_next (elt_i); elt_j; elt_j = g_slist_next (elt_j))
		{
			NMAccessPoint   *list_ap_j = (NMAccessPoint *)(elt_j->data);

			strengthj = nm_ap_get_strength (list_ap_j);
			if (nm_null_safe_strcmp (nm_ap_get_essid (list_ap_i), nm_ap_get_essid (list_ap_j)) == 0)
			{
				if (strengthj > max_strength)
				{
					removal_list = g_slist_append (removal_list, list_ap_max);
					list_ap_max = list_ap_j;
					max_strength = strengthj;
				}
				else
					removal_list = g_slist_append (removal_list, list_ap_j);
			}
		}
	}
	nm_ap_list_unlock (list);

	for (elt = removal_list; elt; elt = g_slist_next (elt))
	{
		if ((removal_ap = (NMAccessPoint *)(elt->data)))
			nm_ap_list_remove_ap (list, removal_ap);
	}
	g_slist_free (removal_list);

}


/*
 * nm_ap_list_get_ap_by_essid
 *
 * Search through an access point list and return the access point
 * that has a given essid.
 *
 */
NMAccessPoint *nm_ap_list_get_ap_by_essid (NMAccessPointList *list, const char *network)
{
	NMAccessPoint	*ap;
	NMAccessPoint	*found_ap = NULL;
	NMAPListIter	*iter;

	if (!network)
		return (NULL);

	if (!list)
		return (NULL);

	if (!(iter = nm_ap_list_iter_new (list)))
		return (NULL);

	while ((ap = nm_ap_list_iter_next (iter)))
	{
		if (nm_ap_get_essid (ap) && (nm_null_safe_strcmp (nm_ap_get_essid (ap), network) == 0))
		{
			found_ap = ap;
			break;
		}
	}
	nm_ap_list_iter_free (iter);

	return (found_ap);
}


/*
 * nm_ap_list_get_ap_by_address
 *
 * Search through an access point list and return the access point
 * that has a given AP address.
 *
 */
NMAccessPoint *nm_ap_list_get_ap_by_address (NMAccessPointList *list, const struct ether_addr *addr)
{
	NMAccessPoint	*ap;
	NMAccessPoint	*found_ap = NULL;
	NMAPListIter	*iter;

	if (!addr)
		return (NULL);

	if (!list)
		return (NULL);

	if (!(iter = nm_ap_list_iter_new (list)))
		return (NULL);

	while ((ap = nm_ap_list_iter_next (iter)))
	{
		GSList	*user_addrs;
		gboolean	 success = FALSE;

		if (nm_ap_get_address (ap) && (memcmp (addr, nm_ap_get_address (ap), sizeof (struct ether_addr)) == 0))
			success = TRUE;

		if (!success && (user_addrs = nm_ap_get_user_addresses (ap)))
		{
			char		 char_addr[20];
			GSList	*elt;

			memset (&char_addr[0], 0, 20);
			iw_ether_ntop (addr, &char_addr[0]);
			for (elt = user_addrs; elt; elt = g_slist_next (elt))
			{
				if (elt->data && !strcmp (elt->data, &char_addr[0]))
				{
					success = TRUE;
					break;
				}
			}

			g_slist_foreach (user_addrs, (GFunc)g_free, NULL);
			g_slist_free (user_addrs);
		}

		if (success)
		{
			found_ap = ap;
			break;
		}
	}
	nm_ap_list_iter_free (iter);

	return (found_ap);
}


/*
 * nm_ap_list_merge_scanned_ap
 *
 * Given an AP list and an access point, merge the access point into the list.
 * If the AP is already in the list, merge just the /attributes/ together for that
 * AP, if its not already in the list then just add it.  This doesn't merge all
 * attributes, just ones that are likely to be new from the scan.
 *
 * Returns:	FALSE if the AP was not new and was merged
 *			TRUE if the ap was completely new
 *
 */
gboolean nm_ap_list_merge_scanned_ap (NMDevice80211Wireless *dev, NMAccessPointList *list, NMAccessPoint *merge_ap)
{
	NMAccessPoint *			list_ap = NULL;
	gboolean					strength_changed = FALSE;
	gboolean					new = FALSE;
	NMData *					app_data;
	const struct ether_addr *	merge_bssid;

	g_return_val_if_fail (dev != NULL, FALSE);
	g_return_val_if_fail (list != NULL, FALSE);
	g_return_val_if_fail (merge_ap != NULL, FALSE);

	app_data = nm_device_get_app_data (NM_DEVICE (dev));
	g_return_val_if_fail (app_data != NULL, FALSE);

	merge_bssid = nm_ap_get_address (merge_ap);
	if (nm_ethernet_address_is_valid (merge_bssid) && (list_ap = nm_ap_list_get_ap_by_address (list, merge_bssid)))
	{
		/* First, we check for an address match.  If the merge AP has a valid
		 * BSSID and the same address as a list AP, then the merge AP and
		 * the list AP must be the same physical AP. The list AP properties must
		 * be from a previous scan so the time_last_seen's are not equal.  Update
		 * encryption, authentication method, strength, and the time_last_seen. */

		const char *	devlist_essid = nm_ap_get_essid (list_ap);
		const char *	merge_essid = nm_ap_get_essid (merge_ap);
		const GTimeVal  *merge_ap_seen = nm_ap_get_last_seen (merge_ap);

		/* Did the AP's name change? */
		if (!devlist_essid || !merge_essid || nm_null_safe_strcmp (devlist_essid, merge_essid))
		{
			nm_dbus_signal_wireless_network_change (app_data->dbus_connection,
			        dev, list_ap, NETWORK_STATUS_DISAPPEARED, -1);
			new = TRUE;
		}

		nm_ap_set_capabilities (list_ap, nm_ap_get_capabilities (merge_ap));
		if (nm_ap_get_strength (merge_ap) != nm_ap_get_strength (list_ap))
		{
			nm_ap_set_strength (list_ap, nm_ap_get_strength (merge_ap));
			strength_changed = TRUE;
		}
		nm_ap_set_last_seen (list_ap, merge_ap_seen);
		nm_ap_set_broadcast (list_ap, nm_ap_get_broadcast (merge_ap));

		/* If the AP is noticed in a scan, it's automatically no longer
		 * artificial, since it clearly exists somewhere.
		 */
		nm_ap_set_artificial (list_ap, FALSE);

		/* Have to change AP's name _after_ dbus signal for old network name
		 * has gone out.
		 */
		nm_ap_set_essid (list_ap, merge_essid);
	}
	else if ((list_ap = nm_ap_list_get_ap_by_essid (list, nm_ap_get_essid (merge_ap))))
	{
		/* Second, we check for an ESSID match. In this case,
		 * a list AP has the same non-NULL ESSID as the merge AP. Update the
		 * encryption and authentication method. Update the strength and address
		 * except when the time_last_seen of the list AP is the same as the
		 * time_last_seen of the merge AP and the strength of the list AP is greater
		 * than or equal to the strength of the merge AP. If the time_last_seen's are
		 * equal, the merge AP and the list AP come from the same scan.
		 * Update the time_last_seen. */

		const GTimeVal *	merge_ap_seen = nm_ap_get_last_seen (merge_ap);
		const GTimeVal *	list_ap_seen = nm_ap_get_last_seen (list_ap);
		const int			merge_ap_strength = nm_ap_get_strength (merge_ap);

		nm_ap_set_capabilities (list_ap, nm_ap_get_capabilities (merge_ap));

		if (!((list_ap_seen->tv_sec == merge_ap_seen->tv_sec)
			&& (nm_ap_get_strength (list_ap) >= merge_ap_strength)))
		{
			nm_ap_set_strength (list_ap, merge_ap_strength);
			nm_ap_set_address (list_ap, nm_ap_get_address (merge_ap));
		}
		nm_ap_set_last_seen (list_ap, merge_ap_seen);
		nm_ap_set_broadcast (list_ap, nm_ap_get_broadcast (merge_ap));

		/* If the AP is noticed in a scan, it's automatically no longer
		 * artificial, since it clearly exists somewhere.
		 */
		nm_ap_set_artificial (list_ap, FALSE);
	}
	else
	{
		/* Add the merge AP to the list. */
		nm_ap_list_append_ap (list, merge_ap);
		list_ap = merge_ap;
		new = TRUE;
	}

	if (list_ap && strength_changed && !new)
	{
		const int new_strength = nm_ap_get_strength (list_ap);
		nm_dbus_signal_wireless_network_change (app_data->dbus_connection,
		        dev, list_ap, NETWORK_STATUS_STRENGTH_CHANGED, new_strength);
	}

	if (list_ap && new)
	{
		nm_dbus_signal_wireless_network_change (app_data->dbus_connection,
		        dev, list_ap, NETWORK_STATUS_APPEARED, -1);
	}

	return TRUE;
}


/*
 * nm_ap_list_copy_properties
 *
 * Update properties (like encryption keys or timestamps) in one access point list from
 * access points in another list, if the APs in the first list are present
 * in the second.
 *
 */
void nm_ap_list_copy_properties (NMAccessPointList *dest, NMAccessPointList *source)
{
	NMAPListIter	*iter;
	NMAccessPoint	*dest_ap;

	if (!dest || !source)
		return;

	if ((iter = nm_ap_list_iter_new (dest)))
	{
		while ((dest_ap = nm_ap_list_iter_next (iter)))
		{
			NMAccessPoint	*src_ap = NULL;

			if ((src_ap = nm_ap_list_get_ap_by_essid (source, nm_ap_get_essid (dest_ap))))
			{
				nm_ap_set_invalid (dest_ap, nm_ap_get_invalid (src_ap));
				nm_ap_set_security (dest_ap, nm_ap_get_security (src_ap));
				nm_ap_set_timestamp_via_timestamp (dest_ap, nm_ap_get_timestamp (src_ap));
			}
		}
		nm_ap_list_iter_free (iter);
	}
}


/*
 * nm_ap_list_copy_one_essid_by_address
 *
 * If the access point doesn't have an ESSID, search through a list of access points
 * and find one (if any) that has the MAC address of the access point we're looking for.
 * If one is found, copy the essid over to the original access point.
 *
 */
void nm_ap_list_copy_one_essid_by_address (NMData *app_data,
								   NMDevice80211Wireless *dev,
								   NMAccessPoint *ap,
								   NMAccessPointList *search_list)
{
	NMAccessPoint	*found_ap;

	if (!ap || !search_list)
		return;

	if (!nm_ap_get_essid (ap) && (found_ap = nm_ap_list_get_ap_by_address (search_list, nm_ap_get_address (ap))))
	{
		if (nm_ap_get_essid (found_ap))
		{
			nm_ap_set_essid (ap, nm_ap_get_essid (found_ap));
			nm_dbus_signal_wireless_network_change (app_data->dbus_connection, dev, ap, NETWORK_STATUS_APPEARED, 0);
		}
	}
}


/*
 * nm_ap_list_copy_essids_by_address
 *
 * For each blank-essid access point in the destination list, try to find
 * an access point in the source list that has the same MAC address, and if
 * its found, copy the source access point's essid to the dest access point.
 *
 */
void nm_ap_list_copy_essids_by_address (NMData *app_data,
								NMDevice80211Wireless *dev,
								NMAccessPointList *dest,
								NMAccessPointList *source)
{
	NMAPListIter	*iter;
	NMAccessPoint	*dest_ap;

	if (!dest || !source)
		return;

	if ((iter = nm_ap_list_iter_new (dest)))
	{
		while ((dest_ap = nm_ap_list_iter_next (iter)))
			nm_ap_list_copy_one_essid_by_address (app_data, dev, dest_ap, source);

		nm_ap_list_iter_free (iter);
	}
}


/*
 * nm_ap_list_get_type
 *
 * Return the type of an AP list
 *
 */
NMNetworkType nm_ap_list_get_type (NMAccessPointList *list)
{
	g_return_val_if_fail (list != NULL, NETWORK_TYPE_UNKNOWN);

	return (list->type);
}


/*
 * nm_ap_list_lock
 *
 * Grab exclusive access to an access point list
 *
 */
gboolean nm_ap_list_lock (NMAccessPointList *list)
{
	g_return_val_if_fail (list != NULL, FALSE);

	return (nm_try_acquire_mutex (list->mutex, __FUNCTION__));
}


/*
 * nm_ap_list_unlock
 *
 * Give up access to an access point list
 *
 */
void nm_ap_list_unlock (NMAccessPointList *list)
{
	g_return_if_fail (list != NULL);

	nm_unlock_mutex (list->mutex, __FUNCTION__);
}



struct NMAPListIter
{
	NMAccessPointList	*list;
	GSList			*cur_pos;
	gboolean			 valid;
};


NMAPListIter * nm_ap_list_iter_new (NMAccessPointList *list)
{
	NMAPListIter	*iter;

	g_return_val_if_fail (list != NULL, NULL);

	if (!(iter = g_new0 (NMAPListIter, 1)))
		return (NULL);

	if (!nm_ap_list_lock (list))
	{
		g_free (iter);
		return (NULL);
	}

	iter->list = list;
	iter->cur_pos = list->ap_list;
	iter->valid = FALSE;

	return (iter);
}


NMAccessPoint * nm_ap_list_iter_get_ap (NMAPListIter *iter)
{
	g_return_val_if_fail (iter != NULL, NULL);
	g_return_val_if_fail (iter->valid, NULL);

	if (!iter->cur_pos)
		return (NULL);

	return ((NMAccessPoint *)(iter->cur_pos->data));
}


NMAccessPoint * nm_ap_list_iter_next (NMAPListIter *iter)
{
	g_return_val_if_fail (iter != NULL, NULL);

	if (iter->valid)
		iter->cur_pos = g_slist_next (iter->cur_pos);
	else
	{
		iter->valid = TRUE;
		iter->cur_pos = iter->list->ap_list;
	}
	return (nm_ap_list_iter_get_ap (iter));
}


void nm_ap_list_iter_free (NMAPListIter *iter)
{
	g_return_if_fail (iter != NULL);

	nm_ap_list_unlock (iter->list);
	memset (iter, 0, sizeof (struct NMAPListIter));
	g_free (iter);
}


/*
 * nm_ap_list_print_members
 *
 * Print the information about each access point in an AP list
 *
 */
void nm_ap_list_print_members (NMAccessPointList *list, const char *name)
{
	NMAccessPoint	*ap;
	NMAPListIter	*iter;
	int			 i = 0;

	g_return_if_fail (list != NULL);
	g_return_if_fail (name != NULL);

	if (!(iter = nm_ap_list_iter_new (list)))
		return;

	nm_warning ("AP_LIST_PRINT: printing members of '%s'", name);
	while ((ap = nm_ap_list_iter_next (iter)))
	{
		const GTimeVal *	timestamp = nm_ap_get_timestamp (ap);
		const GTimeVal *	seen = nm_ap_get_last_seen (ap);
		NMAPSecurity * 	security = nm_ap_get_security (ap);
		nm_warning ("\t%d)\tobj=%p, essid='%s', timestamp=%ld, key='%s', enc=%d, addr=%p, strength=%d, %s=%f, rate=%d, inval=%d, mode=%d, seen=%ld",
				i, ap, nm_ap_get_essid (ap), timestamp->tv_sec, nm_ap_security_get_key (security), nm_ap_get_encrypted (ap),
				nm_ap_get_address (ap), nm_ap_get_strength (ap), (nm_ap_get_freq (ap) < 20) ? "channel" : "freq", nm_ap_get_freq (ap), nm_ap_get_rate (ap),
				nm_ap_get_invalid (ap), nm_ap_get_mode (ap), seen->tv_sec);
		i++;
	}
	nm_warning ("AP_LIST_PRINT: done");
	nm_ap_list_iter_free (iter);
}
