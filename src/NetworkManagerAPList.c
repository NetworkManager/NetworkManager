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
		syslog (LOG_ERR, "nm_ap_list_new() could not create list mutex");
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
		syslog( LOG_ERR, "nm_ap_list_append_ap() could not acquire AP list mutex." );
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
		syslog( LOG_ERR, "nm_ap_list_remove_ap() could not acquire AP list mutex." );
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
		syslog (LOG_WARNING, "nm_ap_list_remove_ap_by_essid() could not acquire AP list mutex." );
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
	GSList		*elt_max = NULL;
	GSList          *removal_list = NULL;
	GSList          *elt;
	gint8            max_strength = 0;
	gint8            strengthj = 0;

	g_return_if_fail (list != NULL);

	if (!nm_ap_list_lock (list))
	{
		syslog (LOG_WARNING, "nm_ap_list_append_ap() could not acquire AP list mutex." );
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
		{
			nm_ap_list_remove_ap (list, removal_ap);
		}
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
			ether_ntoa_r (addr, &char_addr[0]);
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
 * nm_ap_list_update_network_from_nmi
 *
 * Given a network ID, get its information from NetworkManagerInfo
 *
 */
void nm_ap_list_update_network_from_nmi (NMAccessPointList *list, const char *network, NMData *data)
{
	NMAccessPoint	*ap = NULL;
	NMAccessPoint	*list_ap = NULL;

	g_return_if_fail (list != NULL);
	g_return_if_fail (network != NULL);
	g_return_if_fail (list->type == NETWORK_TYPE_ALLOWED);

	if ((ap = nm_dbus_get_network_object (data->dbus_connection, list->type, network)))
	{
		if ((list_ap = nm_ap_list_get_ap_by_essid (list, network)))
		{
			nm_ap_set_essid (list_ap, nm_ap_get_essid (ap));
			nm_ap_set_timestamp (list_ap, nm_ap_get_timestamp (ap));
			nm_ap_set_trusted (list_ap, nm_ap_get_trusted (ap));
			nm_ap_set_enc_key_source (list_ap, nm_ap_get_enc_key_source (ap), nm_ap_get_enc_type (ap));
			nm_ap_set_auth_method (list_ap, nm_ap_get_auth_method (ap));
			nm_ap_set_user_addresses (list_ap, nm_ap_get_user_addresses (ap));
		}
		else
		{
			/* New AP, just add it to the list */
			nm_ap_list_append_ap (list, ap);
		}
		nm_ap_unref (ap);
	}
	else
	{
		/* AP got deleted, remove it from our list */
		if ((list_ap = nm_ap_list_get_ap_by_essid (list, network)))
			nm_ap_list_remove_ap (list, list_ap);
	}
}


/*
 * nm_ap_list_populate_from_nmi
 *
 * Populate an initial list of allowed access points
 *
 */
void nm_ap_list_populate_from_nmi (NMAccessPointList *list, NMData *data)
{
	char		**networks;
	int		  num_networks;	

	g_return_if_fail (list != NULL);
	g_return_if_fail (data != NULL);
	g_return_if_fail (list->type == NETWORK_TYPE_ALLOWED);

	/* If NMI isn't running, don't try to talk to it. */
	if (!nm_dbus_nmi_is_running (data->dbus_connection))
		return;

	networks = nm_dbus_get_networks (data->dbus_connection, list->type, &num_networks);
	if (networks && (num_networks > 0))
	{
		int	i;
		for (i = 0; i < num_networks; i++)
		{
			if (networks[i] && (strlen (networks[i]) > 0))
				nm_ap_list_update_network_from_nmi (list, networks[i], data);
		}

		dbus_free_string_array (networks);
	}
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
gboolean nm_ap_list_merge_scanned_ap (NMAccessPointList *list, NMAccessPoint *merge_ap,
				gboolean *new, gboolean *strength_changed)
{
	NMAccessPoint   *list_ap_addr, *list_ap_essid;

	g_return_val_if_fail (list != NULL, FALSE);
	g_return_val_if_fail (merge_ap != NULL, FALSE);
	g_return_val_if_fail (new != NULL, FALSE);
	g_return_val_if_fail (strength_changed != NULL, FALSE);

	if ((list_ap_addr = nm_ap_list_get_ap_by_address (list, nm_ap_get_address (merge_ap))))
	{

		/* First, we check for an address match. If the merge AP has the
		 * same address as a list AP, the merge AP and the list AP
		 * must be the same physical AP. The list AP properties must be from
		 * a previous scan so the time_last_seen's are not equal.
		 * Update encryption, authentication method,
		 * strength, and the time_last_seen. */

		const GTimeVal  *merge_ap_seen = nm_ap_get_last_seen (merge_ap);

		nm_ap_set_encrypted (list_ap_addr, nm_ap_get_encrypted (merge_ap));
		nm_ap_set_auth_method (list_ap_addr, nm_ap_get_auth_method (merge_ap));
		if  (nm_ap_get_strength (merge_ap) != nm_ap_get_strength (list_ap_addr))
		{
			nm_ap_set_strength (list_ap_addr, nm_ap_get_strength (merge_ap));
			*strength_changed = TRUE;
		}
		nm_ap_set_last_seen (list_ap_addr, merge_ap_seen);
	}
	else if ((list_ap_essid = nm_ap_list_get_ap_by_essid (list, nm_ap_get_essid (merge_ap))))
	{

		/* Second, we check for an ESSID match. In this case,
       		 * a list AP has the same non-NULL ESSID as the merge AP. Update the
		 * encryption and authentication method. Update the strength and address
		 * except when the time_last_seen of the list AP is the same as the
		 * time_last_seen of the merge AP and the strength of the list AP is greater
		 * than or equal to the strength of the merge AP. If the time_last_seen's are
		 * equal, the merge AP and the list AP come from the same scan.
		 * Update the time_last_seen. */

		const GTimeVal  *merge_ap_seen = nm_ap_get_last_seen (merge_ap);
		const GTimeVal *list_ap_essid_seen = nm_ap_get_last_seen (list_ap_essid);

		nm_ap_set_encrypted (list_ap_essid, nm_ap_get_encrypted (merge_ap));
		nm_ap_set_auth_method (list_ap_essid, nm_ap_get_auth_method (merge_ap));

		if (!((list_ap_essid_seen->tv_sec == merge_ap_seen->tv_sec)
			&& (nm_ap_get_strength (list_ap_essid) >= nm_ap_get_strength (merge_ap))))
		{
			nm_ap_set_strength (list_ap_essid, nm_ap_get_strength (merge_ap));
			nm_ap_set_address (list_ap_essid, nm_ap_get_address (merge_ap)); 
			*strength_changed = TRUE;
		}
		nm_ap_set_last_seen (list_ap_essid, merge_ap_seen);
	}
	else
	{
		/* Add the merge AP to the list. */

		nm_ap_list_append_ap (list, merge_ap);
		*new = TRUE;
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
				nm_ap_set_enc_key_source (dest_ap, nm_ap_get_enc_key_source (src_ap), nm_ap_get_enc_type (src_ap));
				if (nm_ap_get_auth_method (src_ap) != NM_DEVICE_AUTH_METHOD_UNKNOWN)
				{
					/* Ensure that we don't set the NONE auth method from the src_ap
					 * if the dest_ap has encryption enabled.
					 */
					if (nm_ap_get_encrypted (dest_ap)  && (nm_ap_get_auth_method (src_ap) != NM_DEVICE_AUTH_METHOD_NONE))
						nm_ap_set_auth_method (dest_ap, nm_ap_get_auth_method (src_ap));
					else if (!nm_ap_get_encrypted (dest_ap))
						nm_ap_set_auth_method (dest_ap, NM_DEVICE_AUTH_METHOD_NONE);
				}
				nm_ap_set_timestamp (dest_ap, nm_ap_get_timestamp (src_ap));
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
void nm_ap_list_copy_one_essid_by_address (NMAccessPoint *ap, NMAccessPointList *search_list)
{
	NMAccessPoint	*found_ap;

	if (!ap || !search_list)
		return;

	if (!nm_ap_get_essid (ap) && (found_ap = nm_ap_list_get_ap_by_address (search_list, nm_ap_get_address (ap))))
	{
		if (nm_ap_get_essid (found_ap))
			nm_ap_set_essid (ap, nm_ap_get_essid (found_ap));
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
void nm_ap_list_copy_essids_by_address (NMAccessPointList *dest, NMAccessPointList *source)
{
	NMAPListIter	*iter;
	NMAccessPoint	*dest_ap;

	if (!dest || !source)
		return;

	if ((iter = nm_ap_list_iter_new (dest)))
	{
		while ((dest_ap = nm_ap_list_iter_next (iter)))
			nm_ap_list_copy_one_essid_by_address (dest_ap, source);

		nm_ap_list_iter_free (iter);
	}
}


/*
 * nm_ap_list_diff
 *
 * Takes two ap lists and determines the differences.  For each ap that is present
 * in the original list, but not in the new list, a WirelessNetworkDisappeared signal is emitted
 * over DBus.  For each ap in the new list but not in the original, a WirelessNetworkAppeared
 * signal is emitted.  For each ap that is the same between the lists, the "invalid" flag is copied
 * over from the old ap to the new ap to preserve "invalid" ap status (ie, user cancelled entering
 * a WEP key so we cannot connect to it anyway, so why try).
 *
 * NOTE: it is assumed that this function is called only ONCE for each list passed into it,
 *       since the "matched" value on access points in the list are never cleared after the
 *       ap is initially created.  Therefore, calling this function twice for any given ap list
 *       may result in undesired behavior.
 *
 */
void nm_ap_list_diff (NMData *data, NMDevice *dev, NMAccessPointList *old, NMAccessPointList *new)
{
	NMAPListIter	*iter;
	NMAccessPoint	*old_ap;
	NMAccessPoint	*new_ap;

	g_return_if_fail (data != NULL);
	g_return_if_fail (dev  != NULL);

	/* Iterate over each item in the old list and find it in the new list */
	if (old && (iter = nm_ap_list_iter_new (old)))
	{
		while ((old_ap = nm_ap_list_iter_next (iter)))
		{
			NMAccessPoint	*new_ap = NULL;

			if (nm_ap_get_essid (old_ap))
			{
				if ((new_ap = nm_ap_list_get_ap_by_essid (new, nm_ap_get_essid (old_ap))))
				{
					nm_ap_set_matched (old_ap, TRUE);
					nm_ap_set_matched (new_ap, TRUE);
				}
				else
					nm_dbus_signal_wireless_network_change (data->dbus_connection, dev, old_ap, NETWORK_STATUS_DISAPPEARED, -1);
			}
		}
		nm_ap_list_iter_free (iter);
	}

	/* Iterate over the new list and compare to the old list.  Items that aren't already
	 * matched are by definition new networks.
	 */
	if (new && (iter = nm_ap_list_iter_new (new)))
	{
		while ((new_ap = nm_ap_list_iter_next (iter)))
		{
			if (!nm_ap_get_matched (new_ap) && nm_ap_get_essid (new_ap))
				nm_dbus_signal_wireless_network_change (data->dbus_connection, dev, new_ap, NETWORK_STATUS_APPEARED, -1);
		}
		nm_ap_list_iter_free (iter);
	}
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

	syslog (LOG_ERR, "AP_LIST_PRINT: printing members of '%s'", name);
	while ((ap = nm_ap_list_iter_next (iter)))
	{
		const GTimeVal *timestamp = nm_ap_get_timestamp (ap);
		const struct ether_addr	*addr;
		char				char_addr[20];

		addr = nm_ap_get_address (ap);
		memset (char_addr, 0, 20);
		ether_ntoa_r (addr, &char_addr[0]);

		syslog (LOG_ERR, "\t%d)\tobj=%p, essid='%s', timestamp=%ld, key='%s', enc=%d, addr='%s', strength=%d, %s=%f, rate=%d, inval=%d, mode=%d",
				i, ap, nm_ap_get_essid (ap), timestamp->tv_sec, nm_ap_get_enc_key_source (ap), nm_ap_get_encrypted (ap),
				char_addr, nm_ap_get_strength (ap), (nm_ap_get_freq (ap) < 20) ? "channel" : "freq", nm_ap_get_freq (ap), nm_ap_get_rate (ap),
				nm_ap_get_invalid (ap), nm_ap_get_mode (ap));
		i++;
	}
	syslog (LOG_ERR, "AP_LIST_PRINT: done");
	nm_ap_list_iter_free (iter);
}
