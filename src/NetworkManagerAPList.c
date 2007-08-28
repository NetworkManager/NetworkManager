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
#include "nm-dbus-manager.h"


struct NMAccessPointList
{
	guint         refcount;
	NMNetworkType type;
	GSList *      ap_list;
};


/*
 * nm_ap_list_new
 *
 * Creates a new empty access point list
 *
 */
NMAccessPointList *nm_ap_list_new (NMNetworkType type)
{
	NMAccessPointList *list = g_slice_new0 (NMAccessPointList);

	nm_ap_list_ref (list);
	list->type = type;
	return list;
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
	if (list->refcount <= 0) {
		g_slist_foreach (list->ap_list, (GFunc) g_object_unref, NULL);
		g_slist_free (list->ap_list);
		g_slice_free (NMAccessPointList, list);
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
	g_return_val_if_fail (list != NULL, 0);

	return g_slist_length (list->ap_list);
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

	list->ap_list = g_slist_append (list->ap_list, g_object_ref (ap));
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

	for (elt = list->ap_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint * list_ap = (NMAccessPoint *) elt->data;

		if (list_ap == ap) {
			list->ap_list = g_slist_remove_link (list->ap_list, elt);
			g_object_unref (list_ap);
			g_slist_free (elt);
			break;
		}
	}
}


/*
 * nm_ap_list_remove_ap_by_ssid
 *
 * Helper to remove an AP from an AP list by the AP's SSID.
 *
 */
void
nm_ap_list_remove_ap_by_ssid (NMAccessPointList *list, const GByteArray * ssid)
{
	GSList * elt = NULL;

	g_return_if_fail (list != NULL);
	g_return_if_fail (ssid != NULL);

	for (elt = list->ap_list; elt; elt = g_slist_next (elt)) {
		NMAccessPoint * list_ap = (NMAccessPoint *) elt->data;

		if (nm_utils_same_ssid (nm_ap_get_ssid (list_ap), ssid, TRUE)) {
			list->ap_list = g_slist_remove_link (list->ap_list, elt);
			g_object_unref (list_ap);
			g_slist_free (elt);
			break;
		}
	}
}

/* nm_ap_list_remove_duplicate_ssids
 *
 */
void    nm_ap_list_remove_duplicate_ssids (NMAccessPointList *list)
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

	for (elt_i = list->ap_list; elt_i; elt_i = g_slist_next (elt_i)) {
		NMAccessPoint * list_ap_i = (NMAccessPoint *) elt_i->data;
		const GByteArray * list_ap_i_ssid = nm_ap_get_ssid (list_ap_i);
		gboolean        found = FALSE;

		for (elt_j = list->ap_list; elt_j < elt_i; elt_j = g_slist_next (elt_j)) {
			NMAccessPoint * list_ap_j = (NMAccessPoint *) elt_j->data;
			const GByteArray * list_ap_j_ssid = nm_ap_get_ssid (list_ap_j);

			if ((found = nm_utils_same_ssid (list_ap_i_ssid, list_ap_j_ssid, TRUE)))
				break;
		}

		if (found)
			continue;

		elt_max = elt_i;
		list_ap_max = (NMAccessPoint *)(elt_i->data);
		max_strength = nm_ap_get_strength (list_ap_i);

		for (elt_j = g_slist_next (elt_i); elt_j; elt_j = g_slist_next (elt_j)) {
			NMAccessPoint   *list_ap_j = (NMAccessPoint *) elt_j->data;
			const GByteArray * list_ap_j_ssid = nm_ap_get_ssid (list_ap_j);

			strengthj = nm_ap_get_strength (list_ap_j);
			if (nm_utils_same_ssid (list_ap_i_ssid, list_ap_j_ssid, TRUE)) {
				if (strengthj > max_strength) {
					removal_list = g_slist_append (removal_list, list_ap_max);
					list_ap_max = list_ap_j;
					max_strength = strengthj;
				} else {
					removal_list = g_slist_append (removal_list, list_ap_j);
				}
			}
		}
	}

	for (elt = removal_list; elt; elt = g_slist_next (elt)) {
		if ((removal_ap = (NMAccessPoint *)(elt->data)))
			nm_ap_list_remove_ap (list, removal_ap);
	}
	g_slist_free (removal_list);
}


/*
 * nm_ap_list_get_ap_by_ssid
 *
 * Search through an access point list and return the access point
 * that has a given SSID.
 *
 */
NMAccessPoint *
nm_ap_list_get_ap_by_ssid (NMAccessPointList *list, const GByteArray * ssid)
{
	NMAccessPoint	*ap;
	NMAccessPoint	*found_ap = NULL;
	NMAPListIter	*iter;

	if (!ssid || !list)
		return NULL;

	if (!(iter = nm_ap_list_iter_new (list)))
		return NULL;

	while ((ap = nm_ap_list_iter_next (iter))) {
		const GByteArray * ap_ssid = nm_ap_get_ssid (ap);
		if (ap_ssid && nm_utils_same_ssid (ap_ssid, ssid, TRUE)) {
			found_ap = ap;
			break;
		}
	}
	nm_ap_list_iter_free (iter);

	return found_ap;
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

	if (!(iter = nm_ap_list_iter_new (dest)))
		return;

	while ((dest_ap = nm_ap_list_iter_next (iter)))
	{
		NMAccessPoint	*src_ap = NULL;

		if ((src_ap = nm_ap_list_get_ap_by_ssid (source, nm_ap_get_ssid (dest_ap))))
		{
			nm_ap_set_invalid (dest_ap, nm_ap_get_invalid (src_ap));
			nm_ap_set_flags (dest_ap, nm_ap_get_flags (src_ap));
			nm_ap_set_wpa_flags (dest_ap, nm_ap_get_wpa_flags (src_ap));
			nm_ap_set_rsn_flags (dest_ap, nm_ap_get_rsn_flags (src_ap));
			nm_ap_set_timestamp_via_timestamp (dest_ap, nm_ap_get_timestamp (src_ap));
		}
	}
	nm_ap_list_iter_free (iter);
}


/*
 * nm_ap_list_copy_one_ssid_by_address
 *
 * If the access point doesn't have an SSID, search through a list of access points
 * and find one (if any) that has the MAC address of the access point we're looking for.
 * If one is found, copy the SSID over to the original access point.
 *
 */
void
nm_ap_list_copy_one_ssid_by_address (NMAccessPoint *ap,
                                     NMAccessPointList *search_list)
{
	NMAccessPoint * found_ap;
	const GByteArray * ssid;

	g_return_if_fail (ap != NULL);

	/* Ignore APs that already have an SSID */
	if (!search_list || nm_ap_get_ssid (ap))
		return;

	found_ap = nm_ap_list_get_ap_by_address (search_list, nm_ap_get_address (ap));
	ssid = found_ap ? nm_ap_get_ssid (found_ap) : NULL; 

	if (ssid)
		nm_ap_set_ssid (ap, ssid);
}


/*
 * nm_ap_list_copy_ssids_by_address
 *
 * For each blank-SSID access point in the destination list, try to find
 * an access point in the source list that has the same MAC address, and if
 * its found, copy the source access point's SSID to the dest access point.
 *
 */
void
nm_ap_list_copy_ssids_by_address (NMAccessPointList *dest,
                                  NMAccessPointList *source)
{
	NMAPListIter	*iter;
	NMAccessPoint	*dest_ap;

	if (!dest || !source)
		return;

	if (!(iter = nm_ap_list_iter_new (dest)))
		return;

	while ((dest_ap = nm_ap_list_iter_next (iter)))
		nm_ap_list_copy_one_ssid_by_address (dest_ap, source);
	nm_ap_list_iter_free (iter);
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


struct NMAPListIter
{
	NMAccessPointList * list;
	GSList *            cur_pos;
	gboolean            valid;
};


NMAPListIter * nm_ap_list_iter_new (NMAccessPointList *list)
{
	NMAPListIter	*iter;

	g_return_val_if_fail (list != NULL, NULL);

	iter = g_slice_new (NMAPListIter);

	iter->list = list;
	iter->cur_pos = list->ap_list;
	iter->valid = FALSE;

	return iter;
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

	if (iter->valid) {
		iter->cur_pos = g_slist_next (iter->cur_pos);
	} else {
		iter->valid = TRUE;
		iter->cur_pos = iter->list->ap_list;
	}
	return (nm_ap_list_iter_get_ap (iter));
}


void nm_ap_list_iter_free (NMAPListIter *iter)
{
	g_return_if_fail (iter != NULL);

	memset (iter, 0, sizeof (struct NMAPListIter));
	g_slice_free (NMAPListIter, iter);
}


/*
 * nm_ap_list_print_members
 *
 * Print the information about each access point in an AP list
 *
 */
void nm_ap_list_print_members (NMAccessPointList *list, const char *name)
{
	NMAccessPoint * ap;
	NMAPListIter *  iter;
	int             i = 0;

	g_return_if_fail (list != NULL);
	g_return_if_fail (name != NULL);

	if (!(iter = nm_ap_list_iter_new (list)))
		return;

	nm_info ("AP_LIST_PRINT: printing members of '%s'", name);
	while ((ap = nm_ap_list_iter_next (iter)))
		nm_ap_print_self (ap, "::\t");
	nm_info ("AP_LIST_PRINT: done");
	nm_ap_list_iter_free (iter);
}

