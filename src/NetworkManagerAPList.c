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
#include "NetworkManagerAP.h"
#include "NetworkManagerAPList.h"
#include "NetworkManagerUtils.h"
#include "NetworkManagerDbus.h"

extern gboolean	debug;

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
	g_return_if_fail (list != NULL);

	list->refcount--;
	if (list->refcount <= 0)
	{
		gboolean	acquired = nm_try_acquire_mutex (list->mutex, __FUNCTION__);

		g_slist_foreach (list->ap_list, nm_ap_list_element_free, NULL);
		g_slist_free (list->ap_list);

		if (acquired)
			nm_unlock_mutex (list->mutex, __FUNCTION__);

		g_mutex_free (list->mutex);
	}
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

	if (!nm_try_acquire_mutex (list->mutex, __FUNCTION__))
	{
		syslog( LOG_ERR, "nm_ap_list_append_ap() could not acquire AP list mutex." );
		return;
	}

	nm_ap_ref (ap);
	list->ap_list = g_slist_append (list->ap_list, ap);

	nm_unlock_mutex (list->mutex, __FUNCTION__);
}


/*
 * nm_ap_list_remove_ap
 *
 * Helper to remove an AP to an ap list of a certain type.
 *
 */
void nm_ap_list_remove_ap (NMAccessPointList *list, NMAccessPoint *ap)
{
	GSList		*element = NULL;

	g_return_if_fail (list != NULL);
	g_return_if_fail (ap != NULL);

	if (!nm_try_acquire_mutex (list->mutex, __FUNCTION__))
	{
		syslog( LOG_ERR, "nm_ap_list_append_ap() could not acquire AP list mutex." );
		return;
	}

	element = list->ap_list;
	while (element)
	{
		NMAccessPoint	*list_ap = (NMAccessPoint *)(element->data);

		if (list_ap == ap)
		{
			list->ap_list = g_slist_remove_link (list->ap_list, element);
			nm_ap_unref (list_ap);
			g_slist_free (element);
			break;
		}
		element = g_slist_next (element);
	}

	nm_unlock_mutex (list->mutex, __FUNCTION__);
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

	g_return_val_if_fail (network != NULL, NULL);

	if (!list)
		return (NULL);

	if (!(iter = nm_ap_list_iter_new (list)))
		return (NULL);

	while ((ap = nm_ap_list_iter_next (iter)))
	{
		if (nm_null_safe_strcmp (nm_ap_get_essid (ap), network) == 0)
		{
			found_ap = ap;
			break;
		}
	}

	nm_ap_list_iter_free (iter);
	return (found_ap);
}


/*
 * nm_ap_list_update_network
 *
 * Given a network ID, get its information from NetworkManagerInfo
 *
 */
void nm_ap_list_update_network (NMAccessPointList *list, const char *network, NMData *data)
{
	NMAccessPoint	*ap = NULL;
	char			*essid = NULL;

	g_return_if_fail (list != NULL);
	g_return_if_fail (network != NULL);
	g_return_if_fail (((list->type == NETWORK_TYPE_TRUSTED) || (list->type == NETWORK_TYPE_PREFERRED)));

	/* Get the allowed access point's details from NetworkManagerInfo */
	if ((essid = nm_dbus_get_network_essid (data->dbus_connection, list->type, network)))
	{
		char		*key = nm_dbus_get_network_key (data->dbus_connection, list->type, network);
		gint		 priority = nm_dbus_get_network_priority (data->dbus_connection, list->type, network);

		if (priority >= 0)
		{
			/* Find access point in list, if not found create a new AP and add it to the list */
			if (!(ap = nm_ap_list_get_ap_by_essid (list, network)))
				nm_ap_list_append_ap (list, (ap = nm_ap_new ()));

			nm_ap_set_essid (ap, essid);
			nm_ap_set_wep_key (ap, key);
			nm_ap_set_priority (ap, priority);
		}

		g_free (essid);
		g_free (key);
	}
	else
	{
		/* AP got deleted, remove it from our list */
		if ((ap = nm_ap_list_get_ap_by_essid (list, network)))
			nm_ap_list_remove_ap (list, ap);
	}
}


/*
 * nm_ap_list_populate
 *
 * Populate an initial list of allowed access points
 *
 */
void nm_ap_list_populate (NMAccessPointList *list, NMData *data)
{
	char		**networks;
	int		  num_networks;	

	g_return_if_fail (list != NULL);
	g_return_if_fail (data != NULL);
	g_return_if_fail (((list->type == NETWORK_TYPE_TRUSTED) || (list->type == NETWORK_TYPE_PREFERRED)));

	networks = nm_dbus_get_networks (data->dbus_connection, list->type, &num_networks);
	if (networks && (num_networks > 0))
	{
		int	i;
		for (i = 0; i < num_networks; i++)
		{
			if (networks[i] && (strlen (networks[i]) > 0))
				nm_ap_list_update_network (list, networks[i], data);
		}

		dbus_free_string_array (networks);
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

			if ((new_ap = nm_ap_list_get_ap_by_essid (new, nm_ap_get_essid (old_ap))))
			{
				nm_ap_set_matched (old_ap, TRUE);
				nm_ap_set_matched (new_ap, TRUE);
				nm_ap_set_invalid (new_ap, nm_ap_get_invalid (old_ap));
				nm_ap_set_enc_method (new_ap, nm_ap_get_enc_method (old_ap));
			}
			else
				nm_dbus_signal_wireless_network_disappeared (data->dbus_connection, dev, old_ap);
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
			if (!nm_ap_get_matched (new_ap))
				nm_dbus_signal_wireless_network_appeared (data->dbus_connection, dev, new_ap);
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

	syslog (LOG_DEBUG, "AP_LIST_PRINT: printing members of '%s'", name);
	while ((ap = nm_ap_list_iter_next (iter)))
	{
		syslog (LOG_DEBUG, "\t%d)\tessid='%s', prio=%d, key='%s', enc=%d, addr=0x%X, qual=%d, freq=%f, rate=%d, inval=%d",
				i, nm_ap_get_essid (ap), nm_ap_get_priority (ap), nm_ap_get_wep_key (ap), nm_ap_get_encrypted (ap),
				nm_ap_get_address (ap), nm_ap_get_quality (ap), nm_ap_get_freq (ap), nm_ap_get_rate (ap),
				nm_ap_get_invalid (ap));
		i++;
	}
	syslog (LOG_DEBUG, "AP_LIST_PRINT: done");
	nm_ap_list_iter_free (iter);
}
