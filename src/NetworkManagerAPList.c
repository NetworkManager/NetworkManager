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

/*
 * nm_ap_list_get_ap_by_essid
 *
 * Search through an allowed access point list and return the access point
 * that has a given essid.
 *
 */
NMAccessPoint *nm_ap_list_get_ap_by_essid (NMData *data, const char *network)
{
	NMAccessPoint	*found_ap = NULL;

	g_return_val_if_fail (data != NULL, NULL);
	g_return_val_if_fail (network != NULL, NULL);

	if (nm_try_acquire_mutex (data->allowed_ap_list_mutex, __FUNCTION__))
	{
		GSList	*element = data->allowed_ap_list;

		while (element)
		{
			NMAccessPoint	*ap = (NMAccessPoint *)(element->data);

			if (ap && (nm_null_safe_strcmp (nm_ap_get_essid (ap), network) == 0))
			{
				found_ap = ap;
				break;
			}
			element = g_slist_next (element);
		}
		nm_unlock_mutex (data->allowed_ap_list_mutex, __FUNCTION__);
	}
	else
		NM_DEBUG_PRINT( "nm_ap_list_get_ap_by_essid() could not acquire allowed access point mutex.\n" );

	return (found_ap);
}


/*
 * nm_ap_list_update_network
 *
 * Given a network ID, 
 *
 */
void nm_ap_list_update_network (NMData *data, const char *network)
{
	NMAccessPoint	*ap = NULL;
	char			*essid = NULL;

	g_return_if_fail (data != NULL);
	g_return_if_fail (network != NULL);

	/* Find access point in list */
	if (!(ap = nm_ap_list_get_ap_by_essid (data, network)))
	{
		ap = nm_ap_new ();
		data->allowed_ap_list = g_slist_append (data->allowed_ap_list, ap);
	}

	/* Get the allowed access point's details from NetworkManagerInfo */
	if ((essid = nm_dbus_get_allowed_network_essid (data->dbus_connection, network)))
	{
		char		*key = nm_dbus_get_allowed_network_key (data->dbus_connection, network);
		guint	 priority = nm_dbus_get_allowed_network_priority (data->dbus_connection, network);

		nm_ap_set_essid (ap, essid);
		nm_ap_set_wep_key (ap, key);
		nm_ap_set_priority (ap, priority);

		g_free (essid);
		g_free (key);
	}
}


/*
 * nm_ap_list_populate
 *
 * Populate the initial list of allowed access points
 *
 */
void nm_ap_list_populate (NMData *data)
{
	char		**networks;
	int		  num_networks;	

	g_return_if_fail (data != NULL);

	networks = nm_dbus_get_allowed_networks (data->dbus_connection, &num_networks);
	if (networks && (num_networks > 0))
	{
		int	i;
		for (i = 0; i < num_networks; i++)
		{
			if (networks[i] && (strlen (networks[i]) > 0))
				nm_ap_list_update_network (data, networks[i]);
		}

		dbus_free_string_array (networks);
	}
	else
		fprintf( stderr, "nm_ap_list_populate(): networks 0x%X, num_networks %d\n", networks, num_networks);
}


/*
 * nm_ap_list_element_free
 *
 * Frees each member of the allowed access point list before the list is
 * disposed of. 
 *
 */
static void nm_ap_list_element_free (void *element, void *user_data)
{
	nm_ap_unref (element);
}


/*
 * nm_ap_list_free
 *
 * Free all access points in an allowed access point list
 *
 */
void nm_ap_list_free (GSList *ap_list)
{
	g_slist_foreach (ap_list, nm_ap_list_element_free, NULL);
	g_slist_free (ap_list);
}

