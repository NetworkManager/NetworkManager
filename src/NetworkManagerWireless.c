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
#include <openssl/md5.h>
#include "NetworkManager.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerWireless.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"

extern gboolean	debug;


/*
 * nm_wireless_128bit_key_from_passphrase
 *
 * From a passphrase, generate a standard 128-bit WEP key using
 * MD5 algorithm.
 *
 */
char *nm_wireless_128bit_key_from_passphrase	(char *passphrase)
{
	char		 temp_buf [65];
	char		*ascii_key = g_new0 (char, 32);
	char		*raw_key = g_new0 (char, 16);
	int		 passphrase_len;
	MD5_CTX	 md5_ctx;
	int		 i;

	g_return_val_if_fail (passphrase != NULL, NULL);
	
	/* Get at least 64 bits */
	passphrase_len = strlen (passphrase);
	for (i = 0; i < 64; i++)
		temp_buf [i] = passphrase [i % passphrase_len];

	/* Generate the actual WEP key */
	MD5_Init (&md5_ctx);
	MD5_Update (&md5_ctx, (const void *)temp_buf, 64);
	MD5_Final (raw_key, &md5_ctx);

	/* Convert raw key into ASCII key.  Unfortunately, we must do this
	 * because we cannot deal with raw keys quite yet.
	 */
	for (i = 0; i < 16; i++)
	{
		char *temp = g_strdup_printf ("%02x", raw_key [i]);
		strncat (ascii_key, temp+(strlen(temp)-2), 2);
		g_free (temp);
	}
	ascii_key [26] = '\0';

	return (ascii_key);
}


/*
 * nm_wireless_is_most_prefered_ap
 *
 * For a given AP, filter it through the allowed list and return TRUE if its
 * both allowed _and_ has a better priority than highest_priority.
 *
 */
gboolean nm_wireless_is_most_prefered_ap (NMData *data, NMAccessPoint *ap, int *highest_priority)
{
	GSList		*element;
	gboolean		 is_most_preferred = FALSE;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (ap != NULL, FALSE);
	g_return_val_if_fail (highest_priority != NULL, FALSE);

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
				*highest_priority = nm_ap_get_priority (allowed_ap);
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
 * nm_wireless_scan_monitor
 *
 * Called every 10s to get a list of access points.
 *
 */
gboolean nm_wireless_scan_monitor (gpointer user_data)
{
	NMData	*data = (NMData *)user_data;

	g_return_val_if_fail (data != NULL, TRUE);

	if (!data->active_device)
		return (TRUE);

	/* Attempt to acquire mutex so that data->active_device sticks around.
	 * If the acquire fails, just ignore the scan completely.
	 */
	if (nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		if (data->active_device && (nm_device_get_iface_type (data->active_device) == NM_IFACE_TYPE_WIRELESS_ETHERNET))
			nm_device_do_wireless_scan (data->active_device);

		nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);
	}
	else
		NM_DEBUG_PRINT( "nm_wireless_scan_monitor() could not acquire device list mutex.\n" );
	
	return (TRUE);
}
