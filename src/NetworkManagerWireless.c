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
#include "config.h"
#ifdef HAVE_GCRYPT
#include <gcrypt.h>
#else
#include "gnome-keyring-md5.h"
#endif
#include "NetworkManager.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerWireless.h"
#include "NetworkManagerPolicy.h"
#include "NetworkManagerUtils.h"

/*
 * nm_wireless_64bit_ascii_to_hex
 *
 * Convert an ASCII string into a suitable WEP key.
 *
 */
char *nm_wireless_64bit_ascii_to_hex (const unsigned char *ascii)
{
	static char	 hex_digits[] = "0123456789abcdef";
	unsigned char	*res;
	int			 i;

	res = g_malloc (33);
	for (i = 0; i < 16; i++)
	{
		res[2*i] = hex_digits[(ascii[i] >> 4) & 0xf];
		res[2*i+1] = hex_digits[ascii[i] & 0xf];
	}

	/* We chomp it at byte 10, since WEP keys only use 40 bits */
	res[10] = 0;
	return (res);
}


/*
 * nm_wireless_128bit_ascii_to_hex
 *
 * Convert an ascii string into a suitable string for use
 * as a WEP key.
 *
 * Code originally by Alex Larsson <alexl@redhat.com> and
 *  copyright Red Hat, Inc. under terms of the LGPL.
 *
 */
char *nm_wireless_128bit_ascii_to_hex (const unsigned char *ascii)
{
	static char	 hex_digits[] = "0123456789abcdef";
	unsigned char	*res;
	int			 i;

	res = g_malloc (33);
	for (i = 0; i < 16; i++)
	{
		res[2*i] = hex_digits[(ascii[i] >> 4) & 0xf];
		res[2*i+1] = hex_digits[ascii[i] & 0xf];
	}
	/* We chomp it at byte 26, since WEP keys only use 104 bits */
	res[26] = 0;

	return (res);
}


/*
 * nm_wireless_128bit_key_from_passphrase
 *
 * From a passphrase, generate a standard 128-bit WEP key using
 * MD5 algorithm.
 *
 */
char *nm_wireless_128bit_key_from_passphrase	(const char *passphrase)
{
	char		 	md5_data[65];
	unsigned char	digest[16];
	int			passphrase_len;
	int			i;

	g_return_val_if_fail (passphrase != NULL, NULL);

	passphrase_len = strlen (passphrase);
	if (passphrase_len < 1)
		return (NULL);

	/* Get at least 64 bits */
	for (i = 0; i < 64; i++)
		md5_data [i] = passphrase [i % passphrase_len];

	/* Null terminate md5 data-to-hash and hash it */
	md5_data[64] = 0;
#ifdef HAVE_GCRYPT
	gcry_md_hash_buffer (GCRY_MD_MD5, digest, md5_data, 64);
#else
	gnome_keyring_md5_string (md5_data, digest);
#endif

	return (nm_wireless_128bit_ascii_to_hex (digest));
}


/*
 * nm_wireless_stats_to_percent
 *
 * Convert an iw_stats structure from a scan or the card into
 * a magical signal strength percentage.
 *
 */
int nm_wireless_qual_to_percent (NMDevice *dev, const struct iw_quality *qual)
{
	int	percent = -1;

	g_return_val_if_fail (dev != NULL, -1);
	g_return_val_if_fail (qual != NULL, -1);

	/* Try using the card's idea of the signal quality first */
	if ((nm_device_get_max_quality (dev) == 100) && (qual->qual < 100))
	{
		/* Atmel driver seems to use qual->qual is the percentage value */
		percent = qual->qual;
	}
	else if (qual->qual == (qual->level - qual->noise))
	{
		/* Ok, simple signal : noise ratio.  Prism54 for example. */
//fprintf (stderr, "20 * log (level / noise) = 20 * log (%d / %d) = %f\n", qual->level, qual->noise, log ((255-qual->level) / (255-qual->noise)) * 100);
		percent = (int)rint ((log (qual->qual) / log (96)) * 100.0);
		percent = CLAMP (percent, 0, 100);
	}
	else if (qual->qual >= 1)
	{
		/* Try it the Gnome Wireless Applet way */
		percent = (int)rint ((log (qual->qual) / log (94)) * 100.0);
		percent = CLAMP (percent, 0, 100);
	}

	/* If that failed, try to calculate the signal quality based on other
	 * values, like Signal-to-Noise ratio.
	 */
	if (((percent == -1) || (percent == 0)))
	{
		/* If the statistics are in dBm or relative */
		if(qual->level > nm_device_get_max_quality (dev))
		{
			#define	BEST_SIGNAL	85		/* In dBm, stuck card next to AP, this is what I got */

			/* Values in dBm  (absolute power measurement) */
			if (qual->level > 0)
				percent = (int)rint ((double)(((256 - qual->level) / (double)BEST_SIGNAL) * 100));
		}
		else
		{
/* FIXME
 * Not quite sure what to do here...  Above we have a "100% strength" number
 * empirically derived, but I don't have any cards that trigger this code below...
 */
#if 0
			/* Relative values (0 -> max) */
			qual_rel = qual->level;
			qual_max_rel = range->max_qual.level;
			noise_rel = qual->noise;
			noise_max_rel = range->max_qual.noise;
#else
			percent = -1;
#endif
		}
	}

	return (percent);
}


/*
 * nm_wireless_process_scan_results
 *
 * Run from main thread to hand scan results off to each device
 * for processing.
 *
 */
static gboolean nm_wireless_process_scan_results (gpointer user_data)
{
	GSList	*results = (GSList *)user_data;
	GSList	*elem = NULL;

	if (!results)
		return FALSE;

	elem = results;
	while (elem)
	{
		NMWirelessScanResults	*res = (NMWirelessScanResults *)(elem->data);

		nm_device_process_scan_results (res->dev, &(res->results));

		/* Release the scan results */
		nm_dispose_scan_results (res->results.result);
		nm_device_unref (res->dev);
		g_free (res);
		elem->data = NULL;

		elem = g_slist_next (elem);
	}
	g_slist_free (results);

	return FALSE;
}


/*
 * nm_wireless_scan_monitor
 *
 * Called every 10s to get a list of access points from the hardware.  When its got
 * the list, it schedules an idle handler in the main thread's event loop to actually
 * integrate the scan results into the NMDevice's access point list.
 *
 */
static gboolean nm_wireless_scan_monitor (gpointer user_data)
{
	NMData	*data = (NMData *)user_data;
	GSList	*element;
	NMDevice	*dev;
	GSList	*scan_results = NULL;

	g_return_val_if_fail (data != NULL, TRUE);

	/* We don't want to lock the device list for the entire duration of the scanning process
	 * for all cards.  Scanning can take quite a while.  Therefore, we grab a list of the devices
	 * and ref each one, then release the device list lock, perform scanning, and pass that list
	 * to the idle handler in the main thread, along iwth the scanning results.
	 */

	if (!nm_try_acquire_mutex (data->dev_list_mutex, __FUNCTION__))
	{
		syslog (LOG_ERR, "nm_wireless_scan_monitor() could not acquire device list mutex." );
		return (TRUE);
	}

	element = data->dev_list;
	while (element)
	{
		if ((dev = (NMDevice *)(element->data)) && nm_device_is_wireless (dev))
		{
			NMWirelessScanResults	*scan_res = g_malloc0 (sizeof (NMWirelessScanResults));

			nm_device_ref (dev);
			scan_res->dev = dev;
			scan_results = g_slist_append (scan_results, scan_res);
		}
		element = g_slist_next (element);
	}
	nm_unlock_mutex (data->dev_list_mutex, __FUNCTION__);

	/* Okay, do the actual scanning now. */
	element = scan_results;
	while (element)
	{
		NMWirelessScanResults *res = (NMWirelessScanResults *)(element->data);
		nm_device_do_wireless_scan (res->dev, &(res->results));
		element = g_slist_next (element);
	}

	/* Schedule an idle handler in the main thread to process the scan results */
	if (scan_results)
	{
		guint	 scan_process_source_id = 0;
		GSource	*scan_process_source = g_idle_source_new ();

		g_source_set_callback (scan_process_source, nm_wireless_process_scan_results, scan_results, NULL);
		scan_process_source_id = g_source_attach (scan_process_source, data->main_context);
		g_source_unref (scan_process_source);
	}
	
	return (TRUE);
}


/*
 * nm_wireless_scan_worker
 *
 * Worker thread main function to handle wireless scanning.
 *
 */
gpointer nm_wireless_scan_worker (gpointer user_data)
{
	NMData	*data = (NMData *)user_data;
	guint	 wscan_source_id = 0;
	GSource	*wscan_source = NULL;

	if (!data)
		return NULL;
	
	wscan_source = g_timeout_source_new (14000);
	g_source_set_callback (wscan_source, nm_wireless_scan_monitor, data, NULL);
	wscan_source_id = g_source_attach (wscan_source, data->wscan_ctx);
	g_source_unref (wscan_source);

	/* Do an initial scan */
	nm_wireless_scan_monitor (user_data);

	g_main_loop_run (data->wscan_loop);

	g_source_remove (wscan_source_id);
	data->wscan_thread_done = TRUE;
	return NULL;
}

