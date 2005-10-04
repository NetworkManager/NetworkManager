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
 * (C) Copyright 2005 Red Hat, Inc.
 */

#include <errno.h>
#include <glib.h>
#include <dbus/dbus-glib.h>
#include <libhal.h>
#include <iwlib.h>
#include <signal.h>
#include <string.h>

#include "NetworkManager.h"
#include "NetworkManagerMain.h"
#include "NetworkManagerDevice.h"
#include "NetworkManagerAPList.h"


/* Wireless device specific options */
typedef struct NMDeviceWirelessOptions
{
	char *			cur_essid;	/* Mainly for test devices */
	gboolean			supports_wireless_scan;
	gint8			strength;
	gint8			invalid_strength_counter;
	iwqual			max_qual;
	iwqual			avg_qual;

	guint			failed_link_count;

	gint8			num_freqs;
	double			freqs[IW_MAX_FREQUENCIES];

	GMutex *			scan_mutex;
	NMAccessPointList *	ap_list;
	guint8			scan_interval; /* seconds */
	guint32			last_scan;
} NMDeviceWirelessOptions;

/* Wired device specific options */
typedef struct NMDeviceWiredOptions
{
	gboolean			 has_carrier_detect;
} NMDeviceWiredOptions;

/* General options structure */
typedef union NMDeviceOptions
{
	NMDeviceWirelessOptions	wireless;
	NMDeviceWiredOptions	wired;
} NMDeviceOptions;


/*
 * NetworkManager device structure
 */
struct NMDevice
{
	guint			 	refcount;

	char *				udi;
	char *				iface;
	NMDeviceType			type;
	NMDriverSupportLevel	driver_support_level;
	gboolean				removed;

	gboolean				link_active;
	guint32				ip4_address;
	/* FIXME: ipv6 address too */
	struct ether_addr		hw_addr;
	NMData *				app_data;
	NMDeviceOptions		options;

	/* IP configuration info */
	void *				system_config_data;	/* Distro-specific config data (parsed config file, etc) */
	gboolean				use_dhcp;
	NMIP4Config *			ip4_config;			/* Config from DHCP, PPP, or system config files */

	GMainContext *			context;
	GMainLoop *			loop;
	GThread *				worker;
	gboolean				worker_started;

	NMActRequest *			act_request;
	gboolean				quit_activation;	/* Flag to signal activation thread to stop activating */

	gboolean				test_device;
	gboolean				test_device_up;
};

