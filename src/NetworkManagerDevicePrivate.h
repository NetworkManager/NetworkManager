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
	char				*cur_essid;	/* Mainly for test devices */
	gboolean			 supports_wireless_scan;
	gint8			 strength;
	gint8			 invalid_strength_counter;
	iwqual			 max_qual;
	iwqual			 avg_qual;

	gint8			 num_freqs;
	double			 freqs[IW_MAX_FREQUENCIES];

	GMutex			*scan_mutex;
	NMAccessPointList	*ap_list;
	guint8			 scan_interval; /* seconds */
	guint32			 last_scan;

	NMAccessPoint		*best_ap;
	GMutex			*best_ap_mutex;
	gboolean			 freeze_best_ap;

	gboolean			 user_key_received;
	gboolean			 now_scanning;
} NMDeviceWirelessOptions;

/* Wired device specific options */
typedef struct NMDeviceWiredOptions
{
	gboolean			 has_carrier_detect;
} NMDeviceWiredOptions;

typedef union NMDeviceOptions
{
	NMDeviceWirelessOptions	wireless;
	NMDeviceWiredOptions	wired;
} NMDeviceOptions;


typedef struct NMDeviceConfigInfo
{
	gboolean	 use_dhcp;
	guint32	 ip4_gateway;
	guint32	 ip4_address;
	guint32	 ip4_netmask;
	guint32  ip4_broadcast;
	/* FIXME: ip6 stuff */
} NMDeviceConfigInfo;

/*
 * NetworkManager device structure
 */
struct NMDevice
{
	guint			 refcount;

	char					*udi;
	char					*iface;
	NMDeviceType			 type;
	NMDriverSupportLevel	 driver_support_level;
	gboolean				 removed;

	gboolean				 link_active;
	guint32				 ip4_address;
	/* FIXME: ipv6 address too */
	unsigned char			 hw_addr[ETH_ALEN];
	NMData				*app_data;
	NMDeviceOptions		 options;
	NMDeviceConfigInfo		 config_info;
	struct dhcp_interface	*dhcp_iface;

	GMainContext			*context;
	GMainLoop				*loop;
	GThread					*worker;
	gboolean				 worker_started;
	guint		 		 renew_timeout;
	guint				 rebind_timeout;

	gboolean				 activating;		/* Set by main thread before beginning activation */
	gboolean				 quit_activation;	/* Flag to signal activation thread to stop activating */

	gboolean				 test_device;
	gboolean				 test_device_up;
};

