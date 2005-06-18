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

#ifndef NETWORK_MANAGER_MAIN_H
#define NETWORK_MANAGER_MAIN_H

#include <glib.h>
#include <glib/gthread.h>
#include <dbus/dbus.h>
#include <libhal.h>
#include "NetworkManager.h"
#include "NetworkManagerAP.h"
#include "nm-named-manager.h"

typedef struct NMDbusMethodList NMDbusMethodList;


typedef struct NMData
{
	GIOChannel			*sigterm_iochannel;
	int					 sigterm_pipe[2];

	LibHalContext			*hal_ctx;

	NMNamedManager			*named;
	GList				*nameserver_ids; /* For now these are global instead of per-device */
	GList				*domain_search_ids;

	DBusConnection			*dbus_connection;
	NMDbusMethodList		*nm_methods;
	NMDbusMethodList		*device_methods;
	NMDbusMethodList		*net_methods;
	NMDbusMethodList		*dhcp_methods;

	GMainContext			*main_context;
	GMainLoop				*main_loop;
	gboolean				 enable_test_devices;

	guint				 state_modified_idle_id;

	GSList				*dev_list;
	GMutex				*dev_list_mutex;

	struct NMDevice		*active_device;
	gboolean				 active_device_locked;

	gboolean				 forcing_device;

	NMWirelessScanMethod	 scanning_method;
	gboolean				 wireless_enabled;
	gboolean				 asleep;

	struct NMAccessPointList	*allowed_ap_list;
	struct NMAccessPointList	*invalid_ap_list;
} NMData;


struct NMDevice	*nm_create_device_and_add_to_list		(NMData *data, const char *udi, const char *iface,
												gboolean test_device, NMDeviceType test_device_type);

void				 nm_remove_device_from_list			(NMData *data, const char *udi);

void				 nm_schedule_status_signal_broadcast	(NMData *data);

#endif
