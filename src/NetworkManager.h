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

#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <glib.h>
#include <glib/gthread.h>
#include <dbus/dbus.h>
#include <hal/libhal.h>
#include "NetworkManagerAP.h"

typedef struct NMData
{
	LibHalContext			*hal_ctx;
	DBusConnection			*dbus_connection;
	gboolean				 info_daemon_avail;
	gboolean				 enable_test_devices;

	GSList				*dev_list;
	GMutex				*dev_list_mutex;

	struct NMDevice		*active_device;
	gboolean				 active_device_locked;

	struct NMDevice		*user_device;			/* Holds a device that the user requests NM to use. */
	GMutex				*user_device_mutex;

	gboolean				 state_modified;
	GMutex				*state_modified_mutex;

	gboolean				 update_ap_lists;
	struct NMAccessPointList	*allowed_ap_list;
	struct NMAccessPointList	*invalid_ap_list;
} NMData;

/*
 * Types of NetworkManager devices
 */
typedef enum NMDeviceType
{
	DEVICE_TYPE_DONT_KNOW = 0,
	DEVICE_TYPE_WIRED_ETHERNET,
	DEVICE_TYPE_WIRELESS_ETHERNET
} NMDeviceType;


struct NMDevice	*nm_create_device_and_add_to_list	(NMData *data, const char *udi, const char *iface,
											gboolean test_device, NMDeviceType test_device_type);

void				 nm_remove_device_from_list		(NMData *data, const char *udi);

void		 		 nm_data_mark_state_changed		(NMData *data);

#endif
