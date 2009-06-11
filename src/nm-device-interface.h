/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#ifndef NM_DEVICE_INTERFACE_H
#define NM_DEVICE_INTERFACE_H

#include <glib-object.h>
#include "NetworkManager.h"
#include "nm-connection.h"
#include "nm-activation-request.h"

#define NM_TYPE_DEVICE_INTERFACE      (nm_device_interface_get_type ())
#define NM_DEVICE_INTERFACE(obj)      (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_INTERFACE, NMDeviceInterface))
#define NM_IS_DEVICE_INTERFACE(obj)   (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_INTERFACE))
#define NM_DEVICE_INTERFACE_GET_INTERFACE(obj) (G_TYPE_INSTANCE_GET_INTERFACE ((obj), NM_TYPE_DEVICE_INTERFACE, NMDeviceInterface))

typedef enum
{
	NM_DEVICE_INTERFACE_ERROR_CONNECTION_ACTIVATING = 0,
	NM_DEVICE_INTERFACE_ERROR_CONNECTION_INVALID,
} NMDeviceInterfaceError;

#define NM_DEVICE_INTERFACE_ERROR (nm_device_interface_error_quark ())
#define NM_TYPE_DEVICE_INTERFACE_ERROR (nm_device_interface_error_get_type ()) 

#define NM_DEVICE_INTERFACE_UDI          "udi"
#define NM_DEVICE_INTERFACE_IFACE        "interface"
#define NM_DEVICE_INTERFACE_DRIVER       "driver"
#define NM_DEVICE_INTERFACE_CAPABILITIES "capabilities"
#define NM_DEVICE_INTERFACE_IP4_ADDRESS  "ip4-address"
#define NM_DEVICE_INTERFACE_IP4_CONFIG   "ip4-config"
#define NM_DEVICE_INTERFACE_DHCP4_CONFIG "dhcp4-config"
#define NM_DEVICE_INTERFACE_STATE        "state"
#define NM_DEVICE_INTERFACE_DEVICE_TYPE  "device-type" /* ugh */
#define NM_DEVICE_INTERFACE_MANAGED      "managed"

typedef enum {
	NM_DEVICE_INTERFACE_PROP_FIRST = 0x1000,

	NM_DEVICE_INTERFACE_PROP_UDI = NM_DEVICE_INTERFACE_PROP_FIRST,
	NM_DEVICE_INTERFACE_PROP_IFACE,
	NM_DEVICE_INTERFACE_PROP_DRIVER,
	NM_DEVICE_INTERFACE_PROP_CAPABILITIES,
	NM_DEVICE_INTERFACE_PROP_IP4_ADDRESS,
	NM_DEVICE_INTERFACE_PROP_IP4_CONFIG,
	NM_DEVICE_INTERFACE_PROP_DHCP4_CONFIG,
	NM_DEVICE_INTERFACE_PROP_STATE,
	NM_DEVICE_INTERFACE_PROP_DEVICE_TYPE,
	NM_DEVICE_INTERFACE_PROP_MANAGED,
} NMDeviceInterfaceProp;


typedef struct _NMDeviceInterface NMDeviceInterface;

struct _NMDeviceInterface {
	GTypeInterface g_iface;

	/* Methods */
	gboolean (*check_connection_compatible) (NMDeviceInterface *device,
	                                         NMConnection *connection,
	                                         GError **error);

	gboolean (*activate) (NMDeviceInterface *device,
	                      NMActRequest *req,
	                      GError **error);

	void (*deactivate) (NMDeviceInterface *device, NMDeviceStateReason reason);

	gboolean (*spec_match_list) (NMDeviceInterface *device, const GSList *specs);

	/* Signals */
	void (*state_changed) (NMDeviceInterface *device,
	                       NMDeviceState new_state,
	                       NMDeviceState old_state,
	                       NMDeviceStateReason reason);
};

GQuark nm_device_interface_error_quark (void);
GType nm_device_interface_error_get_type (void);

GType nm_device_interface_get_type (void);

gboolean nm_device_interface_check_connection_compatible (NMDeviceInterface *device,
                                                          NMConnection *connection,
                                                          GError **error);

gboolean nm_device_interface_activate (NMDeviceInterface *device,
				       NMActRequest *req,
				       GError **error);

void nm_device_interface_deactivate (NMDeviceInterface *device, NMDeviceStateReason reason);

NMDeviceState nm_device_interface_get_state (NMDeviceInterface *device);

gboolean nm_device_interface_spec_match_list (NMDeviceInterface *device,
                                              const GSList *specs);

#endif /* NM_DEVICE_INTERFACE_H */
