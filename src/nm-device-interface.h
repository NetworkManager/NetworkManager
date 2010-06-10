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
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
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

#define IS_ACTIVATING_STATE(state) \
	(state > NM_DEVICE_STATE_DISCONNECTED && state < NM_DEVICE_STATE_ACTIVATED)

typedef enum
{
	NM_DEVICE_INTERFACE_ERROR_CONNECTION_ACTIVATING = 0,
	NM_DEVICE_INTERFACE_ERROR_CONNECTION_INVALID,
	NM_DEVICE_INTERFACE_ERROR_NOT_ACTIVE,
} NMDeviceInterfaceError;

#define NM_DEVICE_INTERFACE_ERROR (nm_device_interface_error_quark ())
#define NM_TYPE_DEVICE_INTERFACE_ERROR (nm_device_interface_error_get_type ()) 

#define NM_DEVICE_INTERFACE_DISCONNECT_REQUEST "disconnect-request"

#define NM_DEVICE_INTERFACE_UDI              "udi"
#define NM_DEVICE_INTERFACE_IFACE            "interface"
#define NM_DEVICE_INTERFACE_IP_IFACE         "ip-interface"
#define NM_DEVICE_INTERFACE_DRIVER           "driver"
#define NM_DEVICE_INTERFACE_CAPABILITIES     "capabilities"
#define NM_DEVICE_INTERFACE_IP4_ADDRESS      "ip4-address"
#define NM_DEVICE_INTERFACE_IP4_CONFIG       "ip4-config"
#define NM_DEVICE_INTERFACE_DHCP4_CONFIG     "dhcp4-config"
#define NM_DEVICE_INTERFACE_IP6_CONFIG       "ip6-config"
#define NM_DEVICE_INTERFACE_DHCP6_CONFIG     "dhcp6-config"
#define NM_DEVICE_INTERFACE_STATE            "state"
#define NM_DEVICE_INTERFACE_DEVICE_TYPE      "device-type" /* ugh */
#define NM_DEVICE_INTERFACE_MANAGED          "managed"
#define NM_DEVICE_INTERFACE_FIRMWARE_MISSING "firmware-missing"
#define NM_DEVICE_INTERFACE_TYPE_DESC        "type-desc"    /* Internal only */
#define NM_DEVICE_INTERFACE_RFKILL_TYPE      "rfkill-type"  /* Internal only */
#define NM_DEVICE_INTERFACE_IFINDEX          "ifindex"      /* Internal only */

typedef enum {
	NM_DEVICE_INTERFACE_PROP_FIRST = 0x1000,

	NM_DEVICE_INTERFACE_PROP_UDI = NM_DEVICE_INTERFACE_PROP_FIRST,
	NM_DEVICE_INTERFACE_PROP_IFACE,
	NM_DEVICE_INTERFACE_PROP_IP_IFACE,
	NM_DEVICE_INTERFACE_PROP_DRIVER,
	NM_DEVICE_INTERFACE_PROP_CAPABILITIES,
	NM_DEVICE_INTERFACE_PROP_IP4_ADDRESS,
	NM_DEVICE_INTERFACE_PROP_IP4_CONFIG,
	NM_DEVICE_INTERFACE_PROP_DHCP4_CONFIG,
	NM_DEVICE_INTERFACE_PROP_IP6_CONFIG,
	NM_DEVICE_INTERFACE_PROP_DHCP6_CONFIG,
	NM_DEVICE_INTERFACE_PROP_STATE,
	NM_DEVICE_INTERFACE_PROP_DEVICE_TYPE,
	NM_DEVICE_INTERFACE_PROP_MANAGED,
	NM_DEVICE_INTERFACE_PROP_FIRMWARE_MISSING,
	NM_DEVICE_INTERFACE_PROP_TYPE_DESC,
	NM_DEVICE_INTERFACE_PROP_RFKILL_TYPE,
	NM_DEVICE_INTERFACE_PROP_IFINDEX,
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
	gboolean (*disconnect) (NMDeviceInterface *device, GError **error);

	gboolean (*spec_match_list) (NMDeviceInterface *device, const GSList *specs);

	NMConnection * (*connection_match_config) (NMDeviceInterface *device, const GSList *specs);

	void (*set_enabled) (NMDeviceInterface *device, gboolean enabled);

	gboolean (*get_enabled) (NMDeviceInterface *device);

	/* Signals */
	void (*state_changed) (NMDeviceInterface *device,
	                       NMDeviceState new_state,
	                       NMDeviceState old_state,
	                       NMDeviceStateReason reason);
};

GQuark nm_device_interface_error_quark (void);
GType nm_device_interface_error_get_type (void);

gboolean nm_device_interface_disconnect (NMDeviceInterface *device, GError **error);

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

NMConnection * nm_device_interface_connection_match_config (NMDeviceInterface *device,
                                                            const GSList *connections);

gboolean nm_device_interface_can_assume_connection (NMDeviceInterface *device);

gboolean nm_device_interface_get_enabled (NMDeviceInterface *device);

void nm_device_interface_set_enabled (NMDeviceInterface *device, gboolean enabled);

#endif /* NM_DEVICE_INTERFACE_H */
