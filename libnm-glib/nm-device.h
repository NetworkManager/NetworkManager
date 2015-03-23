/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2013 Red Hat, Inc.
 */

#ifndef NM_DEVICE_H
#define NM_DEVICE_H

#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-object.h"
#include "NetworkManager.h"
#include "nm-ip4-config.h"
#include "nm-dhcp4-config.h"
#include "nm-ip6-config.h"
#include "nm-dhcp6-config.h"
#include "nm-connection.h"
#include "nm-active-connection.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE            (nm_device_get_type ())
#define NM_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE, NMDevice))
#define NM_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE, NMDeviceClass))
#define NM_IS_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE))
#define NM_IS_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DEVICE))
#define NM_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE, NMDeviceClass))

/**
 * NMDeviceError:
 * @NM_DEVICE_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_DEVICE_ERROR_INTERFACE_MISMATCH: the interface names of the connection and the
 *   device mismatched
 */
typedef enum {
	NM_DEVICE_ERROR_UNKNOWN = 0,        /*< nick=UnknownError >*/
	NM_DEVICE_ERROR_INTERFACE_MISMATCH, /*< nick=InterfaceMismatch >*/
} NMDeviceError;

#define NM_DEVICE_ERROR nm_device_error_quark ()
NM_AVAILABLE_IN_0_9_10
GQuark nm_device_error_quark (void);

#define NM_DEVICE_DEVICE_TYPE "device-type"
#define NM_DEVICE_UDI "udi"
#define NM_DEVICE_INTERFACE "interface"
#define NM_DEVICE_IP_INTERFACE "ip-interface"
#define NM_DEVICE_DRIVER "driver"
#define NM_DEVICE_DRIVER_VERSION "driver-version"
#define NM_DEVICE_FIRMWARE_VERSION "firmware-version"
#define NM_DEVICE_CAPABILITIES "capabilities"
#define NM_DEVICE_MANAGED "managed"
#define NM_DEVICE_AUTOCONNECT "autoconnect"
#define NM_DEVICE_FIRMWARE_MISSING "firmware-missing"
#define NM_DEVICE_IP4_CONFIG "ip4-config"
#define NM_DEVICE_DHCP4_CONFIG "dhcp4-config"
#define NM_DEVICE_IP6_CONFIG "ip6-config"
#define NM_DEVICE_DHCP6_CONFIG "dhcp6-config"
#define NM_DEVICE_STATE "state"
#define NM_DEVICE_STATE_REASON "state-reason"
#define NM_DEVICE_ACTIVE_CONNECTION "active-connection"
#define NM_DEVICE_AVAILABLE_CONNECTIONS "available-connections"
#define NM_DEVICE_VENDOR "vendor"
#define NM_DEVICE_PRODUCT "product"
#define NM_DEVICE_PHYSICAL_PORT_ID "physical-port-id"
#define NM_DEVICE_MTU "mtu"

typedef struct {
	NMObject parent;
} NMDevice;

typedef struct {
	NMObjectClass parent;

	/* Signals */
	void (*state_changed) (NMDevice *device,
	                       NMDeviceState new_state,
	                       NMDeviceState old_state,
	                       NMDeviceStateReason reason);

	gboolean (*connection_compatible) (NMDevice *device,
	                                   NMConnection *connection,
	                                   GError **error);

	const char * (*get_type_description) (NMDevice *device);
	const char * (*get_hw_address) (NMDevice *device);

	GType (*get_setting_type) (NMDevice *device);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
} NMDeviceClass;

GType nm_device_get_type (void);

GObject * nm_device_new (DBusGConnection *connection, const char *path);

const char *         nm_device_get_iface            (NMDevice *device);
const char *         nm_device_get_ip_iface         (NMDevice *device);
NMDeviceType         nm_device_get_device_type      (NMDevice *device);
const char *         nm_device_get_udi              (NMDevice *device);
const char *         nm_device_get_driver           (NMDevice *device);
const char *         nm_device_get_driver_version   (NMDevice *device);
const char *         nm_device_get_firmware_version (NMDevice *device);
NM_AVAILABLE_IN_0_9_10
const char *         nm_device_get_type_description (NMDevice *device);
NM_AVAILABLE_IN_0_9_10
const char *         nm_device_get_hw_address       (NMDevice *device);
NMDeviceCapabilities nm_device_get_capabilities     (NMDevice *device);
gboolean             nm_device_get_managed          (NMDevice *device);
NM_AVAILABLE_IN_1_2
void                 nm_device_set_managed          (NMDevice *device, gboolean managed);
gboolean             nm_device_get_autoconnect      (NMDevice *device);
void                 nm_device_set_autoconnect      (NMDevice *device, gboolean autoconnect);
gboolean             nm_device_get_firmware_missing (NMDevice *device);
NMIP4Config *        nm_device_get_ip4_config       (NMDevice *device);
NMDHCP4Config *      nm_device_get_dhcp4_config     (NMDevice *device);
NMIP6Config *        nm_device_get_ip6_config       (NMDevice *device);
NMDHCP6Config *      nm_device_get_dhcp6_config     (NMDevice *device);
NMDeviceState        nm_device_get_state            (NMDevice *device);
NMDeviceState        nm_device_get_state_reason     (NMDevice *device, NMDeviceStateReason *reason);
NMActiveConnection * nm_device_get_active_connection(NMDevice *device);
const GPtrArray *    nm_device_get_available_connections(NMDevice *device);
NM_AVAILABLE_IN_0_9_10
const char *         nm_device_get_physical_port_id (NMDevice *device);
NM_AVAILABLE_IN_0_9_10
guint32              nm_device_get_mtu              (NMDevice *device);
NM_AVAILABLE_IN_1_0
gboolean             nm_device_is_software          (NMDevice *device);

const char *         nm_device_get_product           (NMDevice  *device);
const char *         nm_device_get_vendor            (NMDevice  *device);
NM_AVAILABLE_IN_0_9_10
const char *         nm_device_get_description       (NMDevice  *device);
NM_AVAILABLE_IN_0_9_10
char **              nm_device_disambiguate_names    (NMDevice **devices,
                                                      int        num_devices);

typedef void (*NMDeviceCallbackFn) (NMDevice *device, GError *error, gpointer user_data);

void                 nm_device_disconnect           (NMDevice *device,
                                                     NMDeviceCallbackFn callback,
                                                     gpointer user_data);

NM_AVAILABLE_IN_1_0
void                 nm_device_delete               (NMDevice *device,
                                                     NMDeviceCallbackFn callback,
                                                     gpointer user_data);

GSList *             nm_device_filter_connections   (NMDevice *device,
                                                     const GSList *connections);

gboolean             nm_device_connection_valid     (NMDevice *device,
                                                     NMConnection *connection);

gboolean             nm_device_connection_compatible (NMDevice *device,
                                                      NMConnection *connection,
                                                      GError **error);

NM_AVAILABLE_IN_0_9_10
GType                nm_device_get_setting_type     (NMDevice *device);

/* Deprecated */
NM_DEPRECATED_IN_1_0
typedef void (*NMDeviceDeactivateFn) (NMDevice *device, GError *error, gpointer user_data);

G_END_DECLS

#endif /* NM_DEVICE_H */
