/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
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

G_BEGIN_DECLS

#define NM_TYPE_DEVICE            (nm_device_get_type ())
#define NM_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE, NMDevice))
#define NM_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DEVICE, NMDeviceClass))
#define NM_IS_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE))
#define NM_IS_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_DEVICE))
#define NM_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DEVICE, NMDeviceClass))

#define NM_DEVICE_UDI "udi"
#define NM_DEVICE_INTERFACE "interface"
#define NM_DEVICE_IP_INTERFACE "ip-interface"
#define NM_DEVICE_DRIVER "driver"
#define NM_DEVICE_CAPABILITIES "capabilities"
#define NM_DEVICE_MANAGED "managed"
#define NM_DEVICE_FIRMWARE_MISSING "firmware-missing"
#define NM_DEVICE_IP4_CONFIG "ip4-config"
#define NM_DEVICE_DHCP4_CONFIG "dhcp4-config"
#define NM_DEVICE_IP6_CONFIG "ip6-config"
#define NM_DEVICE_DHCP6_CONFIG "dhcp6-config"
#define NM_DEVICE_STATE "state"
#define NM_DEVICE_VENDOR "vendor"
#define NM_DEVICE_PRODUCT "product"

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

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMDeviceClass;

GType nm_device_get_type (void);

GObject * nm_device_new (DBusGConnection *connection, const char *path);

const char *  nm_device_get_iface            (NMDevice *device);
const char *  nm_device_get_ip_iface         (NMDevice *device);
const char *  nm_device_get_udi              (NMDevice *device);
const char *  nm_device_get_driver           (NMDevice *device);
guint32       nm_device_get_capabilities     (NMDevice *device);
gboolean      nm_device_get_managed          (NMDevice *device);
gboolean      nm_device_get_firmware_missing (NMDevice *device);
NMIP4Config * nm_device_get_ip4_config       (NMDevice *device);
NMDHCP4Config * nm_device_get_dhcp4_config   (NMDevice *device);
NMIP6Config * nm_device_get_ip6_config       (NMDevice *device);
NMDHCP6Config * nm_device_get_dhcp6_config   (NMDevice *device);
NMDeviceState nm_device_get_state            (NMDevice *device);
const char *  nm_device_get_product          (NMDevice *device);
const char *  nm_device_get_vendor           (NMDevice *device);

typedef void (*NMDeviceDeactivateFn) (NMDevice *device, GError *error, gpointer user_data);

void          nm_device_disconnect         (NMDevice *device,
                                            NMDeviceDeactivateFn callback,
                                            gpointer user_data);

G_END_DECLS

#endif /* NM_DEVICE_H */
