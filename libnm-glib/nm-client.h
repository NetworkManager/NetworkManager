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
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 */

#ifndef NM_CLIENT_H
#define NM_CLIENT_H

#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include <NetworkManager.h>
#include "nm-object.h"
#include "nm-device.h"
#include "nm-active-connection.h"

G_BEGIN_DECLS

#define NM_TYPE_CLIENT            (nm_client_get_type ())
#define NM_CLIENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CLIENT, NMClient))
#define NM_CLIENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_CLIENT, NMClientClass))
#define NM_IS_CLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CLIENT))
#define NM_IS_CLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_CLIENT))
#define NM_CLIENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_CLIENT, NMClientClass))

#define NM_CLIENT_VERSION "version"
#define NM_CLIENT_STATE "state"
#define NM_CLIENT_MANAGER_RUNNING "manager-running"
#define NM_CLIENT_NETWORKING_ENABLED "networking-enabled"
#define NM_CLIENT_WIRELESS_ENABLED "wireless-enabled"
#define NM_CLIENT_WIRELESS_HARDWARE_ENABLED "wireless-hardware-enabled"
#define NM_CLIENT_WWAN_ENABLED "wwan-enabled"
#define NM_CLIENT_WWAN_HARDWARE_ENABLED "wwan-hardware-enabled"
#define NM_CLIENT_WIMAX_ENABLED "wimax-enabled"
#define NM_CLIENT_WIMAX_HARDWARE_ENABLED "wimax-hardware-enabled"
#define NM_CLIENT_ACTIVE_CONNECTIONS "active-connections"

/* Permissions */
typedef enum {
	NM_CLIENT_PERMISSION_NONE = 0,
	NM_CLIENT_PERMISSION_ENABLE_DISABLE_NETWORK = 1,
	NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIFI = 2,
	NM_CLIENT_PERMISSION_ENABLE_DISABLE_WWAN = 3,
	NM_CLIENT_PERMISSION_ENABLE_DISABLE_WIMAX = 4,
	NM_CLIENT_PERMISSION_SLEEP_WAKE = 5,
	NM_CLIENT_PERMISSION_NETWORK_CONTROL = 6,
	NM_CLIENT_PERMISSION_WIFI_SHARE_PROTECTED = 7,
	NM_CLIENT_PERMISSION_WIFI_SHARE_OPEN = 8,
	NM_CLIENT_PERMISSION_SETTINGS_MODIFY_SYSTEM = 9,
	NM_CLIENT_PERMISSION_SETTINGS_MODIFY_OWN = 10,
	NM_CLIENT_PERMISSION_SETTINGS_MODIFY_HOSTNAME = 11,

	NM_CLIENT_PERMISSION_LAST = NM_CLIENT_PERMISSION_SETTINGS_MODIFY_HOSTNAME
} NMClientPermission;

typedef enum {
	NM_CLIENT_PERMISSION_RESULT_UNKNOWN = 0,
	NM_CLIENT_PERMISSION_RESULT_YES,
	NM_CLIENT_PERMISSION_RESULT_AUTH,
	NM_CLIENT_PERMISSION_RESULT_NO
} NMClientPermissionResult;


typedef struct {
	NMObject parent;
} NMClient;

typedef struct {
	NMObjectClass parent;

	/* Signals */
	void (*device_added) (NMClient *client, NMDevice *device);
	void (*device_removed) (NMClient *client, NMDevice *device);
	void (*permission_changed) (NMClient *client,
	                            NMClientPermission permission,
	                            NMClientPermissionResult result);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMClientClass;

GType nm_client_get_type (void);

NMClient *nm_client_new (void);

const GPtrArray *nm_client_get_devices    (NMClient *client);
NMDevice *nm_client_get_device_by_path    (NMClient *client, const char *object_path);

typedef void (*NMClientActivateFn) (NMClient *client,
                                    NMActiveConnection *active_connection,
                                    GError *error,
                                    gpointer user_data);

void nm_client_activate_connection (NMClient *client,
                                    NMConnection *connection,
                                    NMDevice *device,
                                    const char *specific_object,
                                    NMClientActivateFn callback,
                                    gpointer user_data);

typedef void (*NMClientAddActivateFn) (NMClient *client,
                                       NMActiveConnection *connection,
                                       const char *new_connection_path,
                                       GError *error,
                                       gpointer user_data);

void nm_client_add_and_activate_connection (NMClient *client,
                                            NMConnection *partial,
                                            NMDevice *device,
                                            const char *specific_object,
                                            NMClientAddActivateFn callback,
                                            gpointer user_data);

void nm_client_deactivate_connection (NMClient *client, NMActiveConnection *active);

gboolean  nm_client_networking_get_enabled (NMClient *client);
void      nm_client_networking_set_enabled (NMClient *client, gboolean enabled);

gboolean  nm_client_wireless_get_enabled (NMClient *client);
void      nm_client_wireless_set_enabled (NMClient *client, gboolean enabled);
gboolean  nm_client_wireless_hardware_get_enabled (NMClient *client);

gboolean  nm_client_wwan_get_enabled (NMClient *client);
void      nm_client_wwan_set_enabled (NMClient *client, gboolean enabled);
gboolean  nm_client_wwan_hardware_get_enabled (NMClient *client);

gboolean  nm_client_wimax_get_enabled (NMClient *client);
void      nm_client_wimax_set_enabled (NMClient *client, gboolean enabled);
gboolean  nm_client_wimax_hardware_get_enabled (NMClient *client);

const char *nm_client_get_version        (NMClient *client);
NMState   nm_client_get_state            (NMClient *client);
gboolean  nm_client_get_manager_running  (NMClient *client);
const GPtrArray *nm_client_get_active_connections (NMClient *client);
void      nm_client_sleep                (NMClient *client, gboolean sleep);

NMClientPermissionResult nm_client_get_permission_result (NMClient *client,
                                                          NMClientPermission permission);

G_END_DECLS

#endif /* NM_CLIENT_H */
