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

#ifndef NM_MANAGER_H
#define NM_MANAGER_H

#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>
#include "nm-device.h"
#include "nm-settings.h"
#include "nm-auth-subject.h"

#define NM_TYPE_MANAGER            (nm_manager_get_type ())
#define NM_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MANAGER, NMManager))
#define NM_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_MANAGER, NMManagerClass))
#define NM_IS_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MANAGER))
#define NM_IS_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_MANAGER))
#define NM_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_MANAGER, NMManagerClass))

typedef enum {
	NM_MANAGER_ERROR_UNKNOWN_CONNECTION = 0,      /*< nick=UnknownConnection >*/
	NM_MANAGER_ERROR_UNKNOWN_DEVICE,              /*< nick=UnknownDevice >*/
	NM_MANAGER_ERROR_UNMANAGED_DEVICE,            /*< nick=UnmanagedDevice >*/
	NM_MANAGER_ERROR_SYSTEM_CONNECTION,           /*< nick=SystemConnection >*/
	NM_MANAGER_ERROR_PERMISSION_DENIED,           /*< nick=PermissionDenied >*/
	NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,       /*< nick=ConnectionNotActive >*/
	NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE,     /*< nick=AlreadyAsleepOrAwake >*/
	NM_MANAGER_ERROR_ALREADY_ENABLED_OR_DISABLED, /*< nick=AlreadyEnabledOrDisabled >*/
	NM_MANAGER_ERROR_UNSUPPORTED_CONNECTION_TYPE, /*< nick=UnsupportedConnectionType >*/
	NM_MANAGER_ERROR_DEPENDENCY_FAILED,           /*< nick=DependencyFailed >*/
	NM_MANAGER_ERROR_AUTOCONNECT_NOT_ALLOWED,     /*< nick=AutoconnectNotAllowed >*/
	NM_MANAGER_ERROR_CONNECTION_ALREADY_ACTIVE,   /*< nick=ConnectionAlreadyActive >*/
	NM_MANAGER_ERROR_INTERNAL,                    /*< nick=Internal >*/
} NMManagerError;

#define NM_MANAGER_VERSION "version"
#define NM_MANAGER_STATE "state"
#define NM_MANAGER_STARTUP "startup"
#define NM_MANAGER_NETWORKING_ENABLED "networking-enabled"
#define NM_MANAGER_WIRELESS_ENABLED "wireless-enabled"
#define NM_MANAGER_WIRELESS_HARDWARE_ENABLED "wireless-hardware-enabled"
#define NM_MANAGER_WWAN_ENABLED "wwan-enabled"
#define NM_MANAGER_WWAN_HARDWARE_ENABLED "wwan-hardware-enabled"
#define NM_MANAGER_WIMAX_ENABLED "wimax-enabled"
#define NM_MANAGER_WIMAX_HARDWARE_ENABLED "wimax-hardware-enabled"
#define NM_MANAGER_ACTIVE_CONNECTIONS "active-connections"
#define NM_MANAGER_CONNECTIVITY "connectivity"
#define NM_MANAGER_PRIMARY_CONNECTION "primary-connection"
#define NM_MANAGER_PRIMARY_CONNECTION_TYPE "primary-connection-type"
#define NM_MANAGER_ACTIVATING_CONNECTION "activating-connection"
#define NM_MANAGER_DEVICES "devices"

/* Not exported */
#define NM_MANAGER_HOSTNAME "hostname"
#define NM_MANAGER_SLEEPING "sleeping"

/* Internal signals */
#define NM_MANAGER_ACTIVE_CONNECTION_ADDED   "active-connection-added"
#define NM_MANAGER_ACTIVE_CONNECTION_REMOVED "active-connection-removed"


typedef struct {
	GObject parent;
} NMManager;

typedef struct {
	GObjectClass parent;

	/* Signals */
	void (*device_added) (NMManager *manager, NMDevice *device);
	void (*device_removed) (NMManager *manager, NMDevice *device);
	void (*state_changed) (NMManager *manager, guint state);
} NMManagerClass;

GType nm_manager_get_type (void);

/* nm_manager_new() should only be used by main.c */
NMManager *nm_manager_new (NMSettings *settings,
                           const char *state_file,
                           gboolean initial_net_enabled,
                           gboolean initial_wifi_enabled,
                           gboolean initial_wwan_enabled,
                           gboolean initial_wimax_enabled,
                           GError **error);

NMManager *nm_manager_get (void);

void nm_manager_start (NMManager *manager);

const GSList *nm_manager_get_active_connections (NMManager *manager);
GSList *nm_manager_get_activatable_connections (NMManager *manager);

/* Device handling */

const GSList *nm_manager_get_devices (NMManager *manager);

NMDevice *nm_manager_get_device_by_master (NMManager *manager,
                                           const char *master,
                                           const char *driver);
NMDevice *nm_manager_get_device_by_ifindex (NMManager *manager,
                                            int ifindex);

NMActiveConnection *nm_manager_activate_connection (NMManager *manager,
                                                    NMConnection *connection,
                                                    const char *specific_object,
                                                    NMDevice *device,
                                                    NMAuthSubject *subject,
                                                    GError **error);

gboolean nm_manager_deactivate_connection (NMManager *manager,
                                           const char *connection_path,
                                           NMDeviceStateReason reason,
                                           GError **error);

/* State handling */

NMState nm_manager_get_state (NMManager *manager);

#endif /* NM_MANAGER_H */
