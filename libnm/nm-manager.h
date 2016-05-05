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
 * Copyright 2007 - 2014 Red Hat, Inc.
 */

#ifndef __NM_MANAGER_H__
#define __NM_MANAGER_H__

#include <nm-object.h>
#include <nm-client.h>

G_BEGIN_DECLS

#define NM_TYPE_MANAGER            (nm_manager_get_type ())
#define NM_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MANAGER, NMManager))
#define NM_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_MANAGER, NMManagerClass))
#define NM_IS_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MANAGER))
#define NM_IS_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_MANAGER))
#define NM_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_MANAGER, NMManagerClass))

#define NM_MANAGER_VERSION "version"
#define NM_MANAGER_STATE "state"
#define NM_MANAGER_STARTUP "startup"
#define NM_MANAGER_NM_RUNNING "nm-running"
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
#define NM_MANAGER_ACTIVATING_CONNECTION "activating-connection"
#define NM_MANAGER_DEVICES "devices"
#define NM_MANAGER_METERED "metered"
#define NM_MANAGER_ALL_DEVICES "all-devices"

/**
 * NMManager:
 */
typedef struct {
	NMObject parent;
} NMManager;

typedef struct {
	NMObjectClass parent;

	/* Signals */
	void (*device_added) (NMManager *manager, NMDevice *device);
	void (*device_removed) (NMManager *manager, NMDevice *device);
	void (*active_connection_added) (NMManager *manager, NMActiveConnection *ac);
	void (*active_connection_removed) (NMManager *manager, NMActiveConnection *ac);
	void (*permission_changed) (NMManager *manager,
	                            NMClientPermission permission,
	                            NMClientPermissionResult result);

	/* Beware: no more slots. Cannot extend struct without breaking ABI. */
} NMManagerClass;

GType nm_manager_get_type (void);

const char *nm_manager_get_version        (NMManager *manager);
NMState   nm_manager_get_state            (NMManager *manager);
gboolean  nm_manager_get_startup          (NMManager *manager);
gboolean  nm_manager_get_nm_running       (NMManager *manager);

gboolean  nm_manager_networking_get_enabled (NMManager *manager);
gboolean  nm_manager_networking_set_enabled (NMManager *manager,
                                             gboolean enabled,
                                             GError **error);

gboolean  nm_manager_wireless_get_enabled (NMManager *manager);
void      nm_manager_wireless_set_enabled (NMManager *manager, gboolean enabled);
gboolean  nm_manager_wireless_hardware_get_enabled (NMManager *manager);

gboolean  nm_manager_wwan_get_enabled (NMManager *manager);
void      nm_manager_wwan_set_enabled (NMManager *manager, gboolean enabled);
gboolean  nm_manager_wwan_hardware_get_enabled (NMManager *manager);

gboolean  nm_manager_wimax_get_enabled (NMManager *manager);
void      nm_manager_wimax_set_enabled (NMManager *manager, gboolean enabled);
gboolean  nm_manager_wimax_hardware_get_enabled (NMManager *manager);

gboolean nm_manager_get_logging (NMManager *manager,
                                 char **level,
                                 char **domains,
                                 GError **error);
gboolean nm_manager_set_logging (NMManager *manager,
                                 const char *level,
                                 const char *domains,
                                 GError **error);

NMClientPermissionResult nm_manager_get_permission_result (NMManager *manager,
                                                           NMClientPermission permission);

NMConnectivityState nm_manager_get_connectivity          (NMManager *manager);

NMConnectivityState nm_manager_check_connectivity        (NMManager *manager,
                                                          GCancellable *cancellable,
                                                          GError **error);
void                nm_manager_check_connectivity_async  (NMManager *manager,
                                                          GCancellable *cancellable,
                                                          GAsyncReadyCallback callback,
                                                          gpointer user_data);
NMConnectivityState nm_manager_check_connectivity_finish (NMManager *manager,
                                                          GAsyncResult *result,
                                                          GError **error);

/* Devices */

const GPtrArray *nm_manager_get_devices    (NMManager *manager);
NM_AVAILABLE_IN_1_2
const GPtrArray *nm_manager_get_all_devices(NMManager *manager);
NMDevice *nm_manager_get_device_by_path    (NMManager *manager, const char *object_path);
NMDevice *nm_manager_get_device_by_iface   (NMManager *manager, const char *iface);

/* Active Connections */

const GPtrArray *nm_manager_get_active_connections (NMManager *manager);

NMActiveConnection *nm_manager_get_primary_connection (NMManager *manager);
NMActiveConnection *nm_manager_get_activating_connection (NMManager *manager);

void                nm_manager_activate_connection_async  (NMManager *manager,
                                                           NMConnection *connection,
                                                           NMDevice *device,
                                                           const char *specific_object,
                                                           GCancellable *cancellable,
                                                           GAsyncReadyCallback callback,
                                                           gpointer user_data);
NMActiveConnection *nm_manager_activate_connection_finish (NMManager *manager,
                                                           GAsyncResult *result,
                                                           GError **error);

void                nm_manager_add_and_activate_connection_async  (NMManager *manager,
                                                                   NMConnection *partial,
                                                                   NMDevice *device,
                                                                   const char *specific_object,
                                                                   GCancellable *cancellable,
                                                                   GAsyncReadyCallback callback,
                                                                   gpointer user_data);
NMActiveConnection *nm_manager_add_and_activate_connection_finish (NMManager *manager,
                                                                   GAsyncResult *result,
                                                                   GError **error);

gboolean nm_manager_deactivate_connection        (NMManager *manager,
                                                  NMActiveConnection *active,
                                                  GCancellable *cancellable,
                                                  GError **error);
void     nm_manager_deactivate_connection_async  (NMManager *manager,
                                                  NMActiveConnection *active,
                                                  GCancellable *cancellable,
                                                  GAsyncReadyCallback callback,
                                                  gpointer user_data);
gboolean nm_manager_deactivate_connection_finish (NMManager *manager,
                                                  GAsyncResult *result,
                                                  GError **error);

G_END_DECLS

#endif /* __NM_MANAGER_H__ */
