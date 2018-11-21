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

#ifndef __NETWORKMANAGER_MANAGER_H__
#define __NETWORKMANAGER_MANAGER_H__

#include "settings/nm-settings-connection.h"
#include "c-list/src/c-list.h"
#include "nm-dbus-manager.h"

#define NM_TYPE_MANAGER            (nm_manager_get_type ())
#define NM_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_MANAGER, NMManager))
#define NM_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_MANAGER, NMManagerClass))
#define NM_IS_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_MANAGER))
#define NM_IS_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_MANAGER))
#define NM_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_MANAGER, NMManagerClass))

#define NM_MANAGER_VERSION "version"
#define NM_MANAGER_CAPABILITIES "capabilities"
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
#define NM_MANAGER_CONNECTIVITY_CHECK_AVAILABLE "connectivity-check-available"
#define NM_MANAGER_CONNECTIVITY_CHECK_ENABLED "connectivity-check-enabled"
#define NM_MANAGER_PRIMARY_CONNECTION "primary-connection"
#define NM_MANAGER_PRIMARY_CONNECTION_TYPE "primary-connection-type"
#define NM_MANAGER_ACTIVATING_CONNECTION "activating-connection"
#define NM_MANAGER_DEVICES "devices"
#define NM_MANAGER_METERED "metered"
#define NM_MANAGER_GLOBAL_DNS_CONFIGURATION "global-dns-configuration"
#define NM_MANAGER_ALL_DEVICES "all-devices"
#define NM_MANAGER_CHECKPOINTS "checkpoints"

/* Not exported */
#define NM_MANAGER_SLEEPING "sleeping"

/* Signals */
#define NM_MANAGER_DEVICE_ADDED              "device-added"
#define NM_MANAGER_DEVICE_REMOVED            "device-removed"
#define NM_MANAGER_USER_PERMISSIONS_CHANGED  "user-permissions-changed"

#define NM_MANAGER_ACTIVE_CONNECTION_ADDED   "active-connection-added"
#define NM_MANAGER_ACTIVE_CONNECTION_REMOVED "active-connection-removed"
#define NM_MANAGER_CONFIGURE_QUIT            "configure-quit"
#define NM_MANAGER_INTERNAL_DEVICE_ADDED     "internal-device-added"
#define NM_MANAGER_INTERNAL_DEVICE_REMOVED   "internal-device-removed"

GType nm_manager_get_type (void);

/* nm_manager_setup() should only be used by main.c */
NMManager *   nm_manager_setup                         (void);

NMManager *   nm_manager_get                           (void);

gboolean      nm_manager_start                         (NMManager *manager,
                                                        GError **error);
void          nm_manager_stop                          (NMManager *manager);
NMState       nm_manager_get_state                     (NMManager *manager);

const CList * nm_manager_get_active_connections        (NMManager *manager);

#define nm_manager_for_each_active_connection(manager, iter, tmp_list) \
	for (tmp_list = nm_manager_get_active_connections (manager), \
	     iter = c_list_entry (tmp_list->next, NMActiveConnection, active_connections_lst); \
	     ({ \
	         const gboolean _has_next = (&iter->active_connections_lst != tmp_list); \
	         \
	         if (!_has_next) \
	             iter = NULL; \
	         _has_next; \
	    }); \
	    iter = c_list_entry (iter->active_connections_lst.next, NMActiveConnection, active_connections_lst))

#define nm_manager_for_each_active_connection_safe(manager, iter, tmp_list, iter_safe) \
	for (tmp_list = nm_manager_get_active_connections (manager), \
	     iter_safe = tmp_list->next; \
	     ({ \
	        if (iter_safe != tmp_list) { \
	            iter = c_list_entry (iter_safe, NMActiveConnection, active_connections_lst); \
	            iter_safe = iter_safe->next; \
	        } else \
	            iter = NULL; \
	        (iter != NULL); \
	     }); \
	    )

NMSettingsConnection **nm_manager_get_activatable_connections (NMManager *manager,
                                                               gboolean for_auto_activation,
                                                               gboolean sort,
                                                               guint *out_len);

void          nm_manager_write_device_state_all (NMManager *manager);
gboolean      nm_manager_write_device_state (NMManager *manager, NMDevice *device);

/* Device handling */

const CList *       nm_manager_get_devices             (NMManager *manager);

#define nm_manager_for_each_device(manager, iter, tmp_list) \
	for (tmp_list = nm_manager_get_devices (manager), \
	     iter = c_list_entry (tmp_list->next, NMDevice, devices_lst); \
	     ({ \
	         const gboolean _has_next = (&iter->devices_lst != tmp_list); \
	         \
	         if (!_has_next) \
	             iter = NULL; \
	         _has_next; \
	    }); \
	    iter = c_list_entry (iter->devices_lst.next, NMDevice, devices_lst))

#define nm_manager_for_each_device_safe(manager, iter, tmp_list, iter_safe) \
	for (tmp_list = nm_manager_get_devices (manager), \
	     iter_safe = tmp_list->next; \
	     ({ \
	        if (iter_safe != tmp_list) { \
	            iter = c_list_entry (iter_safe, NMDevice, devices_lst); \
	            iter_safe = iter_safe->next; \
	        } else \
	            iter = NULL; \
	        (iter != NULL); \
	     }); \
	    )

NMDevice *          nm_manager_get_device_by_ifindex   (NMManager *manager,
                                                        int ifindex);
NMDevice *          nm_manager_get_device_by_path      (NMManager *manager,
                                                        const char *path);

guint32             nm_manager_device_route_metric_reserve (NMManager *self,
                                                            int ifindex,
                                                            NMDeviceType device_type);

void                nm_manager_device_route_metric_clear (NMManager *self,
                                                          int ifindex);

char *              nm_manager_get_connection_iface (NMManager *self,
                                                     NMConnection *connection,
                                                     NMDevice **out_parent,
                                                     GError **error);

const char *        nm_manager_iface_for_uuid          (NMManager *self,
                                                        const char *uuid);

NMActiveConnection *nm_manager_activate_connection     (NMManager *manager,
                                                        NMSettingsConnection *connection,
                                                        NMConnection *applied_connection,
                                                        const char *specific_object,
                                                        NMDevice *device,
                                                        NMAuthSubject *subject,
                                                        NMActivationType activation_type,
                                                        NMActivationReason activation_reason,
                                                        NMActivationStateFlags initial_state_flags,
                                                        GError **error);

gboolean            nm_manager_deactivate_connection   (NMManager *manager,
                                                        NMActiveConnection *active,
                                                        NMDeviceStateReason reason,
                                                        GError **error);

void                nm_manager_set_capability   (NMManager *self, NMCapability cap);

NMDevice *          nm_manager_get_device    (NMManager *self,
                                              const char *ifname,
                                              NMDeviceType device_type);
gboolean            nm_manager_remove_device (NMManager *self,
                                              const char *ifname,
                                              NMDeviceType device_type);

void nm_manager_dbus_set_property_handle (NMDBusObject *obj,
                                          const NMDBusInterfaceInfoExtended *interface_info,
                                          const NMDBusPropertyInfoExtended *property_info,
                                          GDBusConnection *connection,
                                          const char *sender,
                                          GDBusMethodInvocation *invocation,
                                          GVariant *value,
                                          gpointer user_data);

NMMetered nm_manager_get_metered (NMManager *self);

#endif /* __NETWORKMANAGER_MANAGER_H__ */
