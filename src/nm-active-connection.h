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
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_ACTIVE_CONNECTION_H__
#define __NETWORKMANAGER_ACTIVE_CONNECTION_H__

#include "nm-exported-object.h"
#include "nm-connection.h"

#define NM_TYPE_ACTIVE_CONNECTION            (nm_active_connection_get_type ())
#define NM_ACTIVE_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnection))
#define NM_ACTIVE_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))
#define NM_IS_ACTIVE_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_ACTIVE_CONNECTION))
#define NM_IS_ACTIVE_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_ACTIVE_CONNECTION))
#define NM_ACTIVE_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionClass))

/* D-Bus Exported Properties */
#define NM_ACTIVE_CONNECTION_CONNECTION      "connection"
#define NM_ACTIVE_CONNECTION_ID              "id"
#define NM_ACTIVE_CONNECTION_UUID            "uuid"
#define NM_ACTIVE_CONNECTION_TYPE            "type"
#define NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT "specific-object"
#define NM_ACTIVE_CONNECTION_DEVICES         "devices"
#define NM_ACTIVE_CONNECTION_STATE           "state"
#define NM_ACTIVE_CONNECTION_DEFAULT         "default"
#define NM_ACTIVE_CONNECTION_IP4_CONFIG      "ip4-config"
#define NM_ACTIVE_CONNECTION_DHCP4_CONFIG    "dhcp4-config"
#define NM_ACTIVE_CONNECTION_DEFAULT6        "default6"
#define NM_ACTIVE_CONNECTION_IP6_CONFIG      "ip6-config"
#define NM_ACTIVE_CONNECTION_DHCP6_CONFIG    "dhcp6-config"
#define NM_ACTIVE_CONNECTION_VPN             "vpn"
#define NM_ACTIVE_CONNECTION_MASTER          "master"

/* Internal non-exported properties */
#define NM_ACTIVE_CONNECTION_INT_SETTINGS_CONNECTION "int-settings-connection"
#define NM_ACTIVE_CONNECTION_INT_DEVICE         "int-device"
#define NM_ACTIVE_CONNECTION_INT_SUBJECT        "int-subject"
#define NM_ACTIVE_CONNECTION_INT_MASTER         "int-master"
#define NM_ACTIVE_CONNECTION_INT_MASTER_READY   "int-master-ready"

/* Internal signals*/
#define NM_ACTIVE_CONNECTION_DEVICE_CHANGED          "device-changed"
#define NM_ACTIVE_CONNECTION_DEVICE_METERED_CHANGED  "device-metered-changed"
#define NM_ACTIVE_CONNECTION_PARENT_ACTIVE           "parent-active"

struct _NMActiveConnection {
	NMExportedObject parent;
};

typedef struct {
	NMExportedObjectClass parent;

	/* re-emits device state changes as a convenience for subclasses for
	 * device states >= DISCONNECTED.
	 */
	void (*device_state_changed) (NMActiveConnection *connection,
	                              NMDevice *device,
	                              NMDeviceState new_state,
	                              NMDeviceState old_state);
	void (*master_failed)  (NMActiveConnection *connection);

	void (*device_changed) (NMActiveConnection *connection,
	                        NMDevice *new_device,
	                        NMDevice *old_device);

	void (*device_metered_changed) (NMActiveConnection *connection,
	                                NMMetered new_value);

	void (*parent_active) (NMActiveConnection *connection);
} NMActiveConnectionClass;

guint64 nm_active_connection_version_id_get (NMActiveConnection *self);
guint64 nm_active_connection_version_id_bump (NMActiveConnection *self);

GType         nm_active_connection_get_type (void);

typedef void (*NMActiveConnectionAuthResultFunc) (NMActiveConnection *self,
                                                  gboolean success,
                                                  const char *error_desc,
                                                  gpointer user_data1,
                                                  gpointer user_data2);

void          nm_active_connection_authorize (NMActiveConnection *self,
                                              NMConnection *initial_connection,
                                              NMActiveConnectionAuthResultFunc result_func,
                                              gpointer user_data1,
                                              gpointer user_data2);

NMSettingsConnection *nm_active_connection_get_settings_connection (NMActiveConnection *self);
NMConnection *nm_active_connection_get_applied_connection (NMActiveConnection *self);

NMSettingsConnection *_nm_active_connection_get_settings_connection (NMActiveConnection *self);

void          nm_active_connection_set_settings_connection (NMActiveConnection *self,
                                                            NMSettingsConnection *connection);

gboolean      nm_active_connection_has_unmodified_applied_connection (NMActiveConnection *self,
                                                                      NMSettingCompareFlags compare_flags);

const char *  nm_active_connection_get_settings_connection_id         (NMActiveConnection *self);

const char *  nm_active_connection_get_specific_object (NMActiveConnection *self);

void          nm_active_connection_set_specific_object (NMActiveConnection *self,
                                                        const char *specific_object);

void          nm_active_connection_set_default (NMActiveConnection *self,
                                                gboolean is_default);

gboolean      nm_active_connection_get_default (NMActiveConnection *self);

void          nm_active_connection_set_default6 (NMActiveConnection *self,
                                                 gboolean is_default6);

gboolean      nm_active_connection_get_default6 (NMActiveConnection *self);

NMActiveConnectionState nm_active_connection_get_state (NMActiveConnection *self);

void          nm_active_connection_set_state (NMActiveConnection *self,
                                              NMActiveConnectionState state);

NMDevice *    nm_active_connection_get_device (NMActiveConnection *self);

gboolean      nm_active_connection_set_device (NMActiveConnection *self, NMDevice *device);

NMAuthSubject *nm_active_connection_get_subject (NMActiveConnection *self);

gboolean      nm_active_connection_get_user_requested (NMActiveConnection *self);

NMActiveConnection *nm_active_connection_get_master (NMActiveConnection *self);

gboolean      nm_active_connection_get_master_ready (NMActiveConnection *self);

void          nm_active_connection_set_master (NMActiveConnection *self,
                                               NMActiveConnection *master);

void          nm_active_connection_set_parent (NMActiveConnection *self,
                                               NMActiveConnection *parent);

void          nm_active_connection_set_assumed (NMActiveConnection *self,
                                                gboolean assumed);

gboolean      nm_active_connection_get_assumed (NMActiveConnection *self);

void          nm_active_connection_clear_secrets (NMActiveConnection *self);

#endif /* __NETWORKMANAGER_ACTIVE_CONNECTION_H__ */
