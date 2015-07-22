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
 * Copyright 2007 - 2014 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_CONNECTION_H__
#define __NM_SETTING_CONNECTION_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_CONNECTION            (nm_setting_connection_get_type ())
#define NM_SETTING_CONNECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_CONNECTION, NMSettingConnection))
#define NM_SETTING_CONNECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_CONNECTION, NMSettingConnectionClass))
#define NM_IS_SETTING_CONNECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_CONNECTION))
#define NM_IS_SETTING_CONNECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_CONNECTION))
#define NM_SETTING_CONNECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_CONNECTION, NMSettingConnectionClass))

#define NM_SETTING_CONNECTION_SETTING_NAME "connection"

#define NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MIN -999
#define NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_MAX 999
#define NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY_DEFAULT 0

#define NM_SETTING_CONNECTION_ID             "id"
#define NM_SETTING_CONNECTION_UUID           "uuid"
#define NM_SETTING_CONNECTION_INTERFACE_NAME "interface-name"
#define NM_SETTING_CONNECTION_TYPE           "type"
#define NM_SETTING_CONNECTION_AUTOCONNECT    "autoconnect"
#define NM_SETTING_CONNECTION_AUTOCONNECT_PRIORITY "autoconnect-priority"
#define NM_SETTING_CONNECTION_TIMESTAMP      "timestamp"
#define NM_SETTING_CONNECTION_READ_ONLY      "read-only"
#define NM_SETTING_CONNECTION_PERMISSIONS    "permissions"
#define NM_SETTING_CONNECTION_ZONE           "zone"
#define NM_SETTING_CONNECTION_MASTER         "master"
#define NM_SETTING_CONNECTION_SLAVE_TYPE     "slave-type"
#define NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES "autoconnect-slaves"
#define NM_SETTING_CONNECTION_SECONDARIES    "secondaries"
#define NM_SETTING_CONNECTION_GATEWAY_PING_TIMEOUT "gateway-ping-timeout"
#define NM_SETTING_CONNECTION_METERED        "metered"

/* Types for property values */
/**
 * NMSettingConnectionAutoconnectSlaves:
 * @NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_DEFAULT: default value
 * @NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_NO: slaves are not brought up when
 *   master is activated
 * @NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_YES: slaves are brought up when
 *   master is activated
 *
 * #NMSettingConnectionAutoconnectSlaves values indicate whether slave connections
 * should be activated when master is activated.
 */
NM_AVAILABLE_IN_1_0_4
typedef enum {
	NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_DEFAULT = -1,
	NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_NO = 0,
	NM_SETTING_CONNECTION_AUTOCONNECT_SLAVES_YES = 1,
} NMSettingConnectionAutoconnectSlaves;


/**
 * NMSettingConnection:
 *
 * The NMSettingConnection struct contains only private data.
 * It should only be accessed through the functions described below.
 */
struct _NMSettingConnection {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingConnectionClass;

GType nm_setting_connection_get_type (void);

NMSetting * nm_setting_connection_new                  (void);
const char *nm_setting_connection_get_id               (NMSettingConnection *setting);
const char *nm_setting_connection_get_uuid             (NMSettingConnection *setting);
const char *nm_setting_connection_get_interface_name   (NMSettingConnection *setting);
const char *nm_setting_connection_get_connection_type  (NMSettingConnection *setting);
gboolean    nm_setting_connection_get_autoconnect      (NMSettingConnection *setting);
gint        nm_setting_connection_get_autoconnect_priority (NMSettingConnection *setting);
guint64     nm_setting_connection_get_timestamp        (NMSettingConnection *setting);
gboolean    nm_setting_connection_get_read_only        (NMSettingConnection *setting);

guint32     nm_setting_connection_get_num_permissions  (NMSettingConnection *setting);
gboolean    nm_setting_connection_get_permission       (NMSettingConnection *setting,
                                                        guint32 idx,
                                                        const char **out_ptype,
                                                        const char **out_pitem,
                                                        const char **out_detail);
const char *nm_setting_connection_get_zone             (NMSettingConnection *setting);
gboolean    nm_setting_connection_permissions_user_allowed (NMSettingConnection *setting, const char *uname);
gboolean    nm_setting_connection_add_permission       (NMSettingConnection *setting,
                                                        const char *ptype,
                                                        const char *pitem,
                                                        const char *detail);
void        nm_setting_connection_remove_permission    (NMSettingConnection *setting,
                                                        guint32 idx);
gboolean    nm_setting_connection_remove_permission_by_value (NMSettingConnection *setting,
                                                              const char *ptype,
                                                              const char *pitem,
                                                              const char *detail);

const char *nm_setting_connection_get_master           (NMSettingConnection *setting);
gboolean    nm_setting_connection_is_slave_type        (NMSettingConnection *setting,
                                                        const char *type);
const char *nm_setting_connection_get_slave_type       (NMSettingConnection *setting);
NM_AVAILABLE_IN_1_0_4
NMSettingConnectionAutoconnectSlaves nm_setting_connection_get_autoconnect_slaves (NMSettingConnection *setting);

guint32     nm_setting_connection_get_num_secondaries  (NMSettingConnection *setting);
const char *nm_setting_connection_get_secondary        (NMSettingConnection *setting, guint32 idx);
gboolean    nm_setting_connection_add_secondary        (NMSettingConnection *setting, const char *sec_uuid);
void        nm_setting_connection_remove_secondary     (NMSettingConnection *setting, guint32 idx);
gboolean    nm_setting_connection_remove_secondary_by_value (NMSettingConnection *setting, const char *sec_uuid);

guint32     nm_setting_connection_get_gateway_ping_timeout (NMSettingConnection *setting);
NM_AVAILABLE_IN_1_0_6
NMMetered   nm_setting_connection_get_metered (NMSettingConnection *setting);

G_END_DECLS

#endif /* __NM_SETTING_CONNECTION_H__ */
