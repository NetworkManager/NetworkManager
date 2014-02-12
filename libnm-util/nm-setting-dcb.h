/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
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
 * (C) Copyright 2013 Red Hat, Inc.
 */

#ifndef NM_SETTING_DCB_H
#define NM_SETTING_DCB_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_DCB            (nm_setting_dcb_get_type ())
#define NM_SETTING_DCB(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_DCB, NMSettingDcb))
#define NM_SETTING_DCB_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_DCB, NMSettingDcbClass))
#define NM_IS_SETTING_DCB(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_DCB))
#define NM_IS_SETTING_DCB_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_DCB))
#define NM_SETTING_DCB_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_DCB, NMSettingDcbClass))

#define NM_SETTING_DCB_SETTING_NAME "dcb"

/**
 * NMSettingDcbError:
 * @NM_SETTING_DCB_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_DCB_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_DCB_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 */
typedef enum {
	NM_SETTING_DCB_ERROR_UNKNOWN = 0,      /*< nick=UnknownError >*/
	NM_SETTING_DCB_ERROR_INVALID_PROPERTY, /*< nick=InvalidProperty >*/
	NM_SETTING_DCB_ERROR_MISSING_PROPERTY  /*< nick=MissingProperty >*/
} NMSettingDcbError;

#define NM_SETTING_DCB_ERROR nm_setting_dcb_error_quark ()
GQuark nm_setting_dcb_error_quark (void);

/**
 * NMSettingDcbFlags:
 * @NM_SETTING_DCB_FLAG_NONE: no flag
 * @NM_SETTING_DCB_FLAG_ENABLE: the feature is enabled
 * @NM_SETTING_DCB_FLAG_ADVERTISE: the feature is advertised
 * @NM_SETTING_DCB_FLAG_WILLING: the feature is willing to change based on
 * peer configuration advertisements
 *
 * DCB feature flags.
 *
 * Since: 0.9.10
 **/
typedef enum {
	NM_SETTING_DCB_FLAG_NONE      = 0x00000000,
	NM_SETTING_DCB_FLAG_ENABLE    = 0x00000001,
	NM_SETTING_DCB_FLAG_ADVERTISE = 0x00000002,
	NM_SETTING_DCB_FLAG_WILLING   = 0x00000004
} NMSettingDcbFlags;

/**
 * NM_SETTING_DCB_FCOE_MODE_FABRIC:
 *
 * Indicates that the FCoE controller should use "fabric" mode (default)
 *
 * Since: 0.9.10
 */
#define NM_SETTING_DCB_FCOE_MODE_FABRIC  "fabric"

/**
 * NM_SETTING_DCB_FCOE_MODE_VN2VN:
 *
 * Indicates that the FCoE controller should use "VN2VN" mode.
 *
 * Since: 0.9.10
 */
#define NM_SETTING_DCB_FCOE_MODE_VN2VN   "vn2vn"


/* Properties */
#define NM_SETTING_DCB_APP_FCOE_FLAGS         "app-fcoe-flags"
#define NM_SETTING_DCB_APP_FCOE_PRIORITY      "app-fcoe-priority"
#define NM_SETTING_DCB_APP_FCOE_MODE          "app-fcoe-mode"

#define NM_SETTING_DCB_APP_ISCSI_FLAGS        "app-iscsi-flags"
#define NM_SETTING_DCB_APP_ISCSI_PRIORITY     "app-iscsi-priority"

#define NM_SETTING_DCB_APP_FIP_FLAGS          "app-fip-flags"
#define NM_SETTING_DCB_APP_FIP_PRIORITY       "app-fip-priority"

#define NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS  "priority-flow-control-flags"
#define NM_SETTING_DCB_PRIORITY_FLOW_CONTROL        "priority-flow-control"

#define NM_SETTING_DCB_PRIORITY_GROUP_FLAGS      "priority-group-flags"
#define NM_SETTING_DCB_PRIORITY_GROUP_ID         "priority-group-id"
#define NM_SETTING_DCB_PRIORITY_GROUP_BANDWIDTH  "priority-group-bandwidth"
#define NM_SETTING_DCB_PRIORITY_BANDWIDTH        "priority-bandwidth"
#define NM_SETTING_DCB_PRIORITY_STRICT_BANDWIDTH "priority-strict-bandwidth"
#define NM_SETTING_DCB_PRIORITY_TRAFFIC_CLASS    "priority-traffic-class"


typedef struct {
	NMSetting parent;
} NMSettingDcb;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingDcbClass;

NM_AVAILABLE_IN_0_9_10
GType nm_setting_dcb_get_type (void);

NM_AVAILABLE_IN_0_9_10
NMSetting *       nm_setting_dcb_new                      (void);

NMSettingDcbFlags nm_setting_dcb_get_app_fcoe_flags     (NMSettingDcb *setting);
gint              nm_setting_dcb_get_app_fcoe_priority  (NMSettingDcb *setting);
const char *      nm_setting_dcb_get_app_fcoe_mode      (NMSettingDcb *setting);

NMSettingDcbFlags nm_setting_dcb_get_app_iscsi_flags    (NMSettingDcb *setting);
gint              nm_setting_dcb_get_app_iscsi_priority (NMSettingDcb *setting);

NMSettingDcbFlags nm_setting_dcb_get_app_fip_flags      (NMSettingDcb *setting);
gint              nm_setting_dcb_get_app_fip_priority   (NMSettingDcb *setting);

/* Priority Flow Control */
NMSettingDcbFlags nm_setting_dcb_get_priority_flow_control_flags    (NMSettingDcb *setting);
gboolean          nm_setting_dcb_get_priority_flow_control          (NMSettingDcb *setting,
                                                                     guint user_priority);
void              nm_setting_dcb_set_priority_flow_control          (NMSettingDcb *setting,
                                                                     guint user_priority,
                                                                     gboolean enabled);

/* Priority Groups */
NMSettingDcbFlags nm_setting_dcb_get_priority_group_flags (NMSettingDcb *setting);

guint    nm_setting_dcb_get_priority_group_id         (NMSettingDcb *setting,
                                                       guint user_priority);
void     nm_setting_dcb_set_priority_group_id         (NMSettingDcb *setting,
                                                       guint user_priority,
                                                       guint group_id);

guint    nm_setting_dcb_get_priority_group_bandwidth  (NMSettingDcb *setting,
                                                       guint group_id);
void     nm_setting_dcb_set_priority_group_bandwidth  (NMSettingDcb *setting,
                                                       guint group_id,
                                                       guint bandwidth_percent);

guint    nm_setting_dcb_get_priority_bandwidth        (NMSettingDcb *setting,
                                                       guint user_priority);
void     nm_setting_dcb_set_priority_bandwidth        (NMSettingDcb *setting,
                                                       guint user_priority,
                                                       guint bandwidth_percent);

gboolean nm_setting_dcb_get_priority_strict_bandwidth (NMSettingDcb *setting,
                                                       guint user_priority);
void     nm_setting_dcb_set_priority_strict_bandwidth (NMSettingDcb *setting,
                                                       guint user_priority,
                                                       gboolean strict);

guint    nm_setting_dcb_get_priority_traffic_class    (NMSettingDcb *setting,
                                                       guint user_priority);
void     nm_setting_dcb_set_priority_traffic_class    (NMSettingDcb *setting,
                                                       guint user_priority,
                                                       guint traffic_class);

G_END_DECLS

#endif /* NM_SETTING_DCB_H */
