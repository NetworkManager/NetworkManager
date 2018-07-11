/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2018 Red Hat, Inc.
 */

#ifndef NM_SETTING_SRIOV_H
#define NM_SETTING_SRIOV_H

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_SRIOV            (nm_setting_sriov_get_type ())
#define NM_SETTING_SRIOV(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_SRIOV, NMSettingSriov))
#define NM_SETTING_SRIOV_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_SRIOV, NMSettingSriovClass))
#define NM_IS_SETTING_SRIOV(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_SRIOV))
#define NM_IS_SETTING_SRIOV_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_SRIOV))
#define NM_SETTING_SRIOV_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_SRIOV, NMSettingSriovClass))

#define NM_SETTING_SRIOV_SETTING_NAME          "sriov"

#define NM_SETTING_SRIOV_TOTAL_VFS             "total-vfs"
#define NM_SETTING_SRIOV_VFS                   "vfs"
#define NM_SETTING_SRIOV_AUTOPROBE_DRIVERS     "autoprobe-drivers"

#define NM_SRIOV_VF_ATTRIBUTE_MAC              "mac"
#define NM_SRIOV_VF_ATTRIBUTE_SPOOF_CHECK      "spoof-check"
#define NM_SRIOV_VF_ATTRIBUTE_TRUST            "trust"
#define NM_SRIOV_VF_ATTRIBUTE_MIN_TX_RATE      "min-tx-rate"
#define NM_SRIOV_VF_ATTRIBUTE_MAX_TX_RATE      "max-tx-rate"

typedef struct _NMSettingSriovClass NMSettingSriovClass;
typedef struct _NMSriovVF NMSriovVF;

/**
 * NMSriovVFVlanProtocol:
 * @NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q:  use 802.1Q
 * @NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD: use 802.1ad
 *
 * #NMSriovVFVlanProtocol indicates the VLAN protocol to use.
 *
 * Since: 1.14
 */
typedef enum {
	NM_SRIOV_VF_VLAN_PROTOCOL_802_1Q = 0,
	NM_SRIOV_VF_VLAN_PROTOCOL_802_1AD = 1,
} NMSriovVFVlanProtocol;

NM_AVAILABLE_IN_1_14
GType nm_setting_sriov_get_type (void);
NM_AVAILABLE_IN_1_14
NMSetting *nm_setting_sriov_new (void);
NM_AVAILABLE_IN_1_14
guint nm_setting_sriov_get_total_vfs (NMSettingSriov *setting);
NM_AVAILABLE_IN_1_14
guint nm_setting_sriov_get_num_vfs (NMSettingSriov *setting);
NM_AVAILABLE_IN_1_14
NMSriovVF *nm_setting_sriov_get_vf (NMSettingSriov *setting, guint idx);
NM_AVAILABLE_IN_1_14
void nm_setting_sriov_add_vf (NMSettingSriov *setting, NMSriovVF *vf);
NM_AVAILABLE_IN_1_14
void nm_setting_sriov_remove_vf (NMSettingSriov *setting, guint idx);
NM_AVAILABLE_IN_1_14
gboolean nm_setting_sriov_remove_vf_by_index (NMSettingSriov *setting, guint index);
NM_AVAILABLE_IN_1_14
void nm_setting_sriov_clear_vfs (NMSettingSriov *setting);
NM_AVAILABLE_IN_1_14
NMTernary nm_setting_sriov_get_autoprobe_drivers (NMSettingSriov *setting);

NM_AVAILABLE_IN_1_14
gboolean nm_sriov_vf_add_vlan (NMSriovVF *vf, guint vlan_id);
NM_AVAILABLE_IN_1_14
gboolean nm_sriov_vf_remove_vlan (NMSriovVF *vf, guint vlan_id);
NM_AVAILABLE_IN_1_14
const guint *nm_sriov_vf_get_vlan_ids (const NMSriovVF *vf, guint *length);
NM_AVAILABLE_IN_1_14
void nm_sriov_vf_set_vlan_qos (NMSriovVF *vf, guint vlan_id, guint32 qos);
NM_AVAILABLE_IN_1_14
void nm_sriov_vf_set_vlan_protocol (NMSriovVF *vf, guint vlan_id, NMSriovVFVlanProtocol protocol);
NM_AVAILABLE_IN_1_14
guint32 nm_sriov_vf_get_vlan_qos (const NMSriovVF *vf, guint vlan_id);
NM_AVAILABLE_IN_1_14
NMSriovVFVlanProtocol nm_sriov_vf_get_vlan_protocol (const NMSriovVF *vf, guint vlan_id);

NM_AVAILABLE_IN_1_14
GType nm_sriov_vf_get_type (void);
NM_AVAILABLE_IN_1_14
NMSriovVF *nm_sriov_vf_new (guint index);
NM_AVAILABLE_IN_1_14
void nm_sriov_vf_ref (NMSriovVF *vf);
NM_AVAILABLE_IN_1_14
void nm_sriov_vf_unref (NMSriovVF *vf);
NM_AVAILABLE_IN_1_14
gboolean nm_sriov_vf_equal (const NMSriovVF *vf, const NMSriovVF *other);
NM_AVAILABLE_IN_1_14
NMSriovVF *nm_sriov_vf_dup (const NMSriovVF *vf);
NM_AVAILABLE_IN_1_14
guint nm_sriov_vf_get_index (const NMSriovVF *vf);
NM_AVAILABLE_IN_1_14
void nm_sriov_vf_set_attribute (NMSriovVF *vf, const char *name, GVariant *value);
NM_AVAILABLE_IN_1_14
const char **nm_sriov_vf_get_attribute_names (const NMSriovVF *vf);
NM_AVAILABLE_IN_1_14
GVariant *nm_sriov_vf_get_attribute (const NMSriovVF *vf, const char *name);
NM_AVAILABLE_IN_1_14
gboolean nm_sriov_vf_attribute_validate  (const char *name, GVariant *value, gboolean *known, GError **error);

G_END_DECLS

#endif /* NM_SETTING_SRIOV_H */
