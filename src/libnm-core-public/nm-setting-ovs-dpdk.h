/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2019 Red Hat, Inc.
 */

#ifndef __NM_SETTING_OVS_DPDK_H__
#define __NM_SETTING_OVS_DPDK_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_OVS_DPDK (nm_setting_ovs_dpdk_get_type())
#define NM_SETTING_OVS_DPDK(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_OVS_DPDK, NMSettingOvsDpdk))
#define NM_SETTING_OVS_DPDK_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_OVS_DPDKCONFIG, NMSettingOvsDpdkClass))
#define NM_IS_SETTING_OVS_DPDK(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_OVS_DPDK))
#define NM_IS_SETTING_OVS_DPDK_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_OVS_DPDK))
#define NM_SETTING_OVS_DPDK_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_OVS_DPDK, NMSettingOvsDpdkClass))

#define NM_SETTING_OVS_DPDK_SETTING_NAME "ovs-dpdk"

#define NM_SETTING_OVS_DPDK_DEVARGS "devargs"
#define NM_SETTING_OVS_DPDK_N_RXQ   "n-rxq"

typedef struct _NMSettingOvsDpdkClass NMSettingOvsDpdkClass;

NM_AVAILABLE_IN_1_20
GType nm_setting_ovs_dpdk_get_type(void);
NM_AVAILABLE_IN_1_20
NMSetting *nm_setting_ovs_dpdk_new(void);

NM_AVAILABLE_IN_1_20
const char *nm_setting_ovs_dpdk_get_devargs(NMSettingOvsDpdk *self);
NM_AVAILABLE_IN_1_36
guint32 nm_setting_ovs_dpdk_get_n_rxq(NMSettingOvsDpdk *self);

G_END_DECLS

#endif /* __NM_SETTING_OVS_DPDK_H__ */
