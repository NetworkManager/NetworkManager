/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_SETTING_TUN_H__
#define __NM_SETTING_TUN_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_TUN (nm_setting_tun_get_type())
#define NM_SETTING_TUN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_TUN, NMSettingTun))
#define NM_SETTING_TUN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_TUNCONFIG, NMSettingTunClass))
#define NM_IS_SETTING_TUN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_TUN))
#define NM_IS_SETTING_TUN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_TUN))
#define NM_SETTING_TUN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_TUN, NMSettingTunClass))

#define NM_SETTING_TUN_SETTING_NAME "tun"

#define NM_SETTING_TUN_MODE        "mode"
#define NM_SETTING_TUN_OWNER       "owner"
#define NM_SETTING_TUN_GROUP       "group"
#define NM_SETTING_TUN_PI          "pi"
#define NM_SETTING_TUN_VNET_HDR    "vnet-hdr"
#define NM_SETTING_TUN_MULTI_QUEUE "multi-queue"

/**
 * NMSettingTunMode:
 * @NM_SETTING_TUN_MODE_UNKNOWN: an unknown device type
 * @NM_SETTING_TUN_MODE_TUN: a TUN device
 * @NM_SETTING_TUN_MODE_TAP: a TAP device
 *
 * #NMSettingTunMode values indicate the device type (TUN/TAP)
 */
typedef enum {
    NM_SETTING_TUN_MODE_UNKNOWN = 0,
    NM_SETTING_TUN_MODE_TUN     = 1,
    NM_SETTING_TUN_MODE_TAP     = 2,
} NMSettingTunMode;

typedef struct _NMSettingTunClass NMSettingTunClass;

NM_AVAILABLE_IN_1_2
GType nm_setting_tun_get_type(void);
NM_AVAILABLE_IN_1_2
NMSetting *nm_setting_tun_new(void);

NM_AVAILABLE_IN_1_2
NMSettingTunMode nm_setting_tun_get_mode(NMSettingTun *setting);
NM_AVAILABLE_IN_1_2
const char *nm_setting_tun_get_owner(NMSettingTun *setting);
NM_AVAILABLE_IN_1_2
const char *nm_setting_tun_get_group(NMSettingTun *setting);
NM_AVAILABLE_IN_1_2
gboolean nm_setting_tun_get_pi(NMSettingTun *setting);
NM_AVAILABLE_IN_1_2
gboolean nm_setting_tun_get_vnet_hdr(NMSettingTun *setting);
NM_AVAILABLE_IN_1_2
gboolean nm_setting_tun_get_multi_queue(NMSettingTun *setting);

G_END_DECLS

#endif /* __NM_SETTING_TUN_H__ */
