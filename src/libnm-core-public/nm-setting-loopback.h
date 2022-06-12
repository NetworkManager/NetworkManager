/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */

#ifndef __NM_SETTING_LOOPBACK_H__
#define __NM_SETTING_LOOPBACK_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_LOOPBACK (nm_setting_loopback_get_type())
#define NM_SETTING_LOOPBACK(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_LOOPBACK, NMSettingLoopback))
#define NM_SETTING_LOOPBACK_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_LOOPBACKCONFIG, NMSettingLoopbackClass))
#define NM_IS_SETTING_LOOPBACK(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_LOOPBACK))
#define NM_IS_SETTING_LOOPBACK_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_LOOPBACK))
#define NM_SETTING_LOOPBACK_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_LOOPBACK, NMSettingLoopbackClass))

#define NM_SETTING_LOOPBACK_SETTING_NAME "loopback"

#define NM_SETTING_LOOPBACK_MTU "mtu"

typedef struct _NMSettingLoopbackClass NMSettingLoopbackClass;

NM_AVAILABLE_IN_1_42
GType nm_setting_loopback_get_type(void);
NM_AVAILABLE_IN_1_42
NMSetting *nm_setting_loopback_new(void);

NM_AVAILABLE_IN_1_42
guint32 nm_setting_loopback_get_mtu(NMSettingLoopback *setting);

G_END_DECLS

#endif /* __NM_SETTING_LOOPBACK_H__ */
