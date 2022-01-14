/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_PPPOE_H__
#define __NM_SETTING_PPPOE_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_PPPOE (nm_setting_pppoe_get_type())
#define NM_SETTING_PPPOE(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_PPPOE, NMSettingPppoe))
#define NM_SETTING_PPPOE_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_PPPOE, NMSettingPppoeClass))
#define NM_IS_SETTING_PPPOE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_PPPOE))
#define NM_IS_SETTING_PPPOE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_PPPOE))
#define NM_SETTING_PPPOE_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_PPPOE, NMSettingPppoeClass))

#define NM_SETTING_PPPOE_SETTING_NAME "pppoe"

#define NM_SETTING_PPPOE_PARENT         "parent"
#define NM_SETTING_PPPOE_SERVICE        "service"
#define NM_SETTING_PPPOE_USERNAME       "username"
#define NM_SETTING_PPPOE_PASSWORD       "password"
#define NM_SETTING_PPPOE_PASSWORD_FLAGS "password-flags"

typedef struct _NMSettingPppoeClass NMSettingPppoeClass;

GType nm_setting_pppoe_get_type(void);

NMSetting *nm_setting_pppoe_new(void);
NM_AVAILABLE_IN_1_10
const char          *nm_setting_pppoe_get_parent(NMSettingPppoe *setting);
const char          *nm_setting_pppoe_get_service(NMSettingPppoe *setting);
const char          *nm_setting_pppoe_get_username(NMSettingPppoe *setting);
const char          *nm_setting_pppoe_get_password(NMSettingPppoe *setting);
NMSettingSecretFlags nm_setting_pppoe_get_password_flags(NMSettingPppoe *setting);

G_END_DECLS

#endif /* __NM_SETTING_PPPOE_H__ */
