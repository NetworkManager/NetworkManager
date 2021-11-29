/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2007 - 2011 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NM_SETTING_CDMA_H__
#define __NM_SETTING_CDMA_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_CDMA (nm_setting_cdma_get_type())
#define NM_SETTING_CDMA(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_CDMA, NMSettingCdma))
#define NM_SETTING_CDMA_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_CDMA, NMSettingCdmaClass))
#define NM_IS_SETTING_CDMA(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_CDMA))
#define NM_IS_SETTING_CDMA_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_CDMA))
#define NM_SETTING_CDMA_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_CDMA, NMSettingCdmaClass))

#define NM_SETTING_CDMA_SETTING_NAME "cdma"

#define NM_SETTING_CDMA_NUMBER         "number"
#define NM_SETTING_CDMA_USERNAME       "username"
#define NM_SETTING_CDMA_PASSWORD       "password"
#define NM_SETTING_CDMA_PASSWORD_FLAGS "password-flags"
#define NM_SETTING_CDMA_MTU            "mtu"

typedef struct _NMSettingCdmaClass NMSettingCdmaClass;

GType nm_setting_cdma_get_type(void);

NMSetting           *nm_setting_cdma_new(void);
const char          *nm_setting_cdma_get_number(NMSettingCdma *setting);
const char          *nm_setting_cdma_get_username(NMSettingCdma *setting);
const char          *nm_setting_cdma_get_password(NMSettingCdma *setting);
NMSettingSecretFlags nm_setting_cdma_get_password_flags(NMSettingCdma *setting);

NM_AVAILABLE_IN_1_8
guint32 nm_setting_cdma_get_mtu(NMSettingCdma *setting);

G_END_DECLS

#endif /* __NM_SETTING_CDMA_H__ */
