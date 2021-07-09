/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef __NM_SETTING_GENERIC_H__
#define __NM_SETTING_GENERIC_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_GENERIC (nm_setting_generic_get_type())
#define NM_SETTING_GENERIC(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_GENERIC, NMSettingGeneric))
#define NM_SETTING_GENERIC_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_GENERIC, NMSettingGenericClass))
#define NM_IS_SETTING_GENERIC(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_GENERIC))
#define NM_IS_SETTING_GENERIC_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_GENERIC))
#define NM_SETTING_GENERIC_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_GENERIC, NMSettingGenericClass))

#define NM_SETTING_GENERIC_SETTING_NAME "generic"

typedef struct _NMSettingGenericClass NMSettingGenericClass;

GType nm_setting_generic_get_type(void);

NMSetting *nm_setting_generic_new(void);

G_END_DECLS

#endif /* __NM_SETTING_GENERIC_H__ */
