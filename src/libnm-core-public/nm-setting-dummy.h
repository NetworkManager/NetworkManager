/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_SETTING_DUMMY_H__
#define __NM_SETTING_DUMMY_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_DUMMY (nm_setting_dummy_get_type())
#define NM_SETTING_DUMMY(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_DUMMY, NMSettingDummy))
#define NM_SETTING_DUMMY_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_DUMMYCONFIG, NMSettingDummyClass))
#define NM_IS_SETTING_DUMMY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_DUMMY))
#define NM_IS_SETTING_DUMMY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_DUMMY))
#define NM_SETTING_DUMMY_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_DUMMY, NMSettingDummyClass))

#define NM_SETTING_DUMMY_SETTING_NAME "dummy"

typedef struct _NMSettingDummyClass NMSettingDummyClass;

NM_AVAILABLE_IN_1_8
GType nm_setting_dummy_get_type(void);
NM_AVAILABLE_IN_1_8
NMSetting *nm_setting_dummy_new(void);

G_END_DECLS

#endif /* __NM_SETTING_DUMMY_H__ */
