/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#ifndef __NM_SETTING_6LOWPAN_H__
#define __NM_SETTING_6LOWPAN_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_6LOWPAN (nm_setting_6lowpan_get_type())
#define NM_SETTING_6LOWPAN(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_6LOWPAN, NMSetting6Lowpan))
#define NM_SETTING_6LOWPAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_6LOWPANCONFIG, NMSetting6LowpanClass))
#define NM_IS_SETTING_6LOWPAN(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_6LOWPAN))
#define NM_IS_SETTING_6LOWPAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_6LOWPAN))
#define NM_SETTING_6LOWPAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_6LOWPAN, NMSetting6LowpanClass))

#define NM_SETTING_6LOWPAN_SETTING_NAME "6lowpan"

#define NM_SETTING_6LOWPAN_PARENT "parent"

typedef struct _NMSetting6LowpanClass NMSetting6LowpanClass;

NM_AVAILABLE_IN_1_14
GType nm_setting_6lowpan_get_type(void);
NM_AVAILABLE_IN_1_14
NMSetting *nm_setting_6lowpan_new(void);

NM_AVAILABLE_IN_1_14
const char *nm_setting_6lowpan_get_parent(NMSetting6Lowpan *setting);

G_END_DECLS

#endif /* __NM_SETTING_6LOWPAN_H__ */
