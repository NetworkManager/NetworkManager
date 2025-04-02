/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_SETTING_PREFIX_DELEGATION_H__
#define __NM_SETTING_PREFIX_DELEGATION_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_PREFIX_DELEGATION (nm_setting_prefix_delegation_get_type())
#define NM_SETTING_PREFIX_DELEGATION(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_PREFIX_DELEGATION, NMSettingVrf))
#define NM_SETTING_PREFIX_DELEGATION_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_PREFIX_DELEGATIONCONFIG, NMSettingVrfClass))
#define NM_IS_SETTING_PREFIX_DELEGATION(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_PREFIX_DELEGATION))
#define NM_IS_SETTING_PREFIX_DELEGATION_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_PREFIX_DELEGATION))
#define NM_SETTING_PREFIX_DELEGATION_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_PREFIX_DELEGATION, NMSettingVrfClass))

#define NM_SETTING_PREFIX_DELEGATION_SETTING_NAME "prefix-delegation"

#define NM_SETTING_PREFIX_DELEGATION_SUBNET_ID "subnet-id"

typedef struct _NMSettingPrefixDelegationClass NMSettingPrefixDelegationClass;

NM_AVAILABLE_IN_1_54
GType nm_setting_prefix_delegation_get_type(void);
NM_AVAILABLE_IN_1_54
NMSetting *nm_setting_prefix_delegation_new(void);
NM_AVAILABLE_IN_1_54
gint64 nm_setting_prefix_delegation_get_subnet_id(NMSettingPrefixDelegation *setting);

G_END_DECLS

#endif /* __NM_SETTING_PREFIX_DELEGATION_H__ */
