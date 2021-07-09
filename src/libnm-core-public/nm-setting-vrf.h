/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_SETTING_VRF_H__
#define __NM_SETTING_VRF_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_VRF (nm_setting_vrf_get_type())
#define NM_SETTING_VRF(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SETTING_VRF, NMSettingVrf))
#define NM_SETTING_VRF_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SETTING_VRFCONFIG, NMSettingVrfClass))
#define NM_IS_SETTING_VRF(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SETTING_VRF))
#define NM_IS_SETTING_VRF_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SETTING_VRF))
#define NM_SETTING_VRF_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SETTING_VRF, NMSettingVrfClass))

#define NM_SETTING_VRF_SETTING_NAME "vrf"

#define NM_SETTING_VRF_TABLE "table"

typedef struct _NMSettingVrfClass NMSettingVrfClass;

NM_AVAILABLE_IN_1_24
GType nm_setting_vrf_get_type(void);
NM_AVAILABLE_IN_1_24
NMSetting *nm_setting_vrf_new(void);
NM_AVAILABLE_IN_1_24
guint32 nm_setting_vrf_get_table(NMSettingVrf *setting);

G_END_DECLS

#endif /* __NM_SETTING_VRF_H__ */
