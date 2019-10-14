// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

#ifndef __NM_SETTING_INFINIBAND_H__
#define __NM_SETTING_INFINIBAND_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_INFINIBAND            (nm_setting_infiniband_get_type ())
#define NM_SETTING_INFINIBAND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_INFINIBAND, NMSettingInfiniband))
#define NM_SETTING_INFINIBAND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_INFINIBAND, NMSettingInfinibandClass))
#define NM_IS_SETTING_INFINIBAND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_INFINIBAND))
#define NM_IS_SETTING_INFINIBAND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_INFINIBAND))
#define NM_SETTING_INFINIBAND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_INFINIBAND, NMSettingInfinibandClass))

#define NM_SETTING_INFINIBAND_SETTING_NAME "infiniband"

#define NM_SETTING_INFINIBAND_MAC_ADDRESS    "mac-address"
#define NM_SETTING_INFINIBAND_MTU            "mtu"
#define NM_SETTING_INFINIBAND_TRANSPORT_MODE "transport-mode"
#define NM_SETTING_INFINIBAND_P_KEY          "p-key"
#define NM_SETTING_INFINIBAND_PARENT         "parent"

/**
 * NMSettingInfiniband:
 *
 * Infiniband Settings
 */
struct _NMSettingInfiniband {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingInfinibandClass;

GType nm_setting_infiniband_get_type (void);

NMSetting *       nm_setting_infiniband_new                (void);
const char *      nm_setting_infiniband_get_mac_address    (NMSettingInfiniband *setting);
guint32           nm_setting_infiniband_get_mtu            (NMSettingInfiniband *setting);
const char *      nm_setting_infiniband_get_transport_mode (NMSettingInfiniband *setting);
int               nm_setting_infiniband_get_p_key          (NMSettingInfiniband *setting);
const char *      nm_setting_infiniband_get_parent         (NMSettingInfiniband *setting);

const char *      nm_setting_infiniband_get_virtual_interface_name (NMSettingInfiniband *setting);

G_END_DECLS

#endif /* __NM_SETTING_INFINIBAND_H__ */
