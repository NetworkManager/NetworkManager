/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_COMPAT_H__
#define __NM_COMPAT_H__

#include "nm-setting-vpn.h"

/*****************************************************************************/

const char **_nm_setting_vpn_get_data_keys(NMSettingVpn *setting, guint *out_length);

const char **_nm_setting_vpn_get_secret_keys(NMSettingVpn *setting, guint *out_length);

#if NM_CHECK_VERSION(1, 11, 0)
#define nm_setting_vpn_get_data_keys(setting, out_length)  \
    ({                                                     \
        G_GNUC_BEGIN_IGNORE_DEPRECATIONS                   \
        nm_setting_vpn_get_data_keys(setting, out_length); \
        G_GNUC_END_IGNORE_DEPRECATIONS                     \
    })
#define nm_setting_vpn_get_secret_keys(setting, out_length)  \
    ({                                                       \
        G_GNUC_BEGIN_IGNORE_DEPRECATIONS                     \
        nm_setting_vpn_get_secret_keys(setting, out_length); \
        G_GNUC_END_IGNORE_DEPRECATIONS                       \
    })
#else
#define nm_setting_vpn_get_data_keys(setting, out_length) \
    _nm_setting_vpn_get_data_keys(setting, out_length)
#define nm_setting_vpn_get_secret_keys(setting, out_length) \
    _nm_setting_vpn_get_secret_keys(setting, out_length)
#endif

/*****************************************************************************/

/* possibly missing defines from newer libnm API. */

#ifndef NM_VPN_PLUGIN_CONFIG_PROXY_PAC
#define NM_VPN_PLUGIN_CONFIG_PROXY_PAC "pac"
#endif

#ifndef NM_VPN_PLUGIN_IP4_CONFIG_PRESERVE_ROUTES
#define NM_VPN_PLUGIN_IP4_CONFIG_PRESERVE_ROUTES "preserve-routes"
#endif

#ifndef NM_VPN_PLUGIN_IP6_CONFIG_PRESERVE_ROUTES
#define NM_VPN_PLUGIN_IP6_CONFIG_PRESERVE_ROUTES "preserve-routes"
#endif

/*****************************************************************************/

#endif /* __NM_COMPAT_H__ */
