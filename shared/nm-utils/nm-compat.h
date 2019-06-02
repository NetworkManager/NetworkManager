/* NetworkManager -- Network link manager
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2017 Red Hat, Inc.
 */

#ifndef __NM_COMPAT_H__
#define __NM_COMPAT_H__

#include "nm-setting-vpn.h"

const char **_nm_setting_vpn_get_data_keys (NMSettingVpn *setting,
                                            guint *out_length);

const char **_nm_setting_vpn_get_secret_keys (NMSettingVpn *setting,
                                              guint *out_length);

#if NM_CHECK_VERSION (1, 11, 0)
#define nm_setting_vpn_get_data_keys(setting, out_length) \
	({ \
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
		nm_setting_vpn_get_data_keys (setting, out_length); \
		G_GNUC_END_IGNORE_DEPRECATIONS \
	})
#define nm_setting_vpn_get_secret_keys(setting, out_length) \
	({ \
		G_GNUC_BEGIN_IGNORE_DEPRECATIONS \
		nm_setting_vpn_get_secret_keys (setting, out_length); \
		G_GNUC_END_IGNORE_DEPRECATIONS \
	})
#else
#define nm_setting_vpn_get_data_keys(setting, out_length) \
	_nm_setting_vpn_get_data_keys (setting, out_length)
#define nm_setting_vpn_get_secret_keys(setting, out_length) \
	_nm_setting_vpn_get_secret_keys (setting, out_length)
#endif

#endif /* __NM_COMPAT_H__ */
