/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NM_PLATFORM_UTILS_H__
#define __NM_PLATFORM_UTILS_H__

#include "config.h"

#include <gudev/gudev.h>

#include "nm-platform.h"
#include "nm-setting-wired.h"


const char *nmp_utils_ethtool_get_driver (const char *ifname);
gboolean nmp_utils_ethtool_supports_carrier_detect (const char *ifname);
gboolean nmp_utils_ethtool_supports_vlans (const char *ifname);
int nmp_utils_ethtool_get_peer_ifindex (const char *ifname);
gboolean nmp_utils_ethtool_get_wake_on_lan (const char *ifname);
gboolean nmp_utils_ethtool_set_wake_on_lan (const char *ifname, NMSettingWiredWakeOnLan wol,
                                            const char *wol_password);

gboolean nmp_utils_ethtool_get_link_speed (const char *ifname, guint32 *out_speed);

gboolean nmp_utils_ethtool_get_driver_info (const char *ifname,
                                            char **out_driver_name,
                                            char **out_driver_version,
                                            char **out_fw_version);

gboolean  nmp_utils_ethtool_get_permanent_address (const char *ifname,
                                                   guint8 *buf,
                                                   size_t *length);


gboolean nmp_utils_mii_supports_carrier_detect (const char *ifname);


const char *nmp_utils_udev_get_driver (GUdevDevice *device);

guint32 nmp_utils_lifetime_rebase_relative_time_on_now (guint32 timestamp,
                                                        guint32 duration,
                                                        guint32 now,
                                                        guint32 padding);

gboolean nmp_utils_lifetime_get (guint32 timestamp,
                                 guint32 lifetime,
                                 guint32 preferred,
                                 guint32 now,
                                 guint32 padding,
                                 guint32 *out_lifetime,
                                 guint32 *out_preferred);

#endif /* __NM_PLATFORM_UTILS_H__ */
