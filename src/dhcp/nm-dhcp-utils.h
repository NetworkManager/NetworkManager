/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_UTILS_H__
#define __NETWORKMANAGER_DHCP_UTILS_H__

#include <stdlib.h>

#include "nm-ip4-config.h"
#include "nm-ip6-config.h"

NMIP4Config *nm_dhcp_utils_ip4_config_from_options (struct _NMDedupMultiIndex *multi_idx,
                                                    int ifindex,
                                                    const char *iface,
                                                    GHashTable *options,
                                                    guint32 route_table,
                                                    guint32 route_metric);

NMIP6Config *nm_dhcp_utils_ip6_config_from_options (struct _NMDedupMultiIndex *multi_idx,
                                                    int ifindex,
                                                    const char *iface,
                                                    GHashTable *options,
                                                    gboolean info_only);

NMPlatformIP6Address nm_dhcp_utils_ip6_prefix_from_options (GHashTable *options);

char *       nm_dhcp_utils_duid_to_string          (const GByteArray *duid);

GBytes *     nm_dhcp_utils_client_id_string_to_bytes (const char *client_id);

#endif /* __NETWORKMANAGER_DHCP_UTILS_H__ */

