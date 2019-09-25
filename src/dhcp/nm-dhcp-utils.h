// SPDX-License-Identifier: GPL-2.0+
/*
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

char *nm_dhcp_utils_duid_to_string (GBytes *duid);

GBytes *nm_dhcp_utils_client_id_string_to_bytes (const char *client_id);

gboolean nm_dhcp_utils_get_leasefile_path (int addr_family,
                                           const char *plugin_name,
                                           const char *iface,
                                           const char *uuid,
                                           char **out_leasefile_path);

#endif /* __NETWORKMANAGER_DHCP_UTILS_H__ */

