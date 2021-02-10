/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DHCP_UTILS_H__
#define __NETWORKMANAGER_DHCP_UTILS_H__

#include <stdlib.h>

#include "nm-ip4-config.h"
#include "nm-ip6-config.h"

NMIP4Config *nm_dhcp_utils_ip4_config_from_options(struct _NMDedupMultiIndex *multi_idx,
                                                   int                        ifindex,
                                                   const char *               iface,
                                                   GHashTable *               options,
                                                   guint32                    route_table,
                                                   guint32                    route_metric);

NMIP6Config *nm_dhcp_utils_ip6_config_from_options(struct _NMDedupMultiIndex *multi_idx,
                                                   int                        ifindex,
                                                   const char *               iface,
                                                   GHashTable *               options,
                                                   gboolean                   info_only);

NMPlatformIP6Address nm_dhcp_utils_ip6_prefix_from_options(GHashTable *options);

char *nm_dhcp_utils_duid_to_string(GBytes *duid);

GBytes *nm_dhcp_utils_client_id_string_to_bytes(const char *client_id);

gboolean nm_dhcp_utils_get_leasefile_path(int         addr_family,
                                          const char *plugin_name,
                                          const char *iface,
                                          const char *uuid,
                                          char **     out_leasefile_path);

char *nm_dhcp_utils_get_dhcp6_event_id(GHashTable *lease);

/*****************************************************************************/

static inline gboolean
nm_dhcp_lease_data_consume(const uint8_t **datap, size_t *n_datap, void *out, size_t n_out)
{
    if (*n_datap < n_out)
        return FALSE;

    memcpy(out, *datap, n_out);
    *datap += n_out;
    *n_datap -= n_out;
    return TRUE;
}

static inline gboolean
nm_dhcp_lease_data_consume_in_addr(const uint8_t **datap, size_t *n_datap, in_addr_t *addrp)
{
    return nm_dhcp_lease_data_consume(datap, n_datap, addrp, sizeof(struct in_addr));
}

char *nm_dhcp_lease_data_parse_domain_validate(const char *str);

gboolean nm_dhcp_lease_data_parse_u16(const guint8 *data, gsize n_data, guint16 *out_val);
gboolean nm_dhcp_lease_data_parse_mtu(const guint8 *data, gsize n_data, guint16 *out_val);
gboolean nm_dhcp_lease_data_parse_cstr(const guint8 *data, gsize n_data, gsize *out_new_len);
gboolean nm_dhcp_lease_data_parse_domain(const guint8 *data, gsize n_data, char **out_val);
gboolean nm_dhcp_lease_data_parse_in_addr(const guint8 *data, gsize n_data, in_addr_t *out_val);
char **  nm_dhcp_lease_data_parse_search_list(const guint8 *data, gsize n_data);

#endif /* __NETWORKMANAGER_DHCP_UTILS_H__ */
