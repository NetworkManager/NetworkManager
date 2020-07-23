// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NM_L3_CONFIG_DATA_H__
#define __NM_L3_CONFIG_DATA_H__

#include "nm-glib-aux/nm-dedup-multi.h"
#include "nm-setting-connection.h"
#include "nm-setting-ip6-config.h"
#include "platform/nm-platform.h"

typedef struct _NML3ConfigData NML3ConfigData;

NML3ConfigData *nm_l3_config_data_new (NMDedupMultiIndex *multi_idx,
                                       int ifindex);
NML3ConfigData *nm_l3_config_data_ref (NML3ConfigData *self);
NML3ConfigData *nm_l3_config_data_ref_and_seal (NML3ConfigData *self);
NML3ConfigData *nm_l3_config_data_seal (NML3ConfigData *self);
void nm_l3_config_data_unref (NML3ConfigData *self);

gboolean nm_l3_config_data_is_sealed (NML3ConfigData *self);

NML3ConfigData *nm_l3_config_data_new_from_connection (NMDedupMultiIndex *multi_idx,
                                                       int ifindex,
                                                       NMConnection *connection,
                                                       NMSettingConnectionMdns mdns,
                                                       NMSettingConnectionLlmnr llmnr,
                                                       guint32 route_table,
                                                       guint32 route_metric);

NML3ConfigData *nm_l3_config_data_new_from_platform (NMDedupMultiIndex *multi_idx,
                                                     int ifindex,
                                                     NMPlatform *platform,
                                                     NMSettingIP6ConfigPrivacy ipv6_privacy_rfc4941);

/*****************************************************************************/

const NMDedupMultiHeadEntry *nm_l3_config_data_lookup_addresses (const NML3ConfigData *self, int addr_family);
const NMDedupMultiHeadEntry *nm_l3_config_data_lookup_routes (const NML3ConfigData *self, int addr_family);

int nm_l3_config_data_get_ifindex (const NML3ConfigData *self);

/*****************************************************************************/

gboolean _nm_l3_config_data_add_address (NML3ConfigData *self,
                                         int addr_family,
                                         const NMPObject *obj_new,
                                         const NMPlatformIPAddress *pl_new);

gboolean _nm_l3_config_data_add_route (NML3ConfigData *self,
                                       int addr_family,
                                       const NMPObject *obj_new,
                                       const NMPlatformIPRoute *pl_new,
                                       const NMPObject **out_obj_new,
                                       gboolean *out_changed_best_default_route);

gboolean _nm_l3_config_data_add_domain (NML3ConfigData *self,
                                        int addr_family,
                                        const char *domain);

gboolean _nm_l3_config_data_add_search (NML3ConfigData *self,
                                        int addr_family,
                                        const char *search);

gboolean _nm_l3_config_data_add_dns_option (NML3ConfigData *self,
                                            int addr_family,
                                            const char *dns_option);

gboolean _nm_l3_config_data_set_dns_priority (NML3ConfigData *self,
                                              int addr_family,
                                              int dns_priority);

#endif /* __NM_L3_CONFIG_DATA_H__ */
