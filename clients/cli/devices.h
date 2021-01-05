/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2010 - 2018 Red Hat, Inc.
 */

#ifndef NMC_DEVICES_H
#define NMC_DEVICES_H

#include "nmcli.h"

void nmc_complete_device(NMClient *client, const char *prefix, gboolean wifi_only);

void nmc_complete_bssid(NMClient *client, const char *ifname, const char *bssid_prefix);

void monitor_devices(NmCli *nmc);

NMDevice **nmc_get_devices_sorted(NMClient *client);

NMMetaColor nmc_device_state_to_color(NMDevice *device);

extern const NmcMetaGenericInfo *const metagen_device_status[];
extern const NmcMetaGenericInfo *const metagen_device_detail_general[];
extern const NmcMetaGenericInfo *const metagen_device_detail_connections[];
extern const NmcMetaGenericInfo *const metagen_device_detail_capabilities[];
extern const NmcMetaGenericInfo *const metagen_device_detail_wired_properties[];
extern const NmcMetaGenericInfo *const metagen_device_detail_wifi_properties[];
extern const NmcMetaGenericInfo *const metagen_device_detail_wimax_properties[];
extern const NmcMetaGenericInfo *const nmc_fields_dev_wifi_list[];
extern const NmcMetaGenericInfo *const nmc_fields_dev_wimax_list[];
extern const NmcMetaGenericInfo *const nmc_fields_dev_show_master_prop[];
extern const NmcMetaGenericInfo *const nmc_fields_dev_show_team_prop[];
extern const NmcMetaGenericInfo *const nmc_fields_dev_show_vlan_prop[];
extern const NmcMetaGenericInfo *const nmc_fields_dev_show_bluetooth[];
extern const NmcMetaGenericInfo *const nmc_fields_dev_show_sections[];
extern const NmcMetaGenericInfo *const nmc_fields_dev_lldp_list[];

#endif /* NMC_DEVICES_H */
