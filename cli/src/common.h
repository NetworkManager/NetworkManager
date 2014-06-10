/*
 *  nmcli - command-line tool for controlling NetworkManager
 *  Common functions and data shared between files.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * (C) Copyright 2012 - 2014 Red Hat, Inc.
 */

#ifndef NMC_COMMON_H
#define NMC_COMMON_H

#include <glib.h>

#include <nm-ip4-config.h>
#include <nm-ip6-config.h>
#include <nm-dhcp4-config.h>
#include <nm-dhcp6-config.h>
#include <nm-device.h>

#include "nmcli.h"

gboolean print_ip4_config (NMIP4Config *cfg4, NmCli *nmc, const char *group_prefix, const char *one_field);
gboolean print_ip6_config (NMIP6Config *cfg6, NmCli *nmc, const char *group_prefix, const char *one_field);
gboolean print_dhcp4_config (NMDHCP4Config *dhcp4, NmCli *nmc, const char *group_prefix, const char *one_field);
gboolean print_dhcp6_config (NMDHCP6Config *dhcp6, NmCli *nmc, const char *group_prefix, const char *one_field);

NMIP4Address *nmc_parse_and_build_ip4_address (const char *ip_str, const char *gw_str, GError **error);
NMIP6Address *nmc_parse_and_build_ip6_address (const char *ip_str, const char *gw_str, GError **error);

NMIP4Route *nmc_parse_and_build_ip4_route (const char *first, const char *second, const char *third, GError **error);
NMIP6Route *nmc_parse_and_build_ip6_route (const char *first, const char *second, const char *third, GError **error);

const char * nmc_device_state_to_string (NMDeviceState state);
const char * nmc_device_reason_to_string (NMDeviceStateReason reason);

char **
nmc_vlan_parse_priority_maps (const char *priority_map,
                              NMVlanPriorityMap map_type,
                              GError **error);

const char *nmc_bond_validate_mode (const char *mode, GError **error);
gboolean nmc_team_check_config (const char *config, char **out_config, GError **error);

NMConnection *nmc_find_connection (GSList *list,
                                   const char *filter_type,
                                   const char *filter_val,
                                   GSList **start);

void nmc_cleanup_readline (void);
char *nmc_readline (const char *prompt_fmt, ...) G_GNUC_PRINTF (1, 2);
char *nmc_rl_gen_func_basic (const char *text, int state, const char **words);

#endif /* NMC_COMMON_H */
