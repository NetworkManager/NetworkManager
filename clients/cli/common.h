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
 * Copyright 2012 - 2014 Red Hat, Inc.
 */

#ifndef NMC_COMMON_H
#define NMC_COMMON_H

#include "nmcli.h"
#include "nm-secret-agent-simple.h"

gboolean print_ip4_config (NMIPConfig *cfg4, NmCli *nmc, const char *group_prefix, const char *one_field);
gboolean print_ip6_config (NMIPConfig *cfg6, NmCli *nmc, const char *group_prefix, const char *one_field);
gboolean print_dhcp4_config (NMDhcpConfig *dhcp4, NmCli *nmc, const char *group_prefix, const char *one_field);
gboolean print_dhcp6_config (NMDhcpConfig *dhcp6, NmCli *nmc, const char *group_prefix, const char *one_field);

NMIPAddress *nmc_parse_and_build_address (int family, const char *ip_str, GError **error);
NMIPRoute *nmc_parse_and_build_route (int family, const char *first, const char *second, const char *third, GError **error);

const char * nmc_device_state_to_string (NMDeviceState state);
const char * nmc_device_reason_to_string (NMDeviceStateReason reason);
const char * nmc_device_metered_to_string (NMMetered value);

char **
nmc_vlan_parse_priority_maps (const char *priority_map,
                              NMVlanPriorityMap map_type,
                              GError **error);

const char *nmc_bond_validate_mode (const char *mode, GError **error);
gboolean nmc_team_check_config (const char *config, char **out_config, GError **error);

NMConnection *nmc_find_connection (const GPtrArray *connections,
                                   const char *filter_type,
                                   const char *filter_val,
                                   int *start);

void nmc_secrets_requested (NMSecretAgentSimple *agent,
                            const char          *request_id,
                            const char          *title,
                            const char          *msg,
                            GPtrArray           *secrets,
                            gpointer             user_data);

char *nmc_unique_connection_name (const GPtrArray *connections,
                                  const char *try_name);

void nmc_cleanup_readline (void);
char *nmc_readline (const char *prompt_fmt, ...) G_GNUC_PRINTF (1, 2);
char *nmc_rl_gen_func_basic (const char *text, int state, const char **words);
gboolean nmc_get_in_readline (void);
void nmc_set_in_readline (gboolean in_readline);

/* for pre-filling a string to readline prompt */
extern char *nmc_rl_pre_input_deftext;
int nmc_rl_set_deftext (void);

char *nmc_parse_lldp_capabilities (guint value);

#endif /* NMC_COMMON_H */
