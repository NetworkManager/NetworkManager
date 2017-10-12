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

gboolean print_ip4_config (NMIPConfig *cfg4, const NmcConfig *nmc_config, const char *one_field);
gboolean print_ip6_config (NMIPConfig *cfg6, const NmcConfig *nmc_config, const char *group_prefix, const char *one_field);
gboolean print_dhcp4_config (NMDhcpConfig *dhcp4, const NmcConfig *nmc_config, const char *group_prefix, const char *one_field);
gboolean print_dhcp6_config (NMDhcpConfig *dhcp6, const NmcConfig *nmc_config, const char *group_prefix, const char *one_field);

NMConnection *nmc_find_connection (const GPtrArray *connections,
                                   const char *filter_type,
                                   const char *filter_val,
                                   int *start,
                                   gboolean complete);

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
char *nmc_readline_echo (gboolean echo_on, const char *prompt_fmt, ...) G_GNUC_PRINTF (2, 3);
NmcCompEntryFunc nmc_rl_compentry_func_wrap (const char *const*values);
char *nmc_rl_gen_func_basic (const char *text, int state, const char *const*words);
char *nmc_rl_gen_func_ifnames (const char *text, int state);
gboolean nmc_get_in_readline (void);
void nmc_set_in_readline (gboolean in_readline);

/* for pre-filling a string to readline prompt */
extern char *nmc_rl_pre_input_deftext;
int nmc_rl_set_deftext (void);

char *nmc_parse_lldp_capabilities (guint value);

typedef struct {
	const char *cmd;
	NMCResultCode (*func) (NmCli *nmc, int argc, char **argv);
	void (*usage) (void);
	gboolean needs_client;
	gboolean needs_nm_running;
} NMCCommand;

void nmc_do_cmd (NmCli *nmc, const NMCCommand cmds[], const char *cmd, int argc, char **argv);

void nmc_complete_strings (const char *prefix, ...) G_GNUC_NULL_TERMINATED;

void nmc_complete_bool (const char *prefix);

const char *nmc_error_get_simple_message (GError *error);

extern const NmcMetaGenericInfo *const metagen_ip4_config[];
extern const NmcMetaGenericInfo *const nmc_fields_dhcp4_config[];
extern const NmcMetaGenericInfo *const nmc_fields_ip6_config[];
extern const NmcMetaGenericInfo *const nmc_fields_dhcp6_config[];

#endif /* NMC_COMMON_H */
