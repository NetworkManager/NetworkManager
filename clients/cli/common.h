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


gboolean print_ip_config (NMIPConfig *cfg,
                          int addr_family,
                          const NmcConfig *nmc_config,
                          const char *one_field);

gboolean print_dhcp_config (NMDhcpConfig *dhcp,
                            int addr_family,
                            const NmcConfig *nmc_config,
                            const char *one_field);

NMConnection *nmc_find_connection (const GPtrArray *connections,
                                   const char *filter_type,
                                   const char *filter_val,
                                   GPtrArray **out_result,
                                   gboolean complete);

NMActiveConnection *nmc_find_active_connection (const GPtrArray *active_cons,
                                                const char *filter_type,
                                                const char *filter_val,
                                                GPtrArray **out_result,
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
char *nmc_readline (const NmcConfig *nmc_config,
                    const char *prompt_fmt,
                    ...) G_GNUC_PRINTF (2, 3);
char *nmc_readline_echo (const NmcConfig *nmc_config,
                         gboolean echo_on,
                         const char *prompt_fmt,
                         ...) G_GNUC_PRINTF (3, 4);
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

void nmc_complete_strv (const char *prefix, gssize nargs, const char *const*args);

#define nmc_complete_strings(prefix, ...) nmc_complete_strv ((prefix), NM_NARG (__VA_ARGS__), (const char *const[]) { __VA_ARGS__ })

void nmc_complete_bool (const char *prefix);

const char *nmc_error_get_simple_message (GError *error);

extern const NmcMetaGenericInfo *const metagen_ip4_config[];
extern const NmcMetaGenericInfo *const metagen_ip6_config[];
extern const NmcMetaGenericInfo *const metagen_dhcp_config[];

const char *nm_connectivity_to_string (NMConnectivityState connectivity);

#endif /* NMC_COMMON_H */
