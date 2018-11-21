/* nmcli - command-line tool to control NetworkManager
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
 * (C) Copyright 2010 - 2018 Red Hat, Inc.
 */

#ifndef NMC_CONNECTIONS_H
#define NMC_CONNECTIONS_H

#include "nmcli.h"

NMCResultCode do_connections (NmCli *nmc, int argc, char **argv);

void monitor_connections (NmCli *nmc);

gboolean
nmc_read_connection_properties (NmCli *nmc,
                                NMConnection *connection,
                                int *argc,
                                char ***argv,
                                GError **error);

NMMetaColor nmc_active_connection_state_to_color (NMActiveConnectionState state);

int nmc_active_connection_cmp (NMActiveConnection *ac_a, NMActiveConnection *ac_b);

extern const NmcMetaGenericInfo *const metagen_con_show[];
extern const NmcMetaGenericInfo *const metagen_con_active_general[];
extern const NmcMetaGenericInfo *const metagen_con_active_vpn[];
extern const NmcMetaGenericInfo *const nmc_fields_con_active_details_groups[];

#endif /* NMC_CONNECTIONS_H */
