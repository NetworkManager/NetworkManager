// SPDX-License-Identifier: GPL-2.0+
/* nmcli - command-line tool to control NetworkManager
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
