// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NMC_POLKIT_AGENT_H__
#define __NMC_POLKIT_AGENT_H__

#include "nmcli.h"

gboolean nmc_polkit_agent_init (NmCli *nmc, gboolean for_session, GError **error);
void nmc_polkit_agent_fini (NmCli* nmc);

gboolean nmc_start_polkit_agent_start_try (NmCli *nmc);

#endif /* __NMC_POLKIT_AGENT_H__ */
