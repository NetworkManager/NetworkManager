// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2010 - 2014 Red Hat, Inc.
 */

#ifndef NMC_GENERAL_H
#define NMC_GENERAL_H

#include "nmcli.h"

NMCResultCode do_general    (NmCli *nmc, int argc, char **argv);
NMCResultCode do_networking (NmCli *nmc, int argc, char **argv);
NMCResultCode do_radio      (NmCli *nmc, int argc, char **argv);
NMCResultCode do_monitor    (NmCli *nmc, int argc, char **argv);
NMCResultCode do_overview   (NmCli *nmc, int argc, char **argv);

#endif /* NMC_GENERAL_H */
