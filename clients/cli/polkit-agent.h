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
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef __NMC_POLKIT_AGENT_H__
#define __NMC_POLKIT_AGENT_H__

#include "nmcli.h"

gboolean nmc_polkit_agent_init (NmCli *nmc, gboolean for_session, GError **error);
void nmc_polkit_agent_fini (NmCli* nmc);

gboolean nmc_start_polkit_agent_start_try (NmCli *nmc);

#endif /* __NMC_POLKIT_AGENT_H__ */
