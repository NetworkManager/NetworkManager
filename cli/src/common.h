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
 * (C) Copyright 2012 Red Hat, Inc.
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

gboolean print_ip4_config (NMIP4Config *cfg4, NmCli *nmc, const char *group_prefix);
gboolean print_ip6_config (NMIP6Config *cfg6, NmCli *nmc, const char *group_prefix);
gboolean print_dhcp4_config (NMDHCP4Config *dhcp4, NmCli *nmc, const char *group_prefix);
gboolean print_dhcp6_config (NMDHCP6Config *dhcp6, NmCli *nmc, const char *group_prefix);

const char * nmc_device_state_to_string (NMDeviceState state);
const char * nmc_device_reason_to_string (NMDeviceStateReason reason);

#endif /* NMC_COMMON_H */
