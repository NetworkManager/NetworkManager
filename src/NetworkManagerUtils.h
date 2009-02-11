/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2004 - 2008 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#ifndef NETWORK_MANAGER_UTILS_H
#define NETWORK_MANAGER_UTILS_H

#include <glib.h>
#include <stdio.h>
#include <net/ethernet.h>

#include "nm-device.h"
#include "nm-ip4-config.h"
#include "nm-setting-ip4-config.h"
#include "nm-connection.h"

gboolean nm_ethernet_address_is_valid (const struct ether_addr *test_addr);

int nm_spawn_process (const char *args);

void nm_print_device_capabilities (NMDevice *dev);

char *nm_utils_hexstr2bin (const char *hex, size_t len);

char *nm_ether_ntop (const struct ether_addr *mac);

void nm_utils_merge_ip4_config (NMIP4Config *ip4_config, NMSettingIP4Config *setting);

void nm_utils_call_dispatcher (const char *action,
                               NMConnection *connection,
                               NMDevice *device,
                               const char *vpn_iface);

#endif

