/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef NM_DHCP_UTILS_H
#define NM_DHCP_UTILS_H

#include <stdlib.h>
#include <glib.h>
#include <nm-ip4-config.h>
#include <nm-ip6-config.h>

NMIP4Config *nm_dhcp_utils_ip4_config_from_options (const char *iface,
                                                    GHashTable *options,
                                                    guint priority);

NMIP6Config *nm_dhcp_utils_ip6_config_from_options (const char *iface,
                                                    GHashTable *options,
                                                    guint priority,
                                                    gboolean info_only);

#endif /* NM_DHCP_UTILS_H */

