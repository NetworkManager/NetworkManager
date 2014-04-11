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
 * Copyright (C) 2010 Red Hat, Inc.
 */

#ifndef NM_DHCP_DHCLIENT_UTILS_H
#define NM_DHCP_DHCLIENT_UTILS_H

#include <glib.h>
#include <glib-object.h>

#include <nm-setting-ip4-config.h>
#include <nm-setting-ip6-config.h>

char *nm_dhcp_dhclient_create_config (const char *interface,
                                      gboolean is_ip6,
                                      const char *dhcp_client_id,
                                      GByteArray *anycast_addr,
                                      const char *hostname,
                                      const char *orig_path,
                                      const char *orig_contents);

char *nm_dhcp_dhclient_escape_duid (const GByteArray *duid);

GByteArray *nm_dhcp_dhclient_unescape_duid (const char *duid);

GByteArray *nm_dhcp_dhclient_read_duid (const char *leasefile, GError **error);

gboolean nm_dhcp_dhclient_save_duid (const char *leasefile,
                                     const char *escaped_duid,
                                     GError **error);

GSList *nm_dhcp_dhclient_read_lease_ip_configs (const char *iface,
                                                const char *contents,
                                                gboolean ipv6,
                                                GDateTime *now);

#endif /* NM_DHCP_DHCLIENT_UTILS_H */

