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

#ifndef __NETWORKMANAGER_DHCP_DHCLIENT_UTILS_H__
#define __NETWORKMANAGER_DHCP_DHCLIENT_UTILS_H__

#include "nm-setting-ip4-config.h"
#include "nm-setting-ip6-config.h"

char *nm_dhcp_dhclient_create_config (const char *interface,
                                      int addr_family,
                                      GBytes *client_id,
                                      const char *anycast_addr,
                                      const char *hostname,
                                      guint32 timeout,
                                      gboolean use_fqdn,
                                      const char *orig_path,
                                      const char *orig_contents,
                                      GBytes **out_new_client_id);

char *nm_dhcp_dhclient_escape_duid (GBytes *duid);

GBytes *nm_dhcp_dhclient_unescape_duid (const char *duid);

GBytes *nm_dhcp_dhclient_read_duid (const char *leasefile, GError **error);

gboolean nm_dhcp_dhclient_save_duid (const char *leasefile,
                                     GBytes *duid,
                                     GError **error);

#endif /* __NETWORKMANAGER_DHCP_DHCLIENT_UTILS_H__ */
