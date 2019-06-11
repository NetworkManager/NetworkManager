/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 - 2015 Red Hat, Inc.
 */

#ifndef __NM_VPN_HELPERS_H__
#define __NM_VPN_HELPERS_H__

typedef struct {
	const char *name;
	const char *ui_name;
} VpnPasswordName;

GSList *nm_vpn_get_plugin_infos (void);

NMVpnEditorPlugin *nm_vpn_get_editor_plugin (const char *service_type, GError **error);

gboolean nm_vpn_supports_ipv6 (NMConnection *connection);

const VpnPasswordName * nm_vpn_get_secret_names (const char *service_type);

gboolean nm_vpn_openconnect_authenticate_helper (const char *host,
                                                 char **cookie,
                                                 char **gateway,
                                                 char **gwcert,
                                                 int *status,
                                                 GError **error);

NMConnection *nm_vpn_wireguard_import (const char *filename,
                                       GError **error);

#endif  /* __NM_VPN_HELPERS_H__ */
