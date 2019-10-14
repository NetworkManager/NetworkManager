// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 - 2015 Red Hat, Inc.
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
