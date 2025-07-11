/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2016,2024 Red Hat, Inc.
 */

#ifndef __NM_VPN_PLUGIN_UTILS_H__
#define __NM_VPN_PLUGIN_UTILS_H__

#include <NetworkManager.h>

typedef NMVpnEditor *(NMVpnPluginUtilsEditorFactory) (gpointer           factory,
                                                      NMVpnEditorPlugin *editor_plugin,
                                                      NMConnection      *connection,
                                                      gpointer           user_data,
                                                      GError           **error);

char *nm_vpn_plugin_utils_get_editor_module_path(const char *module_name, GError **error);

NMVpnEditor *nm_vpn_plugin_utils_load_editor(const char                   *module_path,
                                             const char                   *factory_name,
                                             NMVpnPluginUtilsEditorFactory editor_factory,
                                             NMVpnEditorPlugin            *editor_plugin,
                                             NMConnection                 *connection,
                                             gpointer                      user_data,
                                             GError                      **error);

char *nm_vpn_plugin_utils_get_cert_path(const char *plugin);

#endif /* __NM_VPN_PLUGIN_UTILS_H__ */
