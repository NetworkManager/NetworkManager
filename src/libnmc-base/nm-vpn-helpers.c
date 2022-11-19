/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 - 2015 Red Hat, Inc.
 */

/**
 * SECTION:nm-vpn-helpers
 * @short_description: VPN-related utilities
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nm-vpn-helpers.h"

#include <arpa/inet.h>
#include <net/if.h>

#include "nm-client-utils.h"
#include "nm-utils.h"
#include "libnm-glib-aux/nm-io-utils.h"
#include "libnm-glib-aux/nm-secret-utils.h"

/*****************************************************************************/

NMVpnEditorPlugin *
nm_vpn_get_editor_plugin(const char *service_type, GError **error)
{
    NMVpnEditorPlugin    *plugin = NULL;
    NMVpnPluginInfo      *plugin_info;
    gs_free_error GError *local = NULL;

    g_return_val_if_fail(service_type, NULL);
    g_return_val_if_fail(error == NULL || *error == NULL, NULL);

    plugin_info = nm_vpn_plugin_info_list_find_by_service(nm_vpn_get_plugin_infos(), service_type);

    if (!plugin_info) {
        g_set_error(error,
                    NM_VPN_PLUGIN_ERROR,
                    NM_VPN_PLUGIN_ERROR_FAILED,
                    _("unknown VPN plugin \"%s\""),
                    service_type);
        return NULL;
    }
    plugin = nm_vpn_plugin_info_get_editor_plugin(plugin_info);
    if (!plugin)
        plugin = nm_vpn_plugin_info_load_editor_plugin(plugin_info, &local);

    if (!plugin) {
        if (!nm_vpn_plugin_info_get_plugin(plugin_info)
            && nm_vpn_plugin_info_lookup_property(plugin_info,
                                                  NM_VPN_PLUGIN_INFO_KF_GROUP_GNOME,
                                                  "properties")) {
            g_set_error(error,
                        NM_VPN_PLUGIN_ERROR,
                        NM_VPN_PLUGIN_ERROR_FAILED,
                        _("cannot load legacy-only VPN plugin \"%s\" for \"%s\""),
                        nm_vpn_plugin_info_get_name(plugin_info),
                        nm_vpn_plugin_info_get_filename(plugin_info));
        } else if (g_error_matches(local, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
            g_set_error(
                error,
                NM_VPN_PLUGIN_ERROR,
                NM_VPN_PLUGIN_ERROR_FAILED,
                _("cannot load VPN plugin \"%s\" due to missing \"%s\". Missing client plugin?"),
                nm_vpn_plugin_info_get_name(plugin_info),
                nm_vpn_plugin_info_get_plugin(plugin_info));
        } else {
            g_set_error(error,
                        NM_VPN_PLUGIN_ERROR,
                        NM_VPN_PLUGIN_ERROR_FAILED,
                        _("failed to load VPN plugin \"%s\": %s"),
                        nm_vpn_plugin_info_get_name(plugin_info),
                        local->message);
        }
        return NULL;
    }

    return plugin;
}

GSList *
nm_vpn_get_plugin_infos(void)
{
    static bool    plugins_loaded;
    static GSList *plugins = NULL;

    if (G_LIKELY(plugins_loaded))
        return plugins;
    plugins_loaded = TRUE;
    plugins        = nm_vpn_plugin_info_list_load();
    return plugins;
}

gboolean
nm_vpn_supports_ipv6(NMConnection *connection)
{
    NMSettingVpn      *s_vpn;
    const char        *service_type;
    NMVpnEditorPlugin *plugin;
    guint32            capabilities;

    s_vpn = nm_connection_get_setting_vpn(connection);
    g_return_val_if_fail(s_vpn != NULL, FALSE);

    service_type = nm_setting_vpn_get_service_type(s_vpn);
    if (!service_type)
        return FALSE;

    plugin = nm_vpn_get_editor_plugin(service_type, NULL);
    if (!plugin)
        return FALSE;

    capabilities = nm_vpn_editor_plugin_get_capabilities(plugin);
    return NM_FLAGS_HAS(capabilities, NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6);
}

const NmcVpnPasswordName *
nm_vpn_get_secret_names(const char *service_type)
{
    const char *type;

    if (!service_type)
        return NULL;

    if (!NM_STR_HAS_PREFIX(service_type, NM_DBUS_INTERFACE)
        || service_type[NM_STRLEN(NM_DBUS_INTERFACE)] != '.') {
        /* all our well-known, hard-coded vpn-types start with NM_DBUS_INTERFACE. */
        return NULL;
    }

    type = service_type + (NM_STRLEN(NM_DBUS_INTERFACE) + 1);

#define _VPN_PASSWORD_LIST(...)                    \
    ({                                             \
        static const NmcVpnPasswordName _arr[] = { \
            __VA_ARGS__{0},                        \
        };                                         \
        _arr;                                      \
    })

    if (NM_IN_STRSET(type, "pptp", "iodine", "ssh", "l2tp", "fortisslvpn")) {
        return _VPN_PASSWORD_LIST({"password", N_("Password")}, );
    }

    if (NM_IN_STRSET(type, "openvpn")) {
        return _VPN_PASSWORD_LIST({"password", N_("Password")},
                                  {"cert-pass", N_("Certificate password")},
                                  {"http-proxy-password", N_("HTTP proxy password")}, );
    }

    if (NM_IN_STRSET(type, "vpnc")) {
        return _VPN_PASSWORD_LIST({"Xauth password", N_("Password")},
                                  {"IPSec secret", N_("Group password")}, );
    };

    if (NM_IN_STRSET(type, "openswan", "libreswan", "strongswan")) {
        return _VPN_PASSWORD_LIST({"xauthpassword", N_("Password")},
                                  {"pskvalue", N_("Group password")}, );
    };

    if (NM_IN_STRSET(type, "openconnect")) {
        return _VPN_PASSWORD_LIST({"gateway", N_("Gateway")},
                                  {"cookie", N_("Cookie")},
                                  {"gwcert", N_("Gateway certificate hash")}, );
    };

    return NULL;
}

static gboolean
_extract_variable_value(char *line, const char *tag, char **value)
{
    char *p1, *p2;

    if (!g_str_has_prefix(line, tag))
        return FALSE;

    p1 = line + strlen(tag);
    p2 = line + strlen(line) - 1;
    if ((*p1 == '\'' || *p1 == '"') && (*p1 == *p2)) {
        p1++;
        *p2 = '\0';
    }
    NM_SET_OUT(value, g_strdup(p1));
    return TRUE;
}

gboolean
nm_vpn_openconnect_authenticate_helper(const char *host,
                                       char      **cookie,
                                       char      **gateway,
                                       char      **gwcert,
                                       int        *status,
                                       GError    **error)
{
    gs_free char        *output   = NULL;
    gs_free const char **output_v = NULL;
    const char *const   *iter;
    const char          *path;
    const char *const    DEFAULT_PATHS[] = {
        "/sbin/",
        "/usr/sbin/",
        "/usr/local/sbin/",
        "/bin/",
        "/usr/bin/",
        "/usr/local/bin/",
        NULL,
    };

    path = nm_utils_file_search_in_paths("openconnect",
                                         "/usr/sbin/openconnect",
                                         DEFAULT_PATHS,
                                         G_FILE_TEST_IS_EXECUTABLE,
                                         NULL,
                                         NULL,
                                         error);
    if (!path)
        return FALSE;

    if (!g_spawn_sync(NULL,
                      (char **) NM_MAKE_STRV(path, "--authenticate", host),
                      NULL,
                      G_SPAWN_SEARCH_PATH | G_SPAWN_CHILD_INHERITS_STDIN,
                      NULL,
                      NULL,
                      &output,
                      NULL,
                      status,
                      error))
        return FALSE;

    /* Parse output and set cookie, gateway and gwcert
     * output example:
     * COOKIE='loremipsum'
     * HOST='1.2.3.4'
     * FINGERPRINT='sha1:32bac90cf09a722e10ecc1942c67fe2ac8c21e2e'
     */
    output_v = nm_strsplit_set_with_empty(output, "\r\n");
    for (iter = output_v; iter && *iter; iter++) {
        char *s_mutable = (char *) *iter;

        _extract_variable_value(s_mutable, "COOKIE=", cookie);
        _extract_variable_value(s_mutable, "HOST=", gateway);
        _extract_variable_value(s_mutable, "FINGERPRINT=", gwcert);
    }

    return TRUE;
}
