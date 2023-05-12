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
#include "nm-secret-agent-simple.h"
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
        return _VPN_PASSWORD_LIST({"gateway", N_("Gateway URL")},
                                  {"cookie", N_("Cookie")},
                                  {"gwcert", N_("Gateway certificate hash")},
                                  {"resolve", N_("Gateway DNS resolution ('host:IP')")}, );
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

#define NM_OPENCONNECT_KEY_GATEWAY              "gateway"
#define NM_OPENCONNECT_KEY_COOKIE               "cookie"
#define NM_OPENCONNECT_KEY_GWCERT               "gwcert"
#define NM_OPENCONNECT_KEY_RESOLVE              "resolve"
#define NM_OPENCONNECT_KEY_AUTHTYPE             "authtype"
#define NM_OPENCONNECT_KEY_USERCERT             "usercert"
#define NM_OPENCONNECT_KEY_CACERT               "cacert"
#define NM_OPENCONNECT_KEY_PRIVKEY              "userkey"
#define NM_OPENCONNECT_KEY_KEY_PASS             "key_pass"
#define NM_OPENCONNECT_KEY_MTU                  "mtu"
#define NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID  "pem_passphrase_fsid"
#define NM_OPENCONNECT_KEY_PREVENT_INVALID_CERT "prevent_invalid_cert"
#define NM_OPENCONNECT_KEY_DISABLE_UDP          "disable_udp"
#define NM_OPENCONNECT_KEY_PROTOCOL             "protocol"
#define NM_OPENCONNECT_KEY_PROXY                "proxy"
#define NM_OPENCONNECT_KEY_CSD_ENABLE           "enable_csd_trojan"
#define NM_OPENCONNECT_KEY_USERAGENT            "useragent"
#define NM_OPENCONNECT_KEY_CSD_WRAPPER          "csd_wrapper"
#define NM_OPENCONNECT_KEY_TOKEN_MODE           "stoken_source"
#define NM_OPENCONNECT_KEY_TOKEN_SECRET         "stoken_string"
#define NM_OPENCONNECT_KEY_REPORTED_OS          "reported_os"
#define NM_OPENCONNECT_KEY_MCACERT              "mcacert"
#define NM_OPENCONNECT_KEY_MCAKEY               "mcakey"
#define NM_OPENCONNECT_KEY_MCA_PASS             "mca_key_pass"

static const struct {
    const char *property;
    const char *cmdline;
} oc_property_args[] = {
    {NM_OPENCONNECT_KEY_USERCERT, "--certificate"},
    {NM_OPENCONNECT_KEY_CACERT, "--cafile"},
    {NM_OPENCONNECT_KEY_PRIVKEY, "--sslkey"},
    {NM_OPENCONNECT_KEY_KEY_PASS, "--key-password"},
    {NM_OPENCONNECT_KEY_PROTOCOL, "--protocol"},
    {NM_OPENCONNECT_KEY_PROXY, "--proxy"},
    {NM_OPENCONNECT_KEY_USERAGENT, "--useragent"},
    {NM_OPENCONNECT_KEY_REPORTED_OS, "--os"},
    {NM_OPENCONNECT_KEY_MCACERT, "--mca-certificate"},
    {NM_OPENCONNECT_KEY_MCAKEY, "--mca-key"},
    {NM_OPENCONNECT_KEY_MCA_PASS, "--mca-key-password"},
};

/*
 * For old versions of openconnect we need to extract the port# and
 * append it to the hostname that is returned to us. Use a cut-down
 * version of openconnect's own internal_parse_url() function.
 */
static int
extract_url_port(const char *url)
{
    const char *host, *port_str, *path;
    char       *end;
    int         port_nr;

    /* Skip the scheme, if present */
    host = strstr(url, "://");
    if (host)
        host += 3;
    else
        host = url;

    port_str = strrchr(host, ':');
    if (!port_str)
        return 0;

    /*
     * If the host is an IPv6 literal, port_str may point somewhere
     * inside it rather than to an actual port#. But IPv6 literals
     * are always enclosed in [], e.g. '[fec0::1]:443'. So we check
     * that the end pointer returned by strtol points exactly to the
     * end of the hostname (either the end of the string, or to the
     * first '/' of the path element if there is one).
     */
    path    = strchr(host, '/');
    port_nr = strtol(port_str + 1, &end, 10);

    if (end == path || (!path && !*end))
        return port_nr;

    return 0;
}

gboolean
nm_vpn_openconnect_authenticate_helper(NMSettingVpn *s_vpn, GPtrArray *secrets, GError **error)
{
    gs_free char        *output      = NULL;
    gs_free char        *legacy_host = NULL;
    gs_free char        *connect_url = NULL;
    gs_free char        *cookie      = NULL;
    gs_free char        *gwcert      = NULL;
    gs_free char        *resolve     = NULL;
    gs_free const char **output_v    = NULL;
    int                  status      = 0;
    const char *const   *iter;
    const char          *path;
    const char          *opt;
    const char *const    DEFAULT_PATHS[] = {
        "/sbin/",
        "/usr/sbin/",
        "/usr/local/sbin/",
        "/bin/",
        "/usr/bin/",
        "/usr/local/bin/",
        NULL,
    };
    const char *oc_argv[(12 + 2 * G_N_ELEMENTS(oc_property_args))];
    const char *gw;
    int         port;
    guint       oc_argc = 0;
    guint       i;

    /* Get gateway and port */
    gw = nm_setting_vpn_get_data_item(s_vpn, "gateway");
    if (!gw) {
        g_set_error(error,
                    NM_VPN_PLUGIN_ERROR,
                    NM_VPN_PLUGIN_ERROR_FAILED,
                    _("no gateway configured"));
        return FALSE;
    }

    port = extract_url_port(gw);

    path = nm_utils_file_search_in_paths("openconnect",
                                         "/usr/sbin/openconnect",
                                         DEFAULT_PATHS,
                                         G_FILE_TEST_IS_EXECUTABLE,
                                         NULL,
                                         NULL,
                                         error);
    if (!path)
        return FALSE;

    oc_argv[oc_argc++] = path;
    oc_argv[oc_argc++] = "--authenticate";
    oc_argv[oc_argc++] = gw;

    for (i = 0; i < G_N_ELEMENTS(oc_property_args); i++) {
        opt = nm_setting_vpn_get_data_item(s_vpn, oc_property_args[i].property);
        if (opt) {
            oc_argv[oc_argc++] = oc_property_args[i].cmdline;
            oc_argv[oc_argc++] = opt;
        }
    }

    opt = nm_setting_vpn_get_data_item(s_vpn, NM_OPENCONNECT_KEY_PEM_PASSPHRASE_FSID);
    if (opt && nm_streq(opt, "yes"))
        oc_argv[oc_argc++] = "--key-password-from-fsid";

    opt = nm_setting_vpn_get_data_item(s_vpn, NM_OPENCONNECT_KEY_CSD_ENABLE);
    if (opt && nm_streq(opt, "yes")) {
        opt = nm_setting_vpn_get_data_item(s_vpn, NM_OPENCONNECT_KEY_CSD_WRAPPER);
        if (opt) {
            oc_argv[oc_argc++] = "--csd-wrapper";
            oc_argv[oc_argc++] = opt;
        }
    }

    opt = nm_setting_vpn_get_data_item(s_vpn, NM_OPENCONNECT_KEY_TOKEN_MODE);
    if (opt) {
        const char *token_secret =
            nm_setting_vpn_get_data_item(s_vpn, NM_OPENCONNECT_KEY_TOKEN_SECRET);
        if (nm_streq(opt, "manual") && token_secret) {
            opt = "rsa";
        } else if (nm_streq(opt, "stokenrc")) {
            opt          = "rsa";
            token_secret = NULL;
        } else if (!nm_streq(opt, "totp") && !nm_streq(opt, "hotp") && !nm_streq(opt, "yubioath")) {
            opt = NULL;
        }
        if (opt) {
            oc_argv[oc_argc++] = "--token-mode";
            oc_argv[oc_argc++] = opt;
        }
        if (token_secret) {
            oc_argv[oc_argc++] = "--token-secret";
            oc_argv[oc_argc++] = token_secret;
        }
    }

    oc_argv[oc_argc++] = NULL;

    nm_assert(oc_argc <= G_N_ELEMENTS(oc_argv));

    if (!g_spawn_sync(NULL,
                      (char **) oc_argv,
                      NULL,
                      G_SPAWN_SEARCH_PATH | G_SPAWN_CHILD_INHERITS_STDIN,
                      NULL,
                      NULL,
                      &output,
                      NULL,
                      &status,
                      error))
        return FALSE;

    if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
        /* The caller will prepend "Error: openconnect failed: " to this */
        g_set_error(error,
                    NM_VPN_PLUGIN_ERROR,
                    NM_VPN_PLUGIN_ERROR_FAILED,
                    _("exited with status %d"),
                    WEXITSTATUS(status));
        return FALSE;
    } else if (WIFSIGNALED(status)) {
        g_set_error(error,
                    NM_VPN_PLUGIN_ERROR,
                    NM_VPN_PLUGIN_ERROR_FAILED,
                    _("exited on signal %d"),
                    WTERMSIG(status));
        return FALSE;
    }

    /* Parse output and set cookie, gateway and gwcert
     * output example:
     * COOKIE='loremipsum'
     * HOST='1.2.3.4'
     * FINGERPRINT='sha1:32bac90cf09a722e10ecc1942c67fe2ac8c21e2e'
     *
     * Since OpenConnect v8.20 (2022-02-20) OpenConnect has also passed e.g.:
     *
     * CONNECT_URL='https://vpn.example.com:8443/ConnectPath'
     * RESOLVE=vpn.example.com:1.2.3.4
     */
    output_v = nm_strsplit_set_with_empty(output, "\r\n");
    for (iter = output_v; iter && *iter; iter++) {
        char *s_mutable = (char *) *iter;

        _extract_variable_value(s_mutable, "COOKIE=", &cookie);
        _extract_variable_value(s_mutable, "CONNECT_URL=", &connect_url);
        _extract_variable_value(s_mutable, "HOST=", &legacy_host);
        _extract_variable_value(s_mutable, "FINGERPRINT=", &gwcert);
        _extract_variable_value(s_mutable, "RESOLVE=", &resolve);
    }

    if (!cookie || !gwcert || (!legacy_host && !connect_url)) {
        g_set_error(error,
                    NM_VPN_PLUGIN_ERROR,
                    NM_VPN_PLUGIN_ERROR_FAILED,
                    _("insufficent secrets returned"));
        return FALSE;
    }

    for (i = 0; i < secrets->len; i++) {
        NMSecretAgentSimpleSecret *secret = secrets->pdata[i];

        if (secret->secret_type != NM_SECRET_AGENT_SECRET_TYPE_VPN_SECRET)
            continue;
        if (!nm_streq0(secret->vpn_type, NM_SECRET_AGENT_VPN_TYPE_OPENCONNECT))
            continue;
        if (nm_streq0(secret->entry_id, NM_SECRET_AGENT_ENTRY_ID_PREFX_VPN_SECRETS "cookie")) {
            g_free(secret->value);
            secret->value = g_steal_pointer(&cookie);
        } else if (nm_streq0(secret->entry_id,
                             NM_SECRET_AGENT_ENTRY_ID_PREFX_VPN_SECRETS "gateway")) {
            g_free(secret->value);
            if (connect_url)
                secret->value = g_steal_pointer(&connect_url);
            else if (port)
                secret->value = g_strdup_printf("%s:%d", legacy_host, port);
            else
                secret->value = g_steal_pointer(&legacy_host);
        } else if (nm_streq0(secret->entry_id,
                             NM_SECRET_AGENT_ENTRY_ID_PREFX_VPN_SECRETS "gwcert")) {
            g_free(secret->value);
            secret->value = g_steal_pointer(&gwcert);
        } else if (nm_streq0(secret->entry_id,
                             NM_SECRET_AGENT_ENTRY_ID_PREFX_VPN_SECRETS "resolve")) {
            g_free(secret->value);
            secret->value = g_steal_pointer(&resolve);
        }
    }

    return TRUE;
}
