/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2013 - 2015 Red Hat, Inc.
 */

#include "libnm-client-impl/nm-default-libnm.h"

#include "libnm-client-public/nm-conn-utils.h"

#include <net/if.h>

#include "libnmc-base/nm-client-utils.h"
#include "libnm-glib-aux/nm-io-utils.h"
#include "libnm-glib-aux/nm-secret-utils.h"
#include "nm-simple-connection.h"

/**
 * SECTION:nm-conn-utils
 * @short_description: Connection utilities
 *
 * Extra connection functionality.
 */

static gboolean
_wg_complete_peer(GPtrArray      **p_peers,
                  NMWireGuardPeer *peer_take,
                  gsize            peer_start_line_nr,
                  const char      *filename,
                  GError         **error)
{
    nm_auto_unref_wgpeer NMWireGuardPeer *peer  = peer_take;
    gs_free_error GError                 *local = NULL;

    if (!peer)
        return TRUE;

    if (!nm_wireguard_peer_is_valid(peer, TRUE, TRUE, &local)) {
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_UNKNOWN,
                           _("Invalid peer starting at %s:%zu: %s"),
                           filename,
                           peer_start_line_nr,
                           local->message);
        return FALSE;
    }

    if (!*p_peers)
        *p_peers = g_ptr_array_new_with_free_func((GDestroyNotify) nm_wireguard_peer_unref);
    g_ptr_array_add(*p_peers, g_steal_pointer(&peer));
    return TRUE;
}

static gboolean
_line_match(char *line, const char *key, gsize key_len, const char **out_key, char **out_value)
{
    nm_assert(line);
    nm_assert(key);
    nm_assert(strlen(key) == key_len);
    nm_assert(!strchr(key, '='));
    nm_assert(out_key && !*out_key);
    nm_assert(out_value && !*out_value);

    /* Note that `wg-quick` (linux.bash) does case-insensitive comparison (shopt -s nocasematch).
     * `wg setconf` does case-insensitive comparison too (with strncasecmp, which is locale dependent).
     *
     * We do a case-insensitive comparison of the key, however in a locale-independent manner. */

    if (g_ascii_strncasecmp(line, key, key_len) != 0)
        return FALSE;

    if (line[key_len] != '=')
        return FALSE;

    *out_key   = key;
    *out_value = &line[key_len + 1];
    return TRUE;
}

#define line_match(line, key, out_key, out_value) \
    _line_match((line), "" key "", NM_STRLEN(key), (out_key), (out_value))

static gboolean
value_split_word(char **line_remainder, char **out_word)
{
    char *str;

    if ((*line_remainder)[0] == '\0')
        return FALSE;

    *out_word = *line_remainder;

    str = strchrnul(*line_remainder, ',');
    if (str[0] == ',') {
        str[0]          = '\0';
        *line_remainder = &str[1];
    } else
        *line_remainder = str;
    return TRUE;
}

/**
 * nm_conn_wireguard_import:
 * @filename: name of the file to attempt to read into a new #NMConnection
 * @error: on return, an error or %NULL
 *
 * Returns: (transfer full): a new #NMConnection imported from @path, or %NULL
 * on error or if the file with @filename was not recognized as a WireGuard config
 *
 * Since: 1.40
 */
NMConnection *
nm_conn_wireguard_import(const char *filename, GError **error)
{
    nm_auto_clear_secret_ptr NMSecretPtr file_content = NM_SECRET_PTR_INIT();
    char                                 ifname[IFNAMSIZ];
    gs_free char                        *uuid         = NULL;
    gboolean                             ifname_valid = FALSE;
    const char                          *cstr;
    char                                *line_remainder;
    gs_unref_object NMConnection        *connection = NULL;
    NMSettingConnection                 *s_con;
    NMSettingIPConfig                   *s_ip4;
    NMSettingIPConfig                   *s_ip6;
    NMSettingWireGuard                  *s_wg;
    gs_free_error GError                *local = NULL;
    enum {
        LINE_CONTEXT_INIT,
        LINE_CONTEXT_INTERFACE,
        LINE_CONTEXT_PEER,
    } line_context;
    gsize                                 line_nr;
    gsize                                 current_peer_start_line_nr = 0;
    nm_auto_unref_wgpeer NMWireGuardPeer *current_peer               = NULL;
    gs_unref_ptrarray GPtrArray          *data_dns_search            = NULL;
    gs_unref_ptrarray GPtrArray          *data_dns_v4                = NULL;
    gs_unref_ptrarray GPtrArray          *data_dns_v6                = NULL;
    gs_unref_ptrarray GPtrArray          *data_addr_v4               = NULL;
    gs_unref_ptrarray GPtrArray          *data_addr_v6               = NULL;
    gs_unref_ptrarray GPtrArray          *data_peers                 = NULL;
    const char                           *data_private_key           = NULL;
    gint64                                data_table;
    guint                                 data_listen_port = 0;
    guint                                 data_fwmark      = 0;
    guint                                 data_mtu         = 0;
    int                                   is_v4;
    guint                                 i;

    g_return_val_if_fail(filename, NULL);
    g_return_val_if_fail(!error || !*error, NULL);

    /* contrary to "wg-quick", we never interpret the filename as "/etc/wireguard/$INTERFACE.conf".
     * If the filename has no '/', it is interpreted as relative to the current working directory.
     * However, we do require a suitable filename suffix and that the name corresponds to the interface
     * name. */
    cstr = strrchr(filename, '/');
    cstr = cstr ? &cstr[1] : filename;
    if (NM_STR_HAS_SUFFIX(cstr, ".conf")) {
        gsize len = strlen(cstr) - NM_STRLEN(".conf");

        if (len > 0 && len < sizeof(ifname)) {
            memcpy(ifname, cstr, len);
            ifname[len] = '\0';

            if (nm_utils_ifname_valid(ifname, NMU_IFACE_KERNEL, NULL))
                ifname_valid = TRUE;
        }
    }
    if (!ifname_valid) {
        nm_utils_error_set_literal(error,
                                   NM_UTILS_ERROR_UNKNOWN,
                                   _("The name of the WireGuard config must be a valid interface "
                                     "name followed by \".conf\""));
        return FALSE;
    }

    if (!nm_utils_file_get_contents(-1,
                                    filename,
                                    10 * 1024 * 1024,
                                    NM_UTILS_FILE_GET_CONTENTS_FLAG_SECRET,
                                    &file_content.str,
                                    &file_content.len,
                                    NULL,
                                    error)) {
        return NULL;
    }

    /* We interpret the file like `wg-quick up` and `wg setconf` do.
     *
     * Of course the WireGuard scripts do something fundamentlly different. They
     * perform actions to configure the WireGuard link in kernel, add routes and
     * addresses, and call resolvconf. It all happens at the time when the script
     * run.
     *
     * This code here instead generates a NetworkManager connection profile so that
     * NetworkManager will apply a similar configuration when later activating the profile. */

#define _TABLE_AUTO ((gint64) -1)
#define _TABLE_OFF  ((gint64) -2)

    data_table = _TABLE_AUTO;

    line_remainder = file_content.str;
    line_context   = LINE_CONTEXT_INIT;
    line_nr        = 0;
    while (line_remainder[0] != '\0') {
        const char *matched_key = NULL;
        char       *value       = NULL;
        char       *line;
        char        ch;
        gint64      i64;

        line_nr++;

        line           = line_remainder;
        line_remainder = strchrnul(line, '\n');
        if (line_remainder[0] != '\0')
            (line_remainder++)[0] = '\0';

        /* Drop all spaces and truncate at first '#'.
         * See wg's config_read_line().
         *
         * Note that wg-quick doesn't do that.
         *
         * Neither `wg setconf` nor `wg-quick` does a strict parsing.
         * We don't either. Just try to interpret the file (mostly) the same as
         * they would.
         */
        {
            gsize l, n;

            n = 0;
            for (l = 0; (ch = line[l]); l++) {
                if (g_ascii_isspace(ch)) {
                    /* wg-setconf strips all whitespace before parsing the content. That means,
                     * *[I nterface]" will be accepted. We do that too. */
                    continue;
                }
                if (ch == '#')
                    break;
                line[n++] = line[l];
            }
            if (n == 0)
                continue;
            line[n] = '\0';
        }

        if (g_ascii_strcasecmp(line, "[Interface]") == 0) {
            if (!_wg_complete_peer(&data_peers,
                                   g_steal_pointer(&current_peer),
                                   current_peer_start_line_nr,
                                   filename,
                                   error))
                return FALSE;
            line_context = LINE_CONTEXT_INTERFACE;
            continue;
        }

        if (g_ascii_strcasecmp(line, "[Peer]") == 0) {
            if (!_wg_complete_peer(&data_peers,
                                   g_steal_pointer(&current_peer),
                                   current_peer_start_line_nr,
                                   filename,
                                   error))
                return FALSE;
            current_peer_start_line_nr = line_nr;
            current_peer               = nm_wireguard_peer_new();
            line_context               = LINE_CONTEXT_PEER;
            continue;
        }

        if (line_context == LINE_CONTEXT_INTERFACE) {
            if (line_match(line, "Address", &matched_key, &value)) {
                char *value_word;

                while (value_split_word(&value, &value_word)) {
                    GPtrArray **p_data_addr;
                    NMIPAddr    addr_bin;
                    int         addr_family;
                    int         prefix_len;

                    if (!nm_inet_parse_with_prefix_bin(AF_UNSPEC,
                                                       value_word,
                                                       &addr_family,
                                                       &addr_bin,
                                                       &prefix_len))
                        goto fail_invalid_value;

                    p_data_addr = (addr_family == AF_INET) ? &data_addr_v4 : &data_addr_v6;

                    if (!*p_data_addr)
                        *p_data_addr =
                            g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_address_unref);

                    g_ptr_array_add(
                        *p_data_addr,
                        nm_ip_address_new_binary(
                            addr_family,
                            &addr_bin,
                            prefix_len == -1 ? ((addr_family == AF_INET) ? 32 : 128) : prefix_len,
                            NULL));
                }
                continue;
            }

            if (line_match(line, "MTU", &matched_key, &value)) {
                i64 = _nm_utils_ascii_str_to_int64(value, 0, 0, G_MAXUINT32, -1);
                if (i64 == -1)
                    goto fail_invalid_value;

                /* wg-quick accepts the "MTU" value, but it also fetches routes to
                 * autodetect it. NetworkManager won't do that, we can only configure
                 * an explicit MTU or no autodetection will be performed. */
                data_mtu = i64;
                continue;
            }

            if (line_match(line, "DNS", &matched_key, &value)) {
                char *value_word;

                while (value_split_word(&value, &value_word)) {
                    GPtrArray **p_data_dns;
                    NMIPAddr    addr_bin;
                    int         addr_family;

                    if (nm_inet_parse_bin(AF_UNSPEC, value_word, &addr_family, &addr_bin)) {
                        p_data_dns = (addr_family == AF_INET) ? &data_dns_v4 : &data_dns_v6;
                        if (!*p_data_dns)
                            *p_data_dns = g_ptr_array_new_with_free_func(g_free);

                        g_ptr_array_add(*p_data_dns, nm_inet_ntop_dup(addr_family, &addr_bin));
                        continue;
                    }

                    if (!data_dns_search)
                        data_dns_search = g_ptr_array_new_with_free_func(g_free);
                    g_ptr_array_add(data_dns_search, g_strdup(value_word));
                }
                continue;
            }

            if (line_match(line, "Table", &matched_key, &value)) {
                if (nm_streq(value, "auto"))
                    data_table = _TABLE_AUTO;
                else if (nm_streq(value, "off"))
                    data_table = _TABLE_OFF;
                else {
                    /* we don't support table names from /etc/iproute2/rt_tables
                     * But we accept hex like `ip route add` would. */
                    i64 = _nm_utils_ascii_str_to_int64(value, 0, 0, G_MAXINT32, -1);
                    if (i64 == -1)
                        goto fail_invalid_value;
                    data_table = i64;
                }
                continue;
            }

            if (line_match(line, "PreUp", &matched_key, &value)
                || line_match(line, "PreDown", &matched_key, &value)
                || line_match(line, "PostUp", &matched_key, &value)
                || line_match(line, "PostDown", &matched_key, &value)) {
                /* we don't run any scripts. Silently ignore these parameters. */
                continue;
            }

            if (line_match(line, "SaveConfig", &matched_key, &value)) {
                /* we ignore the setting, but enforce that it's either true or false (like
                 * wg-quick. */
                if (!NM_IN_STRSET(value, "true", "false"))
                    goto fail_invalid_value;
                continue;
            }

            if (line_match(line, "ListenPort", &matched_key, &value)) {
                /* we don't use getaddrinfo(), unlike `wg setconf`. Just interpret
                 * the port as plain decimal number. */
                i64 = _nm_utils_ascii_str_to_int64(value, 10, 0, 0xFFFF, -1);
                if (i64 == -1)
                    goto fail_invalid_value;
                data_listen_port = i64;
                continue;
            }

            if (line_match(line, "FwMark", &matched_key, &value)) {
                if (nm_streq(value, "off"))
                    data_fwmark = 0;
                else {
                    i64 = _nm_utils_ascii_str_to_int64(value, 0, 0, G_MAXINT32, -1);
                    if (i64 == -1)
                        goto fail_invalid_value;
                    data_fwmark = i64;
                }
                continue;
            }

            if (line_match(line, "PrivateKey", &matched_key, &value)) {
                if (!nm_utils_base64secret_decode(value, NM_WIREGUARD_PUBLIC_KEY_LEN, NULL))
                    goto fail_invalid_secret;
                data_private_key = value;
                continue;
            }

            goto fail_invalid_line;
        }

        if (line_context == LINE_CONTEXT_PEER) {
            if (line_match(line, "Endpoint", &matched_key, &value)) {
                if (!nm_wireguard_peer_set_endpoint(current_peer, value, FALSE))
                    goto fail_invalid_value;
                continue;
            }

            if (line_match(line, "PublicKey", &matched_key, &value)) {
                if (!nm_wireguard_peer_set_public_key(current_peer, value, FALSE))
                    goto fail_invalid_value;
                continue;
            }

            if (line_match(line, "AllowedIPs", &matched_key, &value)) {
                char *value_word;

                while (value_split_word(&value, &value_word)) {
                    if (!nm_wireguard_peer_append_allowed_ip(current_peer, value_word, FALSE))
                        goto fail_invalid_value;
                }
                continue;
            }

            if (line_match(line, "PersistentKeepalive", &matched_key, &value)) {
                if (nm_streq(value, "off"))
                    i64 = 0;
                else {
                    i64 = _nm_utils_ascii_str_to_int64(value, 10, 0, G_MAXUINT16, -1);
                    if (i64 == -1)
                        goto fail_invalid_value;
                }
                nm_wireguard_peer_set_persistent_keepalive(current_peer, i64);
                continue;
            }

            if (line_match(line, "PresharedKey", &matched_key, &value)) {
                if (!nm_wireguard_peer_set_preshared_key(current_peer, value, FALSE))
                    goto fail_invalid_secret;
                nm_wireguard_peer_set_preshared_key_flags(current_peer,
                                                          NM_SETTING_SECRET_FLAG_NONE);
                continue;
            }

            goto fail_invalid_line;
        }

fail_invalid_line:
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_INVALID_ARGUMENT,
                           _("unrecognized line at %s:%zu"),
                           filename,
                           line_nr);
        return FALSE;
fail_invalid_value:
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_INVALID_ARGUMENT,
                           _("invalid value for '%s' at %s:%zu"),
                           matched_key,
                           filename,
                           line_nr);
        return FALSE;
fail_invalid_secret:
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_INVALID_ARGUMENT,
                           _("invalid secret '%s' at %s:%zu"),
                           matched_key,
                           filename,
                           line_nr);
        return FALSE;
    }

    if (!_wg_complete_peer(&data_peers,
                           g_steal_pointer(&current_peer),
                           current_peer_start_line_nr,
                           filename,
                           error))
        return FALSE;

    connection = nm_simple_connection_new();
    s_con      = NM_SETTING_CONNECTION(nm_setting_connection_new());
    nm_connection_add_setting(connection, NM_SETTING(s_con));
    s_ip4 = NM_SETTING_IP_CONFIG(nm_setting_ip4_config_new());
    nm_connection_add_setting(connection, NM_SETTING(s_ip4));
    s_ip6 = NM_SETTING_IP_CONFIG(nm_setting_ip6_config_new());
    nm_connection_add_setting(connection, NM_SETTING(s_ip6));
    s_wg = NM_SETTING_WIREGUARD(nm_setting_wireguard_new());
    nm_connection_add_setting(connection, NM_SETTING(s_wg));

    uuid = nm_utils_uuid_generate();

    g_object_set(s_con,
                 NM_SETTING_CONNECTION_ID,
                 ifname,
                 NM_SETTING_CONNECTION_UUID,
                 uuid,
                 NM_SETTING_CONNECTION_TYPE,
                 NM_SETTING_WIREGUARD_SETTING_NAME,
                 NM_SETTING_CONNECTION_INTERFACE_NAME,
                 ifname,
                 NULL);

    g_object_set(s_wg,
                 NM_SETTING_WIREGUARD_PRIVATE_KEY,
                 data_private_key,
                 NM_SETTING_WIREGUARD_LISTEN_PORT,
                 data_listen_port,
                 NM_SETTING_WIREGUARD_FWMARK,
                 data_fwmark,
                 NM_SETTING_WIREGUARD_MTU,
                 data_mtu,
                 NULL);

    if (data_peers) {
        for (i = 0; i < data_peers->len; i++)
            nm_setting_wireguard_append_peer(s_wg, data_peers->pdata[i]);
    }

    for (is_v4 = 0; is_v4 < 2; is_v4++) {
        const char *method_disabled =
            is_v4 ? NM_SETTING_IP4_CONFIG_METHOD_DISABLED : NM_SETTING_IP6_CONFIG_METHOD_DISABLED;
        const char *method_manual =
            is_v4 ? NM_SETTING_IP4_CONFIG_METHOD_MANUAL : NM_SETTING_IP6_CONFIG_METHOD_MANUAL;
        NMSettingIPConfig *s_ip             = is_v4 ? s_ip4 : s_ip6;
        GPtrArray         *data_dns         = is_v4 ? data_dns_v4 : data_dns_v6;
        GPtrArray         *data_addr        = is_v4 ? data_addr_v4 : data_addr_v6;
        GPtrArray         *data_dns_search2 = data_dns_search;

        if (!data_addr) {
            /* When specifying "DNS", we also require an "Address" for the same address
             * family. That is because a NMSettingIPConfig cannot have @method_disabled
             * and DNS settings at the same time.
             *
             * We don't have addresses. Silently ignore the DNS setting. */
            data_dns         = NULL;
            data_dns_search2 = NULL;
        }

        g_object_set(s_ip,
                     NM_SETTING_IP_CONFIG_METHOD,
                     data_addr ? method_manual : method_disabled,
                     NULL);

        if (data_addr) {
            for (i = 0; i < data_addr->len; i++)
                nm_setting_ip_config_add_address(s_ip, data_addr->pdata[i]);
        }
        if (data_dns) {
            for (i = 0; i < data_dns->len; i++)
                nm_setting_ip_config_add_dns(s_ip, data_dns->pdata[i]);

            /* Of the wg-quick doesn't specify a search domain, assume the user
             * wants to use the domain server for all searches. */
            if (!data_dns_search2)
                nm_setting_ip_config_add_dns_search(s_ip, "~");
        }
        if (data_dns_search2) {
            for (i = 0; i < data_dns_search2->len; i++)
                nm_setting_ip_config_add_dns_search(s_ip, data_dns_search2->pdata[i]);
        }

        if (data_table == _TABLE_AUTO) {
            /* in the "auto" setting, wg-quick adds peer-routes automatically to the main
             * table. NetworkManager will do that too, but there are differences:
             *
             * - NetworkManager (contrary to wg-quick) does not check whether the peer-route is necessary.
             *   It will always add a route for each allowed-ips range, even if there is already another
             *   route that would ensure packets to the endpoint are routed via the WireGuard interface.
             *   If you don't want that, disable "wireguard.peer-routes", and add the necessary routes
             *   yourself to "ipv4.routes" and "ipv6.routes".
             *
             * - With "auto", wg-quick also configures policy routing to handle default-routes (/0) to
             *   avoid routing loops.
             *   The imported connection profile will have wireguard.ip4-auto-default-route and
             *   wireguard.ip6-auto-default-route set to "default". It will thus configure wg-quick's
             *   policy routing if the profile has any AllowedIPs ranges with /0.
             */
        } else if (data_table == _TABLE_OFF) {
            if (is_v4) {
                g_object_set(s_wg, NM_SETTING_WIREGUARD_PEER_ROUTES, FALSE, NULL);
            }
        } else {
            g_object_set(s_ip, NM_SETTING_IP_CONFIG_ROUTE_TABLE, (guint) data_table, NULL);
        }
    }

    if (!nm_connection_normalize(connection, NULL, NULL, &local)) {
        nm_utils_error_set(error,
                           NM_UTILS_ERROR_INVALID_ARGUMENT,
                           _("Failed to create WireGuard connection: %s"),
                           local->message);
        return FALSE;
    }

    return g_steal_pointer(&connection);
}
