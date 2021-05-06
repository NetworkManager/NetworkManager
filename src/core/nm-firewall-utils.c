/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2016 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-firewall-utils.h"

#include "libnm-glib-aux/nm-str-buf.h"
#include "libnm-platform/nm-platform.h"

#include "nm-config.h"

/*****************************************************************************/

static const struct {
    const char *name;
    const char *path;
} FirewallBackends[] = {
    [NM_FIREWALL_BACKEND_NFTABLES - 1] =
        {
            .name = "nftables",
            .path = NFT_PATH,
        },
    [NM_FIREWALL_BACKEND_IPTABLES - 1] =
        {
            .name = "iptables",
            .path = IPTABLES_PATH,
        },
};

/*****************************************************************************/

#define _SHARE_IPTABLES_SUBNET_TO_STR_LEN (INET_ADDRSTRLEN + 1 + 2 + 1)

static const char *
_share_iptables_subnet_to_str(char      buf[static _SHARE_IPTABLES_SUBNET_TO_STR_LEN],
                              in_addr_t addr,
                              guint8    plen)
{
    char      buf_addr[INET_ADDRSTRLEN];
    in_addr_t netmask;
    int       l;

    netmask = _nm_utils_ip4_prefix_to_netmask(plen);

    l = g_snprintf(buf,
                   _SHARE_IPTABLES_SUBNET_TO_STR_LEN,
                   "%s/%u",
                   _nm_utils_inet4_ntop(addr & netmask, buf_addr),
                   plen);
    nm_assert(l < _SHARE_IPTABLES_SUBNET_TO_STR_LEN);
    return buf;
}

static char *
_share_iptables_get_name(gboolean is_iptables_chain, const char *prefix, const char *ip_iface)
{
    NMStrBuf strbuf = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_40, FALSE);
    gsize    ip_iface_len;

    nm_assert(prefix);
    nm_assert(ip_iface);

    /* This function is used to generate iptables chain names and comments.
     * Chain names must be shorter than 29 chars. Comments don't have this
     * limitation.
     *
     * Below we sanitize the ip_iface. If it's all benign, we use
     * - either "-$IP_IFACE" (at most 16 chars)
     * - otherwise, we base64 encode the name as "$(base64 $IP_IFACE)", at
     *   most 20 chars.
     *
     * Since for benign names we already add a '-', prefix probably should not
     * contain a '-'. The '-' is necessary to distinguish between base64 encoding
     * an plain name.
     *
     * That means, for chain names the prefix must be at most 8 chars long. */
    nm_assert(!is_iptables_chain || (strlen(prefix) <= 8));

    nm_str_buf_append(&strbuf, prefix);

    ip_iface_len = strlen(ip_iface);
    G_STATIC_ASSERT_EXPR(NMP_IFNAMSIZ == 16);
    if (ip_iface_len >= NMP_IFNAMSIZ) {
        nm_assert_not_reached();
        ip_iface_len = NMP_IFNAMSIZ - 1;
    }

    if (NM_STRCHAR_ALL(ip_iface,
                       ch,
                       (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'z')
                           || (ch >= 'A' && ch <= 'Z') || NM_IN_SET(ch, '.', '_', '-', '+'))) {
        nm_str_buf_append_c(&strbuf, '-');
        nm_str_buf_append(&strbuf, ip_iface);
    } else {
        gs_free char *s = NULL;

        s = g_base64_encode((const guchar *) ip_iface, ip_iface_len);
        nm_str_buf_append(&strbuf, s);
    }

    return nm_str_buf_finalize(&strbuf, NULL);
}

static gboolean
_share_iptables_call_v(const char *const *argv)
{
    gs_free_error GError *error    = NULL;
    gs_free char *        argv_str = NULL;
    int                   status;

    nm_log_dbg(LOGD_SHARING, "iptables: %s", (argv_str = g_strjoinv(" ", (char **) argv)));

    if (!g_spawn_sync("/",
                      (char **) argv,
                      (char **) NM_PTRARRAY_EMPTY(const char *),
                      G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
                      NULL,
                      NULL,
                      NULL,
                      NULL,
                      &status,
                      &error)) {
        nm_log_warn(LOGD_SHARING,
                    "iptables: error executing command %s: %s",
                    argv[0],
                    error->message);
        return FALSE;
    }

    if (!g_spawn_check_exit_status(status, &error)) {
        nm_log_warn(LOGD_SHARING, "iptables: command %s failed: %s", argv[0], error->message);
        return FALSE;
    }

    return TRUE;
}

#define _share_iptables_call(...) _share_iptables_call_v(NM_MAKE_STRV(__VA_ARGS__))

static gboolean
_share_iptables_chain_op(const char *table, const char *chain, const char *op)
{
    return _share_iptables_call("" IPTABLES_PATH "", "--table", table, op, chain);
}

static gboolean
_share_iptables_chain_delete(const char *table, const char *chain)
{
    _share_iptables_chain_op(table, chain, "--flush");
    return _share_iptables_chain_op(table, chain, "--delete-chain");
}

static gboolean
_share_iptables_chain_add(const char *table, const char *chain)
{
    if (_share_iptables_chain_op(table, chain, "--new-chain"))
        return TRUE;

    _share_iptables_chain_delete(table, chain);
    return _share_iptables_chain_op(table, chain, "--new-chain");
}

static void
_share_iptables_set_masquerade(gboolean add, const char *ip_iface, in_addr_t addr, guint8 plen)
{
    char          str_subnet[_SHARE_IPTABLES_SUBNET_TO_STR_LEN];
    gs_free char *comment_name = NULL;

    comment_name = _share_iptables_get_name(FALSE, "nm-shared", ip_iface);

    _share_iptables_subnet_to_str(str_subnet, addr, plen);
    _share_iptables_call("" IPTABLES_PATH "",
                         "--table",
                         "nat",
                         add ? "--insert" : "--delete",
                         "POSTROUTING",
                         "--source",
                         str_subnet,
                         "!",
                         "--destination",
                         str_subnet,
                         "--jump",
                         "MASQUERADE",
                         "-m",
                         "comment",
                         "--comment",
                         comment_name);
}

static void
_share_iptables_set_shared_chains_add(const char *chain_input,
                                      const char *chain_forward,
                                      const char *ip_iface,
                                      in_addr_t   addr,
                                      guint       plen)
{
    const char *const input_params[][2] = {
        {
            "tcp",
            "67",
        },
        {
            "udp",
            "67",
        },
        {
            "tcp",
            "53",
        },
        {
            "udp",
            "53",
        },
    };
    char str_subnet[_SHARE_IPTABLES_SUBNET_TO_STR_LEN];
    int  i;

    _share_iptables_subnet_to_str(str_subnet, addr, plen);

    _share_iptables_chain_add("filter", chain_input);

    for (i = 0; i < (int) G_N_ELEMENTS(input_params); i++) {
        _share_iptables_call("" IPTABLES_PATH "",
                             "--table",
                             "filter",
                             "--append",
                             chain_input,
                             "--protocol",
                             input_params[i][0],
                             "--destination-port",
                             input_params[i][1],
                             "--jump",
                             "ACCEPT");
    }

    _share_iptables_chain_add("filter", chain_forward);

    _share_iptables_call("" IPTABLES_PATH "",
                         "--table",
                         "filter",
                         "--append",
                         chain_forward,
                         "--destination",
                         str_subnet,
                         "--out-interface",
                         ip_iface,
                         "--match",
                         "state",
                         "--state",
                         "ESTABLISHED,RELATED",
                         "--jump",
                         "ACCEPT");
    _share_iptables_call("" IPTABLES_PATH "",
                         "--table",
                         "filter",
                         "--append",
                         chain_forward,
                         "--source",
                         str_subnet,
                         "--in-interface",
                         ip_iface,
                         "--jump",
                         "ACCEPT");
    _share_iptables_call("" IPTABLES_PATH "",
                         "--table",
                         "filter",
                         "--append",
                         chain_forward,
                         "--in-interface",
                         ip_iface,
                         "--out-interface",
                         ip_iface,
                         "--jump",
                         "ACCEPT");
    _share_iptables_call("" IPTABLES_PATH "",
                         "--table",
                         "filter",
                         "--append",
                         chain_forward,
                         "--out-interface",
                         ip_iface,
                         "--jump",
                         "REJECT");
    _share_iptables_call("" IPTABLES_PATH "",
                         "--table",
                         "filter",
                         "--append",
                         chain_forward,
                         "--in-interface",
                         ip_iface,
                         "--jump",
                         "REJECT");
}

static void
_share_iptables_set_shared_chains_delete(const char *chain_input, const char *chain_forward)
{
    _share_iptables_chain_delete("filter", chain_input);
    _share_iptables_chain_delete("filter", chain_forward);
}

_nm_unused static void
_share_iptables_set_shared(gboolean add, const char *ip_iface, in_addr_t addr, guint plen)
{
    gs_free char *comment_name  = NULL;
    gs_free char *chain_input   = NULL;
    gs_free char *chain_forward = NULL;

    comment_name  = _share_iptables_get_name(FALSE, "nm-shared", ip_iface);
    chain_input   = _share_iptables_get_name(TRUE, "nm-sh-in", ip_iface);
    chain_forward = _share_iptables_get_name(TRUE, "nm-sh-fw", ip_iface);

    if (add)
        _share_iptables_set_shared_chains_add(chain_input, chain_forward, ip_iface, addr, plen);

    _share_iptables_call("" IPTABLES_PATH "",
                         "--table",
                         "filter",
                         add ? "--insert" : "--delete",
                         "INPUT",
                         "--in-interface",
                         ip_iface,
                         "--jump",
                         chain_input,
                         "-m",
                         "comment",
                         "--comment",
                         comment_name);

    _share_iptables_call("" IPTABLES_PATH "",
                         "--table",
                         "filter",
                         add ? "--insert" : "--delete",
                         "FORWARD",
                         "--jump",
                         chain_forward,
                         "-m",
                         "comment",
                         "--comment",
                         comment_name);

    if (!add)
        _share_iptables_set_shared_chains_delete(chain_input, chain_forward);
}

/*****************************************************************************/

struct _NMFirewallConfig {
    char *    ip_iface;
    in_addr_t addr;
    guint8    plen;
};

NMFirewallConfig *
nm_firewall_config_new(const char *ip_iface, in_addr_t addr, guint8 plen)
{
    NMFirewallConfig *self;

    nm_assert(ip_iface);
    nm_assert(addr != 0u);
    nm_assert(plen <= 32);

    self  = g_slice_new(NMFirewallConfig);
    *self = (NMFirewallConfig){
        .ip_iface = g_strdup(ip_iface),
        .addr     = addr,
        .plen     = plen,
    };
    return self;
}

void
nm_firewall_config_free(NMFirewallConfig *self)
{
    if (!self)
        return;

    g_free(self->ip_iface);
    nm_g_slice_free(self);
}

void
nm_firewall_config_apply(NMFirewallConfig *self, gboolean shared)
{
    _share_iptables_set_masquerade(shared, self->ip_iface, self->addr, self->plen);
    _share_iptables_set_shared(shared, self->ip_iface, self->addr, self->plen);
}

/*****************************************************************************/

static NMFirewallBackend
_firewall_backend_detect(void)
{
    if (g_file_test(NFT_PATH, G_FILE_TEST_IS_EXECUTABLE))
        return NM_FIREWALL_BACKEND_NFTABLES;
    if (g_file_test(IPTABLES_PATH, G_FILE_TEST_IS_EXECUTABLE))
        return NM_FIREWALL_BACKEND_IPTABLES;

    return NM_FIREWALL_BACKEND_NFTABLES;
}

NMFirewallBackend
nm_firewall_utils_get_backend(void)
{
    static int backend = NM_FIREWALL_BACKEND_UNKNOWN;
    int        b;

again:
    b = g_atomic_int_get(&backend);
    if (b == NM_FIREWALL_BACKEND_UNKNOWN) {
        gs_free char *conf_value = NULL;
        gboolean      detect;
        int           i;

        conf_value =
            nm_config_data_get_value(NM_CONFIG_GET_DATA_ORIG,
                                     NM_CONFIG_KEYFILE_GROUP_MAIN,
                                     NM_CONFIG_KEYFILE_KEY_MAIN_FIREWALL_BACKEND,
                                     NM_CONFIG_GET_VALUE_STRIP | NM_CONFIG_GET_VALUE_NO_EMPTY);

        if (conf_value) {
            for (i = 0; i < (int) G_N_ELEMENTS(FirewallBackends); i++) {
                if (!g_ascii_strcasecmp(conf_value, FirewallBackends[i].name)) {
                    b = (i + 1);
                    break;
                }
            }
        }

        detect = (b == NM_FIREWALL_BACKEND_UNKNOWN);
        if (detect)
            b = _firewall_backend_detect();

        nm_assert(NM_IN_SET(b, NM_FIREWALL_BACKEND_IPTABLES, NM_FIREWALL_BACKEND_NFTABLES));

        if (b == NM_FIREWALL_BACKEND_NFTABLES) {
            if (!detect)
                nm_log_warn(LOGD_SHARING,
                            "firewall: backend \"nftables\" is not yet implemented. Fallback to "
                            "\"iptables\"");
            nm_clear_g_free(&conf_value);
            b = NM_FIREWALL_BACKEND_IPTABLES;
        }

        if (!g_atomic_int_compare_and_exchange(&backend, NM_FIREWALL_BACKEND_UNKNOWN, b))
            goto again;

        nm_log_dbg(LOGD_SHARING,
                   "firewall: use %s backend (%s)%s%s%s%s",
                   FirewallBackends[b - 1].name,
                   FirewallBackends[b - 1].path,
                   detect ? " (detected)" : "",
                   NM_PRINT_FMT_QUOTED(detect && conf_value,
                                       " (invalid setting \"",
                                       conf_value,
                                       "\")",
                                       ""));
    }

    nm_assert(NM_IN_SET(b, NM_FIREWALL_BACKEND_IPTABLES, NM_FIREWALL_BACKEND_NFTABLES));
    return b;
}
