/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2004 - 2016 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include "nm-firewall-utils.h"

#include "libnm-glib-aux/nm-str-buf.h"
#include "libnm-glib-aux/nm-io-utils.h"
#include "libnm-platform/nm-platform.h"

#include "nm-config.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

static const struct {
    const char *name;
    const char *path;
} FirewallBackends[] = {
    [NM_FIREWALL_BACKEND_NONE - 1] =
        {
            .name = "none",
        },
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

typedef struct {
    GTask *       task;
    GSubprocess * subprocess;
    GSource *     timeout_source;
    GCancellable *intern_cancellable;
    char *        identifier;
    gulong        cancellable_id;
} FwNftCallData;

static void
_fw_nft_call_data_free(FwNftCallData *call_data, GError *error_take)
{
    nm_clear_g_signal_handler(g_task_get_cancellable(call_data->task), &call_data->cancellable_id);
    nm_clear_g_cancellable(&call_data->intern_cancellable);
    nm_clear_g_source_inst(&call_data->timeout_source);

    if (error_take)
        g_task_return_error(call_data->task, error_take);
    else
        g_task_return_boolean(call_data->task, TRUE);

    g_object_unref(call_data->task);
    nm_g_object_unref(call_data->subprocess);
    g_free(call_data->identifier);

    nm_g_slice_free(call_data);
}

static void
_fw_nft_call_communicate_cb(GObject *source, GAsyncResult *result, gpointer user_data)
{
    FwNftCallData *call_data          = user_data;
    gs_free_error GError *error       = NULL;
    gs_unref_bytes GBytes *stdout_buf = NULL;
    gs_unref_bytes GBytes *stderr_buf = NULL;

    nm_assert(source == (gpointer) call_data->subprocess);

    if (!g_subprocess_communicate_finish(G_SUBPROCESS(source),
                                         result,
                                         &stdout_buf,
                                         &stderr_buf,
                                         &error)) {
        /* on any error, the process might still be running. We need to abort it in
         * the background... */
        if (!nm_utils_error_is_cancelled(error)) {
            nm_log_dbg(LOGD_SHARING,
                       "firewall: nft[%s]: communication failed: %s. Kill process",
                       call_data->identifier,
                       error->message);
        } else if (!call_data->timeout_source) {
            nm_log_dbg(LOGD_SHARING,
                       "firewall: ntf[%s]: communication timed out. Kill process",
                       call_data->identifier);
            nm_clear_error(&error);
            nm_utils_error_set(&error, NM_UTILS_ERROR_UNKNOWN, "timeout communicating with nft");
        } else {
            nm_log_dbg(LOGD_SHARING,
                       "firewall: ntf[%s]: communication cancelled. Kill process",
                       call_data->identifier);
        }

        {
            _nm_unused nm_auto_pop_gmaincontext GMainContext *main_context =
                nm_g_main_context_push_thread_default_if_necessary(NULL);

            nm_shutdown_wait_obj_register_object(call_data->subprocess, "nft-terminate");
            G_STATIC_ASSERT_EXPR(200 < NM_SHUTDOWN_TIMEOUT_MS_WATCHDOG * 2 / 3);
            nm_g_subprocess_terminate_in_background(call_data->subprocess, 200);
        }
    } else if (g_subprocess_get_successful(call_data->subprocess)) {
        nm_log_dbg(LOGD_SHARING, "firewall: nft[%s]: command successful", call_data->identifier);
    } else {
        gs_free char *ss_stdout    = NULL;
        gs_free char *ss_stderr    = NULL;
        gboolean      print_stdout = (stdout_buf && g_bytes_get_size(stdout_buf) > 0);
        gboolean      print_stderr = (stderr_buf && g_bytes_get_size(stderr_buf) > 0);

        nm_log_warn(LOGD_SHARING,
                    "firewall: nft[%s]: command failed:%s%s%s%s%s%s%s",
                    call_data->identifier,
                    print_stdout || print_stderr ? "" : " unknown reason",
                    NM_PRINT_FMT_QUOTED(
                        print_stdout,
                        " (stdout: \"",
                        nm_utils_buf_utf8safe_escape_bytes(stdout_buf,
                                                           NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL,
                                                           &ss_stdout),
                        "\")",
                        ""),
                    NM_PRINT_FMT_QUOTED(
                        print_stderr,
                        " (stderr: \"",
                        nm_utils_buf_utf8safe_escape_bytes(stderr_buf,
                                                           NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL,
                                                           &ss_stderr),
                        "\")",
                        ""));
    }

    _fw_nft_call_data_free(call_data, g_steal_pointer(&error));
}

static void
_fw_nft_call_cancelled_cb(GCancellable *cancellable, gpointer user_data)
{
    FwNftCallData *call_data = user_data;

    if (call_data->cancellable_id == 0)
        return;

    nm_log_dbg(LOGD_SHARING, "firewall: nft[%s]: operation cancelled", call_data->identifier);

    nm_clear_g_signal_handler(g_task_get_cancellable(call_data->task), &call_data->cancellable_id);
    nm_clear_g_cancellable(&call_data->intern_cancellable);
}

static gboolean
_fw_nft_call_timeout_cb(gpointer user_data)
{
    FwNftCallData *call_data = user_data;

    nm_clear_g_source_inst(&call_data->timeout_source);
    nm_log_dbg(LOGD_SHARING,
               "firewall: nft[%s]: cancel operation after timeout",
               call_data->identifier);

    nm_clear_g_cancellable(&call_data->intern_cancellable);
    return G_SOURCE_CONTINUE;
}

static void
_fw_nft_call(GBytes *            stdin_buf,
             GCancellable *      cancellable,
             GAsyncReadyCallback callback,
             gpointer            callback_user_data)
{
    gs_unref_object GSubprocessLauncher *subprocess_launcher = NULL;
    gs_free_error GError *error                              = NULL;
    FwNftCallData *       call_data;

    call_data  = g_slice_new(FwNftCallData);
    *call_data = (FwNftCallData){
        .task       = nm_g_task_new(NULL, cancellable, _fw_nft_call, callback, callback_user_data),
        .subprocess = NULL,
        .timeout_source = NULL,
    };

    if (cancellable) {
        call_data->cancellable_id = g_cancellable_connect(cancellable,
                                                          G_CALLBACK(_fw_nft_call_cancelled_cb),
                                                          call_data,
                                                          NULL);
        if (call_data->cancellable_id == 0) {
            nm_log_dbg(LOGD_SHARING, "firewall: nft: already cancelled");
            nm_utils_error_set_cancelled(&error, FALSE, NULL);
            _fw_nft_call_data_free(call_data, g_steal_pointer(&error));
            return;
        }
    }

    subprocess_launcher =
        g_subprocess_launcher_new(G_SUBPROCESS_FLAGS_STDIN_PIPE | G_SUBPROCESS_FLAGS_STDOUT_PIPE
                                  | G_SUBPROCESS_FLAGS_STDERR_PIPE);
    g_subprocess_launcher_set_environ(subprocess_launcher, NM_STRV_EMPTY());

    call_data->subprocess = g_subprocess_launcher_spawnv(subprocess_launcher,
                                                         NM_MAKE_STRV(NFT_PATH, "-f", "-"),
                                                         &error);

    if (!call_data->subprocess) {
        nm_log_dbg(LOGD_SHARING, "firewall: nft: spawning nft failed: %s", error->message);
        _fw_nft_call_data_free(call_data, g_steal_pointer(&error));
        return;
    }

    call_data->identifier = g_strdup(g_subprocess_get_identifier(call_data->subprocess));

    nm_log_dbg(LOGD_SHARING, "firewall: nft[%s]: communicate with nft", call_data->identifier);

    nm_shutdown_wait_obj_register_object(call_data->task, "nft-call");

    call_data->intern_cancellable = g_cancellable_new(),

    g_subprocess_communicate_async(call_data->subprocess,
                                   stdin_buf,
                                   call_data->intern_cancellable,
                                   _fw_nft_call_communicate_cb,
                                   call_data);

    call_data->timeout_source =
        nm_g_source_attach(nm_g_timeout_source_new((NM_SHUTDOWN_TIMEOUT_MS * 2) / 3,
                                                   G_PRIORITY_DEFAULT,
                                                   _fw_nft_call_timeout_cb,
                                                   call_data,
                                                   NULL),
                           g_task_get_context(call_data->task));
}

static gboolean
_fw_nft_call_finish(GAsyncResult *result, GError **error)
{
    g_return_val_if_fail(nm_g_task_is_valid(result, NULL, _fw_nft_call), FALSE);

    return g_task_propagate_boolean(G_TASK(result), error);
}

/*****************************************************************************/

typedef struct {
    GMainLoop *loop;
    GError **  error;
    gboolean   success;
} FwNftCallSyncData;

static void
_fw_nft_call_sync_done(GObject *source, GAsyncResult *result, gpointer user_data)
{
    FwNftCallSyncData *data = user_data;

    data->success = _fw_nft_call_finish(result, data->error);
    g_main_loop_quit(data->loop);
}

static gboolean
_fw_nft_call_sync(GBytes *stdin_buf, GError **error)
{
    nm_auto_pop_and_unref_gmaincontext GMainContext *main_context =
        nm_g_main_context_push_thread_default(g_main_context_new());
    nm_auto_unref_gmainloop GMainLoop *main_loop = g_main_loop_new(main_context, FALSE);
    FwNftCallSyncData                  data      = (FwNftCallSyncData){
        .loop  = main_loop,
        .error = error,
    };

    _fw_nft_call(stdin_buf, NULL, _fw_nft_call_sync_done, &data);

    g_main_loop_run(main_loop);
    return data.success;
}

/*****************************************************************************/

static void
_fw_nft_set(gboolean add, const char *ip_iface, in_addr_t addr, guint8 plen)
{
    nm_auto_str_buf NMStrBuf strbuf   = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_1000, FALSE);
    gs_unref_bytes GBytes *stdin_buf  = NULL;
    gs_free char *         table_name = NULL;
    gs_free char *         ss1        = NULL;
    char                   str_subnet[_SHARE_IPTABLES_SUBNET_TO_STR_LEN];

    table_name = _share_iptables_get_name(FALSE, "nm-shared", ip_iface);

    _share_iptables_subnet_to_str(str_subnet, addr, plen);

#define _append(p_strbuf, fmt, ...) nm_str_buf_append_printf((p_strbuf), "" fmt "\n", ##__VA_ARGS__)

    _append(&strbuf, "add table ip %s", table_name);
    _append(&strbuf, "%s table ip %s", add ? "flush" : "delete", table_name);

    if (add) {
        _append(&strbuf,
                "add chain ip %s nat_postrouting {"
                " type nat hook postrouting priority 100; policy accept; "
                "};",
                table_name);
        _append(&strbuf,
                "add rule ip %s nat_postrouting ip saddr %s ip daddr != %s masquerade;",
                table_name,
                str_subnet,
                str_subnet);

        /* This filter_input chain serves no real purpose, because "accept" only stops
         * evaluation of the current rule. It cannot fully accept the packet. Since
         * this chain has no other rules, it is useless in this form.
         */
        /*
        _append(&strbuf,
                "add chain ip %s filter_input {"
                " type filter hook input priority 0; policy accept; "
                "};",
                table_name);
        _append(&strbuf, "add rule ip %s filter_input tcp dport { 67, 53 } accept;", table_name);
        _append(&strbuf, "add rule ip %s filter_input udp dport { 67, 53 } accept;", table_name);
        */

        _append(&strbuf,
                "add chain ip %s filter_forward {"
                " type filter hook forward priority 0; policy accept; "
                "};",
                table_name);
        _append(&strbuf,
                "add rule ip %s filter_forward ip daddr %s oifname \"%s\" "
                " ct state { established, related } accept;",
                table_name,
                str_subnet,
                ip_iface);
        _append(&strbuf,
                "add rule ip %s filter_forward ip saddr %s iifname \"%s\" accept;",
                table_name,
                str_subnet,
                ip_iface);
        _append(&strbuf,
                "add rule ip %s filter_forward iifname \"%s\" oifname \"%s\" accept;",
                table_name,
                ip_iface,
                ip_iface);
        _append(&strbuf,
                "add rule ip %s filter_forward iifname \"%s\" reject;",
                table_name,
                ip_iface);
        _append(&strbuf,
                "add rule ip %s filter_forward oifname \"%s\" reject;",
                table_name,
                ip_iface);
    }

    nm_log_trace(LOGD_SHARING,
                 "firewall: nft command: [ %s ]",
                 nm_utils_str_utf8safe_escape(nm_str_buf_get_str(&strbuf),
                                              NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL,
                                              &ss1));

    stdin_buf = g_bytes_new_static(nm_str_buf_get_str(&strbuf), strbuf.len);

    _fw_nft_call_sync(stdin_buf, NULL);
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
    switch (nm_firewall_utils_get_backend()) {
    case NM_FIREWALL_BACKEND_IPTABLES:
        _share_iptables_set_masquerade(shared, self->ip_iface, self->addr, self->plen);
        _share_iptables_set_shared(shared, self->ip_iface, self->addr, self->plen);
        break;
    case NM_FIREWALL_BACKEND_NFTABLES:
        _fw_nft_set(shared, self->ip_iface, self->addr, self->plen);
        break;
    case NM_FIREWALL_BACKEND_NONE:
        break;
    default:
        nm_assert_not_reached();
        break;
    }
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

        nm_assert(NM_IN_SET(b,
                            NM_FIREWALL_BACKEND_NONE,
                            NM_FIREWALL_BACKEND_IPTABLES,
                            NM_FIREWALL_BACKEND_NFTABLES));

        if (!g_atomic_int_compare_and_exchange(&backend, NM_FIREWALL_BACKEND_UNKNOWN, b))
            goto again;

        nm_log_dbg(LOGD_SHARING,
                   "firewall: use %s backend%s%s%s%s%s%s%s",
                   FirewallBackends[b - 1].name,
                   NM_PRINT_FMT_QUOTED(FirewallBackends[b - 1].path,
                                       " (",
                                       FirewallBackends[b - 1].path,
                                       ")",
                                       ""),
                   detect ? " (detected)" : "",
                   NM_PRINT_FMT_QUOTED(detect && conf_value,
                                       " (invalid setting \"",
                                       conf_value,
                                       "\")",
                                       ""));
    }

    nm_assert(NM_IN_SET(b,
                        NM_FIREWALL_BACKEND_NONE,
                        NM_FIREWALL_BACKEND_IPTABLES,
                        NM_FIREWALL_BACKEND_NFTABLES));
    return b;
}
