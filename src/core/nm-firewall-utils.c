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

static const char *
_nft_ifname_valid(const char *str)
{
    gsize i;

    /* `nft -f -` takes certain strings, like "device $IFNAME", but
     * those strings are from a limited character set. Check that
     * @str is valid according to those rules.
     *
     * src/scanner.l:
     *   digit   [0-9]
     *   letter  [a-zA-Z]
     *   string  ({letter}|[_.])({letter}|{digit}|[/\-_\.])*
     **/

    if (!str || !str[0])
        return NULL;

    for (i = 0; str[i]; i++) {
        switch (str[i]) {
        case 'a' ... 'z':
        case 'A' ... 'Z':
        case '_':
        case '.':
            continue;
        case '0' ... '9':
        case '/':
        case '-':
            if (i == 0)
                return NULL;
            continue;
        default:
            return NULL;
        }
    }
    if (i >= NMP_IFNAMSIZ)
        return NULL;

    return str;
}

static const char *
_strbuf_set_sanitized(NMStrBuf *strbuf, const char *prefix, const char *str_to_sanitize)
{
    nm_str_buf_reset(strbuf);

    if (prefix)
        nm_str_buf_append(strbuf, prefix);

    for (; str_to_sanitize[0] != '\0'; str_to_sanitize++) {
        const char ch = str_to_sanitize[0];

        if (g_ascii_isalpha(ch) || g_ascii_isdigit(ch)) {
            nm_str_buf_append_c(strbuf, ch);
            continue;
        }
        nm_str_buf_append_c(strbuf, '_');
        nm_str_buf_append_c_hex(strbuf, ch, FALSE);
    }

    return nm_str_buf_get_str(strbuf);
}

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

    netmask = nm_ip4_addr_netmask_from_prefix(plen);

    l = g_snprintf(buf,
                   _SHARE_IPTABLES_SUBNET_TO_STR_LEN,
                   "%s/%u",
                   nm_inet4_ntop(addr & netmask, buf_addr),
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

/*****************************************************************************/

static gboolean
_share_iptables_call_v(const char *const *argv)
{
    gs_free_error GError *error    = NULL;
    gs_free char         *argv_str = NULL;
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

#define _share_iptables_call(...) \
    _share_iptables_call_v(NM_MAKE_STRV("" IPTABLES_PATH "", "--wait", "2", __VA_ARGS__))

static gboolean
_share_iptables_chain_op(const char *table, const char *chain, const char *op)
{
    return _share_iptables_call("--table", table, op, chain);
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
_share_iptables_set_masquerade_sync(gboolean up, const char *ip_iface, in_addr_t addr, guint8 plen)
{
    char          str_subnet[_SHARE_IPTABLES_SUBNET_TO_STR_LEN];
    gs_free char *comment_name = NULL;

    comment_name = _share_iptables_get_name(FALSE, "nm-shared", ip_iface);

    _share_iptables_subnet_to_str(str_subnet, addr, plen);
    _share_iptables_call("--table",
                         "nat",
                         up ? "--insert" : "--delete",
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
        _share_iptables_call("--table",
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

    _share_iptables_call("--table",
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
    _share_iptables_call("--table",
                         "filter",
                         "--append",
                         chain_forward,
                         "--source",
                         str_subnet,
                         "--in-interface",
                         ip_iface,
                         "--jump",
                         "ACCEPT");
    _share_iptables_call("--table",
                         "filter",
                         "--append",
                         chain_forward,
                         "--in-interface",
                         ip_iface,
                         "--out-interface",
                         ip_iface,
                         "--jump",
                         "ACCEPT");
    _share_iptables_call("--table",
                         "filter",
                         "--append",
                         chain_forward,
                         "--out-interface",
                         ip_iface,
                         "--jump",
                         "REJECT");
    _share_iptables_call("--table",
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

static void
_share_iptables_set_shared_sync(gboolean up, const char *ip_iface, in_addr_t addr, guint plen)
{
    gs_free char *comment_name  = NULL;
    gs_free char *chain_input   = NULL;
    gs_free char *chain_forward = NULL;

    comment_name  = _share_iptables_get_name(FALSE, "nm-shared", ip_iface);
    chain_input   = _share_iptables_get_name(TRUE, "nm-sh-in", ip_iface);
    chain_forward = _share_iptables_get_name(TRUE, "nm-sh-fw", ip_iface);

    if (up)
        _share_iptables_set_shared_chains_add(chain_input, chain_forward, ip_iface, addr, plen);

    _share_iptables_call("--table",
                         "filter",
                         up ? "--insert" : "--delete",
                         "INPUT",
                         "--in-interface",
                         ip_iface,
                         "--jump",
                         chain_input,
                         "-m",
                         "comment",
                         "--comment",
                         comment_name);

    _share_iptables_call("--table",
                         "filter",
                         up ? "--insert" : "--delete",
                         "FORWARD",
                         "--jump",
                         chain_forward,
                         "-m",
                         "comment",
                         "--comment",
                         comment_name);

    if (!up)
        _share_iptables_set_shared_chains_delete(chain_input, chain_forward);
}

/*****************************************************************************/

typedef struct {
    GTask        *task;
    GSubprocess  *subprocess;
    GSource      *timeout_source;
    GCancellable *intern_cancellable;
    char         *identifier;
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
    FwNftCallData         *call_data  = user_data;
    gs_free_error GError  *error      = NULL;
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
            G_STATIC_ASSERT_EXPR(200 < NM_SHUTDOWN_TIMEOUT_ADDITIONAL_MSEC * 2 / 3);
            nm_g_subprocess_terminate_in_background(call_data->subprocess, 200);
        }
    } else if (g_subprocess_get_successful(call_data->subprocess)) {
        nm_log_dbg(LOGD_SHARING, "firewall: nft[%s]: command successful", call_data->identifier);
    } else {
        char          buf[NM_UTILS_GET_PROCESS_EXIT_STATUS_BUF_LEN];
        gs_free char *ss_stdout    = NULL;
        gs_free char *ss_stderr    = NULL;
        gboolean      print_stdout = (stdout_buf && g_bytes_get_size(stdout_buf) > 0);
        gboolean      print_stderr = (stderr_buf && g_bytes_get_size(stderr_buf) > 0);
        int           status;

        status = g_subprocess_get_status(call_data->subprocess);

        nm_utils_get_process_exit_status_desc_buf(status, buf, sizeof(buf));

        nm_log_warn(LOGD_SHARING,
                    "firewall: nft[%s]: command %s:%s%s%s%s%s%s%s",
                    call_data->identifier,
                    buf,
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

        nm_utils_error_set(&error, NM_UTILS_ERROR_COMMAND_FAILED, "nft command %s", buf);
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

void
nm_firewall_nft_call(GBytes             *stdin_buf,
                     GCancellable       *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer            callback_user_data)
{
    gs_unref_object GSubprocessLauncher *subprocess_launcher = NULL;
    gs_free_error GError                *error               = NULL;
    FwNftCallData                       *call_data;
    gs_free char                        *ss1 = NULL;

    call_data  = g_slice_new(FwNftCallData);
    *call_data = (FwNftCallData){
        .task =
            nm_g_task_new(NULL, cancellable, nm_firewall_nft_call, callback, callback_user_data),
        .subprocess     = NULL,
        .timeout_source = NULL,
    };

    nm_log_trace(LOGD_SHARING,
                 "firewall: nft: call command: [ '%s' ]",
                 nm_utils_buf_utf8safe_escape_bytes(stdin_buf,
                                                    NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL,
                                                    &ss1));

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
        nm_g_source_attach(nm_g_timeout_source_new((NM_SHUTDOWN_TIMEOUT_1500_MSEC * 2) / 3,
                                                   G_PRIORITY_DEFAULT,
                                                   _fw_nft_call_timeout_cb,
                                                   call_data,
                                                   NULL),
                           g_task_get_context(call_data->task));
}

gboolean
nm_firewall_nft_call_finish(GAsyncResult *result, GError **error)
{
    g_return_val_if_fail(nm_g_task_is_valid(result, NULL, nm_firewall_nft_call), FALSE);

    return g_task_propagate_boolean(G_TASK(result), error);
}

/*****************************************************************************/

typedef struct {
    GMainLoop *loop;
    GError   **error;
    gboolean   success;
} FwNftCallSyncData;

static void
_fw_nft_call_sync_done(GObject *source, GAsyncResult *result, gpointer user_data)
{
    FwNftCallSyncData *data = user_data;

    data->success = nm_firewall_nft_call_finish(result, data->error);
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

    nm_firewall_nft_call(stdin_buf, NULL, _fw_nft_call_sync_done, &data);

    g_main_loop_run(main_loop);
    return data.success;
}

/*****************************************************************************/

#define _append(p_strbuf, fmt, ...) nm_str_buf_append_printf((p_strbuf), "" fmt "\n", ##__VA_ARGS__)

static void
_fw_nft_append_cmd_table(NMStrBuf *strbuf, const char *family, const char *table_name, gboolean up)
{
    /* Either delete the table, or create/flush it. */
    _append(strbuf, "add table %s %s", family, table_name);
    _append(strbuf, "%s table %s %s", up ? "flush" : "delete", family, table_name);
}

static GBytes *
_fw_nft_set_shared_construct(gboolean up, const char *ip_iface, in_addr_t addr, guint8 plen)
{
    nm_auto_str_buf NMStrBuf strbuf = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_1000, FALSE);
    gs_free char            *table_name = NULL;
    char                     str_subnet[_SHARE_IPTABLES_SUBNET_TO_STR_LEN];

    table_name = _share_iptables_get_name(FALSE, "nm-shared", ip_iface);

    _share_iptables_subnet_to_str(str_subnet, addr, plen);

    _fw_nft_append_cmd_table(&strbuf, "ip", table_name, up);

    if (up) {
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
         *
         * _append(&strbuf,
         *         "add chain ip %s filter_input {"
         *         " type filter hook input priority 0; policy accept; "
         *         "};",
         *         table_name);
         * _append(&strbuf, "add rule ip %s filter_input tcp dport { 67, 53 } accept;", table_name);
         * _append(&strbuf, "add rule ip %s filter_input udp dport { 67, 53 } accept;", table_name);
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

    return nm_str_buf_finalize_to_gbytes(&strbuf);
}

/*****************************************************************************/

GBytes *
nm_firewall_nft_stdio_mlag(gboolean           up,
                           const char        *bond_ifname,
                           const char *const *bond_ifnames_down,
                           const char *const *active_members,
                           const char *const *previous_members)
{
    nm_auto_str_buf NMStrBuf strbuf_table_name =
        NM_STR_BUF_INIT_A(NM_UTILS_GET_NEXT_REALLOC_SIZE_32, FALSE);
    nm_auto_str_buf NMStrBuf strbuf = NM_STR_BUF_INIT(NM_UTILS_GET_NEXT_REALLOC_SIZE_1000, FALSE);
    const char              *table_name;
    gsize                    i;

    if (NM_MORE_ASSERTS > 10 && active_members) {
        /* No duplicates. We make certain assumptions here, and we don't
         * want to check that there are no duplicates. The caller must take
         * care of this. */
        for (i = 0; active_members[i]; i++)
            nm_assert(!nm_strv_contains(&active_members[i + 1], -1, active_members[i]));
    }

    /* If an interface gets renamed, we need to update the nft tables. Since one nft
     * invocation is atomic, it is reasonable to drop the previous tables(s) at the
     * same time when creating the new one. */
    for (; bond_ifnames_down && bond_ifnames_down[0]; bond_ifnames_down++) {
        if (nm_streq(bond_ifname, bond_ifnames_down[0]))
            continue;
        table_name = _strbuf_set_sanitized(&strbuf_table_name, "nm-mlag-", bond_ifnames_down[0]);
        _fw_nft_append_cmd_table(&strbuf, "netdev", table_name, FALSE);
    }

    table_name = _strbuf_set_sanitized(&strbuf_table_name, "nm-mlag-", bond_ifname);

    _fw_nft_append_cmd_table(&strbuf, "netdev", table_name, up);

    if (up) {
        nm_auto_str_buf NMStrBuf strbuf_1 =
            NM_STR_BUF_INIT_A(NM_UTILS_GET_NEXT_REALLOC_SIZE_232, FALSE);
        const gsize n_active_members = NM_PTRARRAY_LEN(active_members);

        if (!_nft_ifname_valid(bond_ifname)) {
            /* We cannot meaningfully express this interface name. Ignore all chains
             * and only create an empty table. */
            goto out;
        }

        for (; previous_members && previous_members[0]; previous_members++) {
            const char *previous_member = previous_members[0];
            const char *chain_name;

            /* The caller already ensures that the previous member is not part of the new
             * active members. Avoid the overhead of checking, and assert against that. */
            nm_assert(!nm_strv_contains(active_members, n_active_members, previous_member));

            if (!_nft_ifname_valid(previous_member))
                continue;

            chain_name = _strbuf_set_sanitized(&strbuf_1, "rx-drop-bc-mc-", previous_member);

            /* We want atomically update our table, however, we don't want to delete
             * and recreate it, because then the sets get lost (which we don't want).
             *
             * Instead, we only "add && flush" the table, which removes all rules from
             * the chain. However, as our active-members change, we want to delete
             * the obsolete chains too.
             *
             * nft has no way to delete all chains in a table, we have to name
             * them one by one. So we keep track of active members that we had
             * in the past, and which are now no longer in use. For those previous
             * members we delete the chains (again, with the "add && delete" dance
             * to avoid failure deleting a non-existing chain (in case our tracking
             * is wrong or somebody else modified the table in the meantime).
             *
             * We need to track the previous members, because we don't want to first
             * ask nft which chains exist. Doing that would be cumbersome as we would
             * have to do one async program invocation and parse stdout. */
            _append(&strbuf,
                    "add chain netdev %s %s {"
                    " type filter hook ingress device %s priority filter; "
                    "}",
                    table_name,
                    chain_name,
                    previous_member);
            _append(&strbuf, "delete chain netdev %s %s", table_name, chain_name);
        }

        /* OVS SLB rule 1
         *
         * "Open vSwitch avoids packet duplication by accepting multicast and broadcast
         *  packets on only the active member, and dropping multicast and broadcast
         *  packets on all other members."
         *
         * primary is first member, we drop on all others */
        for (i = 0; i < n_active_members; i++) {
            const char *active_member = active_members[i];
            const char *chain_name;

            if (!_nft_ifname_valid(active_member))
                continue;

            chain_name = _strbuf_set_sanitized(&strbuf_1, "rx-drop-bc-mc-", active_member);

            _append(&strbuf,
                    "add chain netdev %s %s {"
                    " type filter hook ingress device %s priority filter; "
                    "}",
                    table_name,
                    chain_name,
                    active_member);

            if (i == 0) {
                _append(&strbuf, "delete chain netdev %s %s", table_name, chain_name);
                continue;
            }

            _append(&strbuf,
                    "add rule netdev %s %s pkttype {"
                    " broadcast, multicast "
                    "} counter drop",
                    table_name,
                    chain_name);
        }

        /* OVS SLB rule 2
         *
         * "Open vSwitch deals with this case by dropping packets received on any SLB
         * bonded link that have a source MAC+VLAN that has been learned on any other
         * port."
         */
        _append(&strbuf,
                "add set netdev %s macset-tagged {"
                " typeof ether saddr . vlan id; flags timeout; "
                "}",
                table_name);
        _append(&strbuf,
                "add set netdev %s macset-untagged {"
                " typeof ether saddr; flags timeout;"
                "}",
                table_name);

        _append(&strbuf,
                "add chain netdev %s tx-snoop-source-mac {"
                " type filter hook egress device %s priority filter; "
                "}",
                table_name,
                bond_ifname);
        _append(&strbuf,
                "add rule netdev %s tx-snoop-source-mac set update ether saddr . vlan id"
                " timeout 5s @macset-tagged counter return"
                "", /* tagged */
                table_name);
        _append(&strbuf,
                "add rule netdev %s tx-snoop-source-mac set update ether saddr"
                " timeout 5s @macset-untagged counter"
                "", /* untagged*/
                table_name);

        _append(&strbuf,
                "add chain netdev %s rx-drop-looped-packets {"
                " type filter hook ingress device %s priority filter; "
                "}",
                table_name,
                bond_ifname);
        _append(&strbuf,
                "add rule netdev %s rx-drop-looped-packets ether saddr . vlan id"
                " @macset-tagged counter drop",
                table_name);
        _append(&strbuf,
                "add rule netdev %s rx-drop-looped-packets ether type vlan counter return"
                "", /* avoid looking up tagged packets in untagged table */
                table_name);
        _append(&strbuf,
                "add rule netdev %s rx-drop-looped-packets ether saddr @macset-untagged"
                " counter drop",
                table_name);
    }

out:
    return nm_str_buf_finalize_to_gbytes(&strbuf);
}

/*****************************************************************************/

struct _NMFirewallConfig {
    char     *ip_iface;
    in_addr_t addr;
    guint8    plen;
};

NMFirewallConfig *
nm_firewall_config_new_shared(const char *ip_iface, in_addr_t addr, guint8 plen)
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

/*****************************************************************************/

void
nm_firewall_config_apply_sync(NMFirewallConfig *self, gboolean up)
{
    switch (nm_firewall_utils_get_backend()) {
    case NM_FIREWALL_BACKEND_IPTABLES:
        _share_iptables_set_masquerade_sync(up, self->ip_iface, self->addr, self->plen);
        _share_iptables_set_shared_sync(up, self->ip_iface, self->addr, self->plen);
        break;
    case NM_FIREWALL_BACKEND_NFTABLES:
    {
        gs_unref_bytes GBytes *stdin_buf = NULL;

        stdin_buf = _fw_nft_set_shared_construct(up, self->ip_iface, self->addr, self->plen);
        _fw_nft_call_sync(stdin_buf, NULL);
        break;
    }
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
