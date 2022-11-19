/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "src/core/nm-default-daemon.h"

#include <stdlib.h>
#include <syslog.h>

#include "libnm-glib-aux/nm-str-buf.h"
#include "libnm-glib-aux/nm-io-utils.h"
#include "libnm-platform/nm-linux-platform.h"
#include "libnm-platform/nmp-object.h"

#include "nm-test-utils-core.h"

NMTST_DEFINE();

static struct {
    gboolean persist;
    char    *state_file;
} global_opt = {
    .persist = TRUE,
};

const char *const *const ip_argv_rule6 = NM_MAKE_STRV("ip", "-d", "-6", "rule");

static const struct {
    NMPObjectType      obj_type;
    const char *const *ip_argv;
} dump_obj_types[] = {
    {NMP_OBJECT_TYPE_LINK, NM_MAKE_STRV("ip", "-d", "link")},
    {NMP_OBJECT_TYPE_IP4_ADDRESS, NM_MAKE_STRV("ip", "-d", "-4", "address")},
    {NMP_OBJECT_TYPE_IP6_ADDRESS, NM_MAKE_STRV("ip", "-d", "-6", "address")},
    {NMP_OBJECT_TYPE_IP4_ROUTE, NM_MAKE_STRV("ip", "-d", "-4", "route")},
    {NMP_OBJECT_TYPE_IP6_ROUTE, NM_MAKE_STRV("ip", "-d", "-6", "route")},
    {NMP_OBJECT_TYPE_ROUTING_RULE, NM_MAKE_STRV("ip", "-d", "-4", "rule")},
};

static gboolean
read_argv(int *argc, char ***argv)
{
    GOptionContext *context;
    GOptionEntry    options[] = {
        {"no-persist",
            'P',
            G_OPTION_FLAG_REVERSE,
            G_OPTION_ARG_NONE,
            &global_opt.persist,
            "Exit after processing netlink messages",
            NULL},
        {"state-file",
            'S',
            0,
            G_OPTION_ARG_FILENAME,
            &global_opt.state_file,
            "Dump the platform cache to this file",
            "FILE"},
        {0},
    };
    gs_free_error GError *error = NULL;

    context = g_option_context_new(NULL);
    g_option_context_set_summary(context, "Monitor netlink events in NMPlatform.");
    g_option_context_add_main_entries(context, options, NULL);

    if (!g_option_context_parse(context, argc, argv, &error)) {
        g_warning("Error parsing command line arguments: %s", error->message);
        g_option_context_free(context);
        return FALSE;
    }

    g_option_context_free(context);
    return TRUE;
}

/*****************************************************************************/

static void
mptcp_addr_dump(NMPlatform *platform)
{
    gs_unref_ptrarray GPtrArray *addrs = NULL;

    addrs = nm_platform_mptcp_addrs_dump(platform);
}

/*****************************************************************************/

static void
_dump_state(NMPlatform *platform, const char *state_file)
{
    nm_auto_str_buf NMStrBuf sbuf = NM_STR_BUF_INIT_A(NM_UTILS_GET_NEXT_REALLOC_SIZE_488, FALSE);
    nm_auto_unref_gdatetime GDateTime *time_datetime = NULL;
    gs_free char                      *time_str      = NULL;
    int                                i_obj_type;

    if (!state_file)
        return;

    time_datetime = g_date_time_new_now_local();
    time_str      = g_date_time_format(time_datetime, "%C%y-%m-%dT%H:%M:%S.%f");

    nm_log_dbg(LOGD_PLATFORM, "dump to file \"%s\", at %s", state_file, time_str);

    nm_str_buf_append_printf(&sbuf, "time: %s\n", time_str);
    nm_str_buf_append_printf(&sbuf, "pid: %lld\n", (long long) getpid());

    for (i_obj_type = 0; i_obj_type < (int) G_N_ELEMENTS(dump_obj_types); i_obj_type++) {
        NMPObjectType                obj_type = dump_obj_types[i_obj_type].obj_type;
        const char *const           *ip_argv  = dump_obj_types[i_obj_type].ip_argv;
        const NMDedupMultiHeadEntry *pl_head_entry;
        NMDedupMultiIter             pl_iter;
        const NMPObject             *obj;
        guint                        i;
        char                         buf1[1000];

        pl_head_entry = nm_platform_lookup_obj_type(platform, obj_type);

        nm_str_buf_append_printf(&sbuf,
                                 "\n%s: %u\n",
                                 nmp_class_from_type(obj_type)->obj_type_name,
                                 pl_head_entry ? pl_head_entry->len : 0u);

        i = 0;
        nmp_cache_iter_for_each (&pl_iter, pl_head_entry, &obj) {
            nmp_object_to_string(obj, NMP_OBJECT_TO_STRING_PUBLIC, buf1, sizeof(buf1));
            nm_str_buf_append_printf(&sbuf,
                                     "%s[%u]: %s\n",
                                     nmp_class_from_type(obj_type)->obj_type_name,
                                     i,
                                     buf1);
            g_assert(strlen(buf1) < sizeof(buf1) - 1u);
            i++;
        }

ip_again:
        if (ip_argv) {
            gs_free_error GError *error      = NULL;
            gs_free char         *ip_argv_ss = NULL;
            gs_free char         *s_stdout   = NULL;
            gs_free char         *s_stderr   = NULL;
            int                   exit_code;

            g_spawn_sync(NULL,
                         (char **) ip_argv,
                         NULL,
                         G_SPAWN_SEARCH_PATH,
                         NULL,
                         NULL,
                         &s_stdout,
                         &s_stderr,
                         &exit_code,
                         &error);

            nm_str_buf_append_printf(&sbuf,
                                     "%s: call %s: ",
                                     nmp_class_from_type(obj_type)->obj_type_name,
                                     ip_argv_ss = g_strjoinv(" ", (char **) ip_argv));
            if (error) {
                nm_str_buf_append_printf(&sbuf, "FAILED: %s\n", error->message);
            } else if (WIFEXITED(exit_code) && WEXITSTATUS(exit_code) == 0)
                nm_str_buf_append_printf(&sbuf, "SUCCESS\n");
            else {
                nm_str_buf_append_printf(
                    &sbuf,
                    "ERROR: %s\n",
                    nm_utils_get_process_exit_status_desc_buf(exit_code, buf1, sizeof(buf1)));
            }
            if (!nm_str_is_empty(s_stdout))
                nm_str_buf_append_printf(&sbuf, "STDOUT>\n%s<\n", s_stdout);
            if (!nm_str_is_empty(s_stderr))
                nm_str_buf_append_printf(&sbuf, "STDERR>\n%s<\n", s_stderr);

            if (obj_type == NMP_OBJECT_TYPE_ROUTING_RULE
                && ip_argv == dump_obj_types[i_obj_type].ip_argv) {
                ip_argv = ip_argv_rule6;
                goto ip_again;
            }
        }
    }

    nm_utils_file_set_contents(state_file,
                               nm_str_buf_get_str_unsafe(&sbuf),
                               sbuf.len,
                               00644,
                               NULL,
                               NULL,
                               NULL);

    nm_log_dbg(LOGD_PLATFORM, "dump to file complete");
}

static void
_dump_state_platform_cb(NMPlatform   *platform,
                        int           obj_type_i,
                        int           ifindex,
                        gconstpointer platform_object,
                        int           change_type_i,
                        gpointer      unused_user_data)
{
    _dump_state(platform, global_opt.state_file);
}

/*****************************************************************************/

int
main(int argc, char **argv)
{
    GMainLoop *loop;

    if (!g_getenv("G_MESSAGES_DEBUG"))
        g_setenv("G_MESSAGES_DEBUG", "all", TRUE);

    nmtst_init_with_logging(&argc, &argv, "DEBUG", "ALL");

    if (!read_argv(&argc, &argv))
        return 2;

    nm_log_info(LOGD_PLATFORM, "platform monitor start");

    loop = g_main_loop_new(NULL, FALSE);

    nm_linux_platform_setup();

    if (global_opt.state_file) {
        int i_obj_type;

        for (i_obj_type = 0; i_obj_type < (int) G_N_ELEMENTS(dump_obj_types); i_obj_type++) {
            NMPObjectType obj_type = dump_obj_types[i_obj_type].obj_type;

            g_signal_connect(NM_PLATFORM_GET,
                             nmp_class_from_type(obj_type)->signal_type,
                             G_CALLBACK(_dump_state_platform_cb),
                             NULL);
        }
    }

    mptcp_addr_dump(NM_PLATFORM_GET);

    _dump_state(NM_PLATFORM_GET, global_opt.state_file);

    if (global_opt.persist)
        g_main_loop_run(loop);

    g_main_loop_unref(loop);

    g_signal_handlers_disconnect_by_func(NM_PLATFORM_GET,
                                         G_CALLBACK(_dump_state_platform_cb),
                                         NULL);
    g_object_unref(NM_PLATFORM_GET);

    return EXIT_SUCCESS;
}
