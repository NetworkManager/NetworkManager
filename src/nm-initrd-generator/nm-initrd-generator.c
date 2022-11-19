/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "libnm-core-impl/nm-default-libnm-core.h"

#include "nm-initrd-generator.h"

#include "libnm-base/nm-config-base.h"
#include "libnm-core-intern/nm-core-internal.h"
#include "libnm-core-intern/nm-keyfile-internal.h"
#include "libnm-glib-aux/nm-io-utils.h"
#include "libnm-log-core/nm-logging.h"

/*****************************************************************************/

#define _NMLOG(level, domain, ...)                                 \
    nm_log((level),                                                \
           (domain),                                               \
           NULL,                                                   \
           NULL,                                                   \
           "initrd-generator: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__) \
               _NM_UTILS_MACRO_REST(__VA_ARGS__))

/*****************************************************************************/

static void
add_keyfile_comment(GKeyFile *keyfile, char *reason)
{
    gs_free char *comment = NULL;

    comment = g_strdup_printf(" Created by nm-initrd-generator%s%s%s",
                              reason ? " (" : "",
                              reason ? reason : "",
                              reason ? ")" : "");
    g_key_file_set_comment(keyfile, NULL, NULL, comment, NULL);
}

static void
output_conn(gpointer key, gpointer value, gpointer user_data)
{
    const char                     *basename        = key;
    NMConnection                   *connection      = value;
    char                           *connections_dir = user_data;
    nm_auto_unref_keyfile GKeyFile *file            = NULL;
    gs_free char                   *data            = NULL;
    gs_free_error GError           *error           = NULL;
    gsize                           len;
    NMSetting                      *setting;

    setting = nm_setting_user_new();
    nm_connection_add_setting(connection, setting);
    nm_setting_user_set_data(NM_SETTING_USER(setting),
                             NM_USER_TAG_ORIGIN,
                             "nm-initrd-generator",
                             NULL);

    if (!nm_connection_normalize(connection, NULL, NULL, &error))
        goto err_out;

    file = nm_keyfile_write(connection, NM_KEYFILE_HANDLER_FLAGS_NONE, NULL, NULL, &error);
    if (!file)
        goto err_out;

    if (connections_dir)
        add_keyfile_comment(file, NULL);

    data = g_key_file_to_data(file, &len, &error);
    if (!data)
        goto err_out;

    if (connections_dir) {
        gs_free char *filename      = NULL;
        gs_free char *full_filename = NULL;

        filename      = nm_keyfile_utils_create_filename(basename, TRUE);
        full_filename = g_build_filename(connections_dir, filename, NULL);

        if (!nm_utils_file_set_contents(full_filename, data, len, 0600, NULL, NULL, &error))
            goto err_out;
    } else
        g_print("\n*** Connection '%s' ***\n\n%s", basename, data);

    return;
err_out:
    g_print("%s\n", error->message);
}

#define DEFAULT_SYSFS_DIR       "/sys"
#define DEFAULT_INITRD_DATA_DIR NMRUNDIR "/initrd"
#define DEFAULT_RUN_CONFIG_DIR  NMRUNDIR "/conf.d"

int
main(int argc, char *argv[])
{
    GHashTable        *connections;
    gs_free char      *connections_dir     = NULL;
    gs_free char      *etc_connections_dir = NULL;
    gs_free char      *initrd_dir          = NULL;
    gs_free char      *sysfs_dir           = NULL;
    gs_free char      *run_config_dir      = NULL;
    gboolean           dump_to_stdout      = FALSE;
    gs_strfreev char **remaining           = NULL;
    GOptionEntry       option_entries[]    = {
        {"connections-dir",
                  'c',
                  0,
                  G_OPTION_ARG_FILENAME,
                  &connections_dir,
                  "Output connection directory",
                  NM_KEYFILE_PATH_NAME_RUN},
        {"persistent-connections-dir",
                  'p',
                  0,
                  G_OPTION_ARG_FILENAME,
                  &etc_connections_dir,
                  "Persistent connection directory",
                  NM_KEYFILE_PATH_NAME_ETC_DEFAULT},
        {"initrd-data-dir",
                  'i',
                  0,
                  G_OPTION_ARG_FILENAME,
                  &initrd_dir,
                  "Output initrd data directory",
                  DEFAULT_INITRD_DATA_DIR},
        {"sysfs-dir",
                  'd',
                  0,
                  G_OPTION_ARG_FILENAME,
                  &sysfs_dir,
                  "The sysfs mount point",
                  DEFAULT_SYSFS_DIR},
        {"run-config-dir",
                  'r',
                  0,
                  G_OPTION_ARG_FILENAME,
                  &run_config_dir,
                  "Output config directory",
                  DEFAULT_RUN_CONFIG_DIR},
        {"stdout",
                  's',
                  0,
                  G_OPTION_ARG_NONE,
                  &dump_to_stdout,
                  "Dump connections to standard output",
                  NULL},
        {G_OPTION_REMAINING, '\0', 0, G_OPTION_ARG_STRING_ARRAY, &remaining, NULL, NULL},
        {NULL}};
    nm_auto_free_option_context GOptionContext *option_context = NULL;
    gs_free_error GError                       *error          = NULL;
    gs_free char                               *hostname       = NULL;
    int                                         errsv;
    gint64                                      carrier_timeout_sec = 0;
    gs_unref_array GArray                      *confs               = NULL;
    guint                                       i;

    option_context = g_option_context_new(
        "-- [ip=...] [rd.route=...] [bridge=...] [bond=...] [team=...] [vlan=...] "
        "[bootdev=...] [nameserver=...] [rd.peerdns=...] [rd.bootif=...] [BOOTIF=...] "
        "[rd.znet=...] [rd.net.timeout.carrier=...] ... ");

    g_option_context_set_summary(option_context, "Generate early NetworkManager configuration.");
    g_option_context_set_description(
        option_context,
        "This tool scans the command line for options relevant to network\n"
        "configuration and creates configuration files for an early instance\n"
        "of NetworkManager run from the initial ramdisk during early boot.");
    g_option_context_add_main_entries(option_context, option_entries, GETTEXT_PACKAGE);

    if (!g_option_context_parse(option_context, &argc, &argv, &error)) {
        _LOGW(LOGD_CORE, "%s", error->message);
        return 1;
    }

    if (!remaining) {
        /* No arguments, no networking. Don't bother. */
        return 0;
    }

    if (!etc_connections_dir)
        etc_connections_dir = g_strdup(NM_KEYFILE_PATH_NAME_ETC_DEFAULT);
    if (!connections_dir)
        connections_dir = g_strdup(NM_KEYFILE_PATH_NAME_RUN);
    if (!sysfs_dir)
        sysfs_dir = g_strdup(DEFAULT_SYSFS_DIR);
    if (!initrd_dir)
        initrd_dir = g_strdup(DEFAULT_INITRD_DATA_DIR);
    if (!run_config_dir)
        run_config_dir = g_strdup(DEFAULT_RUN_CONFIG_DIR);

    connections = nmi_cmdline_reader_parse(etc_connections_dir,
                                           sysfs_dir,
                                           (const char *const *) remaining,
                                           &hostname,
                                           &carrier_timeout_sec);

    confs = g_array_new(FALSE, FALSE, sizeof(NMUtilsNamedValue));
    g_array_set_clear_func(confs, (GDestroyNotify) nm_utils_named_value_clear_with_g_free);

    {
        nm_auto_unref_keyfile GKeyFile *keyfile = NULL;
        NMUtilsNamedValue               v;

        keyfile = g_key_file_new();
        g_key_file_set_list_separator(keyfile, NM_CONFIG_KEYFILE_LIST_SEPARATOR);

        g_key_file_set_value(keyfile,
                             NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE "-15-carrier-timeout",
                             NM_CONFIG_KEYFILE_KEY_MATCH_DEVICE,
                             "*");
        g_key_file_set_int64(keyfile,
                             NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE "-15-carrier-timeout",
                             NM_CONFIG_KEYFILE_KEY_DEVICE_CARRIER_WAIT_TIMEOUT,
                             (carrier_timeout_sec != 0 ? carrier_timeout_sec : 10) * 1000);
        if (carrier_timeout_sec == 0) {
            g_key_file_set_value(keyfile,
                                 NM_CONFIG_KEYFILE_GROUP_CONFIG,
                                 NM_CONFIG_KEYFILE_KEY_CONFIG_ENABLE,
                                 "env:initrd");
        }

        if (!dump_to_stdout) {
            add_keyfile_comment(keyfile,
                                carrier_timeout_sec == 0 ? "default initrd carrier timeout"
                                                         : "from \"rd.net.timeout.carrier\"");
        }

        v = (NMUtilsNamedValue){
            .name      = g_strdup_printf("%s/15-carrier-timeout.conf", run_config_dir),
            .value_str = g_key_file_to_data(keyfile, NULL, NULL),
        };
        g_array_append_val(confs, v);
    }

    if (dump_to_stdout) {
        nm_clear_g_free(&connections_dir);
        nm_clear_g_free(&initrd_dir);
        nm_clear_g_free(&run_config_dir);
        if (hostname)
            g_print("\n*** Hostname '%s' ***\n", hostname);

        for (i = 0; i < confs->len; i++) {
            NMUtilsNamedValue *v    = &nm_g_array_index(confs, NMUtilsNamedValue, i);
            gs_free char      *name = g_path_get_basename(v->name);

            g_print("\n*** Configuration '%s' ***\n\n%s\n", name, v->value_str);
        }
    } else {
        if (g_mkdir_with_parents(connections_dir, 0755) != 0) {
            errsv = errno;
            _LOGW(LOGD_CORE, "%s: %s", connections_dir, nm_strerror_native(errsv));
            return 1;
        }
        if (g_mkdir_with_parents(initrd_dir, 0755) != 0) {
            errsv = errno;
            _LOGW(LOGD_CORE, "%s: %s", initrd_dir, nm_strerror_native(errsv));
            return 1;
        }
        if (g_mkdir_with_parents(run_config_dir, 0755) != 0) {
            errsv = errno;
            _LOGW(LOGD_CORE, "%s: %s", run_config_dir, nm_strerror_native(errsv));
            return 1;
        }

        if (hostname) {
            gs_free char *hostname_file = NULL;
            gs_free char *data          = NULL;

            hostname_file = g_strdup_printf("%s/hostname", initrd_dir);
            data          = g_strdup_printf("%s\n", hostname);

            if (!g_file_set_contents(hostname_file, data, strlen(data), &error)) {
                _LOGW(LOGD_CORE, "%s: %s", hostname_file, error->message);
                return 1;
            }
        }

        for (i = 0; i < confs->len; i++) {
            NMUtilsNamedValue *v = &nm_g_array_index(confs, NMUtilsNamedValue, i);

            if (!g_file_set_contents(v->name, v->value_str, strlen(v->value_str), &error)) {
                _LOGW(LOGD_CORE, "%s: %s", v->name, error->message);
                return 1;
            }
        }
    }

    g_hash_table_foreach(connections, output_conn, connections_dir);
    g_hash_table_destroy(connections);

    return 0;
}
