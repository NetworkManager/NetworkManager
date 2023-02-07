/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Jiri Klimes <jklimes@redhat.com>
 * Copyright (C) 2010 - 2018 Red Hat, Inc.
 */

#include "libnm-client-aux-extern/nm-default-client.h"

#include "nmcli.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <locale.h>
#if HAVE_EDITLINE_READLINE
#include <editline/readline.h>
#else
#include <readline/readline.h>
#include <readline/history.h>
#endif

#include "libnmc-base/nm-client-utils.h"

#include "polkit-agent.h"
#include "utils.h"
#include "common.h"
#include "connections.h"
#include "devices.h"
#include "settings.h"

#if defined(NM_DIST_VERSION)
#define NMCLI_VERSION NM_DIST_VERSION
#else
#define NMCLI_VERSION VERSION
#endif

#define _NMC_COLOR_PALETTE_INIT()                              \
    {                                                          \
        .ansi_seq = {                                          \
            [NM_META_COLOR_CONNECTION_ACTIVATED]     = "32",   \
            [NM_META_COLOR_CONNECTION_ACTIVATING]    = "33",   \
            [NM_META_COLOR_CONNECTION_DISCONNECTING] = "31",   \
            [NM_META_COLOR_CONNECTION_INVISIBLE]     = "2",    \
            [NM_META_COLOR_CONNECTION_EXTERNAL]      = "32;2", \
            [NM_META_COLOR_CONNECTION_DEPRECATED]    = "2",    \
            [NM_META_COLOR_CONNECTIVITY_FULL]        = "32",   \
            [NM_META_COLOR_CONNECTIVITY_LIMITED]     = "33",   \
            [NM_META_COLOR_CONNECTIVITY_NONE]        = "31",   \
            [NM_META_COLOR_CONNECTIVITY_PORTAL]      = "33",   \
            [NM_META_COLOR_DEVICE_ACTIVATED]         = "32",   \
            [NM_META_COLOR_DEVICE_ACTIVATING]        = "33",   \
            [NM_META_COLOR_DEVICE_DISCONNECTED]      = "31",   \
            [NM_META_COLOR_DEVICE_FIRMWARE_MISSING]  = "31",   \
            [NM_META_COLOR_DEVICE_PLUGIN_MISSING]    = "31",   \
            [NM_META_COLOR_DEVICE_UNAVAILABLE]       = "2",    \
            [NM_META_COLOR_DEVICE_DISABLED]          = "31",   \
            [NM_META_COLOR_DEVICE_EXTERNAL]          = "32;2", \
            [NM_META_COLOR_MANAGER_RUNNING]          = "32",   \
            [NM_META_COLOR_MANAGER_STARTING]         = "33",   \
            [NM_META_COLOR_MANAGER_STOPPED]          = "31",   \
            [NM_META_COLOR_PERMISSION_AUTH]          = "33",   \
            [NM_META_COLOR_PERMISSION_NO]            = "31",   \
            [NM_META_COLOR_PERMISSION_YES]           = "32",   \
            [NM_META_COLOR_STATE_ASLEEP]             = "31",   \
            [NM_META_COLOR_STATE_CONNECTED_GLOBAL]   = "32",   \
            [NM_META_COLOR_STATE_CONNECTED_LOCAL]    = "32",   \
            [NM_META_COLOR_STATE_CONNECTED_SITE]     = "32",   \
            [NM_META_COLOR_STATE_CONNECTING]         = "33",   \
            [NM_META_COLOR_STATE_DISCONNECTED]       = "31",   \
            [NM_META_COLOR_STATE_DISCONNECTING]      = "33",   \
            [NM_META_COLOR_WIFI_SIGNAL_EXCELLENT]    = "32",   \
            [NM_META_COLOR_WIFI_SIGNAL_FAIR]         = "35",   \
            [NM_META_COLOR_WIFI_SIGNAL_GOOD]         = "33",   \
            [NM_META_COLOR_WIFI_SIGNAL_POOR]         = "36",   \
            [NM_META_COLOR_WIFI_SIGNAL_UNKNOWN]      = "2",    \
            [NM_META_COLOR_WIFI_DEPRECATED]          = "2",    \
            [NM_META_COLOR_ENABLED]                  = "32",   \
            [NM_META_COLOR_DISABLED]                 = "31",   \
        },                                                     \
    }

static NmCli nm_cli = {
    .client = NULL,

    .return_value = NMC_RESULT_SUCCESS,

    .timeout = -1,

    .secret_agent = NULL,
    .pwds_hash    = NULL,
    .pk_listener  = NULL,

    .should_wait                 = 0,
    .nowait_flag                 = TRUE,
    .nmc_config.print_output     = NMC_PRINT_NORMAL,
    .nmc_config.multiline_output = FALSE,
    .mode_specified              = FALSE,
    .nmc_config.escape_values    = TRUE,
    .required_fields             = NULL,
    .ask                         = FALSE,
    .complete                    = FALSE,
    .nmc_config.show_secrets     = FALSE,
    .nmc_config.in_editor        = FALSE,
    .nmc_config.palette          = _NMC_COLOR_PALETTE_INIT(),
    .editor_status_line          = FALSE,
    .editor_save_confirmation    = TRUE,
};

const NmCli *const nm_cli_global_readline   = &nm_cli;
const NmCli *const nmc_meta_environment_arg = &nm_cli;

/*****************************************************************************/

typedef struct {
    NmCli *nmc;
    int    argc;
    char **argv;
} ArgsInfo;

/* --- Global variables --- */
GMainLoop *loop = NULL;

NM_CACHED_QUARK_FCN("nmcli-error-quark", nmcli_error_quark);

static void
complete_field_setting(GHashTable *h, NMMetaSettingType setting_type)
{
    const NMMetaSettingInfoEditor *setting_info = &nm_meta_setting_infos_editor[setting_type];
    guint                          i;

    for (i = 0; i < setting_info->properties_num; i++) {
        g_hash_table_add(h,
                         g_strdup_printf("%s.%s",
                                         setting_info->general->setting_name,
                                         setting_info->properties[i]->property_name));
    }
}

static void
complete_field(GHashTable *h, const NmcMetaGenericInfo *const *field)
{
    int i;

    for (i = 0; field[i]; i++)
        g_hash_table_add(h, g_strdup(field[i]->name));
}

static void
complete_one(gpointer key, gpointer value, gpointer user_data)
{
    const char **option_with_value = user_data;
    const char  *option            = option_with_value[0];
    const char  *prefix            = option_with_value[1];
    const char  *name              = key;
    const char  *last;

    last = strrchr(prefix, ',');
    if (last)
        last++;
    else
        last = prefix;

    if ((!*last && !strchr(name, '.')) || matches(last, name)) {
        if (option != prefix) {
            /* value prefix was not a standalone argument,
             * it was part of --option=<value> argument.
             * Repeat the part leading to "=". */
            nmc_print("%s=", option);
        }
        nmc_print("%.*s%s%s\n",
                  (int) (last - prefix),
                  prefix,
                  name,
                  strcmp(last, name) == 0 ? "," : "");
    }
}

static void
complete_fields(const char *option, const char *prefix)
{
    guint       i;
    GHashTable *h;
    const char *option_with_value[2] = {option, prefix};

    h = g_hash_table_new_full(nm_str_hash, g_str_equal, g_free, NULL);

    complete_field(h, metagen_ip4_config);
    complete_field(h, metagen_dhcp_config);
    complete_field(h, metagen_ip6_config);
    complete_field(h, metagen_con_show);
    complete_field(h, metagen_con_active_general);
    complete_field(h, metagen_con_active_vpn);
    complete_field(h, nmc_fields_con_active_details_groups);
    complete_field(h, metagen_device_status);
    complete_field(h, metagen_device_detail_general);
    complete_field(h, metagen_device_detail_connections);
    complete_field(h, metagen_device_detail_capabilities);
    complete_field(h, metagen_device_detail_wired_properties);
    complete_field(h, metagen_device_detail_wifi_properties);
    complete_field(h, metagen_device_detail_wimax_properties);
    complete_field(h, nmc_fields_dev_wifi_list);
    complete_field(h, nmc_fields_dev_wimax_list);
    complete_field(h, nmc_fields_dev_show_master_prop);
    complete_field(h, nmc_fields_dev_show_team_prop);
    complete_field(h, nmc_fields_dev_show_vlan_prop);
    complete_field(h, nmc_fields_dev_show_bluetooth);
    complete_field(h, nmc_fields_dev_show_sections);
    complete_field(h, nmc_fields_dev_lldp_list);

    for (i = 0; i < _NM_META_SETTING_TYPE_NUM; i++)
        complete_field_setting(h, i);

    g_hash_table_foreach(h, complete_one, (gpointer) &option_with_value[0]);
    g_hash_table_destroy(h);
}

static void
complete_option_with_value(const char *option, const char *prefix, ...)
{
    va_list     args;
    const char *candidate;

    va_start(args, prefix);
    while ((candidate = va_arg(args, const char *))) {
        if (!*prefix || matches(prefix, candidate)) {
            if (option != prefix) {
                /* value prefix was not a standalone argument,
                 * it was part of --option=<value> argument.
                 * Repeat the part leading to "=". */
                nmc_print("%s=", option);
            }
            nmc_print("%s\n", candidate);
        }
    }
    va_end(args);
}

static void
usage(void)
{
    nmc_printerr(_(
        "Usage: nmcli [OPTIONS] OBJECT { COMMAND | help }\n"
        "\n"
        "OPTIONS\n"
        "  -a, --ask                                ask for missing parameters\n"
        "  -c, --colors auto|yes|no                 whether to use colors in output\n"
        "  -e, --escape yes|no                      escape columns separators in values\n"
        "  -f, --fields <field,...>|all|common      specify fields to output\n"
        "  -g, --get-values <field,...>|all|common  shortcut for -m tabular -t -f\n"
        "  -h, --help                               print this help\n"
        "  -m, --mode tabular|multiline             output mode\n"
        "  -o, --overview                           overview mode\n"
        "  -p, --pretty                             pretty output\n"
        "  -s, --show-secrets                       allow displaying passwords\n"
        "  -t, --terse                              terse output\n"
        "  -v, --version                            show program version\n"
        "  -w, --wait <seconds>                     set timeout waiting for finishing operations\n"
        "\n"
        "OBJECT\n"
        "  g[eneral]       NetworkManager's general status and operations\n"
        "  n[etworking]    overall networking control\n"
        "  r[adio]         NetworkManager radio switches\n"
        "  c[onnection]    NetworkManager's connections\n"
        "  d[evice]        devices managed by NetworkManager\n"
        "  a[gent]         NetworkManager secret agent or polkit agent\n"
        "  m[onitor]       monitor NetworkManager changes\n"
        "\n"));
}

static gboolean
matches_arg(NmCli *nmc, int *argc, const char *const **argv, const char *pattern, char **arg)
{
    gs_free char *opt_free = NULL;
    const char   *opt      = (*argv)[0];
    gs_free char *arg_tmp  = NULL;
    const char   *s;

    nm_assert(opt);
    nm_assert(opt[0] == '-');
    nm_assert(!arg || !*arg);

    if (nmc->return_value != NMC_RESULT_SUCCESS) {
        /* Don't process further matches if there has been an error. */
        return FALSE;
    }

    if (opt[1] == '-') {
        /* We know one '-' was already seen by the caller.
         * Skip it if there's a second one*/
        opt++;
    }

    if (arg) {
        /* If there's a "=" separator, replace it with NUL so that matches()
         * works and consider the part after it to be the argument's value. */
        s = strchr(opt, '=');
        if (s) {
            opt     = nm_strndup_a(300, opt, s - opt, &opt_free);
            arg_tmp = g_strdup(&s[1]);
        }
    }

    if (!matches(opt, pattern))
        return FALSE;

    if (arg) {
        if (arg_tmp)
            *arg = g_steal_pointer(&arg_tmp);
        else {
            /* We need a value, but the option didn't contain a "=<value>" part.
             * Proceed to the next argument. */
            if (*argc <= 1) {
                g_string_printf(nmc->return_text,
                                _("Error: missing argument for '%s' option."),
                                opt);
                nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
                return FALSE;
            }
            (*argc)--;
            (*argv)++;
            *arg = g_strdup(*argv[0]);
        }
    }

    return TRUE;
}

/*************************************************************************************/

typedef enum {
    NMC_USE_COLOR_AUTO,
    NMC_USE_COLOR_YES,
    NMC_USE_COLOR_NO,
} NmcColorOption;

static char *
check_colors_construct_filename(const char *base_dir,
                                const char *name,
                                const char *term,
                                const char *type)
{
    return g_strdup_printf("%s/terminal-colors.d/%s%s%s%s%s",
                           base_dir,
                           name ? name : "",
                           term ? "@" : "",
                           term ? term : "",
                           (name || term) ? "." : "",
                           type);
}

static NmcColorOption
check_colors_check_enabled_one_file(const char *base_dir, const char *name, const char *term)
{
    gs_free char *filename_e = NULL;
    gs_free char *filename_d = NULL;

    filename_e = check_colors_construct_filename(base_dir, name, term, "enable");
    if (g_file_test(filename_e, G_FILE_TEST_EXISTS))
        return NMC_USE_COLOR_YES;

    filename_d = check_colors_construct_filename(base_dir, name, term, "disable");
    if (g_file_test(filename_d, G_FILE_TEST_EXISTS))
        return NMC_USE_COLOR_NO;

    return NMC_USE_COLOR_AUTO;
}

static char *
check_colors_check_palette_one_file(const char *base_dir, const char *name, const char *term)
{
    static const char *const extensions[] = {
        "scheme",
        "schem",
    };
    guint i;

    for (i = 0; i < G_N_ELEMENTS(extensions); i++) {
        gs_free char *filename = NULL;
        char         *contents;

        filename = check_colors_construct_filename(base_dir, name, term, extensions[i]);
        if (g_file_get_contents(filename, &contents, NULL, NULL))
            return contents;
    }

    return NULL;
}

static gboolean
check_colors_check_enabled(const char *base_dir_1,
                           const char *base_dir_2,
                           const char *name,
                           const char *term)
{
    int i;

    if (term && strchr(term, '/'))
        term = NULL;

#define CHECK_AND_RETURN(cmd)                          \
    G_STMT_START                                       \
    {                                                  \
        NmcColorOption _color_option;                  \
                                                       \
        _color_option = (cmd);                         \
        if (_color_option != NMC_USE_COLOR_AUTO)       \
            return _color_option == NMC_USE_COLOR_YES; \
    }                                                  \
    G_STMT_END

    for (i = 0; i < 2; i++) {
        const char *base_dir = (i == 0 ? base_dir_1 : base_dir_2);

        if (!base_dir)
            continue;
        if (name && term)
            CHECK_AND_RETURN(check_colors_check_enabled_one_file(base_dir, name, term));
        if (name)
            CHECK_AND_RETURN(check_colors_check_enabled_one_file(base_dir, name, NULL));
        if (term)
            CHECK_AND_RETURN(check_colors_check_enabled_one_file(base_dir, NULL, term));
        if (TRUE)
            CHECK_AND_RETURN(check_colors_check_enabled_one_file(base_dir, NULL, NULL));
    }
#undef CHECK_AND_RETURN
    return TRUE;
}

static char *
check_colors_check_palette(const char *base_dir_1,
                           const char *base_dir_2,
                           const char *name,
                           const char *term)
{
    int i;

    if (term && strchr(term, '/'))
        term = NULL;

#define CHECK_AND_RETURN(cmd) \
    G_STMT_START              \
    {                         \
        char *_palette;       \
                              \
        _palette = (cmd);     \
        if (_palette)         \
            return _palette;  \
    }                         \
    G_STMT_END

    for (i = 0; i < 2; i++) {
        const char *base_dir = (i == 0 ? base_dir_1 : base_dir_2);

        if (!base_dir)
            continue;
        if (name && term)
            CHECK_AND_RETURN(check_colors_check_palette_one_file(base_dir, name, term));
        if (name)
            CHECK_AND_RETURN(check_colors_check_palette_one_file(base_dir, name, NULL));
        if (term)
            CHECK_AND_RETURN(check_colors_check_palette_one_file(base_dir, NULL, term));
        if (TRUE)
            CHECK_AND_RETURN(check_colors_check_palette_one_file(base_dir, NULL, NULL));
    }
#undef CHECK_AND_RETURN
    return NULL;
}

static gboolean
check_colors(NmcColorOption color_option, char **out_palette_str)
{
    const char       *base_dir_1, *base_dir_2;
    const char *const NAME = "nmcli";
    const char       *term;

    *out_palette_str = NULL;

    if (!NM_IN_SET(color_option, NMC_USE_COLOR_AUTO, NMC_USE_COLOR_YES)) {
        /* nothing to do. Colors are disabled. */
        return FALSE;
    }

    if (color_option == NMC_USE_COLOR_AUTO && g_getenv("NO_COLOR")) {
        /* https://no-color.org/ */
        return FALSE;
    }

    term = g_getenv("TERM");

    if (color_option == NMC_USE_COLOR_AUTO) {
        if (nm_streq0(term, "dumb") || !isatty(STDOUT_FILENO))
            return FALSE;
    }

    base_dir_1 = g_get_user_config_dir();
    base_dir_2 = "" SYSCONFDIR;

    if (base_dir_1) {
        if (nm_streq(base_dir_1, base_dir_2) || !g_file_test(base_dir_1, G_FILE_TEST_EXISTS))
            base_dir_1 = NULL;
    }
    if (!g_file_test(base_dir_2, G_FILE_TEST_EXISTS))
        base_dir_2 = NULL;

    if (color_option == NMC_USE_COLOR_AUTO
        && !check_colors_check_enabled(base_dir_1, base_dir_2, NAME, term))
        return FALSE;

    *out_palette_str = check_colors_check_palette(base_dir_1, base_dir_2, NAME, term);
    return TRUE;
}

static NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _resolve_color_alias,
    const char *,
    { nm_assert(name); },
    { return NULL; },
    {"black", "30"},
    {"blink", "5"},
    {"blue", "34"},
    {"bold", "1"},
    {"brown", "33"},
    {"cyan", "36"},
    {"darkgray", "90"},
    {"gray", "37"},
    {"green", "32"},
    {"halfbright", "2"},
    {"lightblue", "94"},
    {"lightcyan", "96"},
    {"lightgray", "97"},
    {"lightgreen", "92"},
    {"lightmagenta", "95"},
    {"lightred", "91"},
    {"magenta", "35"},
    {"red", "31"},
    {"reset", "0"},
    {"reverse", "7"},
    {"underscore", "4"},
    {"white", "1;37"},
    {"yellow", "33" /* well, yellow */}, );

static NM_UTILS_STRING_TABLE_LOOKUP_DEFINE(
    _nm_meta_color_from_name,
    NMMetaColor,
    { nm_assert(name); },
    { return NM_META_COLOR_NONE; },
    {"connection-activated", NM_META_COLOR_CONNECTION_ACTIVATED},
    {"connection-activating", NM_META_COLOR_CONNECTION_ACTIVATING},
    {"connection-disconnecting", NM_META_COLOR_CONNECTION_DISCONNECTING},
    {"connection-external", NM_META_COLOR_CONNECTION_EXTERNAL},
    {"connection-invisible", NM_META_COLOR_CONNECTION_INVISIBLE},
    {"connection-unknown", NM_META_COLOR_CONNECTION_UNKNOWN},
    {"connection-deprecated", NM_META_COLOR_CONNECTION_DEPRECATED},
    {"connectivity-full", NM_META_COLOR_CONNECTIVITY_FULL},
    {"connectivity-limited", NM_META_COLOR_CONNECTIVITY_LIMITED},
    {"connectivity-none", NM_META_COLOR_CONNECTIVITY_NONE},
    {"connectivity-portal", NM_META_COLOR_CONNECTIVITY_PORTAL},
    {"connectivity-unknown", NM_META_COLOR_CONNECTIVITY_UNKNOWN},
    {"device-activated", NM_META_COLOR_DEVICE_ACTIVATED},
    {"device-activating", NM_META_COLOR_DEVICE_ACTIVATING},
    {"device-disabled", NM_META_COLOR_DEVICE_DISABLED},
    {"device-disconnected", NM_META_COLOR_DEVICE_DISCONNECTED},
    {"device-external", NM_META_COLOR_DEVICE_EXTERNAL},
    {"device-firmware-missing", NM_META_COLOR_DEVICE_FIRMWARE_MISSING},
    {"device-plugin-missing", NM_META_COLOR_DEVICE_PLUGIN_MISSING},
    {"device-unavailable", NM_META_COLOR_DEVICE_UNAVAILABLE},
    {"device-unknown", NM_META_COLOR_DEVICE_UNKNOWN},
    {"disabled", NM_META_COLOR_DISABLED},
    {"enabled", NM_META_COLOR_ENABLED},
    {"manager-running", NM_META_COLOR_MANAGER_RUNNING},
    {"manager-starting", NM_META_COLOR_MANAGER_STARTING},
    {"manager-stopped", NM_META_COLOR_MANAGER_STOPPED},
    {"permission-auth", NM_META_COLOR_PERMISSION_AUTH},
    {"permission-no", NM_META_COLOR_PERMISSION_NO},
    {"permission-unknown", NM_META_COLOR_PERMISSION_UNKNOWN},
    {"permission-yes", NM_META_COLOR_PERMISSION_YES},
    {"prompt", NM_META_COLOR_PROMPT},
    {"state-asleep", NM_META_COLOR_STATE_ASLEEP},
    {"state-connected-global", NM_META_COLOR_STATE_CONNECTED_GLOBAL},
    {"state-connected-local", NM_META_COLOR_STATE_CONNECTED_LOCAL},
    {"state-connected-site", NM_META_COLOR_STATE_CONNECTED_SITE},
    {"state-connecting", NM_META_COLOR_STATE_CONNECTING},
    {"state-disconnected", NM_META_COLOR_STATE_DISCONNECTED},
    {"state-disconnecting", NM_META_COLOR_STATE_DISCONNECTING},
    {"state-unknown", NM_META_COLOR_STATE_UNKNOWN},
    {"wifi-signal-excellent", NM_META_COLOR_WIFI_SIGNAL_EXCELLENT},
    {"wifi-signal-fair", NM_META_COLOR_WIFI_SIGNAL_FAIR},
    {"wifi-signal-good", NM_META_COLOR_WIFI_SIGNAL_GOOD},
    {"wifi-signal-poor", NM_META_COLOR_WIFI_SIGNAL_POOR},
    {"wifi-signal-unknown", NM_META_COLOR_WIFI_SIGNAL_UNKNOWN},
    {"wifi-deprecated", NM_META_COLOR_WIFI_DEPRECATED}, );

static gboolean
parse_color_scheme(char *palette_buffer, NmcColorPalette *out_palette, GError **error)
{
    char *p = palette_buffer;

    nm_assert(out_palette);

    *out_palette = (NmcColorPalette) _NMC_COLOR_PALETTE_INIT();

    /* This reads through the raw color scheme file contents, identifying the
     * color names and sequences, putting in terminating NULs in place, so that
     * pointers into the buffer can readily be used as strings in the palette. */
    while (1) {
        NMMetaColor name_idx;
        const char *name;
        const char *color;

        /* Leading whitespace. */
        while (nm_utils_is_separator(*p) || *p == '\n')
            p++;

        if (*p == '\0')
            break;

        /* Comments. */
        if (*p == '#') {
            while (*p != '\n' && *p != '\0')
                p++;
            continue;
        }

        /* Color name. */
        name = p;
        while (g_ascii_isgraph(*p))
            p++;
        if (*p == '\0') {
            g_set_error(error, NMCLI_ERROR, 0, _("Unexpected end of file following '%s'\n"), name);
            return FALSE;
        }

        /* Separating whitespace. */
        if (!nm_utils_is_separator(*p)) {
            *p = '\0';
            g_set_error(error, NMCLI_ERROR, 0, _("Expected whitespace following '%s'\n"), name);
            return FALSE;
        }
        while (nm_utils_is_separator(*p)) {
            *p = '\0';
            p++;
        }

        /* Color sequence. */
        color = p;
        if (!g_ascii_isgraph(*p)) {
            g_set_error(error, NMCLI_ERROR, 0, _("Expected a value for '%s'\n"), name);
            return FALSE;
        }
        while (g_ascii_isgraph(*p))
            p++;

        /* Trailing whitespace. */
        while (nm_utils_is_separator(*p)) {
            *p = '\0';
            p++;
        }
        if (*p != '\0') {
            if (*p != '\n') {
                g_set_error(error,
                            NMCLI_ERROR,
                            0,
                            _("Expected a line break following '%s'\n"),
                            color);
                return FALSE;
            }
            *p = '\0';
            p++;
        }

        name_idx = _nm_meta_color_from_name(name);
        if (name_idx == NM_META_COLOR_NONE) {
            g_debug("Ignoring an unrecognized color: '%s'\n", name);
            continue;
        }

        out_palette->ansi_seq[name_idx] = _resolve_color_alias(color) ?: color;
    }

    return TRUE;
}

static void
set_colors(NmcColorOption   color_option,
           bool            *out_use_colors,
           char           **out_palette_buffer,
           NmcColorPalette *out_palette)
{
    gs_free char *palette_str = NULL;
    gboolean      use_colors;
    gboolean      palette_set = FALSE;

    nm_assert(out_use_colors);
    nm_assert(out_palette);
    nm_assert(out_palette_buffer && !*out_palette_buffer);

    use_colors = check_colors(color_option, &palette_str);

    *out_use_colors = use_colors;

    if (use_colors && palette_str) {
        gs_free_error GError *error = NULL;
        NmcColorPalette       palette;

        if (!parse_color_scheme(palette_str, &palette, &error))
            g_debug("Error parsing color scheme: %s", error->message);
        else {
            *out_palette_buffer = g_steal_pointer(&palette_str);
            *out_palette        = palette;
            palette_set         = TRUE;
        }
    }

    if (!palette_set)
        *out_palette = (NmcColorPalette) _NMC_COLOR_PALETTE_INIT();
}

/*************************************************************************************/

static gboolean
process_command_line(NmCli *nmc, int argc, char **argv_orig)
{
    static const NMCCommand nmcli_cmds[] = {
        {"general", nmc_command_func_general, NULL, FALSE, FALSE},
        {"monitor", nmc_command_func_monitor, NULL, TRUE, FALSE},
        {"networking", nmc_command_func_networking, NULL, FALSE, FALSE},
        {"radio", nmc_command_func_radio, NULL, FALSE, FALSE},
        {"connection", nmc_command_func_connection, NULL, FALSE, FALSE, TRUE},
        {"device", nmc_command_func_device, NULL, FALSE, FALSE},
        {"agent", nmc_command_func_agent, NULL, FALSE, FALSE},
        {NULL, nmc_command_func_overview, usage, TRUE, TRUE},
    };
    NmcColorOption     colors = NMC_USE_COLOR_AUTO;
    const char        *base;
    const char *const *argv;

    base = strrchr(argv_orig[0], '/');
    if (base == NULL)
        base = argv_orig[0];
    else
        base++;

    if (argc > 1 && nm_streq(argv_orig[1], "--complete-args")) {
        nmc->complete = TRUE;
        argv_orig[1]  = argv_orig[0];
        argc--;
        argv_orig++;
    }

    argv = (const char *const *) argv_orig;

    next_arg(nmc, &argc, &argv, NULL);

    /* parse options */
    while (argc) {
        gs_free char *value = NULL;

        if (argv[0][0] != '-')
            break;

        if (argc == 1 && nmc->complete) {
            nmc_complete_strings(argv[0],
                                 "--overview",
                                 "--offline",
                                 "--terse",
                                 "--pretty",
                                 "--mode",
                                 "--colors",
                                 "--escape",
                                 "--fields",
                                 "--get-values",
                                 "--nocheck",
                                 "--wait",
                                 "--version",
                                 "--help");
        }

        if (argv[0][1] == '-' && argv[0][2] == '\0') {
            /* '--' ends options */
            next_arg(nmc, &argc, &argv, NULL);
            break;
        }

        if (matches_arg(nmc, &argc, &argv, "-overview", NULL)) {
            nmc->nmc_config_mutable.overview = TRUE;
        } else if (matches_arg(nmc, &argc, &argv, "-offline", NULL)) {
            nmc->offline = TRUE;
        } else if (matches_arg(nmc, &argc, &argv, "-terse", NULL)) {
            if (nmc->nmc_config.print_output == NMC_PRINT_TERSE) {
                g_string_printf(nmc->return_text,
                                _("Error: Option '--terse' is specified the second time."));
                nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
                return FALSE;
            } else if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY) {
                g_string_printf(
                    nmc->return_text,
                    _("Error: Option '--terse' is mutually exclusive with '--pretty'."));
                nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
                return FALSE;
            } else
                nmc->nmc_config_mutable.print_output = NMC_PRINT_TERSE;
        } else if (matches_arg(nmc, &argc, &argv, "-pretty", NULL)) {
            if (nmc->nmc_config.print_output == NMC_PRINT_PRETTY) {
                g_string_printf(nmc->return_text,
                                _("Error: Option '--pretty' is specified the second time."));
                nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
                return FALSE;
            } else if (nmc->nmc_config.print_output == NMC_PRINT_TERSE) {
                g_string_printf(
                    nmc->return_text,
                    _("Error: Option '--pretty' is mutually exclusive with '--terse'."));
                nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
                return FALSE;
            } else
                nmc->nmc_config_mutable.print_output = NMC_PRINT_PRETTY;
        } else if (matches_arg(nmc, &argc, &argv, "-mode", &value)) {
            nmc->mode_specified = TRUE;
            if (argc == 1 && nmc->complete)
                complete_option_with_value(argv[0], value, "tabular", "multiline", NULL);
            if (matches(value, "tabular"))
                nmc->nmc_config_mutable.multiline_output = FALSE;
            else if (matches(value, "multiline"))
                nmc->nmc_config_mutable.multiline_output = TRUE;
            else {
                g_string_printf(nmc->return_text,
                                _("Error: '%s' is not a valid argument for '%s' option."),
                                value,
                                argv[0]);
                nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
                return FALSE;
            }
        } else if (matches_arg(nmc, &argc, &argv, "-colors", &value)) {
            if (argc == 1 && nmc->complete)
                complete_option_with_value(argv[0], value, "yes", "no", "auto", NULL);
            if (matches(value, "auto"))
                colors = NMC_USE_COLOR_AUTO;
            else if (matches(value, "yes"))
                colors = NMC_USE_COLOR_YES;
            else if (matches(value, "no"))
                colors = NMC_USE_COLOR_NO;
            else {
                g_string_printf(nmc->return_text,
                                _("Error: '%s' is not valid argument for '%s' option."),
                                value,
                                argv[0]);
                nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
                return FALSE;
            }
        } else if (matches_arg(nmc, &argc, &argv, "-escape", &value)) {
            if (argc == 1 && nmc->complete)
                complete_option_with_value(argv[0], value, "yes", "no", NULL);
            if (matches(value, "yes"))
                nmc->nmc_config_mutable.escape_values = TRUE;
            else if (matches(value, "no"))
                nmc->nmc_config_mutable.escape_values = FALSE;
            else {
                g_string_printf(nmc->return_text,
                                _("Error: '%s' is not valid argument for '%s' option."),
                                value,
                                argv[0]);
                nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
                return FALSE;
            }
        } else if (matches_arg(nmc, &argc, &argv, "-fields", &value)) {
            if (argc == 1 && nmc->complete)
                complete_fields(argv[0], value);
            nmc->required_fields = g_strdup(value);
        } else if (matches_arg(nmc, &argc, &argv, "-get-values", &value)) {
            if (argc == 1 && nmc->complete)
                complete_fields(argv[0], value);
            nmc->required_fields                 = g_strdup(value);
            nmc->nmc_config_mutable.print_output = NMC_PRINT_TERSE;
            /* We want fixed tabular mode here, but just set the mode specified and rely on defaults:
             * in this way we allow use of "-m multiline" to swap the output mode also if placed
             * before the "-g <field>" option (-g may be still more practical and easy to remember than -t -f).
             */
            nmc->mode_specified = TRUE;
        } else if (matches_arg(nmc, &argc, &argv, "-nocheck", NULL)) {
            /* ignore for backward compatibility */
        } else if (matches_arg(nmc, &argc, &argv, "-wait", &value)) {
            unsigned long timeout;

            if (!nmc_string_to_uint(value, TRUE, 0, G_MAXINT, &timeout)) {
                g_string_printf(nmc->return_text, _("Error: '%s' is not a valid timeout."), value);
                nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
                return FALSE;
            }
            nmc->timeout = (int) timeout;
        } else if (matches_arg(nmc, &argc, &argv, "-version", NULL)) {
            if (!nmc->complete)
                nmc_print(_("nmcli tool, version %s\n"), NMCLI_VERSION);
            return NMC_RESULT_SUCCESS;
        } else if (matches_arg(nmc, &argc, &argv, "-help", NULL)) {
            if (!nmc->complete)
                usage();
            return NMC_RESULT_SUCCESS;
        } else {
            if (nmc->return_value == NMC_RESULT_SUCCESS) {
                g_string_printf(nmc->return_text,
                                _("Error: Option '%s' is unknown, try 'nmcli -help'."),
                                argv[0]);
                nmc->return_value = NMC_RESULT_ERROR_USER_INPUT;
            }
            return FALSE;
        }

        next_arg(nmc, &argc, &argv, NULL);
    }

    /* Ignore --overview when fields are set explicitly */
    if (nmc->required_fields)
        nmc->nmc_config_mutable.overview = FALSE;

    set_colors(colors,
               &nmc->nmc_config_mutable.use_colors,
               &nmc->palette_buffer,
               &nmc->nmc_config_mutable.palette);

    /* Now run the requested command */
    nmc_do_cmd(nmc, nmcli_cmds, *argv, argc, argv);

    return TRUE;
}

static gboolean nmcli_sigint = FALSE;

gboolean
nmc_seen_sigint(void)
{
    return nmcli_sigint;
}

void
nmc_clear_sigint(void)
{
    nmcli_sigint = FALSE;
}

void
nmc_exit(void)
{
    nmc_cleanup_readline();
    exit(1);
}

static gboolean
signal_handler(gpointer user_data)
{
    int signo = GPOINTER_TO_INT(user_data);

    switch (signo) {
    case SIGINT:
        if (nmc_get_in_readline()) {
            nmcli_sigint = TRUE;
        } else {
            nm_cli.return_value = 0x80 + signo;
            g_string_printf(nm_cli.return_text,
                            _("Error: nmcli terminated by signal %s (%d)"),
                            strsignal(signo),
                            signo);
            g_main_loop_quit(loop);
        }
        break;
    case SIGTERM:
        nm_cli.return_value = 0x80 + signo;
        g_string_printf(nm_cli.return_text,
                        _("Error: nmcli terminated by signal %s (%d)"),
                        strsignal(signo),
                        signo);
        nmc_exit();
        break;
    }

    return G_SOURCE_CONTINUE;
}

void
nm_cli_spawn_pager(const NmcConfig *nmc_config, NmcPagerData *pager_data)
{
    if (pager_data->pid != 0)
        return;
    pager_data->pid = nmc_terminal_spawn_pager(nmc_config);
}

static void
nmc_cleanup(NmCli *nmc)
{
    pid_t ret;

    g_clear_object(&nmc->client);

    if (nmc->return_text)
        g_string_free(g_steal_pointer(&nmc->return_text), TRUE);

    if (nmc->secret_agent) {
        nm_secret_agent_old_unregister(NM_SECRET_AGENT_OLD(nmc->secret_agent), NULL, NULL);
        g_clear_object(&nmc->secret_agent);
    }

    nm_clear_pointer(&nmc->pwds_hash, g_hash_table_destroy);

    nm_clear_g_free(&nmc->required_fields);

    if (nmc->pager_data.pid != 0) {
        pid_t pid = nm_steal_int(&nmc->pager_data.pid);

        fclose(stdout);
        fclose(stderr);
        do {
            ret = waitpid(pid, NULL, 0);
        } while (ret == -1 && errno == EINTR);
    }

    nm_clear_g_free(&nmc->palette_buffer);

    nm_clear_pointer(&nmc->offline_connections, g_ptr_array_unref);

    nmc_polkit_agent_fini(nmc);
}

int
main(int argc, char *argv[])
{
    /* Set locale to use environment variables */
    setlocale(LC_ALL, "");

#ifdef GETTEXT_PACKAGE
    /* Set i18n stuff */
    bindtextdomain(GETTEXT_PACKAGE, NMLOCALEDIR);
    bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8");
    textdomain(GETTEXT_PACKAGE);
#endif

    nm_cli.return_text = g_string_new(_("Success"));
    loop               = g_main_loop_new(NULL, FALSE);

    g_unix_signal_add(SIGTERM, signal_handler, GINT_TO_POINTER(SIGTERM));
    g_unix_signal_add(SIGINT, signal_handler, GINT_TO_POINTER(SIGINT));

    if (process_command_line(&nm_cli, argc, argv))
        g_main_loop_run(loop);

    if (nm_cli.complete) {
        /* Remove error statuses from command completion runs. */
        if (nm_cli.return_value < NMC_RESULT_COMPLETE_FILE)
            nm_cli.return_value = NMC_RESULT_SUCCESS;
    } else if (nm_cli.return_value != NMC_RESULT_SUCCESS) {
        /* Print result descripting text */
        nmc_printerr("%s\n", nm_cli.return_text->str);
    }

    nmc_cleanup(&nm_cli);
    g_main_loop_unref(loop);

    return nm_cli.return_value;
}
