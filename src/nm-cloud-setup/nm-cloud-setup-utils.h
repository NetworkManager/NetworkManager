/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef __NM_CLOUD_SETUP_UTILS_H__
#define __NM_CLOUD_SETUP_UTILS_H__

#include "libnm-glib-aux/nm-logging-base.h"

/*****************************************************************************/

/* Environment variables for configuring nm-cloud-setup */
#define NMCS_ENV_NM_CLOUD_SETUP_ALIYUN "NM_CLOUD_SETUP_ALIYUN"
#define NMCS_ENV_NM_CLOUD_SETUP_AZURE  "NM_CLOUD_SETUP_AZURE"
#define NMCS_ENV_NM_CLOUD_SETUP_EC2    "NM_CLOUD_SETUP_EC2"
#define NMCS_ENV_NM_CLOUD_SETUP_GCP    "NM_CLOUD_SETUP_GCP"
#define NMCS_ENV_NM_CLOUD_SETUP_LOG    "NM_CLOUD_SETUP_LOG"

/* Undocumented/internal environment variables for configuring nm-cloud-setup.
 * These are mainly for testing/debugging. */
#define NMCS_ENV_NM_CLOUD_SETUP_ALIYUN_HOST    "NM_CLOUD_SETUP_ALIYUN_HOST"
#define NMCS_ENV_NM_CLOUD_SETUP_AZURE_HOST     "NM_CLOUD_SETUP_AZURE_HOST"
#define NMCS_ENV_NM_CLOUD_SETUP_EC2_HOST       "NM_CLOUD_SETUP_EC2_HOST"
#define NMCS_ENV_NM_CLOUD_SETUP_GCP_HOST       "NM_CLOUD_SETUP_GCP_HOST"
#define NMCS_ENV_NM_CLOUD_SETUP_MAP_INTERFACES "NM_CLOUD_SETUP_MAP_INTERFACES"

/*****************************************************************************/

#define _nm_log(level, ...) _nm_log_simple_printf((level), __VA_ARGS__);

#define _NMLOG(level, ...)                 \
    G_STMT_START                           \
    {                                      \
        const NMLogLevel _level = (level); \
                                           \
        if (_nm_logging_enabled(_level)) { \
            _nm_log(_level, __VA_ARGS__);  \
        }                                  \
    }                                      \
    G_STMT_END

/*****************************************************************************/

#ifndef NM_DIST_VERSION
#define NM_DIST_VERSION VERSION
#endif

/*****************************************************************************/

gpointer nmcs_wait_for_objects_register(gpointer target);

gboolean nmcs_wait_for_objects_iterate_until_done(GMainContext *context, int timeout_msec);

/*****************************************************************************/

char *nmcs_utils_hwaddr_normalize(const char *hwaddr, gssize len);

static inline char *
nmcs_utils_hwaddr_normalize_gbytes(GBytes *hwaddr)
{
    const char *str;
    gsize       len;

    str = g_bytes_get_data(hwaddr, &len);
    return nmcs_utils_hwaddr_normalize(str, len);
}

/*****************************************************************************/

gboolean nmcs_utils_ipaddr_normalize_bin(int         addr_family,
                                         const char *addr,
                                         gssize      len,
                                         int        *out_addr_family,
                                         gpointer    out_addr_bin);

char *nmcs_utils_ipaddr_normalize(int addr_family, const char *addr, gssize len);

static inline char *
nmcs_utils_ipaddr_normalize_gbytes(int addr_family, GBytes *addr)
{
    const char *str;
    gsize       len;

    str = g_bytes_get_data(addr, &len);
    return nmcs_utils_ipaddr_normalize(addr_family, str, len);
}

/*****************************************************************************/

const char *nmcs_utils_parse_memmem(GBytes *mem, const char *needle);

const char *nmcs_utils_parse_get_full_line(GBytes *mem, const char *needle);

/*****************************************************************************/

#define NMCS_DEFINE_HOST_BASE(base_fcn, nmcs_env_host, default_host)               \
    static const char *base_fcn(void)                                              \
    {                                                                              \
        static const char *base_cached = NULL;                                     \
        const char        *base;                                                   \
                                                                                   \
again:                                                                             \
        base = g_atomic_pointer_get(&base_cached);                                 \
        if (G_UNLIKELY(!base)) {                                                   \
            /* The base URI can be set via environment variable. \
             * This is mainly for testing, it's not usually supposed to be configured. \
             * Consider this private API! */                 \
            base = g_getenv("" nmcs_env_host "");                                  \
            base = nmcs_utils_uri_complete_interned(base) ?: ("" default_host ""); \
                                                                                   \
            if (!g_atomic_pointer_compare_and_exchange(&base_cached, NULL, base))  \
                goto again;                                                        \
                                                                                   \
            if (!nm_streq(base, ("" default_host ""))) {                           \
                _LOGD("test: mock %s=\"%s\" (default \"%s\")",                     \
                      "" nmcs_env_host "",                                         \
                      base,                                                        \
                      "" default_host "");                                         \
            }                                                                      \
        }                                                                          \
                                                                                   \
        return base;                                                               \
    }                                                                              \
    _NM_DUMMY_STRUCT_FOR_TRAILING_SEMICOLON

/*****************************************************************************/

char *nmcs_utils_uri_build_concat_v(const char *base, const char **components, gsize n_components);

#define nmcs_utils_uri_build_concat(base, ...) \
    nmcs_utils_uri_build_concat_v(base, ((const char *[]){__VA_ARGS__}), NM_NARG(__VA_ARGS__))

const char *nmcs_utils_uri_complete_interned(const char *uri);

/*****************************************************************************/

gboolean nmcs_setting_ip_replace_ipv4_addresses(NMSettingIPConfig *s_ip,
                                                NMIPAddress      **entries_arr,
                                                guint              entries_len);

gboolean nmcs_setting_ip_replace_ipv4_routes(NMSettingIPConfig *s_ip,
                                             NMIPRoute        **entries_arr,
                                             guint              entries_len);

gboolean nmcs_setting_ip_replace_ipv4_rules(NMSettingIPConfig *s_ip,
                                            NMIPRoutingRule  **entries_arr,
                                            guint              entries_len);

/*****************************************************************************/

NMConnection *nmcs_device_get_applied_connection(NMDevice     *device,
                                                 GCancellable *cancellable,
                                                 guint64      *version_id,
                                                 GError      **error);

gboolean nmcs_device_reapply(NMDevice     *device,
                             GCancellable *sigterm_cancellable,
                             NMConnection *connection,
                             guint64       version_id,
                             gboolean      maybe_no_preserved_external_ip,
                             gboolean     *out_version_id_changed,
                             GError      **error);

#endif /* __NM_CLOUD_SETUP_UTILS_H__ */
