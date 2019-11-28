// SPDX-License-Identifier: LGPL-2.1+

#ifndef __NM_CLOUD_SETUP_UTILS_H__
#define __NM_CLOUD_SETUP_UTILS_H__

#include "nm-glib-aux/nm-logging-fwd.h"

/*****************************************************************************/

extern volatile NMLogLevel _nm_logging_configured_level;

static inline gboolean
nm_logging_enabled (NMLogLevel level)
{
	return level >= _nm_logging_configured_level;
}

void _nm_logging_enabled_init (const char *level_str);

void _nm_log_impl_cs (NMLogLevel level,
                      const char *fmt,
                      ...) _nm_printf (2, 3);

#define _nm_log(level, ...) \
	_nm_log_impl_cs ((level), __VA_ARGS__);

#define _NMLOG(level, ...) \
	G_STMT_START { \
		const NMLogLevel _level = (level); \
		\
		if (nm_logging_enabled (_level)) { \
			_nm_log (_level, __VA_ARGS__); \
		} \
	} G_STMT_END

/*****************************************************************************/

#ifndef NM_DIST_VERSION
#define NM_DIST_VERSION VERSION
#endif

/*****************************************************************************/

gpointer nmcs_wait_for_objects_register (gpointer target);

gboolean nmcs_wait_for_objects_iterate_until_done (GMainContext *context,
                                                   int timeout_ms);

/*****************************************************************************/

typedef void (*NMCSUtilsPollProbeStartFcn) (GCancellable *cancellable,
                                            gpointer probe_user_data,
                                            GAsyncReadyCallback callback,
                                            gpointer user_data);

typedef gboolean (*NMCSUtilsPollProbeFinishFcn) (GObject *source,
                                                 GAsyncResult *result,
                                                 gpointer probe_user_data,
                                                 GError **error);

void nmcs_utils_poll (int poll_timeout_ms,
                      int ratelimit_timeout_ms,
                      int sleep_timeout_ms,
                      NMCSUtilsPollProbeStartFcn probe_start_fcn,
                      NMCSUtilsPollProbeFinishFcn probe_finish_fcn,
                      gpointer probe_user_data,
                      GCancellable *cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data);

gboolean nmcs_utils_poll_finish (GAsyncResult *result,
                                 gpointer *probe_user_data,
                                 GError **error);

/*****************************************************************************/

char *nmcs_utils_hwaddr_normalize (const char *hwaddr, gssize len);

/*****************************************************************************/

const char *nmcs_utils_parse_memmem (GBytes *mem, const char *needle);

const char *nmcs_utils_parse_get_full_line (GBytes *mem, const char *needle);

/*****************************************************************************/

char *nmcs_utils_uri_build_concat_v (const char *base,
                                     const char **components,
                                     gsize n_components);

#define nmcs_utils_uri_build_concat(base, ...) nmcs_utils_uri_build_concat_v (base, ((const char *[]) { __VA_ARGS__ }), NM_NARG (__VA_ARGS__))

/*****************************************************************************/

gboolean nmcs_setting_ip_replace_ipv4_addresses (NMSettingIPConfig *s_ip,
                                                 NMIPAddress **entries_arr,
                                                 guint entries_len);

gboolean nmcs_setting_ip_replace_ipv4_routes (NMSettingIPConfig *s_ip,
                                              NMIPRoute **entries_arr,
                                              guint entries_len);

gboolean nmcs_setting_ip_replace_ipv4_rules (NMSettingIPConfig *s_ip,
                                             NMIPRoutingRule **entries_arr,
                                             guint entries_len);

/*****************************************************************************/

NMConnection *nmcs_device_get_applied_connection (NMDevice *device,
                                                  GCancellable *cancellable,
                                                  guint64 *version_id,
                                                  GError **error);

gboolean nmcs_device_reapply (NMDevice *device,
                              GCancellable *sigterm_cancellable,
                              NMConnection *connection,
                              guint64 version_id,
                              gboolean *out_version_id_changed,
                              GError **error);

#endif /* __NM_CLOUD_SETUP_UTILS_H__ */
