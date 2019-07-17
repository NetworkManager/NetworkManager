/* NetworkManager system settings service
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * (C) Copyright 2008 - 2017 Red Hat, Inc.
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include "nm-connection.h"
#include "nm-libnm-core-intern/nm-ethtool-utils.h"

#include "shvar.h"

gboolean nms_ifcfg_rh_util_parse_unhandled_spec (const char *unhandled_spec,
                                                 const char **out_unmanaged_spec,
                                                 const char **out_unrecognized_spec);

#define NM_IFCFG_CONNECTION_LOG_PATH(path)  ((path) ?: "in-memory")
#define NM_IFCFG_CONNECTION_LOG_FMT         "%s (%s,\"%s\")"
#define NM_IFCFG_CONNECTION_LOG_ARG(con)    NM_IFCFG_CONNECTION_LOG_PATH (nm_settings_connection_get_filename ((NMSettingsConnection *) (con))), nm_settings_connection_get_uuid ((NMSettingsConnection *) (con)), nm_settings_connection_get_id ((NMSettingsConnection *) (con))
#define NM_IFCFG_CONNECTION_LOG_FMTD        "%s (%s,\"%s\",%p)"
#define NM_IFCFG_CONNECTION_LOG_ARGD(con)   NM_IFCFG_CONNECTION_LOG_PATH (nm_settings_connection_get_filename ((NMSettingsConnection *) (con))), nm_settings_connection_get_uuid ((NMSettingsConnection *) (con)), nm_settings_connection_get_id ((NMSettingsConnection *) (con)), (con)

char *utils_cert_path (const char *parent, const char *suffix, const char *extension);

const char *utils_get_ifcfg_name (const char *file, gboolean only_ifcfg);

gboolean utils_should_ignore_file (const char *filename, gboolean only_ifcfg);

char *utils_get_ifcfg_path (const char *parent);
char *utils_get_keys_path (const char *parent);
char *utils_get_route_path (const char *parent);
char *utils_get_route6_path (const char *parent);

shvarFile *utils_get_extra_ifcfg (const char *parent, const char *tag, gboolean should_create);
shvarFile *utils_get_keys_ifcfg (const char *parent, gboolean should_create);
shvarFile *utils_get_route_ifcfg (const char *parent, gboolean should_create);

gboolean utils_has_route_file_new_syntax (const char *filename);
gboolean utils_has_complex_routes (const char *filename, int addr_family);

gboolean utils_is_ifcfg_alias_file (const char *alias, const char *ifcfg);

char *utils_detect_ifcfg_path (const char *path, gboolean only_ifcfg);

void nms_ifcfg_rh_utils_user_key_encode (const char *key, GString *str_buffer);
gboolean nms_ifcfg_rh_utils_user_key_decode (const char *name, GString *str_buffer);

static inline const char *
_nms_ifcfg_rh_utils_numbered_tag (char *buf, gsize buf_len, const char *tag_name, int which)
{
	gsize l;

	l = g_strlcpy (buf, tag_name, buf_len);
	nm_assert (l < buf_len);
	if (which != -1) {
		buf_len -= l;
		l = g_snprintf (&buf[l], buf_len, "%d", which);
		nm_assert (l < buf_len);
	}
	return buf;
}
#define numbered_tag(buf, tag_name, which) \
	({ \
		_nm_unused char *const _buf = (buf); \
		\
		/* some static assert trying to ensure that the buffer is statically allocated.
		 * It disallows a buffer size of sizeof(gpointer) to catch that. */ \
		G_STATIC_ASSERT (G_N_ELEMENTS (buf) == sizeof (buf) && sizeof (buf) != sizeof (char *) && sizeof (buf) < G_MAXINT); \
		_nms_ifcfg_rh_utils_numbered_tag (buf, sizeof (buf), ""tag_name"", (which)); \
	})

/*****************************************************************************/

extern const char *const _nm_ethtool_ifcfg_names[_NM_ETHTOOL_ID_FEATURE_NUM];

static inline const char *
nms_ifcfg_rh_utils_get_ethtool_name (NMEthtoolID ethtool_id)
{
	nm_assert (ethtool_id >= _NM_ETHTOOL_ID_FEATURE_FIRST && ethtool_id <= _NM_ETHTOOL_ID_FEATURE_LAST);
	nm_assert ((ethtool_id - _NM_ETHTOOL_ID_FEATURE_FIRST) < G_N_ELEMENTS (_nm_ethtool_ifcfg_names));
	nm_assert (_nm_ethtool_ifcfg_names[ethtool_id - _NM_ETHTOOL_ID_FEATURE_FIRST]);

	return _nm_ethtool_ifcfg_names[ethtool_id - _NM_ETHTOOL_ID_FEATURE_FIRST];
}

const NMEthtoolData *nms_ifcfg_rh_utils_get_ethtool_by_name (const char *name);

#endif  /* _UTILS_H_ */
