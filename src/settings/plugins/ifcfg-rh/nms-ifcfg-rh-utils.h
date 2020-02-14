// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2008 - 2017 Red Hat, Inc.
 */

#ifndef _UTILS_H_
#define _UTILS_H_

#include "nm-connection.h"
#include "nm-libnm-core-intern/nm-ethtool-utils.h"

#include "shvar.h"

/*****************************************************************************/

typedef enum {
	NMS_IFCFG_KEY_TYPE_UNKNOWN         = 0,
	NMS_IFCFG_KEY_TYPE_WELL_KNOWN      = (1u << 0),

	NMS_IFCFG_KEY_TYPE_IS_PLAIN        = (1u << 1),
	NMS_IFCFG_KEY_TYPE_IS_NUMBERED     = (1u << 2),
	NMS_IFCFG_KEY_TYPE_IS_PREFIX       = (1u << 3),

	/* by default, well knowns keys that are not explicitly set
	 * by the writer (the unvisited, dirty ones) are removed.
	 * With this flag, such keys are kept if they are present. */
	NMS_IFCFG_KEY_TYPE_KEEP_WHEN_DIRTY = (1u << 4),

} NMSIfcfgKeyTypeFlags;

typedef struct {
	const char *key_name;
	NMSIfcfgKeyTypeFlags key_flags;
} NMSIfcfgKeyTypeInfo;

extern const NMSIfcfgKeyTypeInfo nms_ifcfg_well_known_keys[228];

const NMSIfcfgKeyTypeInfo *nms_ifcfg_well_known_key_find_info (const char *key, gssize *out_idx);

static inline NMSIfcfgKeyTypeFlags
nms_ifcfg_well_known_key_find_info_flags (const char *key)
{
	const NMSIfcfgKeyTypeInfo *ti;

	ti = nms_ifcfg_well_known_key_find_info (key, NULL);
	if (!ti)
		return NMS_IFCFG_KEY_TYPE_UNKNOWN;
	return ti->key_flags;
}

/*****************************************************************************/

gboolean nms_ifcfg_rh_utils_parse_unhandled_spec (const char *unhandled_spec,
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
gboolean utils_has_route_file_new_syntax_content (const char *contents,
                                                  gsize len);
gboolean utils_has_complex_routes (const char *filename, int addr_family);

gboolean utils_is_ifcfg_alias_file (const char *alias, const char *ifcfg);

char *utils_detect_ifcfg_path (const char *path, gboolean only_ifcfg);

void nms_ifcfg_rh_utils_user_key_encode (const char *key, GString *str_buffer);
gboolean nms_ifcfg_rh_utils_user_key_decode (const char *name, GString *str_buffer);

static inline const char *
_nms_ifcfg_rh_utils_numbered_tag (char *buf, gsize buf_len, const char *tag_name, int which)
{
	gsize l;

#if NM_MORE_ASSERTS > 5
	nm_assert (NM_FLAGS_ALL (nms_ifcfg_well_known_key_find_info_flags (tag_name),
	                           NMS_IFCFG_KEY_TYPE_WELL_KNOWN
	                         | NMS_IFCFG_KEY_TYPE_IS_NUMBERED));
#endif

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

gboolean nms_ifcfg_rh_utils_is_numbered_tag_impl (const char *key,
                                                  const char *tag,
                                                  gsize tag_len,
                                                  gint64 *out_idx);

static inline gboolean
nms_ifcfg_rh_utils_is_numbered_tag (const char *key,
                                    const char *tag,
                                    gint64 *out_idx)
{
	nm_assert (tag);

	return nms_ifcfg_rh_utils_is_numbered_tag_impl (key, tag, strlen (tag), out_idx);
}

#define NMS_IFCFG_RH_UTIL_IS_NUMBERED_TAG(key, tag, out_idx) \
	nms_ifcfg_rh_utils_is_numbered_tag_impl (key, tag, NM_STRLEN (tag), out_idx)

/*****************************************************************************/

const NMSIfcfgKeyTypeInfo *nms_ifcfg_rh_utils_is_well_known_key (const char *key);

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
