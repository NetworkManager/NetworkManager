// SPDX-License-Identifier: LGPL-2.1+
/*
 */

#include "nm-default.h"

#include "nm-libnm-core-utils.h"

/*****************************************************************************/

gboolean
nm_utils_vlan_priority_map_parse_str (NMVlanPriorityMap map_type,
                                      const char *str,
                                      gboolean allow_wildcard_to,
                                      guint32 *out_from,
                                      guint32 *out_to,
                                      gboolean *out_has_wildcard_to)
{
	const char *s2;
	gint64 v1, v2;

	nm_assert (str);

	s2 = strchr (str, ':');

	if (!s2) {
		if (!allow_wildcard_to)
			return FALSE;
		v1 = _nm_utils_ascii_str_to_int64 (str, 10, 0, G_MAXUINT32, -1);
		v2 = -1;
	} else {
		gs_free char *s1_free = NULL;
		gsize s1_len = (s2 - str);

		s2 = nm_str_skip_leading_spaces (&s2[1]);
		if (   s2[0] == '\0'
		    || (   s2[0] == '*'
		        && NM_STRCHAR_ALL (&s2[1], ch, g_ascii_isspace (ch)))) {
			if (!allow_wildcard_to)
				return FALSE;
			v2 = -1;
		} else {
			v2 = _nm_utils_ascii_str_to_int64 (s2, 10, 0, G_MAXUINT32, -1);
			if (   v2 < 0
			    || (guint32) v2 > nm_utils_vlan_priority_map_get_max_prio (map_type, FALSE))
				return FALSE;
		}

		v1 = _nm_utils_ascii_str_to_int64 (nm_strndup_a (100, str, s1_len, &s1_free),
		                                   10, 0, G_MAXUINT32, -1);
	}

	if (   v1 < 0
	    || (guint32) v1 > nm_utils_vlan_priority_map_get_max_prio (map_type, TRUE))
		return FALSE;

	NM_SET_OUT (out_from, v1);
	NM_SET_OUT (out_to,   v2 < 0
	                    ? 0u
	                    : (guint) v2);
	NM_SET_OUT (out_has_wildcard_to, v2 < 0);
	return TRUE;
}
