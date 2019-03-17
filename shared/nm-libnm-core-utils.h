/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 */

#ifndef __NM_LIBNM_SHARED_UTILS_H__
#define __NM_LIBNM_SHARED_UTILS_H__

/****************************************************************************/

#include "nm-setting-vlan.h"

static inline guint32
nm_utils_vlan_priority_map_get_max_prio (NMVlanPriorityMap map, gboolean from)
{
	if (map == NM_VLAN_INGRESS_MAP) {
		return   from
		       ? 7u /* MAX_8021P_PRIO */
		       : (guint32) G_MAXUINT32 /* MAX_SKB_PRIO */;
	}
	nm_assert (map == NM_VLAN_EGRESS_MAP);
	return   from
	       ? (guint32) G_MAXUINT32 /* MAX_SKB_PRIO */
	       : 7u /* MAX_8021P_PRIO */;
}

gboolean nm_utils_vlan_priority_map_parse_str (NMVlanPriorityMap map_type,
                                               const char *str,
                                               gboolean allow_wildcard_to,
                                               guint32 *out_from,
                                               guint32 *out_to,
                                               gboolean *out_has_wildcard_to);

#endif /* __NM_LIBNM_SHARED_UTILS_H__ */
