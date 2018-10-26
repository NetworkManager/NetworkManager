/* This library is free software; you can redistribute it and/or
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
 *
 * Copyright (C) 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-sd-utils.h"

#include "nm-core-internal.h"

#include "nm-sd-adapt.h"

#include "path-util.h"
#include "sd-id128.h"
#include "dhcp-identifier.h"

/*****************************************************************************/

gboolean
nm_sd_utils_path_equal (const char *a, const char *b)
{
	return path_equal (a, b);
}

char *
nm_sd_utils_path_simplify (char *path, gboolean kill_dots)
{
	return path_simplify (path, kill_dots);
}

const char *
nm_sd_utils_path_startswith (const char *path, const char *prefix)
{
	return path_startswith (path, prefix);
}

/*****************************************************************************/

NMUuid *
nm_sd_utils_id128_get_machine (NMUuid *out_uuid)
{
	g_assert (out_uuid);

	G_STATIC_ASSERT_EXPR (sizeof (*out_uuid) == sizeof (sd_id128_t));
	if (sd_id128_get_machine ((sd_id128_t *) out_uuid) < 0)
		return NULL;
	return out_uuid;
}

/*****************************************************************************/

/**
 * nm_sd_utils_generate_default_dhcp_client_id:
 * @ifindex: the interface ifindex
 * @mac: the MAC address
 * @mac_addr_len: the length of MAC address.
 *
 * Systemd's sd_dhcp_client generates a default client ID (type 255, node-specific,
 * RFC 4361) if no explicit client-id is set. This function duplicates that
 * implementation and exposes it as (internal) API.
 *
 * Returns: a %GBytes of generated client-id, or %NULL on failure.
 */
GBytes *
nm_sd_utils_generate_default_dhcp_client_id (int ifindex,
                                             const guint8 *mac_addr,
                                             gsize mac_addr_len)
{
	struct _nm_packed {
		guint8 type;
		guint32 iaid;
		struct duid duid;
	} client_id;
	int r;
	gsize duid_len;

	g_return_val_if_fail (ifindex > 0, NULL);
	g_return_val_if_fail (mac_addr, NULL);
	g_return_val_if_fail (mac_addr_len > 0, NULL);

	client_id.type = 255;

	r = dhcp_identifier_set_iaid (ifindex, (guint8 *) mac_addr, mac_addr_len, &client_id.iaid);
	if (r < 0)
		return NULL;

	r = dhcp_identifier_set_duid_en (&client_id.duid, &duid_len);
	if (r < 0)
		return NULL;

	return g_bytes_new (&client_id,
	                    G_STRUCT_OFFSET (typeof (client_id), duid) + duid_len);
}
