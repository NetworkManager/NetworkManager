/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef __NMS_IBFT_READER_H__
#define __NMS_IBFT_READER_H__

#include "nm-connection.h"

static inline void
_nm_auto_free_ibft_blocks (GSList **p_blocks)
{
	if (*p_blocks)
		g_slist_free_full (*p_blocks, (GDestroyNotify) g_ptr_array_unref);
}
#define nm_auto_free_ibft_blocks nm_auto (_nm_auto_free_ibft_blocks)

gboolean nms_ibft_reader_load_blocks (const char *iscsiadm_path,
                                      GSList **out_blocks,
                                      GError **error);

NMConnection *nms_ibft_reader_get_connection_from_block (const GPtrArray *block, GError **error);

gboolean nms_ibft_reader_parse_block (const GPtrArray *block, GError **error, ...) G_GNUC_NULL_TERMINATED;

#endif  /* __NMS_IBFT_READER_H__ */
