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

#include "nm-sd-utils-core.h"

#include "nm-core-internal.h"

#include "nm-sd-adapt-core.h"

#include "sd-id128.h"

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
