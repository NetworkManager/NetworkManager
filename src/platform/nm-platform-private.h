/* nm-platform.c - Handle runtime kernel networking configuration
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_PLATFORM_PRIVATE_H__
#define __NM_PLATFORM_PRIVATE_H__

#include "nm-platform.h"
#include "nmp-object.h"

NMPCache *nm_platform_get_cache (NMPlatform *self);

#define NMTST_ASSERT_PLATFORM_NETNS_CURRENT(platform) \
	G_STMT_START { \
		NMPlatform *_platform = (platform); \
		\
		nm_assert (NM_IS_PLATFORM (_platform)); \
		nm_assert (NM_IN_SET (nm_platform_netns_get (_platform), NULL, nmp_netns_get_current ())); \
	} G_STMT_END

void nm_platform_cache_update_emit_signal (NMPlatform *platform,
                                           NMPCacheOpsType cache_op,
                                           const NMPObject *obj_old,
                                           const NMPObject *obj_new);

#endif /* __NM_PLATFORM_PRIVATE_H__ */
