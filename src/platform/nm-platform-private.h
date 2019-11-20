// SPDX-License-Identifier: GPL-2.0+
/*
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
