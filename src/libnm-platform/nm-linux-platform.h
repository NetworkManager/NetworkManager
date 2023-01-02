/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_LINUX_PLATFORM_H__
#define __NETWORKMANAGER_LINUX_PLATFORM_H__

#include "nm-platform.h"

#define NM_TYPE_LINUX_PLATFORM (nm_linux_platform_get_type())
#define NM_LINUX_PLATFORM(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_LINUX_PLATFORM, NMLinuxPlatform))
#define NM_LINUX_PLATFORM_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_LINUX_PLATFORM, NMLinuxPlatformClass))
#define NM_IS_LINUX_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_LINUX_PLATFORM))
#define NM_IS_LINUX_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_LINUX_PLATFORM))
#define NM_LINUX_PLATFORM_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_LINUX_PLATFORM, NMLinuxPlatformClass))

typedef struct _NMLinuxPlatform      NMLinuxPlatform;
typedef struct _NMLinuxPlatformClass NMLinuxPlatformClass;

GType nm_linux_platform_get_type(void);

struct _NMDedupMultiIndex;

NMPlatform *nm_linux_platform_new(struct _NMDedupMultiIndex *multi_idx,
                                  gboolean                   log_with_ptr,
                                  gboolean                   netns_support,
                                  gboolean                   cache_tc);

#endif /* __NETWORKMANAGER_LINUX_PLATFORM_H__ */
