/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_FAKE_PLATFORM_H__
#define __NETWORKMANAGER_FAKE_PLATFORM_H__

#include "nm-platform.h"

#define NM_TYPE_FAKE_PLATFORM (nm_fake_platform_get_type())
#define NM_FAKE_PLATFORM(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_FAKE_PLATFORM, NMFakePlatform))
#define NM_FAKE_PLATFORM_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_FAKE_PLATFORM, NMFakePlatformClass))
#define NM_IS_FAKE_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_FAKE_PLATFORM))
#define NM_IS_FAKE_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_FAKE_PLATFORM))
#define NM_FAKE_PLATFORM_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_FAKE_PLATFORM, NMFakePlatformClass))

typedef struct _NMFakePlatform      NMFakePlatform;
typedef struct _NMFakePlatformClass NMFakePlatformClass;

GType nm_fake_platform_get_type(void);

void nm_fake_platform_setup(void);

#endif /* __NETWORKMANAGER_FAKE_PLATFORM_H__ */
