/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-fake-platform.h - Fake platform interaction code for testing NetworkManager
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
 * Copyright (C) 2012 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_FAKE_PLATFORM_H__
#define __NETWORKMANAGER_FAKE_PLATFORM_H__

#include "nm-platform.h"

#define NM_TYPE_FAKE_PLATFORM            (nm_fake_platform_get_type ())
#define NM_FAKE_PLATFORM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_FAKE_PLATFORM, NMFakePlatform))
#define NM_FAKE_PLATFORM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_FAKE_PLATFORM, NMFakePlatformClass))
#define NM_IS_FAKE_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_FAKE_PLATFORM))
#define NM_IS_FAKE_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_FAKE_PLATFORM))
#define NM_FAKE_PLATFORM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_FAKE_PLATFORM, NMFakePlatformClass))

/******************************************************************/

typedef struct {
	NMPlatform parent;
} NMFakePlatform;

typedef struct {
	NMPlatformClass parent;
} NMFakePlatformClass;

/******************************************************************/

GType nm_fake_platform_get_type (void);

void nm_fake_platform_setup (void);

#endif /* __NETWORKMANAGER_FAKE_PLATFORM_H__ */
