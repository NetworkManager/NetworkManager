/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-linux-platform.h - Linux kernel & udev network configuration layer
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

#ifndef NM_LINUX_PLATFORM_H
#define NM_LINUX_PLATFORM_H

#include "nm-platform.h"

#define NM_TYPE_LINUX_PLATFORM            (nm_linux_platform_get_type ())
#define NM_LINUX_PLATFORM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_LINUX_PLATFORM, NMLinuxPlatform))
#define NM_LINUX_PLATFORM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_LINUX_PLATFORM, NMLinuxPlatformClass))
#define NM_IS_LINUX_PLATFORM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_LINUX_PLATFORM))
#define NM_IS_LINUX_PLATFORM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_LINUX_PLATFORM))
#define NM_LINUX_PLATFORM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_LINUX_PLATFORM, NMLinuxPlatformClass))

/******************************************************************/

typedef struct {
	NMPlatform parent;
} NMLinuxPlatform;

typedef struct {
	NMPlatformClass parent;
} NMLinuxPlatformClass;

/******************************************************************/

GType nm_linux_platform_get_type (void);

void nm_linux_platform_setup (void);

#endif /* NM_LINUX_PLATFORM_H */
