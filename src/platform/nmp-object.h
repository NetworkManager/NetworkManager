/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright (C) 2015 Red Hat, Inc.
 */

#ifndef __NMP_OBJECT_H__
#define __NMP_OBJECT_H__

#include "config.h"

#include "nm-platform.h"

typedef enum { /*< skip >*/
	OBJECT_TYPE_UNKNOWN,
	OBJECT_TYPE_LINK,
	OBJECT_TYPE_IP4_ADDRESS,
	OBJECT_TYPE_IP6_ADDRESS,
	OBJECT_TYPE_IP4_ROUTE,
	OBJECT_TYPE_IP6_ROUTE,
	__OBJECT_TYPE_LAST,
	OBJECT_TYPE_MAX = __OBJECT_TYPE_LAST - 1,
} ObjectType;

#endif /* __NMP_OBJECT_H__ */
