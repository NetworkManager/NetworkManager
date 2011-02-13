/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
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
 * Copyright (C) 2009 Red Hat, Inc.
 */

#ifndef __NM_REMOTE_CONNECTION_PRIVATE_H__
#define __NM_REMOTE_CONNECTION_PRIVATE_H__

#define NM_REMOTE_CONNECTION_INIT_RESULT "init-result"

typedef enum {
	NM_REMOTE_CONNECTION_INIT_RESULT_UNKNOWN = 0,
	NM_REMOTE_CONNECTION_INIT_RESULT_SUCCESS,
	NM_REMOTE_CONNECTION_INIT_RESULT_ERROR,
	NM_REMOTE_CONNECTION_INIT_RESULT_INVISIBLE,
} NMRemoteConnectionInitResult;

#endif  /* __NM_REMOTE_CONNECTION_PRIVATE__ */

