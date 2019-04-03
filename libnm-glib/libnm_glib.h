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
 * Copyright (C) 2005 - 2008 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#ifndef _LIB_NM_H_
#define _LIB_NM_H_

#ifndef NM_DISABLE_DEPRECATED

#include <glib.h>

G_BEGIN_DECLS

typedef enum libnm_glib_state
{
	LIBNM_NO_DBUS = 0,
	LIBNM_NO_NETWORKMANAGER,
	LIBNM_NO_NETWORK_CONNECTION,
	LIBNM_ACTIVE_NETWORK_CONNECTION,
	LIBNM_INVALID_CONTEXT
} libnm_glib_state G_GNUC_DEPRECATED;

typedef struct libnm_glib_ctx libnm_glib_ctx G_GNUC_DEPRECATED;

typedef void (*libnm_glib_callback_func) (libnm_glib_ctx *libnm_ctx, gpointer user_data) G_GNUC_DEPRECATED;

G_GNUC_DEPRECATED libnm_glib_ctx *  libnm_glib_init                (void);
G_GNUC_DEPRECATED void              libnm_glib_shutdown            (libnm_glib_ctx *ctx);

G_GNUC_DEPRECATED libnm_glib_state  libnm_glib_get_network_state   (const libnm_glib_ctx *ctx);

G_GNUC_DEPRECATED guint             libnm_glib_register_callback   (libnm_glib_ctx *ctx, libnm_glib_callback_func func, gpointer user_data, GMainContext *g_main_ctx);
G_GNUC_DEPRECATED void              libnm_glib_unregister_callback (libnm_glib_ctx *ctx, guint id);

G_END_DECLS

#endif /* NM_DISABLE_DEPRECATED */

#endif /* _LIB_NM_H_ */
