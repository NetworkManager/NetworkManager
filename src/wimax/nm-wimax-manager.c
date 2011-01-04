/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
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
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 */

#include "nm-wimax-manager.h"
#include "nm-logging.h"
#include "iwmxsdk.h"

G_DEFINE_TYPE (NMWimaxManager, nm_wimax_manager, G_TYPE_OBJECT)

#define NM_WIMAX_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                         NM_TYPE_WIMAX_MANAGER, \
                                         NMWimaxManagerPrivate))

typedef struct {
	gboolean disposed;

	gboolean sdk_initialized;
} NMWimaxManagerPrivate;

/***************************************************/

/*************************************************************/

NMWimaxManager *
nm_wimax_manager_get (void)
{
	static NMWimaxManager *singleton = NULL;

	if (!singleton)
		singleton = NM_WIMAX_MANAGER (g_object_new (NM_TYPE_WIMAX_MANAGER, NULL));
	else
		g_object_ref (singleton);

	g_assert (singleton);
	return singleton;
}

static void
nm_wimax_manager_init (NMWimaxManager *self)
{
	NMWimaxManagerPrivate *priv = NM_WIMAX_MANAGER_GET_PRIVATE (self);
	int ret;

	ret = iwmx_sdk_api_init();
	if (ret != 0) {
		nm_log_warn (LOGD_WIMAX, "Failed to initialize WiMAX: %d", ret);
		return;
	}

	priv->sdk_initialized = TRUE;
}

static void
dispose (GObject *object)
{
	NMWimaxManagerPrivate *priv = NM_WIMAX_MANAGER_GET_PRIVATE (object);

	if (!priv->disposed) {
		priv->disposed = TRUE;

		if (priv->sdk_initialized)
			iwmx_sdk_api_exit ();
	}

	G_OBJECT_CLASS (nm_wimax_manager_parent_class)->dispose (object);
}

static void
nm_wimax_manager_class_init (NMWimaxManagerClass *wimax_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (wimax_class);

	g_type_class_add_private (wimax_class, sizeof (NMWimaxManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
}

