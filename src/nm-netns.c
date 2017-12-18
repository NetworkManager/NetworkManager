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
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-netns.h"

#include "nm-utils/nm-dedup-multi.h"

#include "platform/nm-platform.h"
#include "platform/nmp-netns.h"
#include "nm-core-internal.h"
#include "NetworkManagerUtils.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PLATFORM,
);

typedef struct {
	NMPlatform *platform;
	NMPNetns *platform_netns;
} NMNetnsPrivate;

struct _NMNetns {
	GObject parent;
	NMNetnsPrivate _priv;
};

struct _NMNetnsClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMNetns, nm_netns, G_TYPE_OBJECT);

#define NM_NETNS_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMNetns, NM_IS_NETNS)

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMNetns, nm_netns_get, NM_TYPE_NETNS);

/*****************************************************************************/

NMPNetns *
nm_netns_get_platform_netns (NMNetns *self)
{
	return NM_NETNS_GET_PRIVATE (self)->platform_netns;
}

NMPlatform *
nm_netns_get_platform (NMNetns *self)
{
	return NM_NETNS_GET_PRIVATE (self)->platform;
}

NMDedupMultiIndex *
nm_netns_get_multi_idx (NMNetns *self)
{
	return nm_platform_get_multi_idx (NM_NETNS_GET_PRIVATE (self)->platform);
}

/*****************************************************************************/

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMNetns *self = NM_NETNS (object);
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_PLATFORM:
		/* construct-only */
		priv->platform = g_value_get_object (value) ?: NM_PLATFORM_GET;
		if (!priv->platform)
			g_return_if_reached ();
		g_object_ref (priv->platform);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_netns_init (NMNetns *self)
{
}

static void
constructed (GObject *object)
{
	NMNetns *self = NM_NETNS (object);
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	if (!priv->platform)
		g_return_if_reached ();

	priv->platform_netns = nm_platform_netns_get (priv->platform);

	G_OBJECT_CLASS (nm_netns_parent_class)->constructed (object);
}

NMNetns *
nm_netns_new (NMPlatform *platform)
{
	return g_object_new (NM_TYPE_NETNS,
	                     NM_NETNS_PLATFORM, platform,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMNetns *self = NM_NETNS (object);
	NMNetnsPrivate *priv = NM_NETNS_GET_PRIVATE (self);

	g_clear_object (&priv->platform);

	G_OBJECT_CLASS (nm_netns_parent_class)->dispose (object);
}

static void
nm_netns_class_init (NMNetnsClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->constructed = constructed;
	object_class->set_property = set_property;
	object_class->dispose = dispose;

	obj_properties[PROP_PLATFORM] =
	    g_param_spec_object (NM_NETNS_PLATFORM, "", "",
	                         NM_TYPE_PLATFORM,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
