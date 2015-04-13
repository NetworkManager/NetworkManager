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
 * Copyright 2013 Red Hat, Inc.
 */

#include "config.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/sockios.h>
#include <sys/ioctl.h>

#include "nm-device-veth.h"
#include "nm-device-private.h"
#include "nm-logging.h"
#include "nm-manager.h"
#include "nm-platform.h"
#include "nm-device-factory.h"

#include "nm-device-veth-glue.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceVeth);

G_DEFINE_TYPE (NMDeviceVeth, nm_device_veth, NM_TYPE_DEVICE_ETHERNET)

#define NM_DEVICE_VETH_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_VETH, NMDeviceVethPrivate))

typedef struct {
	NMDevice *peer;
	gboolean ever_had_peer;
} NMDeviceVethPrivate;

enum {
	PROP_0,
	PROP_PEER,

	LAST_PROP
};

/**************************************************************/

static void
set_peer (NMDeviceVeth *self, NMDevice *peer)
{
	NMDeviceVethPrivate *priv = NM_DEVICE_VETH_GET_PRIVATE (self);

	if (!priv->peer) {
		priv->ever_had_peer = TRUE;
		priv->peer = peer;
		g_object_add_weak_pointer (G_OBJECT (peer), (gpointer *) &priv->peer);

		g_object_notify (G_OBJECT (self), NM_DEVICE_VETH_PEER);
	}
}

static NMDevice *
get_peer (NMDeviceVeth *self)
{
	NMDeviceVethPrivate *priv = NM_DEVICE_VETH_GET_PRIVATE (self);
	NMDevice *device = NM_DEVICE (self), *peer = NULL;
	NMPlatformVethProperties props;

	if (priv->ever_had_peer)
		return priv->peer;

	if (!nm_platform_veth_get_properties (NM_PLATFORM_GET, nm_device_get_ifindex (device), &props)) {
		_LOGW (LOGD_HW, "could not read veth properties");
		return NULL;
	}

	peer = nm_manager_get_device_by_ifindex (nm_manager_get (), props.peer);
	if (peer && NM_IS_DEVICE_VETH (peer)) {
		set_peer (self, peer);
		set_peer (NM_DEVICE_VETH (peer), device);
	}

	return priv->peer;
}

static gboolean
can_unmanaged_external_down (NMDevice *self)
{
	/* Unless running in a container, an udev rule causes these to be
	 * unmanaged. If there's no udev then we're probably in a container
	 * and should IFF_UP and configure the veth ourselves even if we
	 * didn't create it. */
	return FALSE;
}

/**************************************************************/

static void
nm_device_veth_init (NMDeviceVeth *self)
{
}

static void
dispose (GObject *object)
{
	NMDeviceVeth *self = NM_DEVICE_VETH (object);
	NMDeviceVethPrivate *priv = NM_DEVICE_VETH_GET_PRIVATE (self);

	if (priv->peer) {
		g_object_remove_weak_pointer (G_OBJECT (priv->peer), (gpointer *) &priv->peer);
		priv->peer = NULL;
	}

	G_OBJECT_CLASS (nm_device_veth_parent_class)->dispose (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceVeth *self = NM_DEVICE_VETH (object);
	NMDevice *peer;

	switch (prop_id) {
	case PROP_PEER:
		peer = get_peer (self);
		g_value_set_boxed (value, peer ? nm_device_get_path (peer) : "/");
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_veth_class_init (NMDeviceVethClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDeviceVethPrivate));

	object_class->get_property = get_property;
	object_class->dispose = dispose;

	device_class->can_unmanaged_external_down = can_unmanaged_external_down;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_PEER,
		 g_param_spec_boxed (NM_DEVICE_VETH_PEER, "", "",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        &dbus_glib_nm_device_veth_object_info);
}

/*************************************************************/

#define NM_TYPE_VETH_FACTORY (nm_veth_factory_get_type ())
#define NM_VETH_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VETH_FACTORY, NMVethFactory))

static NMDevice *
new_link (NMDeviceFactory *factory, NMPlatformLink *plink, gboolean *out_ignore, GError **error)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_VETH,
	                                  NM_DEVICE_PLATFORM_DEVICE, plink,
	                                  NM_DEVICE_TYPE_DESC, "Veth",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_ETHERNET,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (VETH, Veth, veth,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_VETH),
	factory_iface->new_link = new_link;
	)

