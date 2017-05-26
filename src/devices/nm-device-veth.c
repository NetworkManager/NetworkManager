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

#include "nm-default.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "nm-device-veth.h"
#include "nm-device-private.h"
#include "nm-manager.h"
#include "platform/nm-platform.h"
#include "nm-device-factory.h"

#include "introspection/org.freedesktop.NetworkManager.Device.Veth.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceVeth);

/*****************************************************************************/

struct _NMDeviceVeth {
	NMDeviceEthernet parent;
};

struct _NMDeviceVethClass {
	NMDeviceEthernetClass parent;
};

NM_GOBJECT_PROPERTIES_DEFINE (NMDeviceVeth,
	PROP_PEER,
);

/*****************************************************************************/

G_DEFINE_TYPE (NMDeviceVeth, nm_device_veth, NM_TYPE_DEVICE_ETHERNET)

/*****************************************************************************/

static void
update_properties (NMDevice *device)
{
	NMDevice *peer;
	int ifindex, peer_ifindex;

	ifindex = nm_device_get_ifindex (device);

	if (!nm_platform_link_veth_get_properties (nm_device_get_platform (device), ifindex, &peer_ifindex))
		peer_ifindex = 0;

	nm_device_parent_set_ifindex (device, peer_ifindex);

	peer = nm_device_parent_get_device (device);
	if (   peer
	    && NM_IS_DEVICE_VETH (peer)
	    && nm_device_parent_get_ifindex (peer) <= 0)
		update_properties (peer);
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

static void
link_changed (NMDevice *device,
              const NMPlatformLink *pllink)
{
	NM_DEVICE_CLASS (nm_device_veth_parent_class)->link_changed (device, pllink);
	update_properties (device);
}

/*****************************************************************************/

static void
nm_device_veth_init (NMDeviceVeth *self)
{
}

static void
notify (GObject *object, GParamSpec *pspec)
{
	if (nm_streq (pspec->name, NM_DEVICE_PARENT))
		_notify (NM_DEVICE_VETH (object), PROP_PEER);
	G_OBJECT_CLASS (nm_device_veth_parent_class)->notify (object, pspec);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceVeth *self = NM_DEVICE_VETH (object);
	NMDevice *peer;

	switch (prop_id) {
	case PROP_PEER:
		peer = nm_device_parent_get_device (NM_DEVICE (self));
		if (peer && !NM_IS_DEVICE_VETH (peer))
			peer = NULL;
		nm_utils_g_value_set_object_path (value, peer);
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

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NULL, NM_LINK_TYPE_VETH)

	object_class->get_property = get_property;
	object_class->notify = notify;

	device_class->can_unmanaged_external_down = can_unmanaged_external_down;
	device_class->link_changed = link_changed;

	obj_properties[PROP_PEER] =
	    g_param_spec_string (NM_DEVICE_VETH_PEER, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_VETH_SKELETON,
	                                        NULL);
}

/*****************************************************************************/

#define NM_TYPE_VETH_DEVICE_FACTORY (nm_veth_device_factory_get_type ())
#define NM_VETH_DEVICE_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VETH_DEVICE_FACTORY, NMVethDeviceFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               const NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_VETH,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Veth",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_VETH,
	                                  NM_DEVICE_LINK_TYPE, NM_LINK_TYPE_VETH,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (VETH, Veth, veth,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_VETH),
	factory_class->create_device = create_device;
);
