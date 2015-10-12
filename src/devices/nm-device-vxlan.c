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
 * Copyright 2013, 2014 Red Hat, Inc.
 */

#include "config.h"

#include <string.h>

#include "nm-device-vxlan.h"
#include "nm-device-private.h"
#include "nm-default.h"
#include "nm-manager.h"
#include "nm-platform.h"
#include "nm-utils.h"
#include "nm-device-factory.h"

#include "nmdbus-device-vxlan.h"

#include "nm-device-logging.h"
_LOG_DECLARE_SELF(NMDeviceVxlan);

G_DEFINE_TYPE (NMDeviceVxlan, nm_device_vxlan, NM_TYPE_DEVICE_GENERIC)

#define NM_DEVICE_VXLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_VXLAN, NMDeviceVxlanPrivate))

typedef struct {
	NMPlatformLnkVxlan props;
} NMDeviceVxlanPrivate;

enum {
	PROP_0,
	PROP_PARENT,
	PROP_ID,
	PROP_GROUP,
	PROP_LOCAL,
	PROP_TOS,
	PROP_TTL,
	PROP_LEARNING,
	PROP_AGEING,
	PROP_LIMIT,
	PROP_DST_PORT,
	PROP_SRC_PORT_MIN,
	PROP_SRC_PORT_MAX,
	PROP_PROXY,
	PROP_RSC,
	PROP_L2MISS,
	PROP_L3MISS,

	LAST_PROP
};

/**************************************************************/

static void
update_properties (NMDevice *device)
{
	NMDeviceVxlan *self = NM_DEVICE_VXLAN (device);
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (device);
	GObject *object = G_OBJECT (device);
	const NMPlatformLnkVxlan *props;

	props = nm_platform_link_get_lnk_vxlan (NM_PLATFORM_GET, nm_device_get_ifindex (device), NULL);
	if (!props) {
		_LOGW (LOGD_HW, "could not get vxlan properties");
		return;
	}

	g_object_freeze_notify (object);

	if (priv->props.parent_ifindex != props->parent_ifindex)
		g_object_notify (object, NM_DEVICE_VXLAN_PARENT);
	if (priv->props.id != props->id)
		g_object_notify (object, NM_DEVICE_VXLAN_ID);
	if (priv->props.group != props->group)
		g_object_notify (object, NM_DEVICE_VXLAN_GROUP);
	if (priv->props.local != props->local)
		g_object_notify (object, NM_DEVICE_VXLAN_LOCAL);
	if (memcmp (&priv->props.group6, &props->group6, sizeof (props->group6)) != 0)
		g_object_notify (object, NM_DEVICE_VXLAN_GROUP);
	if (memcmp (&priv->props.local6, &props->local6, sizeof (props->local6)) != 0)
		g_object_notify (object, NM_DEVICE_VXLAN_LOCAL);
	if (priv->props.tos != props->tos)
		g_object_notify (object, NM_DEVICE_VXLAN_TOS);
	if (priv->props.ttl != props->ttl)
		g_object_notify (object, NM_DEVICE_VXLAN_TTL);
	if (priv->props.learning != props->learning)
		g_object_notify (object, NM_DEVICE_VXLAN_LEARNING);
	if (priv->props.ageing != props->ageing)
		g_object_notify (object, NM_DEVICE_VXLAN_AGEING);
	if (priv->props.limit != props->limit)
		g_object_notify (object, NM_DEVICE_VXLAN_LIMIT);
	if (priv->props.dst_port != props->dst_port)
		g_object_notify (object, NM_DEVICE_VXLAN_DST_PORT);
	if (priv->props.src_port_min != props->src_port_min)
		g_object_notify (object, NM_DEVICE_VXLAN_SRC_PORT_MIN);
	if (priv->props.src_port_max != props->src_port_max)
		g_object_notify (object, NM_DEVICE_VXLAN_SRC_PORT_MAX);
	if (priv->props.proxy != props->proxy)
		g_object_notify (object, NM_DEVICE_VXLAN_PROXY);
	if (priv->props.rsc != props->rsc)
		g_object_notify (object, NM_DEVICE_VXLAN_RSC);
	if (priv->props.l2miss != props->l2miss)
		g_object_notify (object, NM_DEVICE_VXLAN_L2MISS);
	if (priv->props.l3miss != props->l3miss)
		g_object_notify (object, NM_DEVICE_VXLAN_L3MISS);

	priv->props = *props;

	g_object_thaw_notify (object);
}

static void
link_changed (NMDevice *device, NMPlatformLink *info)
{
	NM_DEVICE_CLASS (nm_device_vxlan_parent_class)->link_changed (device, info);
	update_properties (device);
}

static void
setup (NMDevice *device, NMPlatformLink *plink)
{
	g_assert (plink->type == NM_LINK_TYPE_VXLAN);

	NM_DEVICE_CLASS (nm_device_vxlan_parent_class)->setup (device, plink);

	update_properties (device);
}


/**************************************************************/

static void
nm_device_vxlan_init (NMDeviceVxlan *self)
{
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (object);
	NMDevice *parent;

	switch (prop_id) {
	case PROP_PARENT:
		parent = nm_manager_get_device_by_ifindex (nm_manager_get (), priv->props.parent_ifindex);
		nm_utils_g_value_set_object_path (value, parent);
		break;
	case PROP_ID:
		g_value_set_uint (value, priv->props.id);
		break;
	case PROP_GROUP:
		if (priv->props.group)
			g_value_set_string (value, nm_utils_inet4_ntop (priv->props.group, NULL));
		else if (!IN6_IS_ADDR_UNSPECIFIED (&priv->props.group6))
			g_value_set_string (value, nm_utils_inet6_ntop (&priv->props.group6, NULL));
		break;
	case PROP_LOCAL:
		if (priv->props.local)
			g_value_set_string (value, nm_utils_inet4_ntop (priv->props.local, NULL));
		else if (!IN6_IS_ADDR_UNSPECIFIED (&priv->props.local6))
			g_value_set_string (value, nm_utils_inet6_ntop (&priv->props.local6, NULL));
		break;
	case PROP_TOS:
		g_value_set_uchar (value, priv->props.tos);
		break;
	case PROP_TTL:
		g_value_set_uchar (value, priv->props.ttl);
		break;
	case PROP_LEARNING:
		g_value_set_boolean (value, priv->props.learning);
		break;
	case PROP_AGEING:
		g_value_set_uint (value, priv->props.ageing);
		break;
	case PROP_LIMIT:
		g_value_set_uint (value, priv->props.limit);
		break;
	case PROP_DST_PORT:
		g_value_set_uint (value, priv->props.dst_port);
		break;
	case PROP_SRC_PORT_MIN:
		g_value_set_uint (value, priv->props.src_port_min);
		break;
	case PROP_SRC_PORT_MAX:
		g_value_set_uint (value, priv->props.src_port_max);
		break;
	case PROP_PROXY:
		g_value_set_boolean (value, priv->props.proxy);
		break;
	case PROP_RSC:
		g_value_set_boolean (value, priv->props.rsc);
		break;
	case PROP_L2MISS:
		g_value_set_boolean (value, priv->props.l2miss);
		break;
	case PROP_L3MISS:
		g_value_set_boolean (value, priv->props.l3miss);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_vxlan_class_init (NMDeviceVxlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDeviceVxlanPrivate));

	object_class->get_property = get_property;

	device_class->link_changed = link_changed;
	device_class->setup = setup;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_PARENT,
		 g_param_spec_string (NM_DEVICE_VXLAN_PARENT, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_ID,
		 g_param_spec_uint (NM_DEVICE_VXLAN_ID, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_GROUP,
		 g_param_spec_string (NM_DEVICE_VXLAN_GROUP, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_LOCAL,
		 g_param_spec_string (NM_DEVICE_VXLAN_LOCAL, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_TOS,
		 g_param_spec_uchar (NM_DEVICE_VXLAN_TOS, "", "",
		                     0, 255, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_TTL,
		 g_param_spec_uchar (NM_DEVICE_VXLAN_TTL, "", "",
		                     0, 255, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_LEARNING,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_LEARNING, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_AGEING,
		 g_param_spec_uint (NM_DEVICE_VXLAN_AGEING, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_LIMIT,
		 g_param_spec_uint (NM_DEVICE_VXLAN_LIMIT, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_DST_PORT,
		 g_param_spec_uint (NM_DEVICE_VXLAN_DST_PORT, "", "",
		                    0, 65535, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_SRC_PORT_MIN,
		 g_param_spec_uint (NM_DEVICE_VXLAN_SRC_PORT_MIN, "", "",
		                    0, 65535, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_SRC_PORT_MAX,
		 g_param_spec_uint (NM_DEVICE_VXLAN_SRC_PORT_MAX, "", "",
		                    0, 65535, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_PROXY,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_PROXY, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_RSC,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_RSC, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_L2MISS,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_L2MISS, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_L3MISS,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_L3MISS, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_VXLAN_SKELETON,
	                                        NULL);
}

/*************************************************************/

#define NM_TYPE_VXLAN_FACTORY (nm_vxlan_factory_get_type ())
#define NM_VXLAN_FACTORY(obj) (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_VXLAN_FACTORY, NMVxlanFactory))

static NMDevice *
create_device (NMDeviceFactory *factory,
               const char *iface,
               NMPlatformLink *plink,
               NMConnection *connection,
               gboolean *out_ignore)
{
	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_VXLAN,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_TYPE_DESC, "Vxlan",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_GENERIC,
	                                  NULL);
}

NM_DEVICE_FACTORY_DEFINE_INTERNAL (VXLAN, Vxlan, vxlan,
	NM_DEVICE_FACTORY_DECLARE_LINK_TYPES (NM_LINK_TYPE_VXLAN),
	factory_iface->create_device = create_device;
	)

