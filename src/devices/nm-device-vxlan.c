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

#include <string.h>

#include "nm-device-vxlan.h"
#include "nm-dbus-manager.h"
#include "nm-logging.h"
#include "nm-manager.h"
#include "nm-platform.h"

#include "nm-device-vxlan-glue.h"

G_DEFINE_TYPE (NMDeviceVxlan, nm_device_vxlan, NM_TYPE_DEVICE_GENERIC)

#define NM_DEVICE_VXLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_VXLAN, NMDeviceVxlanPrivate))

typedef struct {
	NMDevice *parent;
	NMPlatformVxlanProperties props;
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
	PROP_PORT_MIN,
	PROP_PORT_MAX,
	PROP_PROXY,
	PROP_RSC,
	PROP_L2MISS,
	PROP_L3MISS,

	LAST_PROP
};

/**************************************************************/

static void
link_changed (NMDevice *device)
{
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (device);
	GObject *object = G_OBJECT (device);
	NMPlatformVxlanProperties props;

	if (!nm_platform_vxlan_get_properties (nm_device_get_ifindex (device), &props)) {
		nm_log_warn (LOGD_HW, "(%s): could not read vxlan properties",
		             nm_device_get_iface (device));
		return;
	}

	g_object_freeze_notify (object);

	if (priv->props.parent_ifindex != props.parent_ifindex) {
		g_object_notify (object, NM_DEVICE_VXLAN_PARENT);
		if (priv->parent)
			g_object_remove_weak_pointer (G_OBJECT (priv->parent), (gpointer *) &priv->parent);
		priv->parent = nm_manager_get_device_by_ifindex (nm_manager_get (), props.parent_ifindex);
		if (priv->parent)
			g_object_add_weak_pointer (G_OBJECT (priv->parent), (gpointer *) &priv->parent);
	}

	if (priv->props.id != props.id)
		g_object_notify (object, NM_DEVICE_VXLAN_ID);
	if (priv->props.group != props.group)
		g_object_notify (object, NM_DEVICE_VXLAN_GROUP);
	if (priv->props.local != props.local)
		g_object_notify (object, NM_DEVICE_VXLAN_LOCAL);
	if (priv->props.tos != props.tos)
		g_object_notify (object, NM_DEVICE_VXLAN_TOS);
	if (priv->props.ttl != props.ttl)
		g_object_notify (object, NM_DEVICE_VXLAN_TTL);
	if (priv->props.learning != props.learning)
		g_object_notify (object, NM_DEVICE_VXLAN_LEARNING);
	if (priv->props.ageing != props.ageing)
		g_object_notify (object, NM_DEVICE_VXLAN_AGEING);
	if (priv->props.limit != props.limit)
		g_object_notify (object, NM_DEVICE_VXLAN_LIMIT);
	if (priv->props.port_min != props.port_min)
		g_object_notify (object, NM_DEVICE_VXLAN_PORT_MIN);
	if (priv->props.port_max != props.port_max)
		g_object_notify (object, NM_DEVICE_VXLAN_PORT_MAX);
	if (priv->props.proxy != props.proxy)
		g_object_notify (object, NM_DEVICE_VXLAN_PROXY);
	if (priv->props.rsc != props.rsc)
		g_object_notify (object, NM_DEVICE_VXLAN_RSC);
	if (priv->props.l2miss != props.l2miss)
		g_object_notify (object, NM_DEVICE_VXLAN_L2MISS);
	if (priv->props.l3miss != props.l3miss)
		g_object_notify (object, NM_DEVICE_VXLAN_L3MISS);

	memcpy (&priv->props, &props, sizeof (NMPlatformVxlanProperties));

	g_object_thaw_notify (object);
}

/**************************************************************/

NMDevice *
nm_device_vxlan_new (const char *udi,
                       const char *iface,
                       const char *driver)
{
	g_return_val_if_fail (udi != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_VXLAN,
	                                  NM_DEVICE_UDI, udi,
	                                  NM_DEVICE_IFACE, iface,
	                                  NM_DEVICE_DRIVER, driver,
	                                  NM_DEVICE_TYPE_DESC, "Vxlan",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_GENERIC,
	                                  NULL);
}

static void
nm_device_vxlan_init (NMDeviceVxlan *self)
{
}

static void
constructed (GObject *object)
{
	link_changed (NM_DEVICE (object));

	G_OBJECT_CLASS (nm_device_vxlan_parent_class)->constructed (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (object);
	char buf[INET_ADDRSTRLEN];

	switch (prop_id) {
	case PROP_PARENT:
		g_value_set_boxed (value, priv->parent ? nm_device_get_path (priv->parent) : "/");
		break;
	case PROP_ID:
		g_value_set_uint (value, priv->props.id);
		break;
	case PROP_GROUP:
		g_value_set_string (value, inet_ntop (AF_INET, &priv->props.group, buf, sizeof (buf)));
		break;
	case PROP_LOCAL:
		g_value_set_string (value, inet_ntop (AF_INET, &priv->props.local, buf, sizeof (buf)));
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
	case PROP_PORT_MIN:
		g_value_set_uint (value, priv->props.port_min);
		break;
	case PROP_PORT_MAX:
		g_value_set_uint (value, priv->props.port_max);
		break;
	case PROP_PROXY:
		g_value_set_uint (value, priv->props.proxy);
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

	object_class->constructed = constructed;
	object_class->get_property = get_property;

	device_class->link_changed = link_changed;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_PARENT,
		 g_param_spec_boxed (NM_DEVICE_VXLAN_PARENT,
		                     "Parent",
		                     "Parent device",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_ID,
		 g_param_spec_uint (NM_DEVICE_VXLAN_ID,
		                    "Id",
		                    "Id",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_GROUP,
		 g_param_spec_string (NM_DEVICE_VXLAN_GROUP,
		                      "Group",
		                      "Group",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_LOCAL,
		 g_param_spec_string (NM_DEVICE_VXLAN_LOCAL,
		                      "Local",
		                      "Local",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_TOS,
		 g_param_spec_uchar (NM_DEVICE_VXLAN_TOS,
		                     "ToS",
		                     "ToS",
		                     0, 255, 0,
		                     G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_TTL,
		 g_param_spec_uchar (NM_DEVICE_VXLAN_TTL,
		                     "TTL",
		                     "TTL",
		                     0, 255, 0,
		                     G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_LEARNING,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_LEARNING,
		                       "Learning",
		                       "Learning",
		                       FALSE,
		                       G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_AGEING,
		 g_param_spec_uint (NM_DEVICE_VXLAN_AGEING,
		                    "Ageing",
		                    "Ageing",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_LIMIT,
		 g_param_spec_uint (NM_DEVICE_VXLAN_LIMIT,
		                    "Limit",
		                    "Limit",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_PORT_MIN,
		 g_param_spec_uint (NM_DEVICE_VXLAN_PORT_MIN,
		                    "Port min",
		                    "Port min",
		                    0, 65535, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_PORT_MAX,
		 g_param_spec_uint (NM_DEVICE_VXLAN_PORT_MAX,
		                    "Port max",
		                    "Port max",
		                    0, 65535, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_PROXY,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_PROXY,
		                       "Proxy",
		                       "Proxy",
		                       FALSE,
		                       G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_RSC,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_RSC,
		                       "RSC",
		                       "RSC",
		                       FALSE,
		                       G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_L2MISS,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_L2MISS,
		                       "L2miss",
		                       "L2miss",
		                       FALSE,
		                       G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_L3MISS,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_L3MISS,
		                       "L3miss",
		                       "L3miss",
		                       FALSE,
		                       G_PARAM_READABLE));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_vxlan_object_info);
}
