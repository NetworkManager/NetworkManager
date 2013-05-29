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

#include <stdlib.h>
#include <string.h>

#include "nm-device-tun.h"
#include "nm-device-private.h"
#include "nm-dbus-manager.h"
#include "nm-logging.h"
#include "nm-platform.h"

#include "nm-device-tun-glue.h"

G_DEFINE_TYPE (NMDeviceTun, nm_device_tun, NM_TYPE_DEVICE_GENERIC)

#define NM_DEVICE_TUN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_TUN, NMDeviceTunPrivate))

typedef struct {
	NMPlatformTunProperties props;
} NMDeviceTunPrivate;

enum {
	PROP_0,
	PROP_OWNER,
	PROP_GROUP,
	PROP_FLAGS,
	PROP_MODE,
	PROP_NO_PI,
	PROP_VNET_HDR,
	PROP_MULTI_QUEUE,

	LAST_PROP
};

static void
link_changed (NMDevice *device)
{
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (device);
	GObject *object = G_OBJECT (device);
	NMPlatformTunProperties props;

	if (!nm_platform_tun_get_properties (nm_device_get_ifindex (device), &props)) {
		nm_log_warn (LOGD_HW, "(%s): could not read tun properties",
		             nm_device_get_iface (device));
		return;
	}

	g_object_freeze_notify (object);

	if (priv->props.owner != props.owner)
		g_object_notify (object, NM_DEVICE_TUN_OWNER);
	if (priv->props.group != props.group)
		g_object_notify (object, NM_DEVICE_TUN_GROUP);
	if (g_strcmp0 (priv->props.mode, props.mode) != 0)
		g_object_notify (object, NM_DEVICE_TUN_MODE);
	if (priv->props.no_pi != props.no_pi)
		g_object_notify (object, NM_DEVICE_TUN_NO_PI);
	if (priv->props.vnet_hdr != props.vnet_hdr)
		g_object_notify (object, NM_DEVICE_TUN_VNET_HDR);
	if (priv->props.multi_queue != props.multi_queue)
		g_object_notify (object, NM_DEVICE_TUN_MULTI_QUEUE);

	memcpy (&priv->props, &props, sizeof (NMPlatformTunProperties));

	g_object_thaw_notify (object);
}

/**************************************************************/

NMDevice *
nm_device_tun_new (NMPlatformLink *platform_device)
{
	g_return_val_if_fail (platform_device != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_TUN,
	                                  NM_DEVICE_PLATFORM_DEVICE, platform_device,
	                                  NM_DEVICE_TYPE_DESC, "Tun",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_GENERIC,
	                                  NULL);
}

static void
nm_device_tun_init (NMDeviceTun *self)
{
}

static void
constructed (GObject *object)
{
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (object);

	nm_platform_tun_get_properties (nm_device_get_ifindex (NM_DEVICE (object)), &priv->props);

	G_OBJECT_CLASS (nm_device_tun_parent_class)->constructed (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceTun *self = NM_DEVICE_TUN (object);
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_OWNER:
		g_value_set_uint (value, priv->props.owner);
		break;
	case PROP_GROUP:
		g_value_set_uint (value, priv->props.group);
		break;
	case PROP_MODE:
		g_value_set_string (value, priv->props.mode);
		break;
	case PROP_NO_PI:
		g_value_set_boolean (value, priv->props.no_pi);
		break;
	case PROP_VNET_HDR:
		g_value_set_boolean (value, priv->props.vnet_hdr);
		break;
	case PROP_MULTI_QUEUE:
		g_value_set_boolean (value, priv->props.multi_queue);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_tun_class_init (NMDeviceTunClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDeviceTunPrivate));

	object_class->constructed = constructed;
	object_class->get_property = get_property;

	device_class->link_changed = link_changed;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_OWNER,
		 g_param_spec_int64 (NM_DEVICE_TUN_OWNER,
		                     "Owner",
		                     "Owner",
		                     -1, G_MAXUINT32, -1,
		                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_GROUP,
		 g_param_spec_int64 (NM_DEVICE_TUN_GROUP,
		                     "Group",
		                     "Group",
		                     -1, G_MAXUINT32, -1,
		                     G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_string (NM_DEVICE_TUN_MODE,
		                      "Mode",
		                      "Mode",
		                      "tun",
		                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_NO_PI,
		 g_param_spec_boolean (NM_DEVICE_TUN_NO_PI,
		                      "No Protocol Info",
		                      "No Protocol Info",
		                      FALSE,
		                      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_VNET_HDR,
		 g_param_spec_boolean (NM_DEVICE_TUN_VNET_HDR,
		                       "Virtio networking header",
		                       "Virtio networking header",
		                       FALSE,
		                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_MULTI_QUEUE,
		 g_param_spec_boolean (NM_DEVICE_TUN_MULTI_QUEUE,
		                       "Multi-queue",
		                       "Multi-queue",
		                       FALSE,
		                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_tun_object_info);
}
