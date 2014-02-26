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

#include "nm-device-gre.h"
#include "nm-device-private.h"
#include "nm-dbus-manager.h"
#include "nm-logging.h"
#include "nm-manager.h"
#include "nm-platform.h"

#include "nm-device-gre-glue.h"

G_DEFINE_TYPE (NMDeviceGre, nm_device_gre, NM_TYPE_DEVICE_GENERIC)

#define NM_DEVICE_GRE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_GRE, NMDeviceGrePrivate))

typedef struct {
	NMPlatformGreProperties props;
} NMDeviceGrePrivate;

enum {
	PROP_0,
	PROP_PARENT,
	PROP_INPUT_FLAGS,
	PROP_OUTPUT_FLAGS,
	PROP_INPUT_KEY,
	PROP_OUTPUT_KEY,
	PROP_LOCAL,
	PROP_REMOTE,
	PROP_TTL,
	PROP_TOS,
	PROP_PATH_MTU_DISCOVERY,

	LAST_PROP
};

/**************************************************************/

static void
update_properties (NMDevice *device)
{
	NMDeviceGrePrivate *priv = NM_DEVICE_GRE_GET_PRIVATE (device);
	GObject *object = G_OBJECT (device);
	NMPlatformGreProperties props;

	if (!nm_platform_gre_get_properties (nm_device_get_ifindex (device), &props)) {
		nm_log_warn (LOGD_HW, "(%s): could not read gre properties",
		             nm_device_get_iface (device));
		return;
	}

	g_object_freeze_notify (object);

	if (priv->props.parent_ifindex != props.parent_ifindex)
		g_object_notify (object, NM_DEVICE_GRE_PARENT);
	if (priv->props.input_flags != props.input_flags)
		g_object_notify (object, NM_DEVICE_GRE_INPUT_FLAGS);
	if (priv->props.output_flags != props.output_flags)
		g_object_notify (object, NM_DEVICE_GRE_OUTPUT_FLAGS);
	if (priv->props.input_key != props.input_key)
		g_object_notify (object, NM_DEVICE_GRE_INPUT_KEY);
	if (priv->props.output_key != props.output_key)
		g_object_notify (object, NM_DEVICE_GRE_OUTPUT_KEY);
	if (priv->props.local != props.local)
		g_object_notify (object, NM_DEVICE_GRE_LOCAL);
	if (priv->props.remote != props.remote)
		g_object_notify (object, NM_DEVICE_GRE_REMOTE);
	if (priv->props.ttl != props.ttl)
		g_object_notify (object, NM_DEVICE_GRE_TTL);
	if (priv->props.tos != props.tos)
		g_object_notify (object, NM_DEVICE_GRE_TOS);
	if (priv->props.path_mtu_discovery != props.path_mtu_discovery)
		g_object_notify (object, NM_DEVICE_GRE_PATH_MTU_DISCOVERY);

	memcpy (&priv->props, &props, sizeof (NMPlatformGreProperties));

	g_object_thaw_notify (object);
}

static void
link_changed (NMDevice *device, NMPlatformLink *info)
{
	NM_DEVICE_CLASS (nm_device_gre_parent_class)->link_changed (device, info);
	update_properties (device);
}

/**************************************************************/

NMDevice *
nm_device_gre_new (NMPlatformLink *platform_device)
{
	g_return_val_if_fail (platform_device != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_GRE,
	                                  NM_DEVICE_PLATFORM_DEVICE, platform_device,
	                                  NM_DEVICE_TYPE_DESC, "Gre",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_GENERIC,
	                                  NULL);
}

static void
nm_device_gre_init (NMDeviceGre *self)
{
}

static void
constructed (GObject *object)
{
	update_properties (NM_DEVICE (object));

	G_OBJECT_CLASS (nm_device_gre_parent_class)->constructed (object);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceGrePrivate *priv = NM_DEVICE_GRE_GET_PRIVATE (object);
	char buf[INET_ADDRSTRLEN];
	NMDevice *parent;

	switch (prop_id) {
	case PROP_PARENT:
		parent = nm_manager_get_device_by_ifindex (nm_manager_get (), priv->props.parent_ifindex);
		g_value_set_boxed (value, parent ? nm_device_get_path (parent) : "/");
		break;
	case PROP_INPUT_FLAGS:
		g_value_set_uint (value, priv->props.input_flags);
		break;
	case PROP_OUTPUT_FLAGS:
		g_value_set_uint (value, priv->props.output_flags);
		break;
	case PROP_INPUT_KEY:
		g_value_set_uint (value, priv->props.input_key);
		break;
	case PROP_OUTPUT_KEY:
		g_value_set_uint (value, priv->props.output_key);
		break;
	case PROP_LOCAL:
		g_value_set_string (value, inet_ntop (AF_INET, &priv->props.local, buf, sizeof (buf)));
		break;
	case PROP_REMOTE:
		g_value_set_string (value, inet_ntop (AF_INET, &priv->props.remote, buf, sizeof (buf)));
		break;
	case PROP_TTL:
		g_value_set_uchar (value, priv->props.ttl);
		break;
	case PROP_TOS:
		g_value_set_uchar (value, priv->props.tos);
		break;
	case PROP_PATH_MTU_DISCOVERY:
		g_value_set_boolean (value, priv->props.path_mtu_discovery);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_gre_class_init (NMDeviceGreClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDeviceGrePrivate));

	object_class->constructed = constructed;
	object_class->get_property = get_property;

	device_class->link_changed = link_changed;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_PARENT,
		 g_param_spec_boxed (NM_DEVICE_GRE_PARENT,
		                     "Parent",
		                     "Parent device",
		                     DBUS_TYPE_G_OBJECT_PATH,
		                     G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_INPUT_FLAGS,
		 g_param_spec_uint (NM_DEVICE_GRE_INPUT_FLAGS,
		                    "Input flags",
		                    "Input flags",
		                    0, G_MAXUINT16, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_OUTPUT_FLAGS,
		 g_param_spec_uint (NM_DEVICE_GRE_OUTPUT_FLAGS,
		                    "Output flags",
		                    "Output flags",
		                    0, G_MAXUINT16, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_INPUT_KEY,
		 g_param_spec_uint (NM_DEVICE_GRE_INPUT_KEY,
		                    "Input key",
		                    "Input key",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_OUTPUT_KEY,
		 g_param_spec_uint (NM_DEVICE_GRE_OUTPUT_KEY,
		                    "Output key",
		                    "Output key",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_LOCAL,
		 g_param_spec_string (NM_DEVICE_GRE_LOCAL,
		                      "Local",
		                      "Local",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_REMOTE,
		 g_param_spec_string (NM_DEVICE_GRE_REMOTE,
		                      "Remote",
		                      "Remote",
		                      NULL,
		                      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_TTL,
		 g_param_spec_uchar (NM_DEVICE_GRE_TTL,
		                     "TTL",
		                     "TTL",
		                     0, 255, 0,
		                     G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_TOS,
		 g_param_spec_uchar (NM_DEVICE_GRE_TOS,
		                     "ToS",
		                     "ToS",
		                     0, 255, 0,
		                     G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_PATH_MTU_DISCOVERY,
		 g_param_spec_boolean (NM_DEVICE_GRE_PATH_MTU_DISCOVERY,
		                       "Path MTU Discovery",
		                       "Path MTU Discovery",
		                       FALSE,
		                       G_PARAM_READABLE));

	nm_dbus_manager_register_exported_type (nm_dbus_manager_get (),
	                                        G_TYPE_FROM_CLASS (klass),
	                                        &dbus_glib_nm_device_gre_object_info);
}
