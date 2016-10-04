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

#include "nm-device-generic.h"

#include "nm-device-private.h"
#include "nm-enum-types.h"
#include "nm-platform.h"
#include "nm-core-internal.h"

#include "nmdbus-device-generic.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_TYPE_DESCRIPTION,
);

typedef struct {
	char *type_description;
} NMDeviceGenericPrivate;

struct _NMDeviceGeneric {
	NMDevice parent;
	NMDeviceGenericPrivate _priv;
};

struct _NMDeviceGenericClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceGeneric, nm_device_generic, NM_TYPE_DEVICE)

#define NM_DEVICE_GENERIC_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDeviceGeneric, NM_IS_DEVICE_GENERIC)

/*****************************************************************************/

static NMDeviceCapabilities
get_generic_capabilities (NMDevice *dev)
{
	if (nm_platform_link_supports_carrier_detect (NM_PLATFORM_GET, nm_device_get_ifindex (dev)))
		return NM_DEVICE_CAP_CARRIER_DETECT;
	else
		return NM_DEVICE_CAP_NONE;
}

static const char *
get_type_description (NMDevice *device)
{
	if (NM_DEVICE_GENERIC_GET_PRIVATE ((NMDeviceGeneric *) device)->type_description)
		return NM_DEVICE_GENERIC_GET_PRIVATE ((NMDeviceGeneric *) device)->type_description;
	return NM_DEVICE_CLASS (nm_device_generic_parent_class)->get_type_description (device);
}

static void
realize_start_notify (NMDevice *device, const NMPlatformLink *plink)
{
	NMDeviceGeneric *self = NM_DEVICE_GENERIC (device);
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (self);
	int ifindex;

	NM_DEVICE_CLASS (nm_device_generic_parent_class)->realize_start_notify (device, plink);

	g_clear_pointer (&priv->type_description, g_free);
	ifindex = nm_device_get_ip_ifindex (NM_DEVICE (self));
	if (ifindex > 0)
		priv->type_description = g_strdup (nm_platform_link_get_type_name (NM_PLATFORM_GET, ifindex));
}

static gboolean
check_connection_compatible (NMDevice *device, NMConnection *connection)
{
	NMSettingConnection *s_con;

	if (!NM_DEVICE_CLASS (nm_device_generic_parent_class)->check_connection_compatible (device, connection))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_GENERIC_SETTING_NAME))
		return FALSE;

	s_con = nm_connection_get_setting_connection (connection);
	if (!nm_setting_connection_get_interface_name (s_con))
		return FALSE;

	return TRUE;
}

static void
update_connection (NMDevice *device, NMConnection *connection)
{
	NMSettingConnection *s_con;

	if (!nm_connection_get_setting_generic (connection))
		nm_connection_add_setting (connection, nm_setting_generic_new ());

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);
	g_object_set (G_OBJECT (s_con),
	              NM_SETTING_CONNECTION_INTERFACE_NAME, nm_device_get_iface (device),
	              NULL);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMDeviceGeneric *self = NM_DEVICE_GENERIC (object);
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_TYPE_DESCRIPTION:
		g_value_set_string (value, priv->type_description);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDeviceGeneric *self = NM_DEVICE_GENERIC (object);
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_TYPE_DESCRIPTION:
		priv->type_description = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_device_generic_init (NMDeviceGeneric *self)
{
}

static GObject *
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;

	object = G_OBJECT_CLASS (nm_device_generic_parent_class)->constructor (type,
	                                                                       n_construct_params,
	                                                                       construct_params);

	nm_device_set_unmanaged_flags ((NMDevice *) object, NM_UNMANAGED_BY_DEFAULT, TRUE);

	return object;
}

NMDevice *
nm_device_generic_new (const NMPlatformLink *plink, gboolean nm_plugin_missing)
{
	g_return_val_if_fail (plink != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_GENERIC,
	                                  NM_DEVICE_IFACE, plink->name,
	                                  NM_DEVICE_TYPE_DESC, "Generic",
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_GENERIC,
	                                  NM_DEVICE_NM_PLUGIN_MISSING, nm_plugin_missing,
	                                  NULL);
}

static void
dispose (GObject *object)
{
	NMDeviceGeneric *self = NM_DEVICE_GENERIC (object);
	NMDeviceGenericPrivate *priv = NM_DEVICE_GENERIC_GET_PRIVATE (self);

	g_clear_pointer (&priv->type_description, g_free);

	G_OBJECT_CLASS (nm_device_generic_parent_class)->dispose (object);
}

static void
nm_device_generic_class_init (NMDeviceGenericClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	NM_DEVICE_CLASS_DECLARE_TYPES (klass, NM_SETTING_GENERIC_SETTING_NAME, NM_LINK_TYPE_ANY)

	object_class->constructor = constructor;
	object_class->dispose = dispose;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	parent_class->realize_start_notify = realize_start_notify;
	parent_class->get_generic_capabilities = get_generic_capabilities;
	parent_class->get_type_description = get_type_description;
	parent_class->check_connection_compatible = check_connection_compatible;
	parent_class->update_connection = update_connection;

	obj_properties[PROP_TYPE_DESCRIPTION] =
	     g_param_spec_string (NM_DEVICE_GENERIC_TYPE_DESCRIPTION, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (klass),
	                                        NMDBUS_TYPE_DEVICE_GENERIC_SKELETON,
	                                        NULL);
}
