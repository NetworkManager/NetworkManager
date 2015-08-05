/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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
 * Copyright 2013 Jiri Pirko <jiri@resnulli.us>
 */

#include "config.h"

#include <string.h>
#include <netinet/ether.h>

#include <nm-setting-connection.h>
#include <nm-setting-team.h>
#include <nm-utils.h>

#include "nm-default.h"
#include "nm-device-team.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-types.h"

G_DEFINE_TYPE (NMDeviceTeam, nm_device_team, NM_TYPE_DEVICE)

#define NM_DEVICE_TEAM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_TEAM, NMDeviceTeamPrivate))

typedef struct {
	DBusGProxy *proxy;

	char *hw_address;
	gboolean carrier;
	GPtrArray *slaves;
} NMDeviceTeamPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_CARRIER,
	PROP_SLAVES,

	LAST_PROP
};

/**
 * nm_device_team_error_quark:
 *
 * Registers an error quark for #NMDeviceTeam if necessary.
 *
 * Returns: the error quark used for #NMDeviceTeam errors.
 *
 * Since: 0.9.10
 **/
GQuark
nm_device_team_error_quark (void)
{
	static GQuark quark = 0;

	if (G_UNLIKELY (quark == 0))
		quark = g_quark_from_static_string ("nm-device-team-error-quark");
	return quark;
}

/**
 * nm_device_team_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDeviceTeam.
 *
 * Returns: (transfer full): a new device
 *
 * Since: 0.9.10
 **/
GObject *
nm_device_team_new (DBusGConnection *connection, const char *path)
{
	GObject *device;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	device = g_object_new (NM_TYPE_DEVICE_TEAM,
	                       NM_OBJECT_DBUS_CONNECTION, connection,
	                       NM_OBJECT_DBUS_PATH, path,
	                       NULL);
	_nm_object_ensure_inited (NM_OBJECT (device));
	return device;
}

/**
 * nm_device_team_get_hw_address:
 * @device: a #NMDeviceTeam
 *
 * Gets the hardware (MAC) address of the #NMDeviceTeam
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 0.9.10
 **/
const char *
nm_device_team_get_hw_address (NMDeviceTeam *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TEAM (device), NULL);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_TEAM_GET_PRIVATE (device)->hw_address;
}

/**
 * nm_device_team_get_carrier:
 * @device: a #NMDeviceTeam
 *
 * Whether the device has carrier.
 *
 * Returns: %TRUE if the device has carrier
 *
 * Since: 0.9.10
 **/
gboolean
nm_device_team_get_carrier (NMDeviceTeam *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TEAM (device), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_TEAM_GET_PRIVATE (device)->carrier;
}

/**
 * nm_device_team_get_slaves:
 * @device: a #NMDeviceTeam
 *
 * Gets the devices currently enslaved to @device.
 *
 * Returns: (element-type NMDevice): the #GPtrArray containing
 * #NMDevices that are slaves of @device. This is the internal
 * copy used by the device, and must not be modified.
 *
 * Since: 0.9.10
 **/
const GPtrArray *
nm_device_team_get_slaves (NMDeviceTeam *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TEAM (device), FALSE);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return handle_ptr_array_return (NM_DEVICE_TEAM_GET_PRIVATE (device)->slaves);
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_team_get_hw_address (NM_DEVICE_TEAM (device));
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingConnection *s_con;
	NMSettingTeam *s_team;
	const char *ctype, *dev_iface_name, *team_iface_name;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	ctype = nm_setting_connection_get_connection_type (s_con);
	if (strcmp (ctype, NM_SETTING_TEAM_SETTING_NAME) != 0) {
		g_set_error (error, NM_DEVICE_TEAM_ERROR, NM_DEVICE_TEAM_ERROR_NOT_TEAM_CONNECTION,
		             "The connection was not a team connection.");
		return FALSE;
	}

	s_team = nm_connection_get_setting_team (connection);
	if (!s_team) {
		g_set_error (error, NM_DEVICE_TEAM_ERROR, NM_DEVICE_TEAM_ERROR_INVALID_TEAM_CONNECTION,
		             "The connection was not a valid team connection.");
		return FALSE;
	}

	dev_iface_name = nm_device_get_iface (device);
	team_iface_name = nm_setting_team_get_interface_name (s_team);
	if (g_strcmp0 (dev_iface_name, team_iface_name) != 0) {
		g_set_error (error, NM_DEVICE_TEAM_ERROR, NM_DEVICE_TEAM_ERROR_INTERFACE_MISMATCH,
		             "The interfaces of the device and the connection didn't match.");
		return FALSE;
	}

	/* FIXME: check slaves? */

	return NM_DEVICE_CLASS (nm_device_team_parent_class)->connection_compatible (device, connection, error);
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_TEAM;
}

/***********************************************************/

static void
nm_device_team_init (NMDeviceTeam *device)
{
	_nm_device_set_device_type (NM_DEVICE (device), NM_DEVICE_TYPE_TEAM);
}

static void
register_properties (NMDeviceTeam *device)
{
	NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE (device);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_TEAM_HW_ADDRESS, &priv->hw_address },
		{ NM_DEVICE_TEAM_CARRIER,    &priv->carrier },
		{ NM_DEVICE_TEAM_SLAVES,     &priv->slaves, NULL, NM_TYPE_DEVICE },
		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (device),
	                                priv->proxy,
	                                property_info);
}

static void
constructed (GObject *object)
{
	NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE (object);

	G_OBJECT_CLASS (nm_device_team_parent_class)->constructed (object);

	priv->proxy = _nm_object_new_proxy (NM_OBJECT (object), NULL, NM_DBUS_INTERFACE_DEVICE_TEAM);
	register_properties (NM_DEVICE_TEAM (object));
}

static void
dispose (GObject *object)
{
	NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);

	if (priv->slaves) {
		g_ptr_array_set_free_func (priv->slaves, g_object_unref);
		g_ptr_array_free (priv->slaves, TRUE);
		priv->slaves = NULL;
	}

	G_OBJECT_CLASS (nm_device_team_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE (object);

	g_free (priv->hw_address);

	G_OBJECT_CLASS (nm_device_team_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceTeam *device = NM_DEVICE_TEAM (object);

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_team_get_hw_address (device));
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_team_get_carrier (device));
		break;
	case PROP_SLAVES:
		g_value_set_boxed (value, nm_device_team_get_slaves (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_team_class_init (NMDeviceTeamClass *team_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (team_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (team_class);

	g_type_class_add_private (team_class, sizeof (NMDeviceTeamPrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
	device_class->get_hw_address = get_hw_address;

	/* properties */

	/**
	 * NMDeviceTeam:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_TEAM_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceTeam:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_TEAM_CARRIER, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceTeam:slaves:
	 *
	 * The devices (#NMDevice) enslaved to the team device.
	 **/
	g_object_class_install_property
		(object_class, PROP_SLAVES,
		 g_param_spec_boxed (NM_DEVICE_TEAM_SLAVES, "", "",
		                     NM_TYPE_OBJECT_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));
}
