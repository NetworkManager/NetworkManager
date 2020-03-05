// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2013 Jiri Pirko <jiri@resnulli.us>
 */

#include "nm-default.h"

#include "nm-device-team.h"

#include "nm-setting-connection.h"
#include "nm-setting-team.h"
#include "nm-utils.h"
#include "nm-object-private.h"
#include "nm-core-internal.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_CARRIER,
	PROP_SLAVES,
	PROP_CONFIG,
);

typedef struct {
	NMLDBusPropertyAO slaves;
	char *config;
	bool carrier;
} NMDeviceTeamPrivate;

struct _NMDeviceTeam {
	NMDevice parent;
	NMDeviceTeamPrivate _priv;
};

struct _NMDeviceTeamClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceTeam, nm_device_team, NM_TYPE_DEVICE)

#define NM_DEVICE_TEAM_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceTeam, NM_IS_DEVICE_TEAM, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_team_get_hw_address:
 * @device: a #NMDeviceTeam
 *
 * Gets the hardware (MAC) address of the #NMDeviceTeam
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Deprecated: 1.24 use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_team_get_hw_address (NMDeviceTeam *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TEAM (device), NULL);

	return nm_device_get_hw_address (NM_DEVICE (device));
}

/**
 * nm_device_team_get_carrier:
 * @device: a #NMDeviceTeam
 *
 * Whether the device has carrier.
 *
 * Returns: %TRUE if the device has carrier
 **/
gboolean
nm_device_team_get_carrier (NMDeviceTeam *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TEAM (device), FALSE);

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
 **/
const GPtrArray *
nm_device_team_get_slaves (NMDeviceTeam *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TEAM (device), FALSE);

	return nml_dbus_property_ao_get_objs_as_ptrarray (&NM_DEVICE_TEAM_GET_PRIVATE (device)->slaves);
}

/**
 * nm_device_team_get_config:
 * @device: a #NMDeviceTeam
 *
 * Gets the current JSON configuration of the #NMDeviceTeam
 *
 * Returns: the current configuration. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.4
 **/
const char *
nm_device_team_get_config (NMDeviceTeam *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TEAM (device), NULL);

	return _nml_coerce_property_str_not_empty (NM_DEVICE_TEAM_GET_PRIVATE (device)->config);
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	if (!NM_DEVICE_CLASS (nm_device_team_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_TEAM_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		                     _("The connection was not a team connection."));
		return FALSE;
	}

	/* FIXME: check slaves? */

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_TEAM;
}

/*****************************************************************************/

static void
nm_device_team_init (NMDeviceTeam *device)
{
}

static void
finalize (GObject *object)
{
	NMDeviceTeamPrivate *priv = NM_DEVICE_TEAM_GET_PRIVATE (object);

	g_free (priv->config);

	G_OBJECT_CLASS (nm_device_team_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceTeam *device = NM_DEVICE_TEAM (object);

	switch (prop_id) {
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_team_get_carrier (device));
		break;
	case PROP_SLAVES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_device_team_get_slaves (device)));
		break;
	case PROP_CONFIG:
		g_value_set_string (value, nm_device_team_get_config (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_team = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_TEAM,
	nm_device_team_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_B       ("Carrier",   PROP_CARRIER,    NMDeviceTeam, _priv.carrier                                               ),
		NML_DBUS_META_PROPERTY_INIT_S       ("Config",    PROP_CONFIG,     NMDeviceTeam, _priv.config                                                ),
		NML_DBUS_META_PROPERTY_INIT_FCN     ("HwAddress", 0,               "s",          _nm_device_notify_update_prop_hw_address                    ),
		NML_DBUS_META_PROPERTY_INIT_AO_PROP ("Slaves",    PROP_SLAVES,     NMDeviceTeam, _priv.slaves,                            nm_device_get_type ),
	),
);

static void
nm_device_team_class_init (NMDeviceTeamClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT (nm_object_class, NMDeviceTeam);

	_NM_OBJECT_CLASS_INIT_PROPERTY_AO_FIELDS_1 (nm_object_class, NMDeviceTeamPrivate, slaves);

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceTeam:carrier:
	 *
	 * Whether the device has carrier.
	 **/
	obj_properties[PROP_CARRIER] =
	    g_param_spec_boolean (NM_DEVICE_TEAM_CARRIER, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceTeam:slaves: (type GPtrArray(NMDevice))
	 *
	 * The devices enslaved to the team device.
	 **/
	obj_properties[PROP_SLAVES] =
	    g_param_spec_boxed (NM_DEVICE_TEAM_SLAVES, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceTeam:config:
	 *
	 * The current JSON configuration of the device.
	 *
	 * Since: 1.4
	 **/
	obj_properties[PROP_CONFIG] =
	    g_param_spec_string (NM_DEVICE_TEAM_CONFIG, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_team);
}
