// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-tun.h"

#include <arpa/inet.h>

#include "nm-setting-connection.h"
#include "nm-setting-tun.h"
#include "nm-utils.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_MODE,
	PROP_OWNER,
	PROP_GROUP,
	PROP_NO_PI,
	PROP_VNET_HDR,
	PROP_MULTI_QUEUE,
);

typedef struct {
	char *mode;
	gint64 owner;
	gint64 group;
	bool no_pi;
	bool vnet_hdr;
	bool multi_queue;
} NMDeviceTunPrivate;

struct _NMDeviceTun {
	NMDevice parent;
	NMDeviceTunPrivate _priv;
};

struct _NMDeviceTunClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceTun, nm_device_tun, NM_TYPE_DEVICE)

#define NM_DEVICE_TUN_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceTun, NM_IS_DEVICE_TUN, NMObject, NMDevice)

/*****************************************************************************/

/**
 * nm_device_tun_get_hw_address:
 * @device: a #NMDeviceTun
 *
 * Gets the hardware (MAC) address of the #NMDeviceTun
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.2
 *
 * Deprecated: 1.24: Use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_tun_get_hw_address (NMDeviceTun *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TUN (device), NULL);

	return nm_device_get_hw_address (NM_DEVICE (device));
}

/**
 * nm_device_tun_get_mode:
 * @device: a #NMDeviceTun
 *
 * Returns the TUN/TAP mode for the device.
 *
 * Returns: 'tun' or 'tap'
 *
 * Since: 1.2
 **/
const char *
nm_device_tun_get_mode (NMDeviceTun *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TUN (device), NULL);

	return _nml_coerce_property_str_not_empty (NM_DEVICE_TUN_GET_PRIVATE (device)->mode);
}

/**
 * nm_device_tun_get_owner:
 * @device: a #NMDeviceTun
 *
 * Gets the tunnel owner.
 *
 * Returns: the uid of the tunnel owner, or -1 if it has no owner.
 *
 * Since: 1.2
 **/
gint64
nm_device_tun_get_owner (NMDeviceTun *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TUN (device), -1);

	return NM_DEVICE_TUN_GET_PRIVATE (device)->owner;
}

/**
 * nm_device_tun_get_group:
 * @device: a #NMDeviceTun
 *
 * Gets the tunnel group.
 *
 * Returns: the gid of the tunnel group, or -1 if it has no owner.
 *
 * Since: 1.2
 **/
gint64
nm_device_tun_get_group (NMDeviceTun *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TUN (device), -1);

	return NM_DEVICE_TUN_GET_PRIVATE (device)->group;
}

/**
 * nm_device_tun_get_pi:
 * @device: a #NMDeviceTun
 *
 * Returns whether the #NMDeviceTun has the IFF_NO_PI flag.
 *
 * Returns: %TRUE if the device has the flag, %FALSE otherwise
 *
 * Since: 1.2
 **/
gboolean
nm_device_tun_get_no_pi (NMDeviceTun *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TUN (device), FALSE);

	return NM_DEVICE_TUN_GET_PRIVATE (device)->no_pi;
}

/**
 * nm_device_tun_get_vnet_hdr:
 * @device: a #NMDeviceTun
 *
 * Returns whether the #NMDeviceTun has the IFF_VNET_HDR flag.
 *
 * Returns: %TRUE if the device has the flag, %FALSE otherwise
 *
 * Since: 1.2
 **/
gboolean
nm_device_tun_get_vnet_hdr (NMDeviceTun *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TUN (device), FALSE);

	return NM_DEVICE_TUN_GET_PRIVATE (device)->vnet_hdr;
}

/**
 * nm_device_tun_get_multi_queue:
 * @device: a #NMDeviceTun
 *
 * Returns whether the #NMDeviceTun has the IFF_MULTI_QUEUE flag.
 *
 * Returns: %TRUE if the device doesn't have the flag, %FALSE otherwise
 *
 * Since: 1.2
 **/
gboolean
nm_device_tun_get_multi_queue (NMDeviceTun *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_TUN (device), FALSE);

	return NM_DEVICE_TUN_GET_PRIVATE (device)->multi_queue;
}

static int
tun_mode_from_string (const char *string)
{
	if (!g_strcmp0 (string, "tap"))
		return NM_SETTING_TUN_MODE_TAP;
	else
		return NM_SETTING_TUN_MODE_TUN;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (device);
	NMSettingTunMode mode;
	NMSettingTun *s_tun;

	if (!NM_DEVICE_CLASS (nm_device_tun_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_TUN_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a tun connection."));
		return FALSE;
	}

	s_tun = nm_connection_get_setting_tun (connection);

	mode = tun_mode_from_string (priv->mode);
	if (s_tun && mode != nm_setting_tun_get_mode (s_tun)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The mode of the device and the connection didn't match"));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_TUN;
}

/*****************************************************************************/

static void
nm_device_tun_init (NMDeviceTun *device)
{
}

static void
finalize (GObject *object)
{
	NMDeviceTunPrivate *priv = NM_DEVICE_TUN_GET_PRIVATE (object);

	g_free (priv->mode);

	G_OBJECT_CLASS (nm_device_tun_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceTun *device = NM_DEVICE_TUN (object);

	switch (prop_id) {
	case PROP_MODE:
		g_value_set_string (value, nm_device_tun_get_mode (device));
		break;
	case PROP_OWNER:
		g_value_set_int64 (value, nm_device_tun_get_owner (device));
		break;
	case PROP_GROUP:
		g_value_set_int64 (value, nm_device_tun_get_group (device));
		break;
	case PROP_NO_PI:
		g_value_set_boolean (value, nm_device_tun_get_no_pi (device));
		break;
	case PROP_VNET_HDR:
		g_value_set_boolean (value, nm_device_tun_get_vnet_hdr (device));
		break;
	case PROP_MULTI_QUEUE:
		g_value_set_boolean (value, nm_device_tun_get_multi_queue (device));
		break;

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_tun = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_TUN,
	nm_device_tun_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_X   ("Group",      PROP_GROUP,       NMDeviceTun, _priv.group                              ),
		NML_DBUS_META_PROPERTY_INIT_FCN ("HwAddress",  0,                "s",         _nm_device_notify_update_prop_hw_address ),
		NML_DBUS_META_PROPERTY_INIT_S   ("Mode",       PROP_MODE,        NMDeviceTun, _priv.mode                               ),
		NML_DBUS_META_PROPERTY_INIT_B   ("MultiQueue", PROP_MULTI_QUEUE, NMDeviceTun, _priv.multi_queue                        ),
		NML_DBUS_META_PROPERTY_INIT_B   ("NoPi",       PROP_NO_PI,       NMDeviceTun, _priv.no_pi                              ),
		NML_DBUS_META_PROPERTY_INIT_X   ("Owner",      PROP_OWNER,       NMDeviceTun, _priv.owner                              ),
		NML_DBUS_META_PROPERTY_INIT_B   ("VnetHdr",    PROP_VNET_HDR,    NMDeviceTun, _priv.vnet_hdr                           ),
	),
);

static void
nm_device_tun_class_init (NMDeviceTunClass *gre_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (gre_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (gre_class);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceTun:mode:
	 *
	 * The tunnel mode, either "tun" or "tap".
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_MODE] =
	    g_param_spec_string (NM_DEVICE_TUN_MODE, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceTun:owner:
	 *
	 * The uid of the tunnel owner, or -1 if it has no owner.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_OWNER] =
	    g_param_spec_int64 (NM_DEVICE_TUN_OWNER, "", "",
	                        -1, G_MAXUINT32, -1,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceTun:group:
	 *
	 * The gid of the tunnel group, or -1 if it has no owner.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_GROUP] =
	    g_param_spec_int64 (NM_DEVICE_TUN_GROUP, "", "",
	                        -1, G_MAXUINT32, -1,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceTun:no-pi:
	 *
	 * The tunnel's "TUN_NO_PI" flag; true if no protocol info is
	 * prepended to the tunnel packets.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_NO_PI] =
	    g_param_spec_boolean (NM_DEVICE_TUN_NO_PI, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceTun:vnet-hdr:
	 *
	 * The tunnel's "TUN_VNET_HDR" flag; true if the tunnel packets
	 * include a virtio network header.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_VNET_HDR] =
	    g_param_spec_boolean (NM_DEVICE_TUN_VNET_HDR, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceTun:multi-queue:
	 *
	 * The tunnel's "TUN_TAP_MQ" flag; true if callers can connect to
	 * the tap device multiple times, for multiple send/receive
	 * queues.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_MULTI_QUEUE] =
	    g_param_spec_boolean (NM_DEVICE_TUN_MULTI_QUEUE, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_tun);
}
