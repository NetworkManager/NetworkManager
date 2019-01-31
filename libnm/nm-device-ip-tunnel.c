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
 * Copyright 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-ip-tunnel.h"

#include "nm-setting-connection.h"
#include "nm-setting-ip-tunnel.h"
#include "nm-utils.h"
#include "nm-object-private.h"
#include "nm-core-internal.h"

G_DEFINE_TYPE (NMDeviceIPTunnel, nm_device_ip_tunnel, NM_TYPE_DEVICE)

#define NM_DEVICE_IP_TUNNEL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_IP_TUNNEL, NMDeviceIPTunnelPrivate))

typedef struct {
	NMIPTunnelMode mode;
	NMDevice *parent;
	char *local;
	char *remote;
	guint8 ttl;
	guint8 tos;
	gboolean path_mtu_discovery;
	char *input_key;
	char *output_key;
	guint8 encap_limit;
	guint32 flow_label;
	guint32 flags;
} NMDeviceIPTunnelPrivate;

enum {
	PROP_0,
	PROP_MODE,
	PROP_PARENT,
	PROP_LOCAL,
	PROP_REMOTE,
	PROP_TTL,
	PROP_TOS,
	PROP_PATH_MTU_DISCOVERY,
	PROP_INPUT_KEY,
	PROP_OUTPUT_KEY,
	PROP_ENCAPSULATION_LIMIT,
	PROP_FLOW_LABEL,
	PROP_FLAGS,

	LAST_PROP
};

/**
 * nm_device_ip_tunnel_get_mode:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: the tunneling mode
 *
 * Since: 1.2
 **/
NMIPTunnelMode
nm_device_ip_tunnel_get_mode (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), 0);

	return NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->mode;
}

/**
 * nm_device_ip_tunnel_get_parent:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: (transfer none): the device's parent device
 *
 * Since: 1.2
 **/
NMDevice *
nm_device_ip_tunnel_get_parent (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), NULL);

	return NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->parent;
}

/**
 * nm_device_ip_tunnel_get_local:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: the local endpoint of the tunnel
 *
 * Since: 1.2
 **/
const char *
nm_device_ip_tunnel_get_local (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), NULL);

	return nm_str_not_empty (NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->local);
}

/**
 * nm_device_ip_tunnel_get_remote:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: the remote endpoint of the tunnel
 *
 * Since: 1.2
 **/
const char *
nm_device_ip_tunnel_get_remote (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), NULL);

	return nm_str_not_empty (NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->remote);
}

/**
 * nm_device_ip_tunnel_get_ttl:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: the TTL assigned to tunneled packets
 *
 * Since: 1.2
 **/
guint8
nm_device_ip_tunnel_get_ttl (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), 0);

	return NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->ttl;
}

/**
 * nm_device_ip_tunnel_get_tos:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: type of service (IPv4) or traffic class (IPv6) assigned
 * to tunneled packets.
 *
 * Since: 1.2
 **/
guint8
nm_device_ip_tunnel_get_tos (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), 0);

	return NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->tos;
}

/**
 * nm_device_ip_tunnel_get_path_mtu_discovery:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: whether path MTU discovery is enabled
 *
 * Since: 1.2
 **/
gboolean
nm_device_ip_tunnel_get_path_mtu_discovery (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), TRUE);

	return NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->path_mtu_discovery;
}

/**
 * nm_device_ip_tunnel_get_input_key:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: the key used for incoming packets
 *
 * Since: 1.2
 **/
const char *
nm_device_ip_tunnel_get_input_key (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), NULL);

	return nm_str_not_empty (NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->input_key);
}

/**
 * nm_device_ip_tunnel_get_output_key:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: the key used for outgoing packets
 *
 * Since: 1.2
 **/
const char *
nm_device_ip_tunnel_get_output_key (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), NULL);

	return nm_str_not_empty (NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->output_key);
}

/**
 * nm_device_ip_tunnel_get_encapsulation_limit:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: the maximum permitted encapsulation level
 *
 * Since: 1.2
 **/
guint8
nm_device_ip_tunnel_get_encapsulation_limit (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), 0);

	return NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->encap_limit;
}

/**
 * nm_device_ip_tunnel_get_flow_label:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: the flow label assigned to tunnel packets
 *
 * Since: 1.2
 **/
guint
nm_device_ip_tunnel_get_flow_label (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), 0);

	return NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->flow_label;
}

/**
 * nm_device_ip_tunnel_get_flags:
 * @device: a #NMDeviceIPTunnel
 *
 * Returns: the tunnel flags
 *
 * Since: 1.12
 **/
NMIPTunnelFlags
nm_device_ip_tunnel_get_flags (NMDeviceIPTunnel *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_IP_TUNNEL (device), NM_IP_TUNNEL_FLAG_NONE);

	return NM_DEVICE_IP_TUNNEL_GET_PRIVATE (device)->flags;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	if (!NM_DEVICE_CLASS (nm_device_ip_tunnel_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_IP_TUNNEL_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not an IP tunnel connection."));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_IP_TUNNEL;
}

/*****************************************************************************/

static void
nm_device_ip_tunnel_init (NMDeviceIPTunnel *device)
{
}

static void
init_dbus (NMObject *object)
{
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_IP_TUNNEL_PARENT,               &priv->parent, NULL, NM_TYPE_DEVICE },
		{ NM_DEVICE_IP_TUNNEL_MODE,                 &priv->mode },
		{ NM_DEVICE_IP_TUNNEL_LOCAL,                &priv->local },
		{ NM_DEVICE_IP_TUNNEL_REMOTE,               &priv->remote },
		{ NM_DEVICE_IP_TUNNEL_TTL,                  &priv->ttl },
		{ NM_DEVICE_IP_TUNNEL_TOS,                  &priv->tos },
		{ NM_DEVICE_IP_TUNNEL_PATH_MTU_DISCOVERY,   &priv->path_mtu_discovery },
		{ NM_DEVICE_IP_TUNNEL_INPUT_KEY,            &priv->input_key },
		{ NM_DEVICE_IP_TUNNEL_OUTPUT_KEY,           &priv->output_key },
		{ NM_DEVICE_IP_TUNNEL_ENCAPSULATION_LIMIT,  &priv->encap_limit },
		{ NM_DEVICE_IP_TUNNEL_FLOW_LABEL,           &priv->flow_label },
		{ NM_DEVICE_IP_TUNNEL_FLAGS,                &priv->flags },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_ip_tunnel_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_IP_TUNNEL,
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMDeviceIPTunnelPrivate *priv = NM_DEVICE_IP_TUNNEL_GET_PRIVATE (object);

	g_free (priv->local);
	g_free (priv->remote);
	g_free (priv->input_key);
	g_free (priv->output_key);
	g_clear_object (&priv->parent);

	G_OBJECT_CLASS (nm_device_ip_tunnel_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceIPTunnel *device = NM_DEVICE_IP_TUNNEL (object);

	switch (prop_id) {
	case PROP_PARENT:
		g_value_set_object (value, nm_device_ip_tunnel_get_parent (device));
		break;
	case PROP_MODE:
		g_value_set_uint (value, nm_device_ip_tunnel_get_mode (device));
		break;
	case PROP_LOCAL:
		g_value_set_string (value, nm_device_ip_tunnel_get_local (device));
		break;
	case PROP_REMOTE:
		g_value_set_string (value, nm_device_ip_tunnel_get_remote (device));
		break;
	case PROP_TTL:
		g_value_set_uint (value, nm_device_ip_tunnel_get_ttl (device));
		break;
	case PROP_TOS:
		g_value_set_uint (value, nm_device_ip_tunnel_get_tos (device));
		break;
	case PROP_PATH_MTU_DISCOVERY:
		g_value_set_boolean (value, nm_device_ip_tunnel_get_path_mtu_discovery (device));
		break;
	case PROP_INPUT_KEY:
		g_value_set_string (value, nm_device_ip_tunnel_get_input_key (device));
		break;
	case PROP_OUTPUT_KEY:
		g_value_set_string (value, nm_device_ip_tunnel_get_output_key (device));
		break;
	case PROP_ENCAPSULATION_LIMIT:
		g_value_set_uint (value, nm_device_ip_tunnel_get_encapsulation_limit (device));
		break;
	case PROP_FLOW_LABEL:
		g_value_set_uint (value, nm_device_ip_tunnel_get_flow_label (device));
		break;
	case PROP_FLAGS:
		g_value_set_uint (value, nm_device_ip_tunnel_get_flags (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_ip_tunnel_class_init (NMDeviceIPTunnelClass *bond_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (bond_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (bond_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (bond_class);

	g_type_class_add_private (bond_class, sizeof (NMDeviceIPTunnelPrivate));

	/* virtual methods */
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;

	/* properties */

	/**
	 * NMDeviceIPTunnel:mode:
	 *
	 * The tunneling mode of the device.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_MODE,
		 g_param_spec_uint (NM_DEVICE_IP_TUNNEL_MODE, "", "",
		                    0, G_MAXUINT, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceIPTunnel:parent:
	 *
	 * The devices's parent device.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
	    (object_class, PROP_PARENT,
	     g_param_spec_object (NM_DEVICE_IP_TUNNEL_PARENT, "", "",
	                          NM_TYPE_DEVICE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceIPTunnel:local:
	 *
	 * The local endpoint of the tunnel.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_LOCAL,
		 g_param_spec_string (NM_DEVICE_IP_TUNNEL_LOCAL, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceIPTunnel:remote:
	 *
	 * The remote endpoint of the tunnel.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_REMOTE,
		 g_param_spec_string (NM_DEVICE_IP_TUNNEL_REMOTE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceIPTunnel:ttl:
	 *
	 * The TTL assigned to tunneled packets. 0 is a special value
	 *  meaning that packets inherit the TTL value
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_TTL,
		 g_param_spec_uchar (NM_DEVICE_IP_TUNNEL_TTL, "", "",
		                     0, 255, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceIPTunnel:tos:
	 *
	 * The type of service (IPv4) or traffic class (IPv6) assigned to
	 * tunneled packets.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_TOS,
		 g_param_spec_uchar (NM_DEVICE_IP_TUNNEL_TOS, "", "",
		                     0, 255, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceIPTunnel:path-mtu-discovery:
	 *
	 * Whether path MTU discovery is enabled on this tunnel.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_PATH_MTU_DISCOVERY,
		 g_param_spec_boolean (NM_DEVICE_IP_TUNNEL_PATH_MTU_DISCOVERY, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceIPTunnel:input-key:
	 *
	 * The key used for tunneled input packets, if applicable.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_INPUT_KEY,
		 g_param_spec_string (NM_DEVICE_IP_TUNNEL_INPUT_KEY, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceIPTunnel:output-key:
	 *
	 * The key used for tunneled output packets, if applicable.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_OUTPUT_KEY,
		 g_param_spec_string (NM_DEVICE_IP_TUNNEL_OUTPUT_KEY, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceIPTunnel:encapsulation-limit:
	 *
	 * How many additional levels of encapsulation are permitted to
	 * be prepended to packets. This property applies only to IPv6
	 * tunnels.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_ENCAPSULATION_LIMIT,
		 g_param_spec_uchar (NM_DEVICE_IP_TUNNEL_ENCAPSULATION_LIMIT, "", "",
		                     0, 255, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceIPTunnel:flow-label:
	 *
	 * The flow label to assign to tunnel packets. This property
	 * applies only to IPv6 tunnels.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_FLOW_LABEL,
		 g_param_spec_uint (NM_DEVICE_IP_TUNNEL_FLOW_LABEL, "", "",
		                    0, (1 << 20) - 1, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceIPTunnel:flags:
	 *
	 * Tunnel flags.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
		(object_class, PROP_FLAGS,
		 g_param_spec_uint (NM_DEVICE_IP_TUNNEL_FLAGS, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));
}
