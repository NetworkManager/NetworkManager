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

#include "nm-device-vxlan.h"

#include "nm-setting-connection.h"
#include "nm-setting-vxlan.h"
#include "nm-utils.h"
#include "nm-object-private.h"

G_DEFINE_TYPE (NMDeviceVxlan, nm_device_vxlan, NM_TYPE_DEVICE)

#define NM_DEVICE_VXLAN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_VXLAN, NMDeviceVxlanPrivate))

typedef struct {
	NMDevice *parent;
	char *hw_address;
	gboolean carrier;
	guint id;
	char *group;
	char *local;
	guint src_port_min;
	guint src_port_max;
	guint dst_port;
	guint tos;
	guint ttl;
	guint limit;
	gboolean learning;
	guint ageing;
	gboolean proxy;
	gboolean rsc;
	gboolean l2miss;
	gboolean l3miss;
} NMDeviceVxlanPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_CARRIER,
	PROP_PARENT,
	PROP_ID,
	PROP_GROUP,
	PROP_LOCAL,
	PROP_TOS,
	PROP_TTL,
	PROP_LIMIT,
	PROP_LEARNING,
	PROP_AGEING,
	PROP_DST_PORT,
	PROP_SRC_PORT_MIN,
	PROP_SRC_PORT_MAX,
	PROP_PROXY,
	PROP_RSC,
	PROP_L2MISS,
	PROP_L3MISS,

	LAST_PROP
};

/**
 * nm_device_vxlan_get_hw_address:
 * @device: a #NMDeviceVxlan
 *
 * Gets the hardware (MAC) address of the #NMDeviceVxlan
 *
 * Returns: the hardware address. This is the internal string used by the
 * device, and must not be modified.
 *
 * Since: 1.2
 **/
const char *
nm_device_vxlan_get_hw_address (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), NULL);

	return nm_str_not_empty (NM_DEVICE_VXLAN_GET_PRIVATE (device)->hw_address);
}

/**
 * nm_device_vxlan_get_carrier:
 * @device: a #NMDeviceVxlan
 *
 * Whether the device has carrier.
 *
 * Returns: %TRUE if the device has carrier.
 *
 * Since: 1.2
 **/
gboolean
nm_device_vxlan_get_carrier (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), FALSE);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->carrier;
}

/**
 * nm_device_vxlan_get_parent:
 * @device: a #NMDeviceVxlan
 *
 * Returns: (transfer none): the device's parent device
 *
 * Since: 1.2
 **/
NMDevice *
nm_device_vxlan_get_parent (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), NULL);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->parent;
}

/**
 * nm_device_vxlan_get_id:
 * @device: a #NMDeviceVxlan
 *
 * Returns: the device's VXLAN ID.
 *
 * Since: 1.2
 **/
guint
nm_device_vxlan_get_id (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), 0);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->id;
}

/**
 * nm_device_vxlan_get_group:
 * @device: a #NMDeviceVxlan
 *
 * Returns: The unicast destination IP address or the multicast
 * IP address joined
 *
 * Since: 1.2
 **/
const char *
nm_device_vxlan_get_group (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), NULL);

	return nm_str_not_empty (NM_DEVICE_VXLAN_GET_PRIVATE (device)->group);
}

/**
 * nm_device_vxlan_get_local:
 * @device: a #NMDeviceVxlan
 *
 * Returns: the source IP address to use in outgoing packets
 *
 * Since: 1.2
 **/
const char *
nm_device_vxlan_get_local (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), NULL);

	return nm_str_not_empty (NM_DEVICE_VXLAN_GET_PRIVATE (device)->local);
}

/**
 * nm_device_vxlan_get_src_port_min:
 * @device: a #NMDeviceVxlan
 *
 * Returns: the minimum UDP source port
 *
 * Since: 1.2
 **/
guint
nm_device_vxlan_get_src_port_min (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), 0);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->src_port_min;
}

/**
 * nm_device_vxlan_get_src_port_max:
 * @device: a #NMDeviceVxlan
 *
 * Returns:  the maximum UDP source port
 *
 * Since: 1.2
 **/
guint
nm_device_vxlan_get_src_port_max (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), 0);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->src_port_max;
}

/**
 * nm_device_vxlan_get_dst_port:
 * @device: a #NMDeviceVxlan
 *
 * Returns: the UDP destination port
 *
 * Since: 1.2
 **/
guint
nm_device_vxlan_get_dst_port (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), 0);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->dst_port;
}

/**
 * nm_device_vxlan_get_learning:
 * @device: a #NMDeviceVxlan
 *
 * Returns: whether address learning is enabled
 *
 * Since: 1.2
 **/
gboolean
nm_device_vxlan_get_learning (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), FALSE);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->learning;
}

/**
 * nm_device_vxlan_get_ageing:
 * @device: a #NMDeviceVxlan
 *
 * Returns: the lifetime in seconds of FDB entries learnt by the kernel
 *
 * Since: 1.2
 **/
guint
nm_device_vxlan_get_ageing (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), 0);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->ageing;
}

/**
 * nm_device_vxlan_get_tos:
 * @device: a #NMDeviceVxlan
 *
 * Returns: the TOS value to use in outgoing packets
 *
 * Since: 1.2
 **/
guint
nm_device_vxlan_get_tos (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), 0);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->tos;
}

/**
 * nm_device_vxlan_get_ttl:
 * @device: a #NMDeviceVxlan
 *
 * Returns: the time-to-live value to use in outgoing packets
 *
 * Since: 1.2
 **/
guint
nm_device_vxlan_get_ttl (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), 0);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->ttl;
}

/**
 * nm_device_vxlan_get_limit:
 * @device: a #NMDeviceVxlan
 *
 * Returns: the maximum number of entries that can be added to the
 * forwarding table
 *
 * Since: 1.2
 **/
guint
nm_device_vxlan_get_limit (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), 0);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->limit;
}

/**
 * nm_device_vxlan_get_proxy:
 * @device: a #NMDeviceVxlan
 *
 * Returns: whether ARP proxy is turned on
 *
 * Since: 1.2
 **/
gboolean
nm_device_vxlan_get_proxy (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), FALSE);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->proxy;
}

/**
 * nm_device_vxlan_get_rsc:
 * @device: a #NMDeviceVxlan
 *
 * Returns: whether route short circuit is turned on
 *
 * Since: 1.2
 **/
gboolean
nm_device_vxlan_get_rsc (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), FALSE);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->rsc;
}

/**
 * nm_device_vxlan_get_l2miss:
 * @device: a #NMDeviceVxlan
 *
 * Returns: whether netlink LL ADDR miss notifications are generated
 *
 * Since: 1.2
 **/
gboolean
nm_device_vxlan_get_l2miss (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), FALSE);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->l2miss;
}

/**
 * nm_device_vxlan_get_l3miss:
 * @device: a #NMDeviceVxlan
 *
 * Returns: whether netlink IP ADDR miss notifications are generated
 *
 * Since: 1.2
 **/
gboolean
nm_device_vxlan_get_l3miss (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), FALSE);

	return NM_DEVICE_VXLAN_GET_PRIVATE (device)->l3miss;
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	NMSettingVxlan *s_vxlan;

	if (!NM_DEVICE_CLASS (nm_device_vxlan_parent_class)->connection_compatible (device, connection, error))
		return FALSE;

	if (!nm_connection_is_type (connection, NM_SETTING_VXLAN_SETTING_NAME)) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The connection was not a VXLAN connection."));
		return FALSE;
	}

	s_vxlan = nm_connection_get_setting_vxlan (connection);
	if (nm_setting_vxlan_get_id (s_vxlan) != nm_device_vxlan_get_id (NM_DEVICE_VXLAN (device))) {
		g_set_error_literal (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     _("The VXLAN identifiers of the device and the connection didn't match."));
		return FALSE;
	}

	return TRUE;
}

static GType
get_setting_type (NMDevice *device)
{
	return NM_TYPE_SETTING_VXLAN;
}

static const char *
get_hw_address (NMDevice *device)
{
	return nm_device_vxlan_get_hw_address (NM_DEVICE_VXLAN (device));
}

/*****************************************************************************/

static void
nm_device_vxlan_init (NMDeviceVxlan *device)
{
}

static void
init_dbus (NMObject *object)
{
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_VXLAN_HW_ADDRESS,   &priv->hw_address },
		{ NM_DEVICE_VXLAN_CARRIER,      &priv->carrier },
		{ NM_DEVICE_VXLAN_PARENT,       &priv->parent, NULL, NM_TYPE_DEVICE },
		{ NM_DEVICE_VXLAN_ID,           &priv->id },
		{ NM_DEVICE_VXLAN_GROUP,        &priv->group },
		{ NM_DEVICE_VXLAN_LOCAL,        &priv->local },
		{ NM_DEVICE_VXLAN_SRC_PORT_MIN, &priv->src_port_min },
		{ NM_DEVICE_VXLAN_SRC_PORT_MAX, &priv->src_port_max },
		{ NM_DEVICE_VXLAN_DST_PORT,     &priv->dst_port },
		{ NM_DEVICE_VXLAN_TOS,          &priv->tos },
		{ NM_DEVICE_VXLAN_TTL,          &priv->ttl },
		{ NM_DEVICE_VXLAN_LIMIT,        &priv->limit },
		{ NM_DEVICE_VXLAN_LEARNING,     &priv->learning },
		{ NM_DEVICE_VXLAN_AGEING,       &priv->ageing },
		{ NM_DEVICE_VXLAN_PROXY,        &priv->proxy },
		{ NM_DEVICE_VXLAN_RSC,          &priv->rsc },
		{ NM_DEVICE_VXLAN_L2MISS,       &priv->l2miss },
		{ NM_DEVICE_VXLAN_L3MISS,       &priv->l3miss },
		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_vxlan_parent_class)->init_dbus (object);

	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE_VXLAN,
	                                property_info);
}

static void
finalize (GObject *object)
{
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (object);

	g_free (priv->hw_address);
	g_clear_object (&priv->parent);
	g_free (priv->group);
	g_free (priv->local);

	G_OBJECT_CLASS (nm_device_vxlan_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDeviceVxlan *device = NM_DEVICE_VXLAN (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, nm_device_vxlan_get_hw_address (device));
		break;
	case PROP_CARRIER:
		g_value_set_boolean (value, nm_device_vxlan_get_carrier (device));
		break;
	case PROP_PARENT:
		g_value_set_object (value, nm_device_vxlan_get_parent (device));
		break;
	case PROP_ID:
		g_value_set_uint (value, nm_device_vxlan_get_id (device));
		break;
	case PROP_GROUP:
		g_value_set_string (value, nm_device_vxlan_get_group (device));
		break;
	case PROP_LOCAL:
		g_value_set_string (value, nm_device_vxlan_get_local (device));
		break;
	case PROP_TOS:
		g_value_set_uint (value, nm_device_vxlan_get_tos (device));
		break;
	case PROP_TTL:
		g_value_set_uint (value, nm_device_vxlan_get_ttl (device));
		break;
	case PROP_LIMIT:
		g_value_set_uint (value, nm_device_vxlan_get_limit (device));
		break;
	case PROP_LEARNING:
		g_value_set_boolean (value, nm_device_vxlan_get_learning (device));
		break;
	case PROP_AGEING:
		g_value_set_uint (value, nm_device_vxlan_get_ageing (device));
		break;
	case PROP_DST_PORT:
		g_value_set_uint (value, nm_device_vxlan_get_dst_port (device));
		break;
	case PROP_SRC_PORT_MIN:
		g_value_set_uint (value, nm_device_vxlan_get_src_port_min (device));
		break;
	case PROP_SRC_PORT_MAX:
		g_value_set_uint (value, nm_device_vxlan_get_src_port_max (device));
		break;
	case PROP_PROXY:
		g_value_set_boolean (value, nm_device_vxlan_get_proxy (device));
		break;
	case PROP_RSC:
		g_value_set_boolean (value, nm_device_vxlan_get_rsc (device));
		break;
	case PROP_L2MISS:
		g_value_set_boolean (value, nm_device_vxlan_get_l2miss (device));
		break;
	case PROP_L3MISS:
		g_value_set_boolean (value, nm_device_vxlan_get_l3miss (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_device_vxlan_class_init (NMDeviceVxlanClass *vxlan_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (vxlan_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (vxlan_class);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (vxlan_class);

	g_type_class_add_private (vxlan_class, sizeof (NMDeviceVxlanPrivate));

	/* virtual methods */
	object_class->finalize = finalize;
	object_class->get_property = get_property;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type = get_setting_type;
	device_class->get_hw_address = get_hw_address;

	/* properties */

	/**
	 * NMDeviceVxlan:hw-address:
	 *
	 * The hardware (MAC) address of the device.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_VXLAN_HW_ADDRESS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:carrier:
	 *
	 * Whether the device has carrier.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_CARRIER,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_CARRIER, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:parent:
	 *
	 * The devices's parent device.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
	    (object_class, PROP_PARENT,
	     g_param_spec_object (NM_DEVICE_VXLAN_PARENT, "", "",
	                          NM_TYPE_DEVICE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:id:
	 *
	 * The device's VXLAN ID.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_ID,
		 g_param_spec_uint (NM_DEVICE_VXLAN_ID, "", "",
		                    0, (1 << 24) - 1, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:group:
	 *
	 * The unicast destination IP address used in outgoing packets when the
	 * destination link layer address is not known in the VXLAN device
	 * forwarding database or the multicast IP address joined.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_GROUP,
		 g_param_spec_string (NM_DEVICE_VXLAN_GROUP, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:local:
	 *
	 * The source IP address to use in outgoing packets.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_LOCAL,
		 g_param_spec_string (NM_DEVICE_VXLAN_LOCAL, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:tos:
	 *
	 * The TOS value to use in outgoing packets.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_TOS,
		 g_param_spec_uchar (NM_DEVICE_VXLAN_TOS, "", "",
		                     0, 255, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:ttl:
	 *
	 * The time-to-live value to use in outgoing packets.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_TTL,
		 g_param_spec_uchar (NM_DEVICE_VXLAN_TTL, "", "",
		                     0, 255, 0,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:learning:
	 *
	 * Whether unknown source link layer addresses and IP addresses are entered
	 * into the VXLAN device forwarding database.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_LEARNING,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_LEARNING, "", "",
		                       TRUE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:ageing:
	 *
	 * The lifetime in seconds of FDB entries learnt by the kernel.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_AGEING,
		 g_param_spec_uint (NM_DEVICE_VXLAN_AGEING, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:limit:
	 *
	 * The maximum number of entries that can be added to the forwarding table.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_LIMIT,
		 g_param_spec_uint (NM_DEVICE_VXLAN_LIMIT, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:dst-port:
	 *
	 * The UDP destination port used to communicate with the remote VXLAN tunnel
	 * endpoint.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_DST_PORT,
		 g_param_spec_uint (NM_DEVICE_VXLAN_DST_PORT, "", "",
		                    0, 65535, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:src-port-min:
	 *
	 * The minimum UDP source port used to communicate with the remote VXLAN
	 * tunnel endpoint.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_SRC_PORT_MIN,
		 g_param_spec_uint (NM_DEVICE_VXLAN_SRC_PORT_MIN, "", "",
		                    0, 65535, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:src-port-max:
	 *
	 * The maximum UDP source port used to communicate with the remote VXLAN
	 * tunnel endpoint.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_SRC_PORT_MAX,
		 g_param_spec_uint (NM_DEVICE_VXLAN_SRC_PORT_MAX, "", "",
		                    0, 65535, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:proxy:
	 *
	 * Whether ARP proxy is turned on.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_PROXY,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_PROXY, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:rsc:
	 *
	 * Whether route short circuit is turned on.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_RSC,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_RSC, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:l2miss:
	 *
	 * Whether netlink LL ADDR miss notifications are generated.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_L2MISS,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_L2MISS, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDeviceVxlan:l3miss:
	 *
	 * Whether netlink IP ADDR miss notifications are generated.
	 *
	 * Since: 1.2
	 */
	g_object_class_install_property
		(object_class, PROP_L3MISS,
		 g_param_spec_boolean (NM_DEVICE_VXLAN_L3MISS, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));
}
