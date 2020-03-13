// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2015 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device-vxlan.h"

#include "nm-setting-connection.h"
#include "nm-setting-vxlan.h"
#include "nm-utils.h"
#include "nm-object-private.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
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
);

typedef struct {
	NMLDBusPropertyO parent;
	char *group;
	char *local;
	guint32 id;
	guint32 limit;
	guint32 ageing;
	guint16 src_port_min;
	guint16 src_port_max;
	guint16 dst_port;
	guint8 tos;
	guint8 ttl;
	bool learning;
	bool proxy;
	bool rsc;
	bool l2miss;
	bool l3miss;
} NMDeviceVxlanPrivate;

struct _NMDeviceVxlan {
	NMDevice parent;
	NMDeviceVxlanPrivate _priv;
};

struct _NMDeviceVxlanClass {
	NMDeviceClass parent;
};

G_DEFINE_TYPE (NMDeviceVxlan, nm_device_vxlan, NM_TYPE_DEVICE)

#define NM_DEVICE_VXLAN_GET_PRIVATE(self) _NM_GET_PRIVATE(self, NMDeviceVxlan, NM_IS_DEVICE_VXLAN, NMObject, NMDevice)

/*****************************************************************************/

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
 *
 * Deprecated: 1.24 use nm_device_get_hw_address() instead.
 **/
const char *
nm_device_vxlan_get_hw_address (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), NULL);

	return nm_device_get_hw_address (NM_DEVICE (device));
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
 *
 * This property is not implemented yet, and the function always returns
 * FALSE.
 **/
gboolean
nm_device_vxlan_get_carrier (NMDeviceVxlan *device)
{
	g_return_val_if_fail (NM_IS_DEVICE_VXLAN (device), FALSE);

	return FALSE;
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

	return nml_dbus_property_o_get_obj (&NM_DEVICE_VXLAN_GET_PRIVATE (device)->parent);
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

	return _nml_coerce_property_str_not_empty (NM_DEVICE_VXLAN_GET_PRIVATE (device)->group);
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

	return _nml_coerce_property_str_not_empty (NM_DEVICE_VXLAN_GET_PRIVATE (device)->local);
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

/*****************************************************************************/

static void
nm_device_vxlan_init (NMDeviceVxlan *device)
{
}

static void
finalize (GObject *object)
{
	NMDeviceVxlanPrivate *priv = NM_DEVICE_VXLAN_GET_PRIVATE (object);

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

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_vxlan = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE_VXLAN,
	nm_device_vxlan_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_HIGH,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_U      ("Ageing",     PROP_AGEING,       NMDeviceVxlan, _priv.ageing                                                ),
		NML_DBUS_META_PROPERTY_INIT_Q      ("DstPort",    PROP_DST_PORT,     NMDeviceVxlan, _priv.dst_port                                              ),
		NML_DBUS_META_PROPERTY_INIT_S      ("Group",      PROP_GROUP,        NMDeviceVxlan, _priv.group                                                 ),
		NML_DBUS_META_PROPERTY_INIT_FCN    ("HwAddress",  0,                 "s",           _nm_device_notify_update_prop_hw_address                    ),
		NML_DBUS_META_PROPERTY_INIT_U      ("Id",         PROP_ID,           NMDeviceVxlan, _priv.id                                                    ),
		NML_DBUS_META_PROPERTY_INIT_B      ("L2miss",     PROP_L2MISS,       NMDeviceVxlan, _priv.l2miss                                                ),
		NML_DBUS_META_PROPERTY_INIT_B      ("L3miss",     PROP_L3MISS,       NMDeviceVxlan, _priv.l3miss                                                ),
		NML_DBUS_META_PROPERTY_INIT_B      ("Learning",   PROP_LEARNING,     NMDeviceVxlan, _priv.learning                                              ),
		NML_DBUS_META_PROPERTY_INIT_U      ("Limit",      PROP_LIMIT,        NMDeviceVxlan, _priv.limit                                                 ),
		NML_DBUS_META_PROPERTY_INIT_S      ("Local",      PROP_LOCAL,        NMDeviceVxlan, _priv.local                                                 ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP ("Parent",     PROP_PARENT,       NMDeviceVxlan, _priv.parent,                            nm_device_get_type ),
		NML_DBUS_META_PROPERTY_INIT_B      ("Proxy",      PROP_PROXY,        NMDeviceVxlan, _priv.proxy                                                 ),
		NML_DBUS_META_PROPERTY_INIT_B      ("Rsc",        PROP_RSC,          NMDeviceVxlan, _priv.rsc                                                   ),
		NML_DBUS_META_PROPERTY_INIT_Q      ("SrcPortMax", PROP_SRC_PORT_MAX, NMDeviceVxlan, _priv.src_port_max                                          ),
		NML_DBUS_META_PROPERTY_INIT_Q      ("SrcPortMin", PROP_SRC_PORT_MIN, NMDeviceVxlan, _priv.src_port_min                                          ),
		NML_DBUS_META_PROPERTY_INIT_Y      ("Tos",        PROP_TOS,          NMDeviceVxlan, _priv.tos                                                   ),
		NML_DBUS_META_PROPERTY_INIT_Y      ("Ttl",        PROP_TTL,          NMDeviceVxlan, _priv.ttl                                                   ),
	),
);

static void
nm_device_vxlan_class_init (NMDeviceVxlanClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_DIRECT (nm_object_class, NMDeviceVxlan);

	_NM_OBJECT_CLASS_INIT_PROPERTY_O_FIELDS_1 (nm_object_class, NMDeviceVxlanPrivate, parent);

	device_class->connection_compatible = connection_compatible;
	device_class->get_setting_type      = get_setting_type;

	/**
	 * NMDeviceVxlan:carrier:
	 *
	 * Whether the device has carrier.
	 *
	 * Since: 1.2
	 *
	 * This property is not implemented yet, and the property is always FALSE.
	 **/
	obj_properties[PROP_CARRIER] =
	    g_param_spec_boolean (NM_DEVICE_VXLAN_CARRIER, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:parent:
	 *
	 * The devices's parent device.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_PARENT] =
	    g_param_spec_object (NM_DEVICE_VXLAN_PARENT, "", "",
	                         NM_TYPE_DEVICE,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:id:
	 *
	 * The device's VXLAN ID.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_ID] =
	    g_param_spec_uint (NM_DEVICE_VXLAN_ID, "", "",
	                       0, (1 << 24) - 1, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:group:
	 *
	 * The unicast destination IP address used in outgoing packets when the
	 * destination link layer address is not known in the VXLAN device
	 * forwarding database or the multicast IP address joined.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_GROUP] =
	    g_param_spec_string (NM_DEVICE_VXLAN_GROUP, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:local:
	 *
	 * The source IP address to use in outgoing packets.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_LOCAL] =
	    g_param_spec_string (NM_DEVICE_VXLAN_LOCAL, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:tos:
	 *
	 * The TOS value to use in outgoing packets.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_TOS] =
	    g_param_spec_uchar (NM_DEVICE_VXLAN_TOS, "", "",
	                        0, 255, 0,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:ttl:
	 *
	 * The time-to-live value to use in outgoing packets.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_TTL] =
	    g_param_spec_uchar (NM_DEVICE_VXLAN_TTL, "", "",
	                        0, 255, 0,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:learning:
	 *
	 * Whether unknown source link layer addresses and IP addresses are entered
	 * into the VXLAN device forwarding database.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_LEARNING] =
	    g_param_spec_boolean (NM_DEVICE_VXLAN_LEARNING, "", "",
	                          TRUE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:ageing:
	 *
	 * The lifetime in seconds of FDB entries learnt by the kernel.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_AGEING] =
	    g_param_spec_uint (NM_DEVICE_VXLAN_AGEING, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:limit:
	 *
	 * The maximum number of entries that can be added to the forwarding table.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_LIMIT] =
	    g_param_spec_uint (NM_DEVICE_VXLAN_LIMIT, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:dst-port:
	 *
	 * The UDP destination port used to communicate with the remote VXLAN tunnel
	 * endpoint.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_DST_PORT] =
	    g_param_spec_uint (NM_DEVICE_VXLAN_DST_PORT, "", "",
	                       0, 65535, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:src-port-min:
	 *
	 * The minimum UDP source port used to communicate with the remote VXLAN
	 * tunnel endpoint.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_SRC_PORT_MIN] =
	    g_param_spec_uint (NM_DEVICE_VXLAN_SRC_PORT_MIN, "", "",
	                       0, 65535, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:src-port-max:
	 *
	 * The maximum UDP source port used to communicate with the remote VXLAN
	 * tunnel endpoint.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_SRC_PORT_MAX] =
	    g_param_spec_uint (NM_DEVICE_VXLAN_SRC_PORT_MAX, "", "",
	                       0, 65535, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:proxy:
	 *
	 * Whether ARP proxy is turned on.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_PROXY] =
	    g_param_spec_boolean (NM_DEVICE_VXLAN_PROXY, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:rsc:
	 *
	 * Whether route short circuit is turned on.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_RSC] =
	    g_param_spec_boolean (NM_DEVICE_VXLAN_RSC, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:l2miss:
	 *
	 * Whether netlink LL ADDR miss notifications are generated.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_L2MISS] =
	    g_param_spec_boolean (NM_DEVICE_VXLAN_L2MISS, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDeviceVxlan:l3miss:
	 *
	 * Whether netlink IP ADDR miss notifications are generated.
	 *
	 * Since: 1.2
	 */
	obj_properties[PROP_L3MISS] =
	    g_param_spec_boolean (NM_DEVICE_VXLAN_L3MISS, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device_vxlan);
}
