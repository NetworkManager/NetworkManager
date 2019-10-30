// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2014 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-active-connection.h"

#include "nm-dbus-interface.h"
#include "nm-object-private.h"
#include "nm-core-internal.h"
#include "nm-device.h"
#include "nm-connection.h"
#include "nm-vpn-connection.h"
#include "nm-dbus-helpers.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-remote-connection.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMActiveConnection,
	PROP_CONNECTION,
	PROP_ID,
	PROP_UUID,
	PROP_TYPE,
	PROP_SPECIFIC_OBJECT_PATH,
	PROP_DEVICES,
	PROP_STATE,
	PROP_STATE_FLAGS,
	PROP_DEFAULT,
	PROP_IP4_CONFIG,
	PROP_DHCP4_CONFIG,
	PROP_DEFAULT6,
	PROP_IP6_CONFIG,
	PROP_DHCP6_CONFIG,
	PROP_VPN,
	PROP_MASTER,
);

enum {
	STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL];

enum {
	PROPERTY_O_IDX_CONNECTION,
	PROPERTY_O_IDX_MASTER,
	PROPERTY_O_IDX_IP4_CONFIG,
	PROPERTY_O_IDX_IP6_CONFIG,
	PROPERTY_O_IDX_DHCP4_CONFIG,
	PROPERTY_O_IDX_DHCP6_CONFIG,
	_PROPERTY_O_IDX_NUM,
};

typedef struct _NMActiveConnectionPrivate {
	NMLDBusPropertyO property_o[_PROPERTY_O_IDX_NUM];
	NMLDBusPropertyAO devices;
	NMRefString *specific_object_path;
	char *id;
	char *uuid;
	char *type;

	guint32 state;
	guint32 state_flags;

	bool is_default;
	bool is_default6;
	bool is_vpn;

	guint32 reason;
} NMActiveConnectionPrivate;

G_DEFINE_TYPE (NMActiveConnection, nm_active_connection, NM_TYPE_OBJECT);

#define NM_ACTIVE_CONNECTION_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMActiveConnection, NM_IS_ACTIVE_CONNECTION, NMObject)

/*****************************************************************************/

/**
 * nm_active_connection_get_connection:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMRemoteConnection associated with @connection.
 *
 * Returns: (transfer none): the #NMRemoteConnection which this
 * #NMActiveConnection is an active instance of.
 **/
NMRemoteConnection *
nm_active_connection_get_connection (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	return nml_dbus_property_o_get_obj (&NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->property_o[PROPERTY_O_IDX_CONNECTION]);
}

/**
 * nm_active_connection_get_id:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMConnection's ID.
 *
 * Returns: the ID of the #NMConnection that backs the #NMActiveConnection.
 * This is the internal string used by the connection, and must not be modified.
 **/
const char *
nm_active_connection_get_id (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	return _nml_coerce_property_str_not_empty (NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->id);
}

/**
 * nm_active_connection_get_uuid:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMConnection's UUID.
 *
 * Returns: the UUID of the #NMConnection that backs the #NMActiveConnection.
 * This is the internal string used by the connection, and must not be modified.
 **/
const char *
nm_active_connection_get_uuid (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	return _nml_coerce_property_str_not_empty (NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->uuid);
}

/**
 * nm_active_connection_get_connection_type:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMConnection's type.
 *
 * Returns: the type of the #NMConnection that backs the #NMActiveConnection.
 * This is the internal string used by the connection, and must not be modified.
 **/
const char *
nm_active_connection_get_connection_type (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	return _nml_coerce_property_str_not_empty (NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->type);
}

/**
 * nm_active_connection_get_specific_object_path:
 * @connection: a #NMActiveConnection
 *
 * Gets the path of the "specific object" used at activation.
 *
 * Currently there is no single method that will allow you to automatically turn
 * this into an appropriate #NMObject; you need to know what kind of object it
 * is based on other information. (Eg, if @connection corresponds to a Wi-Fi
 * connection, then the specific object will be an #NMAccessPoint, and you can
 * resolve it with nm_device_wifi_get_access_point_by_path().)
 *
 * Returns: the specific object's D-Bus path. This is the internal string used
 * by the connection, and must not be modified.
 **/
const char *
nm_active_connection_get_specific_object_path (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	return _nml_coerce_property_object_path (NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->specific_object_path);
}

/**
 * nm_active_connection_get_devices:
 * @connection: a #NMActiveConnection
 *
 * Gets the #NMDevices used for the active connections.
 *
 * Returns: (element-type NMDevice): the #GPtrArray containing #NMDevices.
 * This is the internal copy used by the connection, and must not be modified.
 **/
const GPtrArray *
nm_active_connection_get_devices (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	return nml_dbus_property_ao_get_objs_as_ptrarray (&NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->devices);
}

/**
 * nm_active_connection_get_state:
 * @connection: a #NMActiveConnection
 *
 * Gets the active connection's state.
 *
 * Returns: the state
 **/
NMActiveConnectionState
nm_active_connection_get_state (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NM_ACTIVE_CONNECTION_STATE_UNKNOWN);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->state;
}

/**
 * nm_active_connection_get_state_flags:
 * @connection: a #NMActiveConnection
 *
 * Gets the active connection's state flags.
 *
 * Returns: the state flags
 *
 * Since: 1.10
 **/
NMActivationStateFlags
nm_active_connection_get_state_flags (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NM_ACTIVATION_STATE_FLAG_NONE);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->state_flags;
}

/**
 * nm_active_connection_get_state_reason:
 * @connection: a #NMActiveConnection
 *
 * Gets the reason for active connection's state.
 *
 * Returns: the reason
 *
 * Since: 1.8
 **/
NMActiveConnectionStateReason
nm_active_connection_get_state_reason (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NM_ACTIVE_CONNECTION_STATE_REASON_UNKNOWN);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->reason;
}

/**
 * nm_active_connection_get_default:
 * @connection: a #NMActiveConnection
 *
 * Whether the active connection is the default IPv4 one (that is, is used for
 * the default IPv4 route and DNS information).
 *
 * Returns: %TRUE if the active connection is the default IPv4 connection
 **/
gboolean
nm_active_connection_get_default (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), FALSE);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->is_default;
}

/**
 * nm_active_connection_get_ip4_config:
 * @connection: an #NMActiveConnection
 *
 * Gets the current IPv4 #NMIPConfig associated with the #NMActiveConnection.
 *
 * Returns: (transfer none): the IPv4 #NMIPConfig, or %NULL if the connection is
 *   not in the %NM_ACTIVE_CONNECTION_STATE_ACTIVATED state.
 **/
NMIPConfig *
nm_active_connection_get_ip4_config (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	return nml_dbus_property_o_get_obj (&NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->property_o[PROPERTY_O_IDX_IP4_CONFIG]);
}

/**
 * nm_active_connection_get_dhcp4_config:
 * @connection: an #NMActiveConnection
 *
 * Gets the current IPv4 #NMDhcpConfig (if any) associated with the
 * #NMActiveConnection.
 *
 * Returns: (transfer none): the IPv4 #NMDhcpConfig, or %NULL if the connection
 *   does not use DHCP, or is not in the %NM_ACTIVE_CONNECTION_STATE_ACTIVATED
 *   state.
 **/
NMDhcpConfig *
nm_active_connection_get_dhcp4_config (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	return nml_dbus_property_o_get_obj (&NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->property_o[PROPERTY_O_IDX_DHCP4_CONFIG]);
}

/**
 * nm_active_connection_get_default6:
 * @connection: a #NMActiveConnection
 *
 * Whether the active connection is the default IPv6 one (that is, is used for
 * the default IPv6 route and DNS information).
 *
 * Returns: %TRUE if the active connection is the default IPv6 connection
 **/
gboolean
nm_active_connection_get_default6 (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), FALSE);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->is_default6;
}

/**
 * nm_active_connection_get_ip6_config:
 * @connection: an #NMActiveConnection
 *
 * Gets the current IPv6 #NMIPConfig associated with the #NMActiveConnection.
 *
 * Returns: (transfer none): the IPv6 #NMIPConfig, or %NULL if the connection is
 *   not in the %NM_ACTIVE_CONNECTION_STATE_ACTIVATED state.
 **/
NMIPConfig *
nm_active_connection_get_ip6_config (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	return nml_dbus_property_o_get_obj (&NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->property_o[PROPERTY_O_IDX_IP6_CONFIG]);
}

/**
 * nm_active_connection_get_dhcp6_config:
 * @connection: an #NMActiveConnection
 *
 * Gets the current IPv6 #NMDhcpConfig (if any) associated with the
 * #NMActiveConnection.
 *
 * Returns: (transfer none): the IPv6 #NMDhcpConfig, or %NULL if the connection
 *   does not use DHCPv6, or is not in the %NM_ACTIVE_CONNECTION_STATE_ACTIVATED
 *   state.
 **/
NMDhcpConfig *
nm_active_connection_get_dhcp6_config (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	return nml_dbus_property_o_get_obj (&NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->property_o[PROPERTY_O_IDX_DHCP6_CONFIG]);
}

/**
 * nm_active_connection_get_vpn:
 * @connection: a #NMActiveConnection
 *
 * Whether the active connection is a VPN connection.
 *
 * Returns: %TRUE if the active connection is a VPN connection
 **/
gboolean
nm_active_connection_get_vpn (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), FALSE);

	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->is_vpn;
}

/**
 * nm_active_connection_get_master:
 * @connection: a #NMActiveConnection
 *
 * Gets the master #NMDevice of the connection.
 *
 * Returns: (transfer none): the master #NMDevice of the #NMActiveConnection.
 **/
NMDevice *
nm_active_connection_get_master (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	return nml_dbus_property_o_get_obj (&NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->property_o[PROPERTY_O_IDX_MASTER]);
}

/*****************************************************************************/

static void
_notify_event_state_changed (NMClient *client,
                             NMClientNotifyEventWithPtr *notify_event)
{
	gs_unref_object NMActiveConnection *self = notify_event->user_data;
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	/* we expose here the value cache in @priv. In practice, this is the same
	 * value as we received from the signal. In the unexpected case where they
	 * differ, the cached value of the current instance would still be more correct. */
	g_signal_emit (self,
	               signals[STATE_CHANGED],
	               0,
	               (guint) priv->state,
	               (guint) priv->reason);
}

void
_nm_active_connection_state_changed_commit (NMActiveConnection *self,
                                            guint32 state,
                                            guint32 reason)
{
	NMClient *client;
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (self);

	client = _nm_object_get_client (self);

	if (priv->state != state) {
		priv->state = state;
		_nm_client_queue_notify_object (client,
		                                self,
		                                obj_properties[PROP_STATE]);
	}

	priv->reason = reason;

	_nm_client_notify_event_queue_with_ptr (client,
	                                        NM_CLIENT_NOTIFY_EVENT_PRIO_GPROP + 1,
	                                        _notify_event_state_changed,
	                                        g_object_ref (self));
}

/*****************************************************************************/

static void
nm_active_connection_init (NMActiveConnection *self)
{
	NMActiveConnectionPrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionPrivate);

	self->_priv = priv;
}

static void
finalize (GObject *object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	g_free (priv->id);
	g_free (priv->uuid);
	g_free (priv->type);
	nm_ref_string_unref (priv->specific_object_path);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMActiveConnection *self = NM_ACTIVE_CONNECTION (object);

	switch (prop_id) {
	case PROP_CONNECTION:
		g_value_set_object (value, nm_active_connection_get_connection (self));
		break;
	case PROP_ID:
		g_value_set_string (value, nm_active_connection_get_id (self));
		break;
	case PROP_UUID:
		g_value_set_string (value, nm_active_connection_get_uuid (self));
		break;
	case PROP_TYPE:
		g_value_set_string (value, nm_active_connection_get_connection_type (self));
		break;
	case PROP_SPECIFIC_OBJECT_PATH:
		g_value_set_string (value, nm_active_connection_get_specific_object_path (self));
		break;
	case PROP_DEVICES:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_active_connection_get_devices (self)));
		break;
	case PROP_STATE:
		g_value_set_enum (value, nm_active_connection_get_state (self));
		break;
	case PROP_STATE_FLAGS:
		g_value_set_uint (value, nm_active_connection_get_state_flags (self));
		break;
	case PROP_DEFAULT:
		g_value_set_boolean (value, nm_active_connection_get_default (self));
		break;
	case PROP_IP4_CONFIG:
		g_value_set_object (value, nm_active_connection_get_ip4_config (self));
		break;
	case PROP_DHCP4_CONFIG:
		g_value_set_object (value, nm_active_connection_get_dhcp4_config (self));
		break;
	case PROP_DEFAULT6:
		g_value_set_boolean (value, nm_active_connection_get_default6 (self));
		break;
	case PROP_IP6_CONFIG:
		g_value_set_object (value, nm_active_connection_get_ip6_config (self));
		break;
	case PROP_DHCP6_CONFIG:
		g_value_set_object (value, nm_active_connection_get_dhcp6_config (self));
		break;
	case PROP_VPN:
		g_value_set_boolean (value, nm_active_connection_get_vpn (self));
		break;
	case PROP_MASTER:
		g_value_set_object (value, nm_active_connection_get_master (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_connection_active = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
	nm_active_connection_get_type,
	NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_LOW,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("Connection",     PROP_CONNECTION,           NMActiveConnectionPrivate, property_o[PROPERTY_O_IDX_CONNECTION],   nm_remote_connection_get_type ),
		NML_DBUS_META_PROPERTY_INIT_B       ("Default",        PROP_DEFAULT,              NMActiveConnectionPrivate, is_default                                                             ),
		NML_DBUS_META_PROPERTY_INIT_B       ("Default6",       PROP_DEFAULT6,             NMActiveConnectionPrivate, is_default6                                                            ),
		NML_DBUS_META_PROPERTY_INIT_AO_PROP ("Devices",        PROP_DEVICES,              NMActiveConnectionPrivate, devices,                                 nm_device_get_type            ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("Dhcp4Config",    PROP_DHCP4_CONFIG,         NMActiveConnectionPrivate, property_o[PROPERTY_O_IDX_DHCP4_CONFIG], nm_dhcp4_config_get_type      ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("Dhcp6Config",    PROP_DHCP6_CONFIG,         NMActiveConnectionPrivate, property_o[PROPERTY_O_IDX_DHCP6_CONFIG], nm_dhcp6_config_get_type      ),
		NML_DBUS_META_PROPERTY_INIT_S       ("Id",             PROP_ID,                   NMActiveConnectionPrivate, id                                                                     ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("Ip4Config",      PROP_IP4_CONFIG,           NMActiveConnectionPrivate, property_o[PROPERTY_O_IDX_IP4_CONFIG],   nm_ip4_config_get_type        ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("Ip6Config",      PROP_IP6_CONFIG,           NMActiveConnectionPrivate, property_o[PROPERTY_O_IDX_IP6_CONFIG],   nm_ip6_config_get_type        ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("Master",         PROP_MASTER,               NMActiveConnectionPrivate, property_o[PROPERTY_O_IDX_MASTER],       nm_device_get_type            ),
		NML_DBUS_META_PROPERTY_INIT_O       ("SpecificObject", PROP_SPECIFIC_OBJECT_PATH, NMActiveConnectionPrivate, specific_object_path                                                   ),
		NML_DBUS_META_PROPERTY_INIT_U       ("State",          PROP_STATE,                NMActiveConnectionPrivate, state                                                                  ),
		NML_DBUS_META_PROPERTY_INIT_U       ("StateFlags",     PROP_STATE_FLAGS,          NMActiveConnectionPrivate, state_flags                                                            ),
		NML_DBUS_META_PROPERTY_INIT_S       ("Type",           PROP_TYPE,                 NMActiveConnectionPrivate, type                                                                   ),
		NML_DBUS_META_PROPERTY_INIT_S       ("Uuid",           PROP_UUID,                 NMActiveConnectionPrivate, uuid                                                                   ),
		NML_DBUS_META_PROPERTY_INIT_B       ("Vpn",            PROP_VPN,                  NMActiveConnectionPrivate, is_vpn                                                                 ),
	),
	.base_struct_offset = G_STRUCT_OFFSET (NMActiveConnection, _priv),
);

static void
nm_active_connection_class_init (NMActiveConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMActiveConnectionPrivate));

	object_class->get_property = get_property;
	object_class->finalize     = finalize;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_INDIRECT (nm_object_class, NMActiveConnection);

	_NM_OBJECT_CLASS_INIT_PROPERTY_O_FIELDS_N (nm_object_class, NMActiveConnectionPrivate, property_o);
	_NM_OBJECT_CLASS_INIT_PROPERTY_AO_FIELDS_1 (nm_object_class, NMActiveConnectionPrivate, devices);

	/**
	 * NMActiveConnection:connection:
	 *
	 * The connection that this is an active instance of.
	 **/
	obj_properties[PROP_CONNECTION] =
	    g_param_spec_object (NM_ACTIVE_CONNECTION_CONNECTION, "", "",
	                         NM_TYPE_REMOTE_CONNECTION,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:id:
	 *
	 * The active connection's ID
	 **/
	obj_properties[PROP_ID] =
	    g_param_spec_string (NM_ACTIVE_CONNECTION_ID, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:uuid:
	 *
	 * The active connection's UUID
	 **/
	obj_properties[PROP_UUID] =
	    g_param_spec_string (NM_ACTIVE_CONNECTION_UUID, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:type:
	 *
	 * The active connection's type
	 **/
	obj_properties[PROP_TYPE] =
	    g_param_spec_string (NM_ACTIVE_CONNECTION_TYPE, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:specific-object-path:
	 *
	 * The path to the "specific object" of the active connection; see
	 * nm_active_connection_get_specific_object_path() for more details.
	 **/
	obj_properties[PROP_SPECIFIC_OBJECT_PATH] =
	    g_param_spec_string (NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT_PATH, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:devices: (type GPtrArray(NMDevice))
	 *
	 * The devices of the active connection.
	 **/
	obj_properties[PROP_DEVICES] =
	    g_param_spec_boxed (NM_ACTIVE_CONNECTION_DEVICES, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:state:
	 *
	 * The state of the active connection.
	 **/
	obj_properties[PROP_STATE] =
	    g_param_spec_enum (NM_ACTIVE_CONNECTION_STATE, "", "",
	                       NM_TYPE_ACTIVE_CONNECTION_STATE,
	                       NM_ACTIVE_CONNECTION_STATE_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:state-flags:
	 *
	 * The state flags of the active connection.
	 *
	 * Since: 1.10
	 **/
	obj_properties[PROP_STATE_FLAGS] =
	    g_param_spec_uint (NM_ACTIVE_CONNECTION_STATE_FLAGS, "", "",
	                       0, G_MAXUINT32,
	                       NM_ACTIVATION_STATE_FLAG_NONE,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:default:
	 *
	 * Whether the active connection is the default IPv4 one.
	 **/
	obj_properties[PROP_DEFAULT] =
	    g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:ip4-config:
	 *
	 * The IPv4 #NMIPConfig of the connection.
	 **/
	obj_properties[PROP_IP4_CONFIG] =
	    g_param_spec_object (NM_ACTIVE_CONNECTION_IP4_CONFIG, "", "",
	                         NM_TYPE_IP_CONFIG,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:dhcp4-config:
	 *
	 * The IPv4 #NMDhcpConfig of the connection.
	 **/
	obj_properties[PROP_DHCP4_CONFIG] =
	    g_param_spec_object (NM_ACTIVE_CONNECTION_DHCP4_CONFIG, "", "",
	                         NM_TYPE_DHCP_CONFIG,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:default6:
	 *
	 * Whether the active connection is the default IPv6 one.
	 **/
	obj_properties[PROP_DEFAULT6] =
	    g_param_spec_boolean (NM_ACTIVE_CONNECTION_DEFAULT6, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:ip6-config:
	 *
	 * The IPv6 #NMIPConfig of the connection.
	 **/
	obj_properties[PROP_IP6_CONFIG] =
	    g_param_spec_object (NM_ACTIVE_CONNECTION_IP6_CONFIG, "", "",
	                         NM_TYPE_IP_CONFIG,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:dhcp6-config:
	 *
	 * The IPv6 #NMDhcpConfig of the connection.
	 **/
	obj_properties[PROP_DHCP6_CONFIG] =
	    g_param_spec_object (NM_ACTIVE_CONNECTION_DHCP6_CONFIG, "", "",
	                         NM_TYPE_DHCP_CONFIG,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:vpn:
	 *
	 * Whether the active connection is a VPN connection.
	 **/
	obj_properties[PROP_VPN] =
	    g_param_spec_boolean (NM_ACTIVE_CONNECTION_VPN, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMActiveConnection:master:
	 *
	 * The master device if one exists.
	 **/
	obj_properties[PROP_MASTER] =
	    g_param_spec_object (NM_ACTIVE_CONNECTION_MASTER, "", "",
	                         NM_TYPE_DEVICE,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_connection_active);

	/* TODO: the state reason should also be exposed as a property in libnm's NMActiveConnection,
	 * like done for NMDevice's state reason. */

	/* TODO: the D-Bus API should also expose the state-reason as a property instead of
	 * a "StateChanged" signal. Like done for Device's "StateReason".  */

	/**
	 * NMActiveConnection::state-changed:
	 * @active_connection: the source #NMActiveConnection
	 * @state: the new state number (#NMActiveConnectionState)
	 * @reason: the state change reason (#NMActiveConnectionStateReason)
	 */
	signals[STATE_CHANGED] =
	    g_signal_new ("state-changed",
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 2,
	                  G_TYPE_UINT, G_TYPE_UINT);
}
