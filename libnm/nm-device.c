// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device.h"

#include <libudev.h>

#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-dbus-interface.h"
#include "nm-active-connection.h"
#include "nm-device-bt.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-object-private.h"
#include "nm-remote-connection.h"
#include "nm-core-internal.h"
#include "nm-utils.h"
#include "nm-dbus-helpers.h"
#include "nm-device-tun.h"
#include "nm-setting-connection.h"
#include "nm-udev-aux/nm-udev-utils.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMDevice,
	PROP_INTERFACE,
	PROP_UDI,
	PROP_DRIVER,
	PROP_DRIVER_VERSION,
	PROP_FIRMWARE_VERSION,
	PROP_CAPABILITIES,
	PROP_REAL,
	PROP_MANAGED,
	PROP_AUTOCONNECT,
	PROP_FIRMWARE_MISSING,
	PROP_NM_PLUGIN_MISSING,
	PROP_IP4_CONFIG,
	PROP_DHCP4_CONFIG,
	PROP_IP6_CONFIG,
	PROP_STATE,
	PROP_STATE_REASON,
	PROP_PRODUCT,
	PROP_VENDOR,
	PROP_DHCP6_CONFIG,
	PROP_IP_INTERFACE,
	PROP_DEVICE_TYPE,
	PROP_ACTIVE_CONNECTION,
	PROP_AVAILABLE_CONNECTIONS,
	PROP_PHYSICAL_PORT_ID,
	PROP_MTU,
	PROP_METERED,
	PROP_LLDP_NEIGHBORS,
	PROP_IP4_CONNECTIVITY,
	PROP_IP6_CONNECTIVITY,
	PROP_INTERFACE_FLAGS,
);

enum {
	STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROPERTY_O_IDX_ACTIVE_CONNECTION,
	PROPERTY_O_IDX_IP4_CONFIG,
	PROPERTY_O_IDX_IP6_CONFIG,
	PROPERTY_O_IDX_DHCP4_CONFIG,
	PROPERTY_O_IDX_DHCP6_CONFIG,
	_PROPERTY_O_IDX_NUM,
};

typedef struct _NMDevicePrivate {
	NMLDBusPropertyO property_o[_PROPERTY_O_IDX_NUM];
	NMLDBusPropertyAO available_connections;
	GPtrArray *lldp_neighbors;
	char *driver;
	char *driver_version;
	char *interface;
	char *ip_interface;
	char *firmware_version;
	char *physical_port_id;
	char *udi;
	guint32 capabilities;
	guint32 device_type;
	guint32 ip4_connectivity;
	guint32 ip6_connectivity;
	guint32 metered;
	guint32 mtu;
	guint32 state;
	guint32 state_reason;
	guint32 interface_flags;
	bool firmware_missing;
	bool nm_plugin_missing;
	bool autoconnect;
	bool managed;
	bool real;

	guint32 old_state;

	struct udev *udev;
	char *type_description;
	char *product;
	char *vendor;
	char *short_vendor;
	char *description;
	char *bus_name;

} NMDevicePrivate;

G_DEFINE_ABSTRACT_TYPE (NMDevice, nm_device, NM_TYPE_OBJECT);

#define NM_DEVICE_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR(self, NMDevice, NM_IS_DEVICE, NMObject)

/*****************************************************************************/

static gboolean connection_compatible (NMDevice *device, NMConnection *connection, GError **error);
static NMLldpNeighbor *nm_lldp_neighbor_dup (NMLldpNeighbor *neighbor);

/*****************************************************************************/

struct _NMLldpNeighbor {
	guint refcount;
	GHashTable *attrs;
};

G_DEFINE_BOXED_TYPE (NMLldpNeighbor, nm_lldp_neighbor, nm_lldp_neighbor_dup, nm_lldp_neighbor_unref)

/*****************************************************************************/

static void
nm_device_init (NMDevice *self)
{
	NMDevicePrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_DEVICE, NMDevicePrivate);

	self->_priv = priv;

	priv->old_state = NM_DEVICE_STATE_UNKNOWN;
}

/*****************************************************************************/

static void
_notify_event_state_changed (NMClient *client,
                             NMClientNotifyEventWithPtr *notify_event)
{
	gs_unref_object NMDevice *self = notify_event->user_data;
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	NML_NMCLIENT_LOG_T (_nm_object_get_client (self),
	                    "[%s] emit Device's StateChanged signal %u -> %u, reason: %u",
	                    _nm_object_get_path (self),
	                    (guint) priv->old_state,
	                    (guint) priv->state,
	                    (guint) priv->state_reason);

	g_signal_emit (self,
	               signals[STATE_CHANGED],
	               0,
	               (guint) priv->state,
	               (guint) priv->old_state,
	               (guint) priv->state_reason);
}

static NMLDBusNotifyUpdatePropFlags
_notify_update_prop_state_reason (NMClient *client,
                                  NMLDBusObject *dbobj,
                                  const NMLDBusMetaIface *meta_iface,
                                  guint dbus_property_idx,
                                  GVariant *value)
{
	NMDevice *self = NM_DEVICE (dbobj->nmobj);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	guint32 new_state = NM_DEVICE_STATE_UNKNOWN;
	guint32 reason = NM_DEVICE_STATE_REASON_NONE;

	/* We ignore the "State" property and the "StateChanged" signal of the device.
	 * This information is redundant to the "StateReason" property, and we rely
	 * on that one alone. In the best case, the information is identical. If it
	 * would not be, then we stick to the information from "StateReason" property. */

	if (value)
		g_variant_get (value, "(uu)", &new_state, &reason);

	if (   priv->state == new_state
	    && priv->state_reason == reason) {
		/* no changes. */
		return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NONE;
	}

	if (priv->state != new_state) {
		priv->old_state = priv->state;
		priv->state = new_state;
		_nm_client_queue_notify_object (client,
		                                self,
		                                obj_properties[PROP_STATE]);
	}

	if (priv->state_reason != reason) {
		priv->state_reason = reason;
		_nm_client_queue_notify_object (client,
		                                self,
		                                obj_properties[PROP_STATE_REASON]);
	}

	_nm_client_notify_event_queue_with_ptr (client,
	                                        NM_CLIENT_NOTIFY_EVENT_PRIO_GPROP + 1,
	                                        _notify_event_state_changed,
	                                        g_object_ref (self));

	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NONE;
}

static NMLDBusNotifyUpdatePropFlags
_notify_update_prop_lldp_neighbors (NMClient *client,
                                    NMLDBusObject *dbobj,
                                    const NMLDBusMetaIface *meta_iface,
                                    guint dbus_property_idx,
                                    GVariant *value)
{
	NMDevice *self = NM_DEVICE (dbobj->nmobj);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gs_unref_ptrarray GPtrArray *old = NULL;
	gs_unref_ptrarray GPtrArray *new = NULL;
	GVariantIter *attrs_iter;
	GVariantIter iter;

	new = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_lldp_neighbor_unref);

	if (value) {
		g_variant_iter_init (&iter, value);
		while (g_variant_iter_next (&iter, "a{sv}", &attrs_iter)) {
			GVariant *attr_variant;
			const char *attr_name;
			NMLldpNeighbor *neigh;

			neigh = nm_lldp_neighbor_new ();
			while (g_variant_iter_next (attrs_iter, "{&sv}", &attr_name, &attr_variant))
				g_hash_table_insert (neigh->attrs, g_strdup (attr_name), attr_variant);
			g_ptr_array_add (new, neigh);

			g_variant_iter_free (attrs_iter);
		}
	}

	old = g_steal_pointer (&priv->lldp_neighbors);
	priv->lldp_neighbors = g_steal_pointer (&new);
	return NML_DBUS_NOTIFY_UPDATE_PROP_FLAGS_NOTIFY;
}

/*****************************************************************************/

static NMDeviceType
coerce_type (NMDeviceType type)
{
	switch (type) {
	case NM_DEVICE_TYPE_ETHERNET:
	case NM_DEVICE_TYPE_WIFI:
	case NM_DEVICE_TYPE_BT:
	case NM_DEVICE_TYPE_OLPC_MESH:
	case NM_DEVICE_TYPE_OVS_INTERFACE:
	case NM_DEVICE_TYPE_OVS_PORT:
	case NM_DEVICE_TYPE_OVS_BRIDGE:
	case NM_DEVICE_TYPE_WIMAX:
	case NM_DEVICE_TYPE_MODEM:
	case NM_DEVICE_TYPE_INFINIBAND:
	case NM_DEVICE_TYPE_BOND:
	case NM_DEVICE_TYPE_TEAM:
	case NM_DEVICE_TYPE_BRIDGE:
	case NM_DEVICE_TYPE_VLAN:
	case NM_DEVICE_TYPE_ADSL:
	case NM_DEVICE_TYPE_MACSEC:
	case NM_DEVICE_TYPE_MACVLAN:
	case NM_DEVICE_TYPE_VXLAN:
	case NM_DEVICE_TYPE_IP_TUNNEL:
	case NM_DEVICE_TYPE_TUN:
	case NM_DEVICE_TYPE_VETH:
	case NM_DEVICE_TYPE_GENERIC:
	case NM_DEVICE_TYPE_UNUSED1:
	case NM_DEVICE_TYPE_UNUSED2:
	case NM_DEVICE_TYPE_UNKNOWN:
	case NM_DEVICE_TYPE_DUMMY:
	case NM_DEVICE_TYPE_PPP:
	case NM_DEVICE_TYPE_WPAN:
	case NM_DEVICE_TYPE_6LOWPAN:
	case NM_DEVICE_TYPE_WIREGUARD:
	case NM_DEVICE_TYPE_WIFI_P2P:
		return type;
	}
	return NM_DEVICE_TYPE_UNKNOWN;
}

/*****************************************************************************/

static void
register_client (NMObject *nmobj,
                 NMClient *client,
                 NMLDBusObject *dbobj)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (nmobj);

	priv->udev = _nm_client_get_udev (client);
	if (priv->udev)
		udev_ref (priv->udev);

	NM_OBJECT_CLASS (nm_device_parent_class)->register_client (nmobj, client, dbobj);
}

/*****************************************************************************/

static void
finalize (GObject *object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);

	g_clear_pointer (&priv->lldp_neighbors, g_ptr_array_unref);

	g_free (priv->interface);
	g_free (priv->ip_interface);
	g_free (priv->udi);
	g_free (priv->driver);
	g_free (priv->driver_version);
	g_free (priv->firmware_version);
	g_free (priv->product);
	g_free (priv->vendor);
	g_free (priv->short_vendor);
	g_free (priv->description);
	g_free (priv->bus_name);
	g_free (priv->type_description);
	g_free (priv->physical_port_id);

	nm_clear_pointer (&priv->udev, udev_unref);

	G_OBJECT_CLASS (nm_device_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDevice *device = NM_DEVICE (object);

	switch (prop_id) {
	case PROP_DEVICE_TYPE:
		g_value_set_enum (value, nm_device_get_device_type (device));
		break;
	case PROP_UDI:
		g_value_set_string (value, nm_device_get_udi (device));
		break;
	case PROP_INTERFACE:
		g_value_set_string (value, nm_device_get_iface (device));
		break;
	case PROP_IP_INTERFACE:
		g_value_set_string (value, nm_device_get_ip_iface (device));
		break;
	case PROP_DRIVER:
		g_value_set_string (value, nm_device_get_driver (device));
		break;
	case PROP_DRIVER_VERSION:
		g_value_set_string (value, nm_device_get_driver_version (device));
		break;
	case PROP_FIRMWARE_VERSION:
		g_value_set_string (value, nm_device_get_firmware_version (device));
		break;
	case PROP_CAPABILITIES:
		g_value_set_flags (value, nm_device_get_capabilities (device));
		break;
	case PROP_REAL:
		g_value_set_boolean (value, nm_device_is_real (device));
		break;
	case PROP_MANAGED:
		g_value_set_boolean (value, nm_device_get_managed (device));
		break;
	case PROP_AUTOCONNECT:
		g_value_set_boolean (value, nm_device_get_autoconnect (device));
		break;
	case PROP_FIRMWARE_MISSING:
		g_value_set_boolean (value, nm_device_get_firmware_missing (device));
		break;
	case PROP_NM_PLUGIN_MISSING:
		g_value_set_boolean (value, nm_device_get_nm_plugin_missing (device));
		break;
	case PROP_IP4_CONFIG:
		g_value_set_object (value, nm_device_get_ip4_config (device));
		break;
	case PROP_DHCP4_CONFIG:
		g_value_set_object (value, nm_device_get_dhcp4_config (device));
		break;
	case PROP_IP6_CONFIG:
		g_value_set_object (value, nm_device_get_ip6_config (device));
		break;
	case PROP_DHCP6_CONFIG:
		g_value_set_object (value, nm_device_get_dhcp6_config (device));
		break;
	case PROP_STATE:
		g_value_set_enum (value, nm_device_get_state (device));
		break;
	case PROP_STATE_REASON:
		g_value_set_uint (value, nm_device_get_state_reason (device));
		break;
	case PROP_ACTIVE_CONNECTION:
		g_value_set_object (value, nm_device_get_active_connection (device));
		break;
	case PROP_AVAILABLE_CONNECTIONS:
		g_value_take_boxed (value, _nm_utils_copy_object_array (nm_device_get_available_connections (device)));
		break;
	case PROP_PRODUCT:
		g_value_set_string (value, nm_device_get_product (device));
		break;
	case PROP_VENDOR:
		g_value_set_string (value, nm_device_get_vendor (device));
		break;
	case PROP_PHYSICAL_PORT_ID:
		g_value_set_string (value, nm_device_get_physical_port_id (device));
		break;
	case PROP_MTU:
		g_value_set_uint (value, nm_device_get_mtu (device));
		break;
	case PROP_METERED:
		g_value_set_uint (value, nm_device_get_metered (device));
		break;
	case PROP_LLDP_NEIGHBORS:
		g_value_set_boxed (value, nm_device_get_lldp_neighbors (device));
		break;
	case PROP_IP4_CONNECTIVITY:
		g_value_set_enum (value, nm_device_get_connectivity (device, AF_INET));
		break;
	case PROP_IP6_CONNECTIVITY:
		g_value_set_enum (value, nm_device_get_connectivity (device, AF_INET6));
		break;
	case PROP_INTERFACE_FLAGS:
		g_value_set_uint (value, nm_device_get_interface_flags (device));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NMDevice *self = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);
	gboolean b;

	switch (prop_id) {
	case PROP_AUTOCONNECT:
		b = g_value_get_boolean (value);
		if (priv->autoconnect != b)
			nm_device_set_autoconnect (NM_DEVICE (object), b);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/* TODO: statistics interface not yet implemented. */
const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_statistics = NML_DBUS_META_IFACE_INIT (
	NM_DBUS_INTERFACE_DEVICE_STATISTICS,
	NULL,
	NML_DBUS_META_INTERFACE_PRIO_NONE,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_TODO ("RefreshRateMs", "u" ),
		NML_DBUS_META_PROPERTY_INIT_TODO ("RxBytes",       "t" ),
		NML_DBUS_META_PROPERTY_INIT_TODO ("TxBytes",       "t" ),
	),
);

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device = NML_DBUS_META_IFACE_INIT_PROP (
	NM_DBUS_INTERFACE_DEVICE,
	nm_device_get_type,
	NML_DBUS_META_INTERFACE_PRIO_PARENT_TYPE,
	NML_DBUS_META_IFACE_DBUS_PROPERTIES (
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("ActiveConnection",     PROP_ACTIVE_CONNECTION,     NMDevicePrivate, property_o[PROPERTY_O_IDX_ACTIVE_CONNECTION], nm_active_connection_get_type, .is_always_ready = TRUE ),
		NML_DBUS_META_PROPERTY_INIT_B       ("Autoconnect",          PROP_AUTOCONNECT,           NMDevicePrivate, autoconnect                                                                                          ),
		NML_DBUS_META_PROPERTY_INIT_AO_PROP ("AvailableConnections", PROP_AVAILABLE_CONNECTIONS, NMDevicePrivate, available_connections,                        nm_remote_connection_get_type, .is_always_ready = TRUE ),
		NML_DBUS_META_PROPERTY_INIT_U       ("Capabilities",         PROP_CAPABILITIES,          NMDevicePrivate, capabilities                                                                                         ),
		NML_DBUS_META_PROPERTY_INIT_U       ("DeviceType",           PROP_DEVICE_TYPE,           NMDevicePrivate, device_type                                                                                          ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("Dhcp4Config",          PROP_DHCP4_CONFIG,          NMDevicePrivate, property_o[PROPERTY_O_IDX_DHCP4_CONFIG],      nm_dhcp4_config_get_type                               ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("Dhcp6Config",          PROP_DHCP6_CONFIG,          NMDevicePrivate, property_o[PROPERTY_O_IDX_DHCP6_CONFIG],      nm_dhcp6_config_get_type                               ),
		NML_DBUS_META_PROPERTY_INIT_S       ("Driver",               PROP_DRIVER,                NMDevicePrivate, driver                                                                                               ),
		NML_DBUS_META_PROPERTY_INIT_S       ("DriverVersion",        PROP_DRIVER_VERSION,        NMDevicePrivate, driver_version                                                                                       ),
		NML_DBUS_META_PROPERTY_INIT_B       ("FirmwareMissing",      PROP_FIRMWARE_MISSING,      NMDevicePrivate, firmware_missing                                                                                     ),
		NML_DBUS_META_PROPERTY_INIT_S       ("FirmwareVersion",      PROP_FIRMWARE_VERSION,      NMDevicePrivate, firmware_version                                                                                     ),
		NML_DBUS_META_PROPERTY_INIT_S       ("Interface",            PROP_INTERFACE,             NMDevicePrivate, interface                                                                                            ),
		NML_DBUS_META_PROPERTY_INIT_U       ("InterfaceFlags",       PROP_INTERFACE_FLAGS,       NMDevicePrivate, interface_flags                                                                                      ),
		NML_DBUS_META_PROPERTY_INIT_IGNORE  ("Ip4Address",           "u"                                                                                                                                               ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("Ip4Config",            PROP_IP4_CONFIG,            NMDevicePrivate, property_o[PROPERTY_O_IDX_IP4_CONFIG],        nm_ip4_config_get_type                                 ),
		NML_DBUS_META_PROPERTY_INIT_U       ("Ip4Connectivity",      PROP_IP4_CONNECTIVITY,      NMDevicePrivate, ip4_connectivity                                                                                     ),
		NML_DBUS_META_PROPERTY_INIT_O_PROP  ("Ip6Config",            PROP_IP6_CONFIG,            NMDevicePrivate, property_o[PROPERTY_O_IDX_IP6_CONFIG],        nm_ip6_config_get_type                                 ),
		NML_DBUS_META_PROPERTY_INIT_U       ("Ip6Connectivity",      PROP_IP6_CONNECTIVITY,      NMDevicePrivate, ip6_connectivity                                                                                     ),
		NML_DBUS_META_PROPERTY_INIT_S       ("IpInterface",          PROP_IP_INTERFACE,          NMDevicePrivate, ip_interface                                                                                         ),
		NML_DBUS_META_PROPERTY_INIT_FCN     ("LldpNeighbors",        PROP_LLDP_NEIGHBORS,        "aa{sv}",        _notify_update_prop_lldp_neighbors                                                                   ),
		NML_DBUS_META_PROPERTY_INIT_B       ("Managed",              PROP_MANAGED,               NMDevicePrivate, managed                                                                                              ),
		NML_DBUS_META_PROPERTY_INIT_U       ("Metered",              PROP_METERED,               NMDevicePrivate, metered                                                                                              ),
		NML_DBUS_META_PROPERTY_INIT_U       ("Mtu",                  PROP_MTU,                   NMDevicePrivate, mtu                                                                                                  ),
		NML_DBUS_META_PROPERTY_INIT_B       ("NmPluginMissing",      PROP_NM_PLUGIN_MISSING,     NMDevicePrivate, nm_plugin_missing                                                                                    ),
		NML_DBUS_META_PROPERTY_INIT_S       ("PhysicalPortId",       PROP_PHYSICAL_PORT_ID,      NMDevicePrivate, physical_port_id                                                                                     ),
		NML_DBUS_META_PROPERTY_INIT_B       ("Real",                 PROP_REAL,                  NMDevicePrivate, real                                                                                                 ),
		NML_DBUS_META_PROPERTY_INIT_IGNORE  ("State",                "u"                                                                                                                                               ),
		NML_DBUS_META_PROPERTY_INIT_FCN     ("StateReason",          PROP_STATE_REASON,          "(uu)",          _notify_update_prop_state_reason                                                                     ),
		NML_DBUS_META_PROPERTY_INIT_S       ("Udi",                  PROP_UDI,                   NMDevicePrivate, udi                                                                                                  ),
	),
	.base_struct_offset = G_STRUCT_OFFSET (NMDevice, _priv),
);

static void
nm_device_class_init (NMDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NMDevicePrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	nm_object_class->register_client   = register_client;

	_NM_OBJECT_CLASS_INIT_PRIV_PTR_INDIRECT (nm_object_class, NMDevice);

	_NM_OBJECT_CLASS_INIT_PROPERTY_O_FIELDS_N (nm_object_class, NMDevicePrivate, property_o);
	_NM_OBJECT_CLASS_INIT_PROPERTY_AO_FIELDS_1 (nm_object_class, NMDevicePrivate, available_connections);

	klass->connection_compatible = connection_compatible;

	/**
	 * NMDevice:interface:
	 *
	 * The interface of the device.
	 **/
	obj_properties[PROP_INTERFACE] =
	    g_param_spec_string (NM_DEVICE_INTERFACE, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:ip-interface:
	 *
	 * The IP interface of the device which should be used for all IP-related
	 * operations like addressing and routing.
	 **/
	obj_properties[PROP_IP_INTERFACE] =
	    g_param_spec_string (NM_DEVICE_IP_INTERFACE, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:device-type:
	 *
	 * The numeric type of the device.
	 **/
	obj_properties[PROP_DEVICE_TYPE] =
	    g_param_spec_enum (NM_DEVICE_DEVICE_TYPE, "", "",
	                       NM_TYPE_DEVICE_TYPE,
	                       NM_DEVICE_TYPE_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);
	/**
	 * NMDevice:udi:
	 *
	 * An operating-system specific device hardware identifier; this is not
	 * unique to a specific hardware device across reboots or hotplugs.  It
	 * is an opaque string which for some device types (Bluetooth, Modem)
	 * contains an identifier provided by the underlying hardware service daemon
	 * such as Bluez or ModemManager, and clients can use this property to
	 * request more information about the device from those services.
	 **/
	obj_properties[PROP_UDI] =
	    g_param_spec_string (NM_DEVICE_UDI, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:driver:
	 *
	 * The driver of the device.
	 **/
	obj_properties[PROP_DRIVER] =
	    g_param_spec_string (NM_DEVICE_DRIVER, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:driver-version:
	 *
	 * The version of the device driver.
	 **/
	obj_properties[PROP_DRIVER_VERSION] =
	    g_param_spec_string (NM_DEVICE_DRIVER_VERSION, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:firmware-version:
	 *
	 * The firmware version of the device.
	 **/
	obj_properties[PROP_FIRMWARE_VERSION] =
	    g_param_spec_string (NM_DEVICE_FIRMWARE_VERSION, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:capabilities:
	 *
	 * The capabilities of the device.
	 **/
	obj_properties[PROP_CAPABILITIES] =
	    g_param_spec_flags (NM_DEVICE_CAPABILITIES, "", "",
	                        NM_TYPE_DEVICE_CAPABILITIES,
	                        NM_DEVICE_CAP_NONE,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:real:
	 *
	 * Whether the device is real or is a placeholder device that could
	 * be created automatically by NetworkManager if one of its
	 * #NMDevice:available-connections was activated.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_REAL] =
	    g_param_spec_boolean (NM_DEVICE_REAL, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:managed:
	 *
	 * Whether the device is managed by NetworkManager.
	 **/
	obj_properties[PROP_MANAGED] =
	    g_param_spec_boolean (NM_DEVICE_MANAGED, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:autoconnect:
	 *
	 * Whether the device can auto-activate a connection.
	 *
	 * The property setter is a synchronous D-Bus call. This is deprecated since 1.22.
	 **/
	obj_properties[PROP_AUTOCONNECT] =
	    g_param_spec_boolean (NM_DEVICE_AUTOCONNECT, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:firmware-missing:
	 *
	 * When %TRUE indicates the device is likely missing firmware required
	 * for its operation.
	 **/
	obj_properties[PROP_FIRMWARE_MISSING] =
	    g_param_spec_boolean (NM_DEVICE_FIRMWARE_MISSING, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:nm-plugin-missing:
	 *
	 * When %TRUE indicates that the NetworkManager plugin for the device
	 * is not installed.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_NM_PLUGIN_MISSING] =
	    g_param_spec_boolean (NM_DEVICE_NM_PLUGIN_MISSING, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:ip4-config:
	 *
	 * The #NMIP4Config of the device.
	 **/
	obj_properties[PROP_IP4_CONFIG] =
	    g_param_spec_object (NM_DEVICE_IP4_CONFIG, "", "",
	                         NM_TYPE_IP_CONFIG,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:dhcp4-config:
	 *
	 * The IPv4 #NMDhcpConfig of the device.
	 **/
	obj_properties[PROP_DHCP4_CONFIG] =
	    g_param_spec_object (NM_DEVICE_DHCP4_CONFIG, "", "",
	                         NM_TYPE_DHCP_CONFIG,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:ip6-config:
	 *
	 * The IPv6 #NMIPConfig of the device.
	 **/
	obj_properties[PROP_IP6_CONFIG] =
	    g_param_spec_object (NM_DEVICE_IP6_CONFIG, "", "",
	                         NM_TYPE_IP_CONFIG,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:dhcp6-config:
	 *
	 * The IPv6 #NMDhcpConfig of the device.
	 **/
	obj_properties[PROP_DHCP6_CONFIG] =
	    g_param_spec_object (NM_DEVICE_DHCP6_CONFIG, "", "",
	                         NM_TYPE_DHCP_CONFIG,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:ip4-connectivity:
	 *
	 * The IPv4 connectivity state of the device.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_IP4_CONNECTIVITY] =
	    g_param_spec_enum (NM_DEVICE_IP4_CONNECTIVITY, "", "",
	                       NM_TYPE_CONNECTIVITY_STATE,
	                       NM_CONNECTIVITY_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:ip6-connectivity:
	 *
	 * The IPv6 connectivity state of the device.
	 *
	 * Since: 1.16
	 **/
	obj_properties[PROP_IP6_CONNECTIVITY] =
	    g_param_spec_enum (NM_DEVICE_IP6_CONNECTIVITY, "", "",
	                       NM_TYPE_CONNECTIVITY_STATE,
	                       NM_CONNECTIVITY_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:state:
	 *
	 * The state of the device.
	 **/
	obj_properties[PROP_STATE] =
	    g_param_spec_enum (NM_DEVICE_STATE, "", "",
	                       NM_TYPE_DEVICE_STATE,
	                       NM_DEVICE_STATE_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:state-reason:
	 *
	 * The reason for the device state.
	 **/
	obj_properties[PROP_STATE_REASON] =
	    g_param_spec_uint (NM_DEVICE_STATE_REASON, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:active-connection:
	 *
	 * The #NMActiveConnection object that "owns" this device during activation.
	 **/
	obj_properties[PROP_ACTIVE_CONNECTION] =
	    g_param_spec_object (NM_DEVICE_ACTIVE_CONNECTION, "", "",
	                         NM_TYPE_ACTIVE_CONNECTION,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:available-connections: (type GPtrArray(NMRemoteConnection))
	 *
	 * The available connections of the device
	 **/
	obj_properties[PROP_AVAILABLE_CONNECTIONS] =
	    g_param_spec_boxed (NM_DEVICE_AVAILABLE_CONNECTIONS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:vendor:
	 *
	 * The vendor string of the device.
	 **/
	obj_properties[PROP_VENDOR] =
	    g_param_spec_string (NM_DEVICE_VENDOR, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:product:
	 *
	 * The product string of the device.
	 **/
	obj_properties[PROP_PRODUCT] =
	    g_param_spec_string (NM_DEVICE_PRODUCT, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:physical-port-id:
	 *
	 * The physical port ID of the device. (See
	 * nm_device_get_physical_port_id().)
	 **/
	obj_properties[PROP_PHYSICAL_PORT_ID] =
	    g_param_spec_string (NM_DEVICE_PHYSICAL_PORT_ID, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:mtu:
	 *
	 * The MTU of the device.
	 **/
	obj_properties[PROP_MTU] =
	    g_param_spec_uint (NM_DEVICE_MTU, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:metered:
	 *
	 * Whether the device is metered.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_METERED] =
	    g_param_spec_uint (NM_DEVICE_METERED, "", "",
	                       0, G_MAXUINT32, NM_METERED_UNKNOWN,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:lldp-neighbors:
	 *
	 * The LLDP neighbors.
	 **/
	obj_properties[PROP_LLDP_NEIGHBORS] =
	    g_param_spec_boxed (NM_DEVICE_LLDP_NEIGHBORS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READABLE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMDevice:interface-flags:
	 *
	 * The interface flags.
	 *
	 * Since: 1.22
	 **/
	obj_properties[PROP_INTERFACE_FLAGS] =
	    g_param_spec_uint (NM_DEVICE_INTERFACE_FLAGS, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	_nml_dbus_meta_class_init_with_properties (object_class, &_nml_dbus_meta_iface_nm_device);

	/**
	 * NMDevice::state-changed:
	 * @device: the device object that received the signal
	 * @new_state: the new state of the device
	 * @old_state: the previous state of the device
	 * @reason: the reason describing the state change
	 *
	 * Notifies the state change of a #NMDevice.
	 **/
	signals[STATE_CHANGED] =
	    g_signal_new ("state-changed",
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 3,
	                  G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT);
}

/**
 * nm_device_get_iface:
 * @device: a #NMDevice
 *
 * Gets the interface name of the #NMDevice.
 *
 * Returns: the interface of the device. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_get_iface (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return _nml_coerce_property_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->interface);
}

/**
 * nm_device_get_ip_iface:
 * @device: a #NMDevice
 *
 * Gets the IP interface name of the #NMDevice over which IP traffic flows
 * when the device is in the ACTIVATED state.
 *
 * Returns: the IP traffic interface of the device. This is the internal string
 * used by the device, and must not be modified.
 **/
const char *
nm_device_get_ip_iface (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return _nml_coerce_property_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->ip_interface);
}

/**
 * nm_device_get_device_type:
 * @device: a #NMDevice
 *
 * Returns the numeric type of the #NMDevice, ie Ethernet, Wi-Fi, etc.
 *
 * Returns: the device type
 **/
NMDeviceType
nm_device_get_device_type (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_DEVICE_TYPE_UNKNOWN);

	return coerce_type (NM_DEVICE_GET_PRIVATE (self)->device_type);
}

/**
 * nm_device_get_udi:
 * @device: a #NMDevice
 *
 * Gets the Unique Device Identifier of the #NMDevice.
 *
 * Returns: the Unique Device Identifier of the device.  This identifier may be
 * used to gather more information about the device from various operating
 * system services like udev or sysfs.
 **/
const char *
nm_device_get_udi (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return _nml_coerce_property_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->udi);
}

/**
 * nm_device_get_driver:
 * @device: a #NMDevice
 *
 * Gets the driver of the #NMDevice.
 *
 * Returns: the driver of the device. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_get_driver (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return _nml_coerce_property_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->driver);
}

/**
 * nm_device_get_driver_version:
 * @device: a #NMDevice
 *
 * Gets the driver version of the #NMDevice.
 *
 * Returns: the version of the device driver. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_get_driver_version (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return _nml_coerce_property_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->driver_version);
}

/**
 * nm_device_get_firmware_version:
 * @device: a #NMDevice
 *
 * Gets the firmware version of the #NMDevice.
 *
 * Returns: the firmware version of the device. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_get_firmware_version (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return _nml_coerce_property_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->firmware_version);
}

/**
 * nm_device_get_type_description:
 * @device: a #NMDevice
 *
 * Gets a (non-localized) description of the type of device that
 * @device is.
 *
 * Returns: the type description of the device. This is the internal
 * string used by the device, and must not be modified.
 **/
const char *
nm_device_get_type_description (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	const char *desc, *typename;

	/* BEWARE: this function should return the same value
	 * as nm_device_get_type_description() in nm-core. */

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	if (priv->type_description)
		return _nml_coerce_property_str_not_empty (priv->type_description);

	if (NM_DEVICE_GET_CLASS (device)->get_type_description) {
		desc = NM_DEVICE_GET_CLASS (device)->get_type_description (device);
		if (desc)
			return desc;
	}

	typename = G_OBJECT_TYPE_NAME (device);
	if (g_str_has_prefix (typename, "NMDevice"))
		typename += 8;
	priv->type_description = g_ascii_strdown (typename, -1);

	return _nml_coerce_property_str_not_empty (priv->type_description);
}

/**
 * nm_device_get_hw_address:
 * @device: a #NMDevice
 *
 * Gets the current a hardware address (MAC) for the @device.
 *
 * Returns: the current MAC of the device, or %NULL.
 * This is the internal string used by the device, and must not be modified.
 **/
const char *
nm_device_get_hw_address (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	if (NM_DEVICE_GET_CLASS (device)->get_hw_address)
		return NM_DEVICE_GET_CLASS (device)->get_hw_address (device);

	return NULL;
}

/**
 * nm_device_get_capabilities:
 * @device: a #NMDevice
 *
 * Gets the device' capabilities.
 *
 * Returns: the capabilities
 **/
NMDeviceCapabilities
nm_device_get_capabilities (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	return NM_DEVICE_GET_PRIVATE (device)->capabilities;
}

/**
 * nm_device_get_managed:
 * @device: a #NMDevice
 *
 * Whether the #NMDevice is managed by NetworkManager.
 *
 * Returns: %TRUE if the device is managed by NetworkManager
 **/
gboolean
nm_device_get_managed (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	return NM_DEVICE_GET_PRIVATE (device)->managed;
}

/**
 * nm_device_set_managed:
 * @device: a #NMDevice
 * @managed: %TRUE to make the device managed by NetworkManager.
 *
 * Enables or disables management of  #NMDevice by NetworkManager.
 *
 * Since: 1.2
 *
 * Deprecated: 1.22, use nm_device_set_managed_async() or GDBusConnection
 *
 * This function is deprecated because it calls a synchronous D-Bus method
 * and modifies the content of the NMClient cache client side. Also, it does
 * not emit a property changed signal.
 **/
void
nm_device_set_managed (NMDevice *device, gboolean managed)
{
	g_return_if_fail (NM_IS_DEVICE (device));

	/* FIXME(libnm-async-api): add nm_device_set_managed_async(). */

	managed = !!managed;

	NM_DEVICE_GET_PRIVATE (device)->managed = managed;

	_nm_client_set_property_sync_legacy (_nm_object_get_client (device),
	                                     _nm_object_get_path (device),
	                                     NM_DBUS_INTERFACE_DEVICE,
	                                     "Managed",
	                                     "b",
	                                     managed);
}

/**
 * nm_device_get_autoconnect:
 * @device: a #NMDevice
 *
 * Whether the #NMDevice can be autoconnected.
 *
 * Returns: %TRUE if the device is allowed to be autoconnected
 **/
gboolean
nm_device_get_autoconnect (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	return NM_DEVICE_GET_PRIVATE (device)->autoconnect;
}

/**
 * nm_device_set_autoconnect:
 * @device: a #NMDevice
 * @autoconnect: %TRUE to enable autoconnecting
 *
 * Enables or disables automatic activation of the #NMDevice.
 *
 * Deprecated: 1.22, use nm_device_set_autoconnect_async() or GDBusConnection
 *
 * This function is deprecated because it calls a synchronous D-Bus method
 * and modifies the content of the NMClient cache client side.
 **/
void
nm_device_set_autoconnect (NMDevice *device, gboolean autoconnect)
{
	g_return_if_fail (NM_IS_DEVICE (device));

	/* FIXME(libnm-async-api): add nm_device_set_autoconnect_async(). */

	NM_DEVICE_GET_PRIVATE (device)->autoconnect = autoconnect;

	_nm_client_set_property_sync_legacy (_nm_object_get_client (device),
	                                     _nm_object_get_path (device),
	                                     NM_DBUS_INTERFACE_DEVICE,
	                                     "AutoConnect",
	                                     "b",
	                                     autoconnect);
}

/**
 * nm_device_get_firmware_missing:
 * @device: a #NMDevice
 *
 * Indicates that firmware required for the device's operation is likely
 * to be missing.
 *
 * Returns: %TRUE if firmware required for the device's operation is likely
 * to be missing.
 **/
gboolean
nm_device_get_firmware_missing (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	return NM_DEVICE_GET_PRIVATE (device)->firmware_missing;
}

/**
 * nm_device_get_nm_plugin_missing:
 * @device: a #NMDevice
 *
 * Indicates that the NetworkManager plugin for the device is not installed.
 *
 * Returns: %TRUE if the device plugin not installed.
 *
 * Since: 1.2
 **/
gboolean
nm_device_get_nm_plugin_missing (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	return NM_DEVICE_GET_PRIVATE (device)->nm_plugin_missing;
}

/**
 * nm_device_get_ip4_config:
 * @device: a #NMDevice
 *
 * Gets the current IPv4 #NMIPConfig associated with the #NMDevice.
 *
 * You can alternatively use nm_active_connection_get_ip4_config(), which also
 * works with VPN connections.
 *
 * Returns: (transfer none): the IPv4 #NMIPConfig, or %NULL if the device is not
 * activated.
 **/
NMIPConfig *
nm_device_get_ip4_config (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return nml_dbus_property_o_get_obj (&NM_DEVICE_GET_PRIVATE (device)->property_o[PROPERTY_O_IDX_IP4_CONFIG]);
}

/**
 * nm_device_get_dhcp4_config:
 * @device: a #NMDevice
 *
 * Gets the current IPv4 #NMDhcpConfig associated with the #NMDevice.
 *
 * You can alternatively use nm_active_connection_get_dhcp4_config(), which also
 * works with VPN connections.
 *
 * Returns: (transfer none): the IPv4 #NMDhcpConfig, or %NULL if the device is
 * not activated or not using DHCP.
 **/
NMDhcpConfig *
nm_device_get_dhcp4_config (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return nml_dbus_property_o_get_obj (&NM_DEVICE_GET_PRIVATE (device)->property_o[PROPERTY_O_IDX_DHCP4_CONFIG]);
}

/**
 * nm_device_get_ip6_config:
 * @device: a #NMDevice
 *
 * Gets the current IPv6 #NMIPConfig associated with the #NMDevice.
 *
 * You can alternatively use nm_active_connection_get_ip6_config(), which also
 * works with VPN connections.
 *
 * Returns: (transfer none): the IPv6 #NMIPConfig or %NULL if the device is not activated.
 **/
NMIPConfig *
nm_device_get_ip6_config (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return nml_dbus_property_o_get_obj (&NM_DEVICE_GET_PRIVATE (device)->property_o[PROPERTY_O_IDX_IP6_CONFIG]);
}

/**
 * nm_device_get_dhcp6_config:
 * @device: a #NMDevice
 *
 * Gets the current IPv6 #NMDhcpConfig associated with the #NMDevice.
 *
 * You can alternatively use nm_active_connection_get_dhcp6_config(), which also
 * works with VPN connections.
 *
 * Returns: (transfer none): the IPv6 #NMDhcpConfig, or %NULL if the device is
 * not activated or not using DHCPv6.
 **/
NMDhcpConfig *
nm_device_get_dhcp6_config (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return nml_dbus_property_o_get_obj (&NM_DEVICE_GET_PRIVATE (device)->property_o[PROPERTY_O_IDX_DHCP6_CONFIG]);
}

/**
 * nm_device_get_connectivity:
 * @device: a #NMDevice
 * @addr_family: network address family
 *
 * The connectivity state of the device for given address family.
 * Supported address families are %AF_INET for IPv4, %AF_INET6
 * for IPv6 or %AF_UNSPEC for any.
 *
 * Returns: the current connectivity state
 *
 * Since: 1.16
 **/
NMConnectivityState
nm_device_get_connectivity (NMDevice *device, int addr_family)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	switch (addr_family) {
	case AF_INET:
		return priv->ip4_connectivity;
	case AF_INET6:
		return priv->ip6_connectivity;
	case AF_UNSPEC:
		return NM_MAX (priv->ip4_connectivity, priv->ip6_connectivity);
	default:
		g_return_val_if_reached (NM_CONNECTIVITY_UNKNOWN);
	}
}

/**
 * nm_device_get_interface_flags:
 * @device: a #NMDevice
 *
 * Gets the interface flags of the device.
 *
 * Returns: the flags
 *
 * Since: 1.22
 **/
NMDeviceInterfaceFlags
nm_device_get_interface_flags (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NM_DEVICE_INTERFACE_FLAG_NONE);

	return NM_DEVICE_GET_PRIVATE (device)->interface_flags;
}

/**
 * nm_device_get_state:
 * @device: a #NMDevice
 *
 * Gets the current #NMDevice state.
 *
 * Returns: the current device state
 **/
NMDeviceState
nm_device_get_state (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NM_DEVICE_STATE_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (device)->state;
}

/**
 * nm_device_get_state_reason:
 * @device: a #NMDevice
 *
 * Gets the reason for entering the current #NMDevice state.
 *
 * Returns: the reason for entering the current device state
 **/
NMDeviceStateReason
nm_device_get_state_reason (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NM_DEVICE_STATE_REASON_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (device)->state_reason;
}

/**
 * nm_device_get_active_connection:
 * @device: a #NMDevice
 *
 * Gets the #NMActiveConnection object which owns this device during activation.
 *
 * Returns: (transfer none): the #NMActiveConnection or %NULL if the device is
 * not part of an active connection
 **/
NMActiveConnection *
nm_device_get_active_connection (NMDevice *device)
{
	NMActiveConnection *ac;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	ac = nml_dbus_property_o_get_obj (&NM_DEVICE_GET_PRIVATE (device)->property_o[PROPERTY_O_IDX_ACTIVE_CONNECTION]);

	nm_assert (!ac || NM_IS_ACTIVE_CONNECTION (ac));
	return ac;
}

/**
 * nm_device_get_available_connections:
 * @device: a #NMDevice
 *
 * Gets the #NMRemoteConnections currently known to the daemon that could
 * be activated on @device.
 *
 * Returns: (element-type NMRemoteConnection): the #GPtrArray
 * containing #NMRemoteConnections. This is the internal copy used by
 * the connection, and must not be modified.
 **/
const GPtrArray *
nm_device_get_available_connections (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return nml_dbus_property_ao_get_objs_as_ptrarray (&NM_DEVICE_GET_PRIVATE (device)->available_connections);
}

static const char *
get_type_name (NMDevice *device)
{
	switch (nm_device_get_device_type (device)) {
	case NM_DEVICE_TYPE_ETHERNET:
		return _("Ethernet");
	case NM_DEVICE_TYPE_WIFI:
		return _("Wi-Fi");
	case NM_DEVICE_TYPE_BT:
		return _("Bluetooth");
	case NM_DEVICE_TYPE_OLPC_MESH:
		return _("OLPC Mesh");
	case NM_DEVICE_TYPE_OVS_INTERFACE:
		return _("Open vSwitch Interface");
	case NM_DEVICE_TYPE_OVS_PORT:
		return _("Open vSwitch Port");
	case NM_DEVICE_TYPE_OVS_BRIDGE:
		return _("Open vSwitch Bridge");
	case NM_DEVICE_TYPE_WIMAX:
		return _("WiMAX");
	case NM_DEVICE_TYPE_MODEM:
		return _("Mobile Broadband");
	case NM_DEVICE_TYPE_INFINIBAND:
		return _("InfiniBand");
	case NM_DEVICE_TYPE_BOND:
		return _("Bond");
	case NM_DEVICE_TYPE_TEAM:
		return _("Team");
	case NM_DEVICE_TYPE_BRIDGE:
		return _("Bridge");
	case NM_DEVICE_TYPE_VLAN:
		return _("VLAN");
	case NM_DEVICE_TYPE_ADSL:
		return _("ADSL");
	case NM_DEVICE_TYPE_MACVLAN:
		return _("MACVLAN");
	case NM_DEVICE_TYPE_VXLAN:
		return _("VXLAN");
	case NM_DEVICE_TYPE_IP_TUNNEL:
		return _("IPTunnel");
	case NM_DEVICE_TYPE_TUN:
		return _("Tun");
	case NM_DEVICE_TYPE_VETH:
		return _("Veth");
	case NM_DEVICE_TYPE_MACSEC:
		return _("MACsec");
	case NM_DEVICE_TYPE_DUMMY:
		return _("Dummy");
	case NM_DEVICE_TYPE_PPP:
		return _("PPP");
	case NM_DEVICE_TYPE_WPAN:
		return _("IEEE 802.15.4");
	case NM_DEVICE_TYPE_6LOWPAN:
		return _("6LoWPAN");
	case NM_DEVICE_TYPE_WIREGUARD:
		return _("WireGuard");
	case NM_DEVICE_TYPE_WIFI_P2P:
		return _("Wi-Fi P2P");
	case NM_DEVICE_TYPE_GENERIC:
	case NM_DEVICE_TYPE_UNUSED1:
	case NM_DEVICE_TYPE_UNUSED2:
	case NM_DEVICE_TYPE_UNKNOWN:
		break;
	}
	return _("Unknown");
}

static char *
get_device_type_name_with_iface (NMDevice *device)
{
	const char *type_name = get_type_name (device);

	switch (nm_device_get_device_type (device)) {
	case NM_DEVICE_TYPE_BOND:
	case NM_DEVICE_TYPE_TEAM:
	case NM_DEVICE_TYPE_BRIDGE:
	case NM_DEVICE_TYPE_VLAN:
		return g_strdup_printf ("%s (%s)", type_name, nm_device_get_iface (device));
	default:
		return g_strdup (type_name);
	}
}

static char *
get_device_generic_type_name_with_iface (NMDevice *device)
{
	switch (nm_device_get_device_type (device)) {
	case NM_DEVICE_TYPE_ETHERNET:
	case NM_DEVICE_TYPE_INFINIBAND:
		return g_strdup (_("Wired"));
	default:
		return get_device_type_name_with_iface (device);
	}
}

static const char *
get_bus_name (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	struct udev_device *udevice;
	const char *ifname;
	const char *bus;

	if (priv->bus_name)
		goto out;

	if (!priv->udev)
		return NULL;

	ifname = nm_device_get_iface (device);
	if (!ifname)
		return NULL;

	udevice = udev_device_new_from_subsystem_sysname (priv->udev, "net", ifname);
	if (!udevice) {
		udevice = udev_device_new_from_subsystem_sysname (priv->udev, "tty", ifname);
		if (!udevice)
			return NULL;
	}
	bus = udev_device_get_property_value (udevice, "ID_BUS");
	if (!g_strcmp0 (bus, "pci"))
		priv->bus_name = g_strdup (_("PCI"));
	else if (!g_strcmp0 (bus, "usb"))
		priv->bus_name = g_strdup (_("USB"));
	else {
		/* Use "" instead of NULL so we can tell later that we've
		 * already tried.
		 */
		priv->bus_name = g_strdup ("");
	}
	udev_device_unref (udevice);

out:
	if (*priv->bus_name)
		return priv->bus_name;
	else
		return NULL;
}

static char *
_get_udev_property (NMDevice *device,
                    const char *enc_prop,  /* ID_XXX_ENC */
                    const char *db_prop)   /* ID_XXX_FROM_DATABASE */
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	struct udev_device *udev_device;
	struct udev_device *tmpdev;
	const char *ifname;
	guint32 count = 0;
	char *enc_value = NULL;
	char *db_value = NULL;

	if (!priv->udev)
		return NULL;

	ifname = nm_device_get_iface (device);
	if (!ifname)
		return NULL;

	udev_device = udev_device_new_from_subsystem_sysname (priv->udev, "net", ifname);
	if (!udev_device) {
		udev_device = udev_device_new_from_subsystem_sysname (priv->udev, "tty", ifname);
		if (!udev_device)
			return NULL;
	}
	/* Walk up the chain of the device and its parents a few steps to grab
	 * vendor and device ID information off it.
	 */
	tmpdev = udev_device;
	while ((count++ < 3) && tmpdev && !enc_value) {
		if (!enc_value)
			enc_value = nm_udev_utils_property_decode_cp (udev_device_get_property_value (tmpdev, enc_prop));
		if (!db_value)
			db_value = g_strdup (udev_device_get_property_value (tmpdev, db_prop));

		tmpdev = udev_device_get_parent (tmpdev);
	}
	udev_device_unref (udev_device);

	/* Prefer the hwdata database value over what comes directly
	 * from the device. */
	if (db_value) {
		g_free (enc_value);
		return db_value;
	}

	return enc_value;
}

static char *
_get_udev_property_utf8safe (NMDevice *device,
                             const char *enc_prop,  /* ID_XXX_ENC */
                             const char *db_prop)   /* ID_XXX_FROM_DATABASE */
{
	return nm_utils_str_utf8safe_escape_take (_get_udev_property (device,
	                                                              enc_prop,
	                                                              db_prop),
	                                          NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL);
}

/**
 * nm_device_get_product:
 * @device: a #NMDevice
 *
 * Gets the product string of the #NMDevice.
 *
 * Returns: the product name of the device. This is the internal string used by the
 * device, and must not be modified.
 *
 * The string is backslash escaped (C escaping) for invalid characters. The escaping
 * can be reverted with g_strcompress(), however the result may not be valid UTF-8.
 **/
const char *
nm_device_get_product (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->product) {
		priv->product = _get_udev_property_utf8safe (device, "ID_MODEL_ENC", "ID_MODEL_FROM_DATABASE");

		/* Sometimes ID_PRODUCT_FROM_DATABASE is used? */
		if (!priv->product)
			priv->product = _get_udev_property_utf8safe (device, "ID_MODEL_ENC", "ID_PRODUCT_FROM_DATABASE");

		if (!priv->product)
			priv->product = g_strdup ("");
	}

	return priv->product;
}

/**
 * nm_device_get_vendor:
 * @device: a #NMDevice
 *
 * Gets the vendor string of the #NMDevice.
 *
 * Returns: the vendor name of the device. This is the internal string used by the
 * device, and must not be modified.
 *
 * The string is backslash escaped (C escaping) for invalid characters. The escaping
 * can be reverted with g_strcompress(), however the result may not be valid UTF-8.
 **/
const char *
nm_device_get_vendor (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);

	if (!priv->vendor)
		priv->vendor = _get_udev_property_utf8safe (device, "ID_VENDOR_ENC", "ID_VENDOR_FROM_DATABASE");

	if (!priv->vendor)
		priv->vendor = g_strdup ("");

	return priv->vendor;
}

static void
ensure_description (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	GParamSpec *name_prop;
	gs_free char *short_product = NULL;

	priv->short_vendor = nm_str_realloc (nm_utils_fixup_vendor_string (nm_device_get_vendor (device)));

	/* Grab device's preferred name, if any */
	name_prop = g_object_class_find_property (G_OBJECT_GET_CLASS (G_OBJECT (device)), "name");
	if (name_prop) {
		g_object_get (device, "name", &priv->description, NULL);
		if (priv->description && priv->description[0])
			return;
		g_clear_pointer (&priv->description, g_free);
	}

	if (!priv->short_vendor) {
		priv->description = g_strdup (nm_device_get_iface (device) ?: "");
		return;
	}

	short_product = nm_utils_fixup_product_string (nm_device_get_product (device));
	if (short_product == NULL)
		short_product = g_strdup (get_type_name (device));

	/* Another quick hack; if all of the fixed up vendor string
	 * is found in product, ignore the vendor.
	 */
	{
		gs_free char *pdown = g_ascii_strdown (short_product, -1);
		gs_free char *vdown = g_ascii_strdown (priv->short_vendor, -1);

		if (!strstr (pdown, vdown))
			priv->description = g_strconcat (priv->short_vendor, " ", short_product, NULL);
		else
			priv->description = g_steal_pointer (&short_product);
	}
}

static const char *
get_short_vendor (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);

	if (!priv->description)
		ensure_description (device);

	return priv->short_vendor;
}

/**
 * nm_device_get_description:
 * @device: an #NMDevice
 *
 * Gets a description of @device, based on its vendor and product names.
 *
 * Returns: a description of @device. If either the vendor or the
 *   product name is unknown, this returns the interface name.
 */
const char *
nm_device_get_description (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);

	if (!priv->description)
		ensure_description (device);

	return priv->description;
}

static gboolean
find_duplicates (char     **names,
                 gboolean  *duplicates,
                 int        num_devices)
{
	int i, j;
	gboolean found_any = FALSE;

	memset (duplicates, 0, num_devices * sizeof (gboolean));
	for (i = 0; i < num_devices; i++) {
		if (duplicates[i])
			continue;
		for (j = i + 1; j < num_devices; j++) {
			if (duplicates[j])
				continue;
			if (!strcmp (names[i], names[j]))
				duplicates[i] = duplicates[j] = found_any = TRUE;
		}
	}

	return found_any;
}

/**
 * nm_device_disambiguate_names:
 * @devices: (array length=num_devices): an array of #NMDevice
 * @num_devices: length of @devices
 *
 * Generates a list of short-ish unique presentation names for the
 * devices in @devices.
 *
 * Returns: (transfer full) (array zero-terminated=1): the device names
 */
char **
nm_device_disambiguate_names (NMDevice **devices,
                              int        num_devices)
{
	char **names;
	gboolean *duplicates;
	int i;

	names = g_new (char *, num_devices + 1);
	duplicates = g_new (gboolean, num_devices);

	/* Generic device name */
	for (i = 0; i < num_devices; i++)
		names[i] = get_device_generic_type_name_with_iface (devices[i]);
	if (!find_duplicates (names, duplicates, num_devices))
		goto done;

	/* Try specific names (eg, "Ethernet" and "InfiniBand" rather
	 * than "Wired")
	 */
	for (i = 0; i < num_devices; i++) {
		if (duplicates[i]) {
			g_free (names[i]);
			names[i] = get_device_type_name_with_iface (devices[i]);
		}
	}
	if (!find_duplicates (names, duplicates, num_devices))
		goto done;

	/* Try prefixing bus name (eg, "PCI Ethernet" vs "USB Ethernet") */
	for (i = 0; i < num_devices; i++) {
		if (duplicates[i]) {
			const char *bus = get_bus_name (devices[i]);
			char *name;

			if (!bus)
				continue;

			g_free (names[i]);
			name = get_device_type_name_with_iface (devices[i]);
			/* TRANSLATORS: the first %s is a bus name (eg, "USB") or
			 * product name, the second is a device type (eg,
			 * "Ethernet"). You can change this to something like
			 * "%2$s (%1$s)" if there's no grammatical way to combine
			 * the strings otherwise.
			 */
			names[i] = g_strdup_printf (C_("long device name", "%s %s"),
			                            bus, name);
			g_free (name);
		}
	}
	if (!find_duplicates (names, duplicates, num_devices))
		goto done;

	/* Try prefixing vendor name */
	for (i = 0; i < num_devices; i++) {
		if (duplicates[i]) {
			const char *vendor = get_short_vendor (devices[i]);
			char *name;

			if (!vendor)
				continue;

			g_free (names[i]);
			name = get_device_type_name_with_iface (devices[i]);
			names[i] = g_strdup_printf (C_("long device name", "%s %s"),
			                            vendor,
			                            get_type_name (devices[i]));
			g_free (name);
		}
	}
	if (!find_duplicates (names, duplicates, num_devices))
		goto done;

	/* If dealing with Bluetooth devices, try to distinguish them by
	 * device name.
	 */
	for (i = 0; i < num_devices; i++) {
		if (duplicates[i] && NM_IS_DEVICE_BT (devices[i])) {
			const char *devname = nm_device_bt_get_name (NM_DEVICE_BT (devices[i]));
			char *name;

			if (!devname)
				continue;

			g_free (names[i]);
			name = get_device_type_name_with_iface (devices[i]);
			names[i] = g_strdup_printf ("%s (%s)", name, devname);
			g_free (name);
		}
	}
	if (!find_duplicates (names, duplicates, num_devices))
		goto done;

	/* We have multiple identical network cards, so we have to differentiate
	 * them by interface name.
	 */
	for (i = 0; i < num_devices; i++) {
		if (duplicates[i]) {
			const char *interface = nm_device_get_iface (devices[i]);

			if (!interface)
				continue;

			g_free (names[i]);
			names[i] = g_strdup_printf ("%s (%s)",
			                            get_type_name (devices[i]),
			                            interface);
		}
	}

done:
	g_free (duplicates);
	names[num_devices] = NULL;
	return names;
}

/**
 * nm_device_get_physical_port_id:
 * @device: a #NMDevice
 *
 * Gets the physical port ID of the #NMDevice. If non-%NULL, this is
 * an opaque string that can be used to recognize when
 * seemingly-unrelated #NMDevices are actually just different virtual
 * ports on a single physical port. (Eg, NPAR / SR-IOV.)
 *
 * Returns: the physical port ID of the device, or %NULL if the port
 *   ID is unknown. This is the internal string used by the device and
 *   must not be modified.
 **/
const char *
nm_device_get_physical_port_id (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return _nml_coerce_property_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->physical_port_id);
}

/**
 * nm_device_get_mtu:
 * @device: a #NMDevice
 *
 * Gets the  MTU of the #NMDevice.
 *
 * Returns: the MTU of the device in bytes.
 **/
guint32
nm_device_get_mtu (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	return NM_DEVICE_GET_PRIVATE (device)->mtu;
}

/**
 * nm_device_get_metered:
 * @device: a #NMDevice
 *
 * Gets the metered setting of a #NMDevice.
 *
 * Returns: the metered setting.
 *
 * Since: 1.2
 **/
NMMetered
nm_device_get_metered (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NM_METERED_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (device)->metered;
}

NM_BACKPORT_SYMBOL (libnm_1_0_6, NMMetered, nm_device_get_metered, (NMDevice *device), (device));

/**
 * nm_device_get_lldp_neighbors:
 * @device: a #NMDevice
 *
 * Gets the list of neighbors discovered through LLDP.
 *
 * Returns: (element-type NMLldpNeighbor) (transfer none): the #GPtrArray
 * containing #NMLldpNeighbor<!-- -->s. This is the internal copy used by the
 * device and must not be modified. The library never modifies the returned
 * array and thus it is safe for callers to reference and keep using it.
 *
 * Since: 1.2
 **/
GPtrArray *
nm_device_get_lldp_neighbors (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->lldp_neighbors)
		priv->lldp_neighbors = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_lldp_neighbor_unref);
	return priv->lldp_neighbors;
}

/**
 * nm_device_is_real:
 * @device: a #NMDevice
 *
 * Returns: %TRUE if the device exists, or %FALSE if it is a placeholder device
 * that could be automatically created by NetworkManager if one of its
 * #NMDevice:available-connections was activated.
 *
 * Since: 1.2
 **/
gboolean
nm_device_is_real (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	return NM_DEVICE_GET_PRIVATE (device)->real;
}

/**
 * nm_device_is_software:
 * @device: a #NMDevice
 *
 * Whether the device is a software device.
 *
 * Returns: %TRUE if @device is a software device, %FALSE if it is a hardware device.
 **/
gboolean
nm_device_is_software (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	return !!(NM_DEVICE_GET_PRIVATE (device)->capabilities & NM_DEVICE_CAP_IS_SOFTWARE);
}

/**
 * nm_device_reapply:
 * @device: a #NMDevice
 * @connection: (allow-none): the #NMConnection to replace the applied
 *   settings with or %NULL to reuse existing
 * @version_id: zero or the expected version id of the applied connection.
 *   If specified and the version id mismatches, the call fails without
 *   modification. This allows to catch concurrent accesses.
 * @flags: always set this to zero
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Attempts to update device with changes to the currently active connection
 * made since it was last applied.
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be set.
 *
 * Since: 1.2
 *
 * Deprecated: 1.22, use nm_device_reapply_async() or GDBusConnection
 **/
gboolean
nm_device_reapply (NMDevice *device,
                   NMConnection *connection,
                   guint64 version_id,
                   guint32 flags,
                   GCancellable *cancellable,
                   GError **error)
{
	GVariant *arg_connection = NULL;

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (!connection || NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (connection)
		arg_connection = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
	if (!arg_connection)
		arg_connection = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);

	return _nm_client_dbus_call_sync_void (_nm_object_get_client (device),
	                                       cancellable,
	                                       _nm_object_get_path (device),
	                                       NM_DBUS_INTERFACE_DEVICE,
	                                       "Reapply",
	                                       g_variant_new ("(@a{sa{sv}}tu)",
	                                                      arg_connection,
	                                                      version_id,
	                                                      flags),
	                                       G_DBUS_CALL_FLAGS_NONE,
	                                       NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                       TRUE,
	                                       error);
}

/**
 * nm_device_reapply_async:
 * @device: a #NMDevice
 * @connection: (allow-none): the #NMConnection to replace the applied
 *   settings with or %NULL to reuse existing
 * @version_id: zero or the expected version id of the applied
 *   connection. If specified and the version id mismatches, the call
 *   fails without modification. This allows to catch concurrent
 *   accesses.
 * @flags: always set this to zero
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the reapply operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously begins an attempt to update device with changes to the
 * currently active connection made since it was last applied.
 *
 * Since: 1.2
 **/
void
nm_device_reapply_async (NMDevice *device,
                         NMConnection *connection,
                         guint64 version_id,
                         guint32 flags,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
	GVariant *arg_connection = NULL;

	g_return_if_fail (NM_IS_DEVICE (device));
	g_return_if_fail (!connection || NM_IS_CONNECTION (connection));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	if (connection)
		arg_connection = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
	if (!arg_connection)
		arg_connection = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);

	_nm_client_dbus_call (_nm_object_get_client (device),
	                      device,
	                      nm_device_reapply_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      _nm_object_get_path (device),
	                      NM_DBUS_INTERFACE_DEVICE,
	                      "Reapply",
	                      g_variant_new ("(@a{sa{sv}}tu)",
	                                     arg_connection,
	                                     version_id,
	                                     flags),
	                      G_VARIANT_TYPE ("()"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_void_strip_dbus_error_cb);
}

/**
 * nm_device_reapply_finish:
 * @device: a #NMDevice
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_device_reapply_async().
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error
 * will be set.
 *
 * Since: 1.2
 **/
gboolean
nm_device_reapply_finish (NMDevice *device,
                          GAsyncResult *result,
                          GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, device, nm_device_reapply_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/*****************************************************************************/

/**
 * nm_device_get_applied_connection:
 * @device: a #NMDevice
 * @flags: the flags argument. Currently this value must always be zero.
 * @version_id: (out) (allow-none): returns the current version id of
 *   the applied connection
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Fetch the currently applied connection on the device.
 *
 * Returns: (transfer full): a %NMConnection with the currently applied settings
 *   or %NULL on error.
 *
 * The connection is as received from D-Bus and might not validate according
 * to nm_connection_verify().
 *
 * Since: 1.2
 *
 * Deprecated: 1.22, use nm_device_get_applied_connection_async() or GDBusConnection
 **/
NMConnection *
nm_device_get_applied_connection (NMDevice *device,
                                  guint32 flags,
                                  guint64 *version_id,
                                  GCancellable *cancellable,
                                  GError **error)
{
	gs_unref_variant GVariant *ret = NULL;
	gs_unref_variant GVariant *v_connection = NULL;
	guint64 v_version_id;
	NMConnection *connection;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	ret = _nm_client_dbus_call_sync (_nm_object_get_client (device),
	                                 cancellable,
	                                 _nm_object_get_path (device),
	                                 NM_DBUS_INTERFACE_DEVICE,
	                                 "GetAppliedConnection",
	                                 g_variant_new ("(u)", flags),
	                                 G_VARIANT_TYPE ("(a{sa{sv}}t)"),
	                                 G_DBUS_CALL_FLAGS_NONE,
	                                 NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                 TRUE,
	                                 error);
	if (!ret)
		return NULL;

	g_variant_get (ret,
	               "(@a{sa{sv}}t)",
	               &v_connection,
	               &v_version_id);

	connection = _nm_simple_connection_new_from_dbus (v_connection, NM_SETTING_PARSE_FLAGS_BEST_EFFORT, error);
	if (!connection)
		return NULL;

	NM_SET_OUT (version_id, v_version_id);
	return connection;
}

/**
 * nm_device_get_applied_connection_async:
 * @device: a #NMDevice
 * @flags: the flags argument. Currently this value must always be zero.
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the reapply operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously begins and gets the currently applied connection.
 *
 * Since: 1.2
 **/
void
nm_device_get_applied_connection_async  (NMDevice *device,
                                         guint32 flags,
                                         GCancellable *cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
	g_return_if_fail (NM_IS_DEVICE (device));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	_nm_client_dbus_call (_nm_object_get_client (device),
	                      device,
	                      nm_device_get_applied_connection_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      _nm_object_get_path (device),
	                      NM_DBUS_INTERFACE_DEVICE,
	                      "GetAppliedConnection",
	                      g_variant_new ("(u)", flags),
	                      G_VARIANT_TYPE ("(a{sa{sv}}t)"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_variant_strip_dbus_error_cb);
}

/**
 * nm_device_get_applied_connection_finish:
 * @device: a #NMDevice
 * @result: the result passed to the #GAsyncReadyCallback
 * @version_id: (out) (allow-none): the current version id of the applied
 *   connection.
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_device_get_applied_connection_async().
 *
 * Returns: (transfer full): a currently applied %NMConnection or %NULL in case
 *   of error.
 *
 * The connection is as received from D-Bus and might not validate according
 * to nm_connection_verify().
 *
 * Since: 1.2
 **/
NMConnection *
nm_device_get_applied_connection_finish (NMDevice *device,
                                         GAsyncResult *result,
                                         guint64 *version_id,
                                         GError **error)
{
	gs_unref_variant GVariant *ret = NULL;
	gs_unref_variant GVariant *v_connection = NULL;
	guint64 v_version_id;
	NMConnection *connection;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (nm_g_task_is_valid (result, device, nm_device_get_applied_connection_async), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	ret = g_task_propagate_pointer (G_TASK (result), error);
	if (!ret)
		return NULL;

	g_variant_get (ret,
	               "(@a{sa{sv}}t)",
	               &v_connection,
	               &v_version_id);

	connection = _nm_simple_connection_new_from_dbus (v_connection, NM_SETTING_PARSE_FLAGS_BEST_EFFORT, error);
	if (!connection)
		return NULL;

	NM_SET_OUT (version_id, v_version_id);
	return connection;
}

/*****************************************************************************/

/**
 * nm_device_disconnect:
 * @device: a #NMDevice
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Disconnects the device if currently connected, and prevents the device from
 * automatically connecting to networks until the next manual network connection
 * request.
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error will be set.
 *
 * Deprecated: 1.22, use nm_device_disconnect_async() or GDBusConnection
 **/
gboolean
nm_device_disconnect (NMDevice *device,
                      GCancellable *cancellable,
                      GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	return _nm_client_dbus_call_sync_void (_nm_object_get_client (device),
	                                       cancellable,
	                                       _nm_object_get_path (device),
	                                       NM_DBUS_INTERFACE_DEVICE,
	                                       "Disconnect",
	                                       g_variant_new ("()"),
	                                       G_DBUS_CALL_FLAGS_NONE,
	                                       NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                       TRUE,
	                                       error);
}

/**
 * nm_device_disconnect_async:
 * @device: a #NMDevice
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when the disconnect operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously begins disconnecting the device if currently connected, and
 * prevents the device from automatically connecting to networks until the next
 * manual network connection request.
 **/
void
nm_device_disconnect_async (NMDevice *device,
                            GCancellable *cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
	g_return_if_fail (NM_IS_DEVICE (device));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	_nm_client_dbus_call (_nm_object_get_client (device),
	                      device,
	                      nm_device_disconnect_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      _nm_object_get_path (device),
	                      NM_DBUS_INTERFACE_DEVICE,
	                      "Disconnect",
	                      g_variant_new ("()"),
	                      G_VARIANT_TYPE ("()"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_void_strip_dbus_error_cb);
}

/**
 * nm_device_disconnect_finish:
 * @device: a #NMDevice
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_device_disconnect_async().
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error
 * will be set.
 **/
gboolean
nm_device_disconnect_finish (NMDevice *device,
                             GAsyncResult *result,
                             GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, device, nm_device_disconnect_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/**
 * nm_device_delete:
 * @device: a #NMDevice
 * @cancellable: a #GCancellable, or %NULL
 * @error: location for a #GError, or %NULL
 *
 * Deletes the software device. Hardware devices can't be deleted.
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error
 * will be set.
 *
 * Deprecated: 1.22, use nm_device_delete_async() or GDBusConnection
 **/
gboolean
nm_device_delete (NMDevice *device,
                  GCancellable *cancellable,
                  GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	return _nm_client_dbus_call_sync_void (_nm_object_get_client (device),
	                                       cancellable,
	                                       _nm_object_get_path (device),
	                                       NM_DBUS_INTERFACE_DEVICE,
	                                       "Delete",
	                                       g_variant_new ("()"),
	                                       G_DBUS_CALL_FLAGS_NONE,
	                                       NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                                       TRUE,
	                                       error);
}

/**
 * nm_device_delete_async:
 * @device: a #NMDevice
 * @cancellable: a #GCancellable, or %NULL
 * @callback: callback to be called when delete operation completes
 * @user_data: caller-specific data passed to @callback
 *
 * Asynchronously begins deleting the software device. Hardware devices can't
 * be deleted.
 **/
void
nm_device_delete_async (NMDevice *device,
                        GCancellable *cancellable,
                        GAsyncReadyCallback callback,
                        gpointer user_data)
{
	g_return_if_fail (NM_IS_DEVICE (device));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	_nm_client_dbus_call (_nm_object_get_client (device),
	                      device,
	                      nm_device_delete_async,
	                      cancellable,
	                      callback,
	                      user_data,
	                      _nm_object_get_path (device),
	                      NM_DBUS_INTERFACE_DEVICE,
	                      "Delete",
	                      g_variant_new ("()"),
	                      G_VARIANT_TYPE ("()"),
	                      G_DBUS_CALL_FLAGS_NONE,
	                      NM_DBUS_DEFAULT_TIMEOUT_MSEC,
	                      nm_dbus_connection_call_finish_void_strip_dbus_error_cb);
}

/**
 * nm_device_delete_finish:
 * @device: a #NMDevice
 * @result: the result passed to the #GAsyncReadyCallback
 * @error: location for a #GError, or %NULL
 *
 * Gets the result of a call to nm_device_delete_async().
 *
 * Returns: %TRUE on success, %FALSE on error, in which case @error
 * will be set.
 **/
gboolean
nm_device_delete_finish (NMDevice *device,
                         GAsyncResult *result,
                         GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (nm_g_task_is_valid (result, device, nm_device_delete_async), FALSE);

	return g_task_propagate_boolean (G_TASK (result), error);
}

/**
 * nm_device_connection_valid:
 * @device: an #NMDevice to validate @connection against
 * @connection: an #NMConnection to validate against @device
 *
 * Validates a given connection for a given #NMDevice object and returns
 * whether the connection may be activated with the device. For example if
 * @device is a Wi-Fi device that supports only WEP encryption, the connection
 * will only be valid if it is a Wi-Fi connection which describes a WEP or open
 * network, and will not be valid if it describes a WPA network, or if it is
 * an Ethernet, Bluetooth, WWAN, etc connection that is incompatible with the
 * device.
 *
 * Returns: %TRUE if the connection may be activated with this device, %FALSE
 * if is incompatible with the device's capabilities and characteristics.
 **/
gboolean
nm_device_connection_valid (NMDevice *device, NMConnection *connection)
{
	return nm_device_connection_compatible (device, connection, NULL);
}

static gboolean
connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	const char *config_iface, *device_iface;
	GError *local = NULL;

	if (!nm_connection_verify (connection, &local)) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		             _("The connection was not valid: %s"), local->message);
		g_error_free (local);
		return FALSE;
	}

	config_iface = nm_connection_get_interface_name (connection);
	device_iface = nm_device_get_iface (device);
	if (config_iface && g_strcmp0 (config_iface, device_iface) != 0) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		             _("The interface names of the device and the connection didn't match."));
		return FALSE;
	}

	return TRUE;
}

/**
 * nm_device_connection_compatible:
 * @device: an #NMDevice to validate @connection against
 * @connection: an #NMConnection to validate against @device
 * @error: return location for a #GError, or %NULL
 *
 * Validates a given connection for a given #NMDevice object and returns
 * whether the connection may be activated with the device. For example if
 * @device is a Wi-Fi device that supports only WEP encryption, the connection
 * will only be valid if it is a Wi-Fi connection which describes a WEP or open
 * network, and will not be valid if it describes a WPA network, or if it is
 * an Ethernet, Bluetooth, WWAN, etc connection that is incompatible with the
 * device.
 *
 * This function does the same as nm_device_connection_valid(), i.e. checking
 * compatibility of the given device and connection. But, in addition, it sets
 * GError when FALSE is returned.
 *
 * Returns: %TRUE if the connection may be activated with this device, %FALSE
 * if is incompatible with the device's capabilities and characteristics.
 **/
gboolean
nm_device_connection_compatible (NMDevice *device, NMConnection *connection, GError **error)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	return NM_DEVICE_GET_CLASS (device)->connection_compatible (device, connection, error);
}

/**
 * nm_device_filter_connections:
 * @device: an #NMDevice to filter connections for
 * @connections: (element-type NMConnection): an array of #NMConnections to filter
 *
 * Filters a given array of connections for a given #NMDevice object and returns
 * connections which may be activated with the device. For example if @device
 * is a Wi-Fi device that supports only WEP encryption, the returned array will
 * contain any Wi-Fi connections in @connections that allow connection to
 * unencrypted or WEP-enabled SSIDs.  The returned array will not contain
 * Ethernet, Bluetooth, Wi-Fi WPA connections, or any other connection that is
 * incompatible with the device. To get the full list of connections see
 * nm_client_get_connections().
 *
 * Returns: (transfer full) (element-type NMConnection): an array of
 * #NMConnections that could be activated with the given @device.  The array
 * should be freed with g_ptr_array_unref() when it is no longer required.
 **/
GPtrArray *
nm_device_filter_connections (NMDevice *device, const GPtrArray *connections)
{
	GPtrArray *filtered;
	int i;

	filtered = g_ptr_array_new_with_free_func (g_object_unref);
	for (i = 0; i < connections->len; i++) {
		NMConnection *candidate = connections->pdata[i];

		/* Connection applies to this device */
		if (nm_device_connection_valid (device, candidate))
			g_ptr_array_add (filtered, g_object_ref (candidate));
	}

	return filtered;
}

/**
 * nm_device_get_setting_type:
 * @device: an #NMDevice
 *
 * Gets the (primary) #NMSetting subtype associated with connections
 * that can be used on @device.
 *
 * Returns: @device's associated #NMSetting type
 */
GType
nm_device_get_setting_type (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), G_TYPE_INVALID);
	g_return_val_if_fail (NM_DEVICE_GET_CLASS (device)->get_setting_type != NULL, G_TYPE_INVALID);

	return NM_DEVICE_GET_CLASS (device)->get_setting_type (device);
}

/*****************************************************************************/

static gboolean
NM_IS_LLDP_NEIGHBOR (const NMLldpNeighbor *self)
{
	nm_assert (   !self
	           || (   self->refcount > 0
	               && self->attrs));
	return    self
	       && self->refcount > 0;
}

/**
 * nm_lldp_neighbor_new:
 *
 * Creates a new #NMLldpNeighbor object.
 *
 * Returns: (transfer full): the new #NMLldpNeighbor object.
 *
 * Since: 1.2
 **/
NMLldpNeighbor *
nm_lldp_neighbor_new (void)
{
	NMLldpNeighbor *neigh;

	neigh = g_new0 (NMLldpNeighbor, 1);
	neigh->refcount = 1;
	neigh->attrs = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free,
	                                      (GDestroyNotify) g_variant_unref);

	return neigh;
}

static NMLldpNeighbor *
nm_lldp_neighbor_dup (NMLldpNeighbor *neighbor)
{
	NMLldpNeighbor *copy;
	GHashTableIter iter;
	const char *key;
	GVariant *value;

	copy = nm_lldp_neighbor_new ();

	g_hash_table_iter_init (&iter, neighbor->attrs);
	while (g_hash_table_iter_next (&iter, (gpointer *) &key, (gpointer *) &value))
		g_hash_table_insert (copy->attrs, g_strdup (key), g_variant_ref (value));

	return copy;
}

/**
 * nm_lldp_neighbor_ref:
 * @neighbor: the #NMLldpNeighbor
 *
 * Increases the reference count of the object.
 *
 * Since: 1.2
 **/
void
nm_lldp_neighbor_ref (NMLldpNeighbor *neighbor)
{
	g_return_if_fail (NM_IS_LLDP_NEIGHBOR (neighbor));

	neighbor->refcount++;
}

/**
 * nm_lldp_neighbor_unref:
 * @neighbor: the #NMLldpNeighbor
 *
 * Decreases the reference count of the object.  If the reference count
 * reaches zero, the object will be destroyed.
 *
 * Since: 1.2
 **/
void
nm_lldp_neighbor_unref (NMLldpNeighbor *neighbor)
{
	g_return_if_fail (NM_IS_LLDP_NEIGHBOR (neighbor));

	if (--neighbor->refcount == 0) {
		g_hash_table_unref (neighbor->attrs);
		g_free (neighbor);
	}
}

/**
 * nm_lldp_neighbor_get_attr_names:
 * @neighbor: the #NMLldpNeighbor
 *
 * Gets an array of attribute names available for @neighbor.
 *
 * Returns: (transfer full): a %NULL-terminated array of attribute names.
 *
 * Since: 1.2
 **/
char **
nm_lldp_neighbor_get_attr_names (NMLldpNeighbor *neighbor)
{
	GHashTableIter iter;
	const char *key;
	GPtrArray *names;

	g_return_val_if_fail (NM_IS_LLDP_NEIGHBOR (neighbor), NULL);

	names = g_ptr_array_new ();

	g_hash_table_iter_init (&iter, neighbor->attrs);
	while (g_hash_table_iter_next (&iter, (gpointer *) &key, NULL))
		g_ptr_array_add (names, g_strdup (key));

	g_ptr_array_add (names, NULL);

	return (char **) g_ptr_array_free (names, FALSE);
}

/**
 * nm_lldp_neighbor_get_attr_string_value:
 * @neighbor: the #NMLldpNeighbor
 * @name: the attribute name
 * @out_value: (out) (allow-none) (transfer none): on return, the attribute value
 *
 * Gets the string value of attribute with name @name on @neighbor
 *
 * Returns: %TRUE if a string attribute with name @name was found, %FALSE otherwise
 *
 * Since: 1.2
 **/
gboolean
nm_lldp_neighbor_get_attr_string_value (NMLldpNeighbor *neighbor, const char *name,
                                        const char **out_value)
{
	GVariant *variant;

	g_return_val_if_fail (NM_IS_LLDP_NEIGHBOR (neighbor), FALSE);
	g_return_val_if_fail (name && name[0], FALSE);

	variant = g_hash_table_lookup (neighbor->attrs, name);
	if (variant && g_variant_is_of_type (variant, G_VARIANT_TYPE_STRING)) {
		if (out_value)
			*out_value = g_variant_get_string (variant, NULL);
		return TRUE;
	} else
		return FALSE;
}

/**
 * nm_lldp_neighbor_get_attr_uint_value:
 * @neighbor: the #NMLldpNeighbor
 * @name: the attribute name
 * @out_value: (out) (allow-none): on return, the attribute value
 *
 * Gets the uint value of attribute with name @name on @neighbor
 *
 * Returns: %TRUE if a uint attribute with name @name was found, %FALSE otherwise
 *
 * Since: 1.2
 **/
gboolean
nm_lldp_neighbor_get_attr_uint_value (NMLldpNeighbor *neighbor, const char *name,
                                      guint *out_value)
{
	GVariant *variant;

	g_return_val_if_fail (NM_IS_LLDP_NEIGHBOR (neighbor), FALSE);
	g_return_val_if_fail (name && name[0], FALSE);

	variant = g_hash_table_lookup (neighbor->attrs, name);
	if (variant && g_variant_is_of_type (variant, G_VARIANT_TYPE_UINT32)) {
		if (out_value)
			*out_value = g_variant_get_uint32 (variant);
		return TRUE;
	} else
		return FALSE;
}

/**
 * nm_lldp_neighbor_get_attr_value:
 * @neighbor: the #NMLldpNeighbor
 * @name: the attribute name
 *
 * Gets the value (as a GVariant) of attribute with name @name on @neighbor
 *
 * Returns: (transfer none): the value or %NULL if the attribute with @name was
 * not found.
 *
 * Since: 1.18
 **/
GVariant *
nm_lldp_neighbor_get_attr_value (NMLldpNeighbor *neighbor, const char *name)
{
	g_return_val_if_fail (NM_IS_LLDP_NEIGHBOR (neighbor), FALSE);
	g_return_val_if_fail (name && name[0], FALSE);

	return g_hash_table_lookup (neighbor->attrs, name);
}

/**
 * nm_lldp_neighbor_get_attr_type:
 * @neighbor: the #NMLldpNeighbor
 * @name: the attribute name
 *
 * Get the type of an attribute.
 *
 * Returns: the #GVariantType of the attribute with name @name
 *
 * Since: 1.2
 **/
const GVariantType *
nm_lldp_neighbor_get_attr_type (NMLldpNeighbor *neighbor, const char *name)
{
	GVariant *variant;

	g_return_val_if_fail (NM_IS_LLDP_NEIGHBOR (neighbor), NULL);
	g_return_val_if_fail (name && name[0], NULL);

	variant = g_hash_table_lookup (neighbor->attrs, name);
	if (variant)
		return g_variant_get_type (variant);
	else
		return NULL;
}
