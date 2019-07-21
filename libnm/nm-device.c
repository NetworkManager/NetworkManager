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
 * Copyright 2007 - 2008 Novell, Inc.
 * Copyright 2007 - 2018 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-device.h"

#include <libudev.h>

#include "nm-libnm-utils.h"
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

#include "introspection/org.freedesktop.NetworkManager.Device.h"

static gboolean connection_compatible (NMDevice *device, NMConnection *connection, GError **error);
static NMLldpNeighbor *nm_lldp_neighbor_dup (NMLldpNeighbor *neighbor);

G_DEFINE_ABSTRACT_TYPE (NMDevice, nm_device, NM_TYPE_OBJECT);

#define NM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE, NMDevicePrivate))

typedef struct {
	NMDBusDevice *proxy;

	char *iface;
	char *ip_iface;
	NMDeviceType device_type;
	char *udi;
	char *driver;
	char *driver_version;
	char *firmware_version;
	char *type_description;
	NMMetered metered;
	NMDeviceCapabilities capabilities;
	gboolean real;
	gboolean managed;
	gboolean firmware_missing;
	gboolean nm_plugin_missing;
	gboolean autoconnect;
	NMIPConfig *ip4_config;
	NMDhcpConfig *dhcp4_config;
	NMIPConfig *ip6_config;
	NMDhcpConfig *dhcp6_config;
	NMConnectivityState ip4_connectivity;
	NMConnectivityState ip6_connectivity;
	NMDeviceState state;
	NMDeviceState last_seen_state;
	NMDeviceStateReason reason;

	NMActiveConnection *active_connection;
	GPtrArray *available_connections;

	struct udev *udev;
	char *product;
	char *vendor, *short_vendor;
	char *description, *bus_name;

	char *physical_port_id;
	guint32 mtu;
	GPtrArray *lldp_neighbors;
} NMDevicePrivate;

enum {
	PROP_0,
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

	LAST_PROP
};

enum {
	STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct _NMLldpNeighbor {
	guint refcount;
	GHashTable *attrs;
};

G_DEFINE_BOXED_TYPE (NMLldpNeighbor, nm_lldp_neighbor, nm_lldp_neighbor_dup, nm_lldp_neighbor_unref)

static void
nm_device_init (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	priv->ip4_connectivity = NM_CONNECTIVITY_UNKNOWN;
	priv->ip6_connectivity = NM_CONNECTIVITY_UNKNOWN;
	priv->state = NM_DEVICE_STATE_UNKNOWN;
	priv->reason = NM_DEVICE_STATE_REASON_NONE;
	priv->lldp_neighbors = g_ptr_array_new ();
}

static gboolean
demarshal_state_reason (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field)
{
	guint32 *reason_field = field;

	g_variant_get (value, "(uu)", NULL, reason_field);
	_nm_object_queue_notify (object, NM_DEVICE_STATE_REASON);
	return TRUE;
}

static gboolean
demarshal_lldp_neighbors (NMObject *object, GParamSpec *pspec, GVariant *value, gpointer field)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);
	GVariantIter iter, attrs_iter;
	GVariant *variant, *attr_variant;
	const char *attr_name;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), FALSE);

	g_ptr_array_unref (priv->lldp_neighbors);
	priv->lldp_neighbors = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_lldp_neighbor_unref);
	g_variant_iter_init (&iter, value);

	while (g_variant_iter_next (&iter, "@a{sv}", &variant)) {
		NMLldpNeighbor *neigh;

		neigh = nm_lldp_neighbor_new ();
		g_variant_iter_init (&attrs_iter, variant);

		while (g_variant_iter_next (&attrs_iter, "{&sv}", &attr_name, &attr_variant))
			g_hash_table_insert (neigh->attrs, g_strdup (attr_name), attr_variant);

		g_variant_unref (variant);
		g_ptr_array_add (priv->lldp_neighbors, neigh);
	}

	_nm_object_queue_notify (object, NM_DEVICE_LLDP_NEIGHBORS);

	return TRUE;
}

static void
device_state_reason_changed (GObject *object, GParamSpec *pspec, gpointer user_data);

static void
init_dbus (NMObject *object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_UDI,               &priv->udi },
		{ NM_DEVICE_INTERFACE,         &priv->iface },
		{ NM_DEVICE_DEVICE_TYPE,       &priv->device_type },
		{ NM_DEVICE_IP_INTERFACE,      &priv->ip_iface },
		{ NM_DEVICE_DRIVER,            &priv->driver },
		{ NM_DEVICE_DRIVER_VERSION,    &priv->driver_version },
		{ NM_DEVICE_FIRMWARE_VERSION,  &priv->firmware_version },
		{ NM_DEVICE_CAPABILITIES,      &priv->capabilities },
		{ NM_DEVICE_REAL,              &priv->real },
		{ NM_DEVICE_MANAGED,           &priv->managed },
		{ NM_DEVICE_AUTOCONNECT,       &priv->autoconnect },
		{ NM_DEVICE_FIRMWARE_MISSING,  &priv->firmware_missing },
		{ NM_DEVICE_NM_PLUGIN_MISSING, &priv->nm_plugin_missing },
		{ NM_DEVICE_IP4_CONFIG,        &priv->ip4_config, NULL, NM_TYPE_IP4_CONFIG },
		{ NM_DEVICE_DHCP4_CONFIG,      &priv->dhcp4_config, NULL, NM_TYPE_DHCP4_CONFIG },
		{ NM_DEVICE_IP6_CONFIG,        &priv->ip6_config, NULL, NM_TYPE_IP6_CONFIG },
		{ NM_DEVICE_DHCP6_CONFIG,      &priv->dhcp6_config, NULL, NM_TYPE_DHCP6_CONFIG },
		{ NM_DEVICE_IP4_CONNECTIVITY,  &priv->ip4_connectivity },
		{ NM_DEVICE_IP6_CONNECTIVITY,  &priv->ip6_connectivity },
		{ NM_DEVICE_STATE,             &priv->state },
		{ NM_DEVICE_STATE_REASON,      &priv->reason, demarshal_state_reason },
		{ NM_DEVICE_ACTIVE_CONNECTION, &priv->active_connection, NULL, NM_TYPE_ACTIVE_CONNECTION },
		{ NM_DEVICE_AVAILABLE_CONNECTIONS, &priv->available_connections, NULL, NM_TYPE_REMOTE_CONNECTION },
		{ NM_DEVICE_PHYSICAL_PORT_ID,  &priv->physical_port_id },
		{ NM_DEVICE_MTU,               &priv->mtu },
		{ NM_DEVICE_METERED,           &priv->metered },
		{ NM_DEVICE_LLDP_NEIGHBORS,    &priv->lldp_neighbors, demarshal_lldp_neighbors },

		/* Properties that exist in D-Bus but that we don't track */
		{ "ip4-address", NULL },

		{ NULL },
	};

	NM_OBJECT_CLASS (nm_device_parent_class)->init_dbus (object);

	priv->proxy = NMDBUS_DEVICE (_nm_object_get_proxy (object, NM_DBUS_INTERFACE_DEVICE));
	_nm_object_register_properties (object,
	                                NM_DBUS_INTERFACE_DEVICE,
	                                property_info);

	g_signal_connect (priv->proxy, "notify::state-reason",
	                  G_CALLBACK (device_state_reason_changed), object);
}

static void
device_state_reason_changed (GObject *object, GParamSpec *pspec, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	g_signal_emit (self, signals[STATE_CHANGED], 0,
	               priv->state, priv->last_seen_state, priv->reason);
	priv->last_seen_state = priv->state;
}

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

static void
dispose (GObject *object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);

	g_clear_object (&priv->ip4_config);
	g_clear_object (&priv->dhcp4_config);
	g_clear_object (&priv->ip6_config);
	g_clear_object (&priv->dhcp6_config);
	g_clear_object (&priv->active_connection);

	udev_unref (priv->udev);
	priv->udev = NULL;

	g_clear_pointer (&priv->available_connections, g_ptr_array_unref);
	g_clear_pointer (&priv->lldp_neighbors, g_ptr_array_unref);

	if (priv->proxy)
		g_signal_handlers_disconnect_by_func (priv->proxy, device_state_reason_changed, object);
	g_clear_object (&priv->proxy);

	G_OBJECT_CLASS (nm_device_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);

	g_free (priv->iface);
	g_free (priv->ip_iface);
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
	case PROP_MANAGED:
		b = g_value_get_boolean (value);
		if (priv->managed != b)
			nm_device_set_managed (NM_DEVICE (object), b);
		break;
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

static void
nm_device_class_init (NMDeviceClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);
	NMObjectClass *nm_object_class = NM_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMDevicePrivate));

	/* virtual methods */
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	nm_object_class->init_dbus = init_dbus;

	device_class->connection_compatible = connection_compatible;

	/* properties */

	/**
	 * NMDevice:interface:
	 *
	 * The interface of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_INTERFACE,
		 g_param_spec_string (NM_DEVICE_INTERFACE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:ip-interface:
	 *
	 * The IP interface of the device which should be used for all IP-related
	 * operations like addressing and routing.
	 **/
	g_object_class_install_property
		(object_class, PROP_IP_INTERFACE,
		 g_param_spec_string (NM_DEVICE_IP_INTERFACE, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:device-type:
	 *
	 * The numeric type of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_DEVICE_TYPE,
		 g_param_spec_enum (NM_DEVICE_DEVICE_TYPE, "", "",
		                    NM_TYPE_DEVICE_TYPE,
		                    NM_DEVICE_TYPE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));
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
	g_object_class_install_property
		(object_class, PROP_UDI,
		 g_param_spec_string (NM_DEVICE_UDI, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:driver:
	 *
	 * The driver of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_DRIVER,
		 g_param_spec_string (NM_DEVICE_DRIVER, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:driver-version:
	 *
	 * The version of the device driver.
	 **/
	g_object_class_install_property
		(object_class, PROP_DRIVER_VERSION,
		 g_param_spec_string (NM_DEVICE_DRIVER_VERSION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:firmware-version:
	 *
	 * The firmware version of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_FIRMWARE_VERSION,
		 g_param_spec_string (NM_DEVICE_FIRMWARE_VERSION, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:capabilities:
	 *
	 * The capabilities of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_flags (NM_DEVICE_CAPABILITIES, "", "",
		                     NM_TYPE_DEVICE_CAPABILITIES,
		                     NM_DEVICE_CAP_NONE,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:real:
	 *
	 * Whether the device is real or is a placeholder device that could
	 * be created automatically by NetworkManager if one of its
	 * #NMDevice:available-connections was activated.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_REAL,
		 g_param_spec_boolean (NM_DEVICE_REAL, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:managed:
	 *
	 * Whether the device is managed by NetworkManager.
	 **/
	g_object_class_install_property
		(object_class, PROP_MANAGED,
		 g_param_spec_boolean (NM_DEVICE_MANAGED, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:autoconnect:
	 *
	 * Whether the device can auto-activate a connection.
	 **/
	g_object_class_install_property
		(object_class, PROP_AUTOCONNECT,
		 g_param_spec_boolean (NM_DEVICE_AUTOCONNECT, "", "",
		                       TRUE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:firmware-missing:
	 *
	 * When %TRUE indicates the device is likely missing firmware required
	 * for its operation.
	 **/
	g_object_class_install_property
		(object_class, PROP_FIRMWARE_MISSING,
		 g_param_spec_boolean (NM_DEVICE_FIRMWARE_MISSING, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:nm-plugin-missing:
	 *
	 * When %TRUE indicates that the NetworkManager plugin for the device
	 * is not installed.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_NM_PLUGIN_MISSING,
		 g_param_spec_boolean (NM_DEVICE_NM_PLUGIN_MISSING, "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:ip4-config:
	 *
	 * The #NMIP4Config of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_IP4_CONFIG,
		 g_param_spec_object (NM_DEVICE_IP4_CONFIG, "", "",
		                      NM_TYPE_IP_CONFIG,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:dhcp4-config:
	 *
	 * The IPv4 #NMDhcpConfig of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP4_CONFIG,
		 g_param_spec_object (NM_DEVICE_DHCP4_CONFIG, "", "",
		                      NM_TYPE_DHCP_CONFIG,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:ip6-config:
	 *
	 * The IPv6 #NMIPConfig of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_IP6_CONFIG,
		 g_param_spec_object (NM_DEVICE_IP6_CONFIG, "", "",
		                      NM_TYPE_IP_CONFIG,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:dhcp6-config:
	 *
	 * The IPv6 #NMDhcpConfig of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP6_CONFIG,
		 g_param_spec_object (NM_DEVICE_DHCP6_CONFIG, "", "",
		                      NM_TYPE_DHCP_CONFIG,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:ip4-connectivity:
	 *
	 * The IPv4 connectivity state of the device.
	 *
	 * Since: 1.16
	 **/
	g_object_class_install_property
		(object_class, PROP_IP4_CONNECTIVITY,
		 g_param_spec_enum (NM_DEVICE_IP4_CONNECTIVITY, "", "",
		                    NM_TYPE_CONNECTIVITY_STATE,
		                    NM_CONNECTIVITY_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:ip6-connectivity:
	 *
	 * The IPv6 connectivity state of the device.
	 *
	 * Since: 1.16
	 **/
	g_object_class_install_property
		(object_class, PROP_IP6_CONNECTIVITY,
		 g_param_spec_enum (NM_DEVICE_IP6_CONNECTIVITY, "", "",
		                    NM_TYPE_CONNECTIVITY_STATE,
		                    NM_CONNECTIVITY_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:state:
	 *
	 * The state of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_enum (NM_DEVICE_STATE, "", "",
		                    NM_TYPE_DEVICE_STATE,
		                    NM_DEVICE_STATE_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:state-reason:
	 *
	 * The reason for the device state.
	 **/
	g_object_class_install_property
		(object_class, PROP_STATE_REASON,
		 g_param_spec_uint (NM_DEVICE_STATE_REASON, "", "",
		                    0, G_MAXUINT32, 0,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:active-connection:
	 *
	 * The #NMActiveConnection object that "owns" this device during activation.
	 **/
	g_object_class_install_property
		(object_class, PROP_ACTIVE_CONNECTION,
		 g_param_spec_object (NM_DEVICE_ACTIVE_CONNECTION, "", "",
		                      NM_TYPE_ACTIVE_CONNECTION,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:available-connections: (type GPtrArray(NMRemoteConnection))
	 *
	 * The available connections of the device
	 **/
	g_object_class_install_property
		(object_class, PROP_AVAILABLE_CONNECTIONS,
		 g_param_spec_boxed (NM_DEVICE_AVAILABLE_CONNECTIONS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READABLE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:vendor:
	 *
	 * The vendor string of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_VENDOR,
		 g_param_spec_string (NM_DEVICE_VENDOR, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:product:
	 *
	 * The product string of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_PRODUCT,
		 g_param_spec_string (NM_DEVICE_PRODUCT, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:physical-port-id:
	 *
	 * The physical port ID of the device. (See
	 * nm_device_get_physical_port_id().)
	 **/
	g_object_class_install_property
		(object_class, PROP_PHYSICAL_PORT_ID,
		 g_param_spec_string (NM_DEVICE_PHYSICAL_PORT_ID, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:mtu:
	 *
	 * The MTU of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_MTU,
		 g_param_spec_uint (NM_DEVICE_MTU, "", "",
		                    0, G_MAXUINT32, 1500,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:metered:
	 *
	 * Whether the device is metered.
	 *
	 * Since: 1.2
	 **/
	g_object_class_install_property
		(object_class, PROP_METERED,
		 g_param_spec_uint (NM_DEVICE_METERED, "", "",
		                    0, G_MAXUINT32, NM_METERED_UNKNOWN,
		                    G_PARAM_READABLE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMDevice:lldp-neighbors:
	 *
	 * The LLDP neighbors.
	 **/
	g_object_class_install_property
	    (object_class, PROP_LLDP_NEIGHBORS,
	     g_param_spec_boxed (NM_DEVICE_LLDP_NEIGHBORS, "", "",
	                         G_TYPE_PTR_ARRAY,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS));

	/* signals */

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
		              G_STRUCT_OFFSET (NMDeviceClass, state_changed),
		              NULL, NULL, NULL,
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

	return nm_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->iface);
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

	return nm_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->ip_iface);
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

	return nm_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->udi);
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

	return nm_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->driver);
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

	return nm_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->driver_version);
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

	return nm_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->firmware_version);
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
		return nm_str_not_empty (priv->type_description);

	if (NM_DEVICE_GET_CLASS (device)->get_type_description) {
		desc = NM_DEVICE_GET_CLASS (device)->get_type_description (device);
		if (desc)
			return desc;
	}

	typename = G_OBJECT_TYPE_NAME (device);
	if (g_str_has_prefix (typename, "NMDevice"))
		typename += 8;
	priv->type_description = g_ascii_strdown (typename, -1);

	return nm_str_not_empty (priv->type_description);
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
 **/
void
nm_device_set_managed (NMDevice *device, gboolean managed)
{
	g_return_if_fail (NM_IS_DEVICE (device));

	managed = !!managed;

	NM_DEVICE_GET_PRIVATE (device)->managed = managed;

	_nm_object_set_property (NM_OBJECT (device),
	                         NM_DBUS_INTERFACE_DEVICE,
	                         "Managed",
	                         "b", managed);
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
 **/
void
nm_device_set_autoconnect (NMDevice *device, gboolean autoconnect)
{
	g_return_if_fail (NM_IS_DEVICE (device));

	NM_DEVICE_GET_PRIVATE (device)->autoconnect = autoconnect;

	_nm_object_set_property (NM_OBJECT (device),
	                         NM_DBUS_INTERFACE_DEVICE,
	                         "Autoconnect",
	                         "b", autoconnect);
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

	return NM_DEVICE_GET_PRIVATE (device)->ip4_config;
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

	return NM_DEVICE_GET_PRIVATE (device)->dhcp4_config;
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

	return NM_DEVICE_GET_PRIVATE (device)->ip6_config;
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

	return NM_DEVICE_GET_PRIVATE (device)->dhcp6_config;
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

	return NM_DEVICE_GET_PRIVATE (device)->reason;
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
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	return NM_DEVICE_GET_PRIVATE (device)->active_connection;
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

	return NM_DEVICE_GET_PRIVATE (device)->available_connections;
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
	const char *ifname, *bus;

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

void
_nm_device_set_udev (NMDevice *device, struct udev *udev)
{
	NMDevicePrivate *priv;

	nm_assert (NM_IS_DEVICE (device));
	nm_assert (udev);

	priv = NM_DEVICE_GET_PRIVATE (device);

	nm_assert (!priv->udev);

	priv->udev = udev_ref (udev);
}

static char *
_get_udev_property (NMDevice *device,
                    const char *enc_prop,  /* ID_XXX_ENC */
                    const char *db_prop)   /* ID_XXX_FROM_DATABASE */
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	struct udev_device *udev_device, *tmpdev;
	const char *ifname;
	guint32 count = 0;
	char *enc_value = NULL, *db_value = NULL;

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

	return nm_str_not_empty (NM_DEVICE_GET_PRIVATE (device)->physical_port_id);
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
       g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

       return NM_DEVICE_GET_PRIVATE (device)->lldp_neighbors;
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
 **/
gboolean
nm_device_reapply (NMDevice *device,
                   NMConnection *connection,
                   guint64 version_id,
                   guint32 flags,
                   GCancellable *cancellable,
                   GError **error)
{
	GVariant *dict = NULL;
	gboolean ret;

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	if (connection)
		dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
	if (!dict)
		dict = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);

	ret = nmdbus_device_call_reapply_sync (NM_DEVICE_GET_PRIVATE (device)->proxy,
	                                       dict, version_id, flags, cancellable, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

static void
device_reapply_cb (GObject *proxy,
                   GAsyncResult *result,
                   gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nmdbus_device_call_reapply_finish (NMDBUS_DEVICE (proxy), result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
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
	GVariant *dict = NULL;
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_DEVICE (device));

	if (connection)
		dict = nm_connection_to_dbus (connection, NM_CONNECTION_SERIALIZE_ALL);
	if (!dict)
		dict = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);

	simple = g_simple_async_result_new (G_OBJECT (device), callback, user_data,
	                                    nm_device_reapply_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nmdbus_device_call_reapply (NM_DEVICE_GET_PRIVATE (device)->proxy,
	                            dict, version_id, flags, cancellable,
	                            device_reapply_cb, simple);
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
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (device), nm_device_reapply_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
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
 **/
NMConnection *
nm_device_get_applied_connection (NMDevice *device,
                                  guint32 flags,
                                  guint64 *version_id,
                                  GCancellable *cancellable,
                                  GError **error)
{
	gs_unref_variant GVariant *dict = NULL;
	guint64 my_version_id;
	gboolean success;
	NMConnection *connection;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	success = nmdbus_device_call_get_applied_connection_sync (NM_DEVICE_GET_PRIVATE (device)->proxy,
	                                                          flags, &dict, &my_version_id, cancellable, error);
	if (!success) {
		if (error && *error)
			g_dbus_error_strip_remote_error (*error);
		return NULL;
	}

	connection = _nm_simple_connection_new_from_dbus (dict, NM_SETTING_PARSE_FLAGS_BEST_EFFORT, error);
	if (!connection)
		return NULL;

	NM_SET_OUT (version_id, my_version_id);
	return connection;
}

typedef struct {
	NMConnection *connection;
	guint64 version_id;
} GetAppliedConnectionData;

static void
device_get_applied_connection_data_free (gpointer user_data)
{
	GetAppliedConnectionData *data = user_data;

	g_return_if_fail (data);

	g_object_unref (data->connection);
	g_slice_free (GetAppliedConnectionData, data);
}

static void
device_get_applied_connection_cb (GObject *proxy,
                                  GAsyncResult *result,
                                  gpointer user_data)
{
	gs_unref_object GSimpleAsyncResult *simple = user_data;
	gs_unref_variant GVariant *dict = NULL;
	guint64 my_version_id;
	GError *error = NULL;
	NMConnection *connection;
	GetAppliedConnectionData *data;

	if (!nmdbus_device_call_get_applied_connection_finish (NMDBUS_DEVICE (proxy), &dict, &my_version_id, result, &error)) {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
		goto out;
	}

	connection = _nm_simple_connection_new_from_dbus (dict, NM_SETTING_PARSE_FLAGS_BEST_EFFORT, &error);
	if (!connection) {
		g_simple_async_result_take_error (simple, error);
		goto out;
	}

	data = g_slice_new (GetAppliedConnectionData);
	data->connection = connection;
	data->version_id = my_version_id;
	g_simple_async_result_set_op_res_gpointer (simple, data, device_get_applied_connection_data_free);

out:
	g_simple_async_result_complete (simple);
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
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_DEVICE (device));
	g_return_if_fail (!cancellable || G_IS_CANCELLABLE (cancellable));

	simple = g_simple_async_result_new (G_OBJECT (device), callback, user_data,
	                                    nm_device_get_applied_connection_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nmdbus_device_call_get_applied_connection (NM_DEVICE_GET_PRIVATE (device)->proxy,
	                                           flags, cancellable,
	                                           device_get_applied_connection_cb, simple);
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
	GSimpleAsyncResult *simple;
	GetAppliedConnectionData *data;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (device), nm_device_get_applied_connection_async), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return NULL;

	data = g_simple_async_result_get_op_res_gpointer (simple);
	g_return_val_if_fail (data, NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (data->connection), NULL);

	NM_SET_OUT (version_id, data->version_id);
	return g_object_ref (data->connection);
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
 **/
gboolean
nm_device_disconnect (NMDevice *device,
                      GCancellable *cancellable,
                      GError **error)
{
	gboolean ret;

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	ret = nmdbus_device_call_disconnect_sync (NM_DEVICE_GET_PRIVATE (device)->proxy,
	                                          cancellable, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

static void
device_disconnect_cb (GObject *proxy,
                      GAsyncResult *result,
                      gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nmdbus_device_call_disconnect_finish (NMDBUS_DEVICE (proxy), result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
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
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_DEVICE (device));

	simple = g_simple_async_result_new (G_OBJECT (device), callback, user_data,
	                                    nm_device_disconnect_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nmdbus_device_call_disconnect (NM_DEVICE_GET_PRIVATE (device)->proxy,
	                               cancellable,
	                               device_disconnect_cb, simple);
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
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (device), nm_device_disconnect_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
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
 **/
gboolean
nm_device_delete (NMDevice *device,
                  GCancellable *cancellable,
                  GError **error)
{
	gboolean ret;

	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

	ret = nmdbus_device_call_delete_sync (NM_DEVICE_GET_PRIVATE (device)->proxy,
	                                      cancellable, error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);
	return ret;
}

static void
device_delete_cb (GObject *proxy,
                  GAsyncResult *result,
                  gpointer user_data)
{
	GSimpleAsyncResult *simple = user_data;
	GError *error = NULL;

	if (nmdbus_device_call_delete_finish (NMDBUS_DEVICE (proxy), result, &error))
		g_simple_async_result_set_op_res_gboolean (simple, TRUE);
	else {
		g_dbus_error_strip_remote_error (error);
		g_simple_async_result_take_error (simple, error);
	}

	g_simple_async_result_complete (simple);
	g_object_unref (simple);
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
	GSimpleAsyncResult *simple;

	g_return_if_fail (NM_IS_DEVICE (device));

	simple = g_simple_async_result_new (G_OBJECT (device), callback, user_data,
	                                    nm_device_delete_async);
	if (cancellable)
		g_simple_async_result_set_check_cancellable (simple, cancellable);

	nmdbus_device_call_delete (NM_DEVICE_GET_PRIVATE (device)->proxy,
	                           cancellable,
	                           device_delete_cb, simple);
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
	GSimpleAsyncResult *simple;

	g_return_val_if_fail (g_simple_async_result_is_valid (result, G_OBJECT (device), nm_device_delete_async), FALSE);

	simple = G_SIMPLE_ASYNC_RESULT (result);
	if (g_simple_async_result_propagate_error (simple, error))
		return FALSE;
	else
		return g_simple_async_result_get_op_res_gboolean (simple);
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
