/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#include <string.h>

#include <gudev/gudev.h>

#include "NetworkManager.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "nm-device-modem.h"
#include "nm-device-bt.h"
#include "nm-device-olpc-mesh.h"
#include "nm-device-wimax.h"
#include "nm-device-infiniband.h"
#include "nm-device-bond.h"
#include "nm-device-vlan.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-object-cache.h"
#include "nm-glib-marshal.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"

static GType _nm_device_type_for_path (DBusGConnection *connection,
                                       const char *path);
static void _nm_device_type_for_path_async (DBusGConnection *connection,
                                            const char *path,
                                            NMObjectTypeCallbackFunc callback,
                                            gpointer user_data);

G_DEFINE_TYPE_WITH_CODE (NMDevice, nm_device, NM_TYPE_OBJECT,
                         _nm_object_register_type_func (g_define_type_id, _nm_device_type_for_path,
                                                        _nm_device_type_for_path_async);
                         )

#define DBUS_G_TYPE_UINT_STRUCT (dbus_g_type_get_struct ("GValueArray", G_TYPE_UINT, G_TYPE_UINT, G_TYPE_INVALID))

#define NM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE, NMDevicePrivate))

typedef struct {
	DBusGProxy *proxy;

	char *iface;
	char *ip_iface;
	NMDeviceType device_type;
	char *udi;
	char *driver;
	NMDeviceCapabilities capabilities;
	gboolean managed;
	gboolean firmware_missing;
	NMIP4Config *ip4_config;
	NMDHCP4Config *dhcp4_config;
	NMIP6Config *ip6_config;
	NMDHCP6Config *dhcp6_config;
	NMDeviceState state;
	NMDeviceStateReason reason;

	NMActiveConnection *active_connection;

	GUdevClient *client;
	char *product;
	char *vendor;
} NMDevicePrivate;

enum {
	PROP_0,
	PROP_INTERFACE,
	PROP_UDI,
	PROP_DRIVER,
	PROP_CAPABILITIES,
	PROP_MANAGED,
	PROP_FIRMWARE_MISSING,
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

	LAST_PROP
};

enum {
	STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


static void
nm_device_init (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	priv->state = NM_DEVICE_STATE_UNKNOWN;
	priv->reason = NM_DEVICE_STATE_REASON_NONE;
}

static gboolean
demarshal_state_reason (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);

	if (!G_VALUE_HOLDS (value, DBUS_G_TYPE_UINT_STRUCT))
		return FALSE;

	dbus_g_type_struct_get (value,
	                        0, &priv->state,
	                        1, &priv->reason,
	                        G_MAXUINT);

	_nm_object_queue_notify (object, NM_DEVICE_STATE_REASON);
	return TRUE;
}

static void
register_properties (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	const NMPropertiesInfo property_info[] = {
		{ NM_DEVICE_UDI,               &priv->udi },
		{ NM_DEVICE_INTERFACE,         &priv->iface },
		{ NM_DEVICE_IP_INTERFACE,      &priv->ip_iface },
		{ NM_DEVICE_DRIVER,            &priv->driver },
		{ NM_DEVICE_CAPABILITIES,      &priv->capabilities },
		{ NM_DEVICE_MANAGED,           &priv->managed },
		{ NM_DEVICE_FIRMWARE_MISSING,  &priv->firmware_missing },
		{ NM_DEVICE_IP4_CONFIG,        &priv->ip4_config, NULL, NM_TYPE_IP4_CONFIG },
		{ NM_DEVICE_DHCP4_CONFIG,      &priv->dhcp4_config, NULL, NM_TYPE_DHCP4_CONFIG },
		{ NM_DEVICE_IP6_CONFIG,        &priv->ip6_config, NULL, NM_TYPE_IP6_CONFIG },
		{ NM_DEVICE_DHCP6_CONFIG,      &priv->dhcp6_config, NULL, NM_TYPE_DHCP6_CONFIG },
		{ NM_DEVICE_STATE,             &priv->state },
		{ NM_DEVICE_STATE_REASON,      &priv->state, demarshal_state_reason },
		{ NM_DEVICE_ACTIVE_CONNECTION, &priv->active_connection, NULL, NM_TYPE_ACTIVE_CONNECTION },

		/* Properties that exist in D-Bus but that we don't track */
		{ "ip4-address", NULL },
		{ "device-type", NULL },

		{ NULL },
	};

	_nm_object_register_properties (NM_OBJECT (device),
	                                priv->proxy,
	                                property_info);
}

static void
device_state_changed (DBusGProxy *proxy,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	if (old_state != new_state) {
		/* Update state here since the PropertyChanged signal for state
		 * might come in a bit later, but a client might ask for the
		 * state via nm_device_get_state() as a result of this signal.
		 * When the PC signal does come in that will trigger the glib
		 * property notify signal so we don't need to do that here.
		 */
		NM_DEVICE_GET_PRIVATE (self)->state = new_state;
		g_signal_emit (self, signals[STATE_CHANGED], 0, new_state, old_state, reason);
	}
}

static GType
_nm_device_gtype_from_dtype (NMDeviceType dtype)
{
	switch (dtype) {
	case NM_DEVICE_TYPE_ETHERNET:
		return NM_TYPE_DEVICE_ETHERNET;
	case NM_DEVICE_TYPE_WIFI:
		return NM_TYPE_DEVICE_WIFI;
	case NM_DEVICE_TYPE_MODEM:
		return NM_TYPE_DEVICE_MODEM;
	case NM_DEVICE_TYPE_BT:
		return NM_TYPE_DEVICE_BT;
	case NM_DEVICE_TYPE_OLPC_MESH:
		return NM_TYPE_DEVICE_OLPC_MESH;
	case NM_DEVICE_TYPE_WIMAX:
		return NM_TYPE_DEVICE_WIMAX;
	case NM_DEVICE_TYPE_INFINIBAND:
		return NM_TYPE_DEVICE_INFINIBAND;
	case NM_DEVICE_TYPE_BOND:
		return NM_TYPE_DEVICE_BOND;
	case NM_DEVICE_TYPE_VLAN:
		return NM_TYPE_DEVICE_VLAN;
	default:
		g_warning ("Unknown device type %d", dtype);
		return G_TYPE_INVALID;
	}
}

static void
constructed (GObject *object)
{
	NMDevicePrivate *priv;

	G_OBJECT_CLASS (nm_device_parent_class)->constructed (object);

	priv = NM_DEVICE_GET_PRIVATE (object);
	/* Catch failure of subclasses to call _nm_device_set_device_type() */
	g_warn_if_fail (priv->device_type != NM_DEVICE_TYPE_UNKNOWN);
	/* Catch a subclass setting the wrong type */
	g_warn_if_fail (G_OBJECT_TYPE (object) == _nm_device_gtype_from_dtype (priv->device_type));

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (NM_OBJECT (object)),
											 NM_DBUS_SERVICE,
											 nm_object_get_path (NM_OBJECT (object)),
											 NM_DBUS_INTERFACE_DEVICE);

	register_properties (NM_DEVICE (object));

	dbus_g_object_register_marshaller (_nm_glib_marshal_VOID__UINT_UINT_UINT,
									   G_TYPE_NONE,
									   G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT,
									   G_TYPE_INVALID);

	dbus_g_proxy_add_signal (priv->proxy,
	                         "StateChanged",
	                         G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT,
	                         G_TYPE_INVALID);

	dbus_g_proxy_connect_signal (priv->proxy, "StateChanged",
								 G_CALLBACK (device_state_changed),
								 NM_DEVICE (object),
								 NULL);
}

static void
dispose (GObject *object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);

	g_clear_object (&priv->proxy);
	g_clear_object (&priv->ip4_config);
	g_clear_object (&priv->dhcp4_config);
	g_clear_object (&priv->ip6_config);
	g_clear_object (&priv->dhcp6_config);
	g_clear_object (&priv->client);
	g_clear_object (&priv->active_connection);

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
	g_free (priv->product);
	g_free (priv->vendor);

	G_OBJECT_CLASS (nm_device_parent_class)->finalize (object);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMDevice *device = NM_DEVICE (object);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);

	_nm_object_ensure_inited (NM_OBJECT (object));

	switch (prop_id) {
	case PROP_DEVICE_TYPE:
		g_value_set_uint (value, nm_device_get_device_type (device));
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
	case PROP_CAPABILITIES:
		g_value_set_uint (value, nm_device_get_capabilities (device));
		break;
	case PROP_MANAGED:
		g_value_set_boolean (value, nm_device_get_managed (device));
		break;
	case PROP_FIRMWARE_MISSING:
		g_value_set_boolean (value, nm_device_get_firmware_missing (device));
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
		g_value_set_uint (value, nm_device_get_state (device));
		break;
	case PROP_STATE_REASON:
		g_value_set_boxed (value,
		                   dbus_g_type_specialized_construct (DBUS_G_TYPE_UINT_STRUCT));
		dbus_g_type_struct_set (value,
		                        0, priv->state,
		                        1, priv->reason,
		                        G_MAXUINT);
		break;
	case PROP_ACTIVE_CONNECTION:
		g_value_set_object (value, nm_device_get_active_connection (device));
		break;
	case PROP_PRODUCT:
		g_value_set_string (value, nm_device_get_product (device));
		break;
	case PROP_VENDOR:
		g_value_set_string (value, nm_device_get_vendor (device));
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

	switch (prop_id) {
	case PROP_DEVICE_TYPE:
		/* Construct only */
		priv->device_type = g_value_get_uint (value);
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

	g_type_class_add_private (device_class, sizeof (NMDevicePrivate));

	/* virtual methods */
	object_class->constructed = constructed;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */

	/**
	 * NMDevice:interface:
	 *
	 * The interface of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_INTERFACE,
		 g_param_spec_string (NM_DEVICE_INTERFACE,
						  "Interface",
						  "Interface name",
						  NULL,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:ip-interface:
	 *
	 * The IP interface of the device which should be used for all IP-related
	 * operations like addressing and routing.
	 **/
	g_object_class_install_property
		(object_class, PROP_IP_INTERFACE,
		 g_param_spec_string (NM_DEVICE_IP_INTERFACE,
						  "IP Interface",
						  "IP Interface name",
						  NULL,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:device-type:
	 *
	 * The numeric type of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_DEVICE_TYPE,
		 g_param_spec_uint (NM_DEVICE_DEVICE_TYPE,
						  "Device Type",
						  "Numeric device type (ie ethernet, wifi, etc)",
						  NM_DEVICE_TYPE_UNKNOWN, G_MAXUINT32, NM_DEVICE_TYPE_UNKNOWN,
						  G_PARAM_READABLE));
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
		 g_param_spec_string (NM_DEVICE_UDI,
						  "UDI",
						  "Unique Device Identifier",
						  NULL,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:driver:
	 *
	 * The driver of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_DRIVER,
		 g_param_spec_string (NM_DEVICE_DRIVER,
						  "Driver",
						  "Driver",
						  NULL,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:capabilities:
	 *
	 * The capabilities of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_CAPABILITIES,
						  "Capabilities",
						  "Capabilities",
						  0, G_MAXUINT32, 0,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:managed:
	 *
	 * Whether the device is managed by NetworkManager.
	 **/
	g_object_class_install_property
		(object_class, PROP_MANAGED,
		 g_param_spec_boolean (NM_DEVICE_MANAGED,
						  "Managed",
						  "Managed",
						  FALSE,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:firmware-missing:
	 *
	 * When %TRUE indicates the device is likely missing firmware required
	 * for its operation.
	 **/
	g_object_class_install_property
		(object_class, PROP_FIRMWARE_MISSING,
		 g_param_spec_boolean (NM_DEVICE_FIRMWARE_MISSING,
						  "FirmwareMissing",
						  "Firmware missing",
						  FALSE,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:ip4-config:
	 *
	 * The #NMIP4Config of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_IP4_CONFIG,
		 g_param_spec_object (NM_DEVICE_IP4_CONFIG,
						  "IP4 Config",
						  "IP4 Config",
						  NM_TYPE_IP4_CONFIG,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:dhcp4-config:
	 *
	 * The #NMDHCP4Config of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP4_CONFIG,
		 g_param_spec_object (NM_DEVICE_DHCP4_CONFIG,
						  "DHCP4 Config",
						  "DHCP4 Config",
						  NM_TYPE_DHCP4_CONFIG,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:ip6-config:
	 *
	 * The #NMIP6Config of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_IP6_CONFIG,
		 g_param_spec_object (NM_DEVICE_IP6_CONFIG,
		                      "IP6 Config",
		                      "IP6 Config",
		                      NM_TYPE_IP6_CONFIG,
		                      G_PARAM_READABLE));

	/**
	 * NMDevice:dhcp6-config:
	 *
	 * The #NMDHCP6Config of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_DHCP6_CONFIG,
		 g_param_spec_object (NM_DEVICE_DHCP6_CONFIG,
						  "DHCP6 Config",
						  "DHCP6 Config",
						  NM_TYPE_DHCP6_CONFIG,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:state:
	 *
	 * The state of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_DEVICE_STATE,
						  "State",
						  "State",
						  0, G_MAXUINT32, 0,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:state-reason:
	 *
	 * The state and reason of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_STATE_REASON,
		 g_param_spec_boxed (NM_DEVICE_STATE_REASON,
		                     "StateReason",
		                     "StateReason",
		                     DBUS_G_TYPE_UINT_STRUCT,
		                     G_PARAM_READABLE));

	/**
	 * NMDevice:active-connection:
	 *
	 * The #NMActiveConnection object that "owns" this device during activation.
	 **/
	g_object_class_install_property
		(object_class, PROP_ACTIVE_CONNECTION,
		 g_param_spec_object (NM_DEVICE_ACTIVE_CONNECTION,
		                      "ActiveConnection",
		                      "Active Connection",
		                      NM_TYPE_ACTIVE_CONNECTION,
		                      G_PARAM_READABLE));

	/**
	 * NMDevice:vendor:
	 *
	 * The vendor string of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_VENDOR,
		 g_param_spec_string (NM_DEVICE_VENDOR,
						  "Vendor",
						  "Vendor string",
						  NULL,
						  G_PARAM_READABLE));

	/**
	 * NMDevice:product:
	 *
	 * The product string of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_PRODUCT,
		 g_param_spec_string (NM_DEVICE_PRODUCT,
						  "Product",
						  "Product string",
						  NULL,
						  G_PARAM_READABLE));

	/* signals */

	/**
	 * NMDevice::state-changed:
	 * @device: the client that received the signal
	 * @state: the new state of the device
	 *
	 * Notifies the state change of a #NMDevice.
	 **/
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMDeviceClass, state_changed),
				    NULL, NULL,
				    _nm_glib_marshal_VOID__UINT_UINT_UINT,
				    G_TYPE_NONE, 3,
				    G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT);
}

/**
 * _nm_device_set_device_type:
 * @device: the device
 * @dtype: the NM device type
 *
 * Sets the NM device type if it wasn't set during construction.  INTERNAL
 * ONLY METHOD.
 **/
void
_nm_device_set_device_type (NMDevice *device, NMDeviceType dtype)
{
	NMDevicePrivate *priv;

	g_return_if_fail (device != NULL);
	g_return_if_fail (dtype != NM_DEVICE_TYPE_UNKNOWN);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (priv->device_type == NM_DEVICE_TYPE_UNKNOWN)
		priv->device_type = dtype;
	else
		g_warn_if_fail (dtype == priv->device_type);
}

static GType
_nm_device_type_for_path (DBusGConnection *connection,
                          const char *path)
{
	DBusGProxy *proxy;
	GError *err = NULL;
	GValue value = {0,};
	NMDeviceType nm_dtype;

	proxy = dbus_g_proxy_new_for_name (connection,
									   NM_DBUS_SERVICE,
									   path,
									   "org.freedesktop.DBus.Properties");
	if (!proxy) {
		g_warning ("%s: couldn't create D-Bus object proxy.", __func__);
		return G_TYPE_INVALID;
	}

	if (!dbus_g_proxy_call (proxy,
						    "Get", &err,
						    G_TYPE_STRING, NM_DBUS_INTERFACE_DEVICE,
						    G_TYPE_STRING, "DeviceType",
						    G_TYPE_INVALID,
						    G_TYPE_VALUE, &value, G_TYPE_INVALID)) {
		g_object_unref (proxy);
		g_warning ("Error in get_property: %s\n", err->message);
		g_error_free (err);
	}
	g_object_unref (proxy);

	nm_dtype = g_value_get_uint (&value);
	return _nm_device_gtype_from_dtype (nm_dtype);
}

/**
 * nm_device_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDevice.
 *
 * Returns: (transfer full): a new device
 **/
GObject *
nm_device_new (DBusGConnection *connection, const char *path)
{
	GType dtype;
	NMDevice *device = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	dtype = _nm_device_type_for_path (connection, path);
	if (dtype == G_TYPE_INVALID)
		return NULL;

	device = (NMDevice *) g_object_new (dtype,
	                                    NM_OBJECT_DBUS_CONNECTION, connection,
	                                    NM_OBJECT_DBUS_PATH, path,
	                                    NULL);
	_nm_object_ensure_inited (NM_OBJECT (device));
	return G_OBJECT (device);
}

typedef struct {
	DBusGConnection *connection;
	NMObjectTypeCallbackFunc callback;
	gpointer user_data;
} NMDeviceAsyncData;

static void
async_got_type (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	NMDeviceAsyncData *async_data = user_data;
	GValue value = G_VALUE_INIT;
	const char *path = dbus_g_proxy_get_path (proxy);
	GError *error = NULL;
	GType type;

	if (dbus_g_proxy_end_call (proxy, call, &error,
	                           G_TYPE_VALUE, &value,
	                           G_TYPE_INVALID)) {
		NMDeviceType dtype;

		dtype = g_value_get_uint (&value);
		type = _nm_device_gtype_from_dtype (dtype);
	} else {
		g_warning ("%s: could not read properties for %s: %s", __func__, path, error->message);
		g_error_free (error);
		type = G_TYPE_INVALID;
	}

	async_data->callback (type, async_data->user_data);
	g_object_unref (proxy);
	g_slice_free (NMDeviceAsyncData, async_data);
}

static void
_nm_device_type_for_path_async (DBusGConnection *connection,
                                const char *path,
                                NMObjectTypeCallbackFunc callback,
                                gpointer user_data)
{
	NMDeviceAsyncData *async_data;
	DBusGProxy *proxy;

	async_data = g_slice_new (NMDeviceAsyncData);
	async_data->connection = connection;
	async_data->callback = callback;
	async_data->user_data = user_data;

	proxy = dbus_g_proxy_new_for_name (connection, NM_DBUS_SERVICE, path,
	                                   "org.freedesktop.DBus.Properties");
	dbus_g_proxy_begin_call (proxy, "Get",
	                         async_got_type, async_data, NULL,
	                         G_TYPE_STRING, NM_DBUS_INTERFACE_DEVICE,
	                         G_TYPE_STRING, "DeviceType",
	                         G_TYPE_INVALID);
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->iface;
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->ip_iface;
}

/**
 * nm_device_get_device_type:
 * @device: a #NMDevice
 *
 * Returns the numeric type of the #NMDevice, ie ethernet, wifi, etc.
 *
 * Returns: the device type
 **/
NMDeviceType
nm_device_get_device_type (NMDevice *self)
{
	g_return_val_if_fail (NM_IS_DEVICE (self), NM_DEVICE_TYPE_UNKNOWN);

	return NM_DEVICE_GET_PRIVATE (self)->device_type;
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->udi;
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->driver;
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

	_nm_object_ensure_inited (NM_OBJECT (device));
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->managed;
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->firmware_missing;
}

/**
 * nm_device_get_ip4_config:
 * @device: a #NMDevice
 *
 * Gets the current #NMIP4Config associated with the #NMDevice.
 *
 * Returns: (transfer none): the #NMIP4Config or %NULL if the device is not activated.
 **/
NMIP4Config *
nm_device_get_ip4_config (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->ip4_config;
}

/**
 * nm_device_get_dhcp4_config:
 * @device: a #NMDevice
 *
 * Gets the current #NMDHCP4Config associated with the #NMDevice.
 *
 * Returns: (transfer none): the #NMDHCPConfig or %NULL if the device is not activated or not
 * using DHCP.
 **/
NMDHCP4Config *
nm_device_get_dhcp4_config (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->dhcp4_config;
}

/**
 * nm_device_get_ip6_config:
 * @device: a #NMDevice
 *
 * Gets the current #NMIP6Config associated with the #NMDevice.
 *
 * Returns: (transfer none): the #NMIP6Config or %NULL if the device is not activated.
 **/
NMIP6Config *
nm_device_get_ip6_config (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->ip6_config;
}

/**
 * nm_device_get_dhcp6_config:
 * @device: a #NMDevice
 *
 * Gets the current #NMDHCP6Config associated with the #NMDevice.
 *
 * Returns: (transfer none): the #NMDHCPConfig or %NULL if the device is not activated or not
 * using DHCP.
 **/
NMDHCP6Config *
nm_device_get_dhcp6_config (NMDevice *device)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->dhcp6_config;
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->state;
}

/**
 * nm_device_get_state_reason:
 * @device: a #NMDevice
 * @reason: (out) (allow-none): location to store reason (#NMDeviceStateReason), or NULL
 *
 * Gets the current #NMDevice state (return value) and the reason for entering
 * the state (@reason argument).
 *
 * Returns: the current device state
 **/
NMDeviceState
nm_device_get_state_reason (NMDevice *device, NMDeviceStateReason *reason)
{
	g_return_val_if_fail (NM_IS_DEVICE (device), NM_DEVICE_STATE_UNKNOWN);

	_nm_object_ensure_inited (NM_OBJECT (device));
	if (reason)
		*reason = NM_DEVICE_GET_PRIVATE (device)->reason;
	return NM_DEVICE_GET_PRIVATE (device)->state;
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

	_nm_object_ensure_inited (NM_OBJECT (device));
	return NM_DEVICE_GET_PRIVATE (device)->active_connection;
}

/* From hostap, Copyright (c) 2002-2005, Jouni Malinen <jkmaline@cc.hut.fi> */

static int hex2num (char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

static int hex2byte (const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0)
		return -1;
	b = hex2num(*hex++);
	if (b < 0)
		return -1;
	return (a << 4) | b;
}

/* End from hostap */

static char *
get_decoded_property (GUdevDevice *device, const char *property)
{
	const char *orig, *p;
	char *unescaped, *n;
	guint len;

	p = orig = g_udev_device_get_property (device, property);
	if (!orig)
		return NULL;

	len = strlen (orig);
	n = unescaped = g_malloc0 (len + 1);
	while (*p) {
		if ((len >= 4) && (*p == '\\') && (*(p+1) == 'x')) {
			*n++ = (char) hex2byte (p + 2);
			p += 4;
			len -= 4;
		} else {
			*n++ = *p++;
			len--;
		}
	}

	return unescaped;
}

static void
_device_update_description (NMDevice *device)
{
	NMDevicePrivate *priv;
	const char *subsys[3] = { "net", "tty", NULL };
	GUdevDevice *udev_device = NULL, *tmpdev, *olddev;
	const char *ifname;
	guint32 count = 0;
	const char *vendor, *model;

	g_return_if_fail (NM_IS_DEVICE (device));
	priv = NM_DEVICE_GET_PRIVATE (device);

	if (!priv->client) {
		priv->client = g_udev_client_new (subsys);
		if (!priv->client)
			return;
	}

	ifname = nm_device_get_iface (device);
	if (!ifname)
		return;

	udev_device = g_udev_client_query_by_subsystem_and_name (priv->client, "net", ifname);
	if (!udev_device)
		udev_device = g_udev_client_query_by_subsystem_and_name (priv->client, "tty", ifname);
	if (!udev_device)
		return;

	g_free (priv->product);
	priv->product = NULL;
	g_free (priv->vendor);
	priv->vendor = NULL;

	/* Walk up the chain of the device and its parents a few steps to grab
	 * vendor and device ID information off it.
	 */

	/* Ref the device again because we have to unref it each iteration,
	 * as g_udev_device_get_parent() returns a ref-ed object.
	 */
	tmpdev = g_object_ref (udev_device);
	while ((count++ < 3) && tmpdev && (!priv->vendor || !priv->product)) {
		if (!priv->vendor)
			priv->vendor = get_decoded_property (tmpdev, "ID_VENDOR_ENC");

		if (!priv->product)
			priv->product = get_decoded_property (tmpdev, "ID_MODEL_ENC");

		olddev = tmpdev;
		tmpdev = g_udev_device_get_parent (tmpdev);
		g_object_unref (olddev);
	}

	/* Unref the last device if we found what we needed before running out
	 * of parents.
	 */
	if (tmpdev)
		g_object_unref (tmpdev);

	/* If we didn't get strings directly from the device, try database strings */

	/* Again, ref the original device as we need to unref it every iteration
	 * since g_udev_device_get_parent() returns a refed object.
	 */
	tmpdev = g_object_ref (udev_device);
	count = 0;
	while ((count++ < 3) && tmpdev && (!priv->vendor || !priv->product)) {
		if (!priv->vendor) {
			vendor = g_udev_device_get_property (tmpdev, "ID_VENDOR_FROM_DATABASE");
			if (vendor)
				priv->vendor = g_strdup (vendor);
		}

		if (!priv->product) {
			model = g_udev_device_get_property (tmpdev, "ID_MODEL_FROM_DATABASE");
			if (model)
				priv->product = g_strdup (model);
		}

		olddev = tmpdev;
		tmpdev = g_udev_device_get_parent (tmpdev);
		g_object_unref (olddev);
	}

	/* Unref the last device if we found what we needed before running out
	 * of parents.
	 */
	if (tmpdev)
		g_object_unref (tmpdev);

	/* Balance the initial g_udev_client_query_by_subsystem_and_name() */
	g_object_unref (udev_device);

	_nm_object_queue_notify (NM_OBJECT (device), NM_DEVICE_VENDOR);
	_nm_object_queue_notify (NM_OBJECT (device), NM_DEVICE_PRODUCT);
}

/**
 * nm_device_get_product:
 * @device: a #NMDevice
 *
 * Gets the product string of the #NMDevice.
 *
 * Returns: the product name of the device. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_get_product (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->product)
		_device_update_description (device);
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
 **/
const char *
nm_device_get_vendor (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->vendor)
		_device_update_description (device);
	return priv->vendor;
}

typedef struct {
	NMDevice *device;
	NMDeviceDeactivateFn fn;
	gpointer user_data;
} DeactivateInfo;

static void
deactivate_cb (DBusGProxy *proxy,
               DBusGProxyCall *call,
               gpointer user_data)
{
	DeactivateInfo *info = user_data;
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call, &error,
	                       G_TYPE_INVALID);
	if (info->fn)
		info->fn (info->device, error, info->user_data);
	else if (error) {
		g_warning ("%s: device %s deactivation failed: (%d) %s",
		           __func__,
		           nm_object_get_path (NM_OBJECT (info->device)),
		           error ? error->code : -1,
		           error && error->message ? error->message : "(unknown)");
	}
	g_clear_error (&error);

	g_object_unref (info->device);
	g_slice_free (DeactivateInfo, info);
}

/**
 * nm_device_disconnect:
 * @device: a #NMDevice
 * @callback: (scope async) (allow-none): callback to be called when disconnect
 * operation completes
 * @user_data: (closure): caller-specific data passed to @callback
 *
 * Disconnects the device if currently connected, and prevents the device from
 * automatically connecting to networks until the next manual network connection
 * request.
 **/
void
nm_device_disconnect (NMDevice *device,
                      NMDeviceDeactivateFn callback,
                      gpointer user_data)
{
	DeactivateInfo *info;

	g_return_if_fail (NM_IS_DEVICE (device));

	info = g_slice_new (DeactivateInfo);
	info->fn = callback;
	info->user_data = user_data;
	info->device = g_object_ref (device);

	dbus_g_proxy_begin_call (NM_DEVICE_GET_PRIVATE (device)->proxy, "Disconnect",
	                         deactivate_cb, info, NULL,
	                         G_TYPE_INVALID);
}

/**
 * nm_device_connection_valid:
 * @device: an #NMDevice to validate @connection against
 * @connection: an #NMConnection to validate against @device
 *
 * Validates a given connection for a given #NMDevice object and returns
 * whether the connection may be activated with the device. For example if
 * @device is a WiFi device that supports only WEP encryption, the connection
 * will only be valid if it is a WiFi connection which describes a WEP or open
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

/**
 * nm_device_connection_compatible:
 * @device: an #NMDevice to validate @connection against
 * @connection: an #NMConnection to validate against @device
 * @error: return location for a #GError, or %NULL
 *
 * Validates a given connection for a given #NMDevice object and returns
 * whether the connection may be activated with the device. For example if
 * @device is a WiFi device that supports only WEP encryption, the connection
 * will only be valid if it is a WiFi connection which describes a WEP or open
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
	if (NM_DEVICE_GET_CLASS (device)->connection_compatible)
		return NM_DEVICE_GET_CLASS (device)->connection_compatible (device, connection, error);
	return FALSE;
}

/**
 * nm_device_filter_connections:
 * @device: an #NMDevice to filter connections for
 * @connections: (element-type NetworkManager.Connection): a list of #NMConnection objects to filter
 *
 * Filters a given list of connections for a given #NMDevice object and return
 * connections which may be activated with the device. For example if @device
 * is a WiFi device that supports only WEP encryption, the returned list will
 * contain any WiFi connections in @connections that allow connection to
 * unencrypted or WEP-enabled SSIDs.  The returned list will not contain
 * Ethernet, Bluetooth, WiFi WPA connections, or any other connection that is
 * incompatible with the device. To get the full list of connections see
 * nm_remote_settings_list_connections().
 *
 * Returns: (transfer container) (element-type NetworkManager.Connection): a
 * list of #NMConnection objects that could be activated with the given @device.
 * The elements of the list are owned by their creator and should not be freed
 * by the caller, but the returned list itself is owned by the caller and should
 * be freed with g_slist_free() when it is no longer required.
 **/
GSList *
nm_device_filter_connections (NMDevice *device, const GSList *connections)
{
	GSList *filtered = NULL;
	const GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *candidate = NM_CONNECTION (iter->data);

		/* Connection applies to this device */
		if (nm_device_connection_valid (device, candidate))
			filtered = g_slist_prepend (filtered, candidate);
	}

	return g_slist_reverse (filtered);
}

