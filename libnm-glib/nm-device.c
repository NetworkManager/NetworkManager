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
 * Copyright (C) 2007 - 2010 Red Hat, Inc.
 */

#include <string.h>

#define G_UDEV_API_IS_SUBJECT_TO_CHANGE
#include <gudev/gudev.h>

#include "NetworkManager.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "nm-gsm-device.h"
#include "nm-cdma-device.h"
#include "nm-device-bt.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-object-cache.h"
#include "nm-marshal.h"

#include "nm-device-bindings.h"

G_DEFINE_TYPE (NMDevice, nm_device, NM_TYPE_OBJECT)

#define NM_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE, NMDevicePrivate))

typedef struct {
	gboolean disposed;
	DBusGProxy *proxy;

	char *iface;
	char *ip_iface;
	char *udi;
	char *driver;
	guint32 capabilities;
	gboolean managed;
	gboolean firmware_missing;
	NMIP4Config *ip4_config;
	gboolean null_ip4_config;
	NMDHCP4Config *dhcp4_config;
	gboolean null_dhcp4_config;
	NMIP6Config *ip6_config;
	gboolean null_ip6_config;
	NMDHCP6Config *dhcp6_config;
	gboolean null_dhcp6_config;
	NMDeviceState state;

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
	PROP_PRODUCT,
	PROP_VENDOR,
	PROP_DHCP6_CONFIG,
	PROP_IP_INTERFACE,

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
}

static gboolean
demarshal_ip4_config (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);
	const char *path;
	NMIP4Config *config = NULL;
	DBusGConnection *connection;

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_OBJECT_PATH))
		return FALSE;

	priv->null_ip4_config = FALSE;

	path = g_value_get_boxed (value);
	if (path) {
		if (!strcmp (path, "/"))
			priv->null_ip4_config = TRUE;
		else {
			config = NM_IP4_CONFIG (_nm_object_cache_get (path));
			if (config)
				config = g_object_ref (config);
			else {
				connection = nm_object_get_connection (object);
				config = NM_IP4_CONFIG (nm_ip4_config_new (connection, path));
			}
		}
	}

	if (priv->ip4_config) {
		g_object_unref (priv->ip4_config);
		priv->ip4_config = NULL;
	}

	if (config)
		priv->ip4_config = config;

	_nm_object_queue_notify (object, NM_DEVICE_IP4_CONFIG);
	return TRUE;
}

static gboolean
demarshal_dhcp4_config (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);
	const char *path;
	NMDHCP4Config *config = NULL;
	DBusGConnection *connection;

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_OBJECT_PATH))
		return FALSE;

	priv->null_dhcp4_config = FALSE;

	path = g_value_get_boxed (value);
	if (path) {
		if (!strcmp (path, "/"))
			priv->null_dhcp4_config = TRUE;
		else {
			config = NM_DHCP4_CONFIG (_nm_object_cache_get (path));
			if (config)
				config = g_object_ref (config);
			else {
				connection = nm_object_get_connection (object);
				config = NM_DHCP4_CONFIG (nm_dhcp4_config_new (connection, path));
			}
		}
	}

	if (priv->dhcp4_config) {
		g_object_unref (priv->dhcp4_config);
		priv->dhcp4_config = NULL;
	}

	if (config)
		priv->dhcp4_config = config;

	_nm_object_queue_notify (object, NM_DEVICE_DHCP4_CONFIG);
	return TRUE;
}

static gboolean
demarshal_ip6_config (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);
	const char *path;
	NMIP6Config *config = NULL;
	DBusGConnection *connection;

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_OBJECT_PATH))
		return FALSE;

	priv->null_ip6_config = FALSE;

	path = g_value_get_boxed (value);
	if (path) {
		if (!strcmp (path, "/"))
			priv->null_ip6_config = TRUE;
		else {
			config = NM_IP6_CONFIG (_nm_object_cache_get (path));
			if (config)
				config = g_object_ref (config);
			else {
				connection = nm_object_get_connection (object);
				config = NM_IP6_CONFIG (nm_ip6_config_new (connection, path));
			}
		}
	}

	if (priv->ip6_config) {
		g_object_unref (priv->ip6_config);
		priv->ip6_config = NULL;
	}

	if (config)
		priv->ip6_config = config;

	_nm_object_queue_notify (object, NM_DEVICE_IP6_CONFIG);
	return TRUE;
}

static gboolean
demarshal_dhcp6_config (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);
	const char *path;
	NMDHCP6Config *config = NULL;
	DBusGConnection *connection;

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_OBJECT_PATH))
		return FALSE;

	priv->null_dhcp6_config = FALSE;

	path = g_value_get_boxed (value);
	if (path) {
		if (!strcmp (path, "/"))
			priv->null_dhcp6_config = TRUE;
		else {
			config = NM_DHCP6_CONFIG (_nm_object_cache_get (path));
			if (config)
				config = g_object_ref (config);
			else {
				connection = nm_object_get_connection (object);
				config = NM_DHCP6_CONFIG (nm_dhcp6_config_new (connection, path));
			}
		}
	}

	if (priv->dhcp6_config) {
		g_object_unref (priv->dhcp6_config);
		priv->dhcp6_config = NULL;
	}

	if (config)
		priv->dhcp6_config = config;

	_nm_object_queue_notify (object, NM_DEVICE_DHCP6_CONFIG);
	return TRUE;
}

static void
register_for_property_changed (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_DEVICE_UDI,              _nm_object_demarshal_generic, &priv->udi },
		{ NM_DEVICE_INTERFACE,        _nm_object_demarshal_generic, &priv->iface },
		{ NM_DEVICE_IP_INTERFACE,     _nm_object_demarshal_generic, &priv->ip_iface },
		{ NM_DEVICE_DRIVER,           _nm_object_demarshal_generic, &priv->driver },
		{ NM_DEVICE_CAPABILITIES,     _nm_object_demarshal_generic, &priv->capabilities },
		{ NM_DEVICE_MANAGED,          _nm_object_demarshal_generic, &priv->managed },
		{ NM_DEVICE_FIRMWARE_MISSING, _nm_object_demarshal_generic, &priv->firmware_missing },
		{ NM_DEVICE_IP4_CONFIG,       demarshal_ip4_config,         &priv->ip4_config },
		{ NM_DEVICE_DHCP4_CONFIG,     demarshal_dhcp4_config,       &priv->dhcp4_config },
		{ NM_DEVICE_IP6_CONFIG,       demarshal_ip6_config,         &priv->ip6_config },
		{ NM_DEVICE_DHCP6_CONFIG,     demarshal_dhcp6_config,       &priv->dhcp6_config },
		{ NULL },
	};

	_nm_object_handle_properties_changed (NM_OBJECT (device),
	                                     priv->proxy,
	                                     property_changed_info);
}

static void
device_state_changed (DBusGProxy *proxy,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (self);

	if (priv->state != new_state) {
		priv->state = new_state;
		g_signal_emit (self, signals[STATE_CHANGED], 0, new_state, old_state, reason);
		_nm_object_queue_notify (NM_OBJECT (self), "state");
	}
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	NMObject *object;
	NMDevicePrivate *priv;

	object = (NMObject *) G_OBJECT_CLASS (nm_device_parent_class)->constructor (type,
																				n_construct_params,
																				construct_params);
	if (!object)
		return NULL;

	priv = NM_DEVICE_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (object),
											 NM_DBUS_SERVICE,
											 nm_object_get_path (object),
											 NM_DBUS_INTERFACE_DEVICE);

	register_for_property_changed (NM_DEVICE (object));

	dbus_g_object_register_marshaller (_nm_marshal_VOID__UINT_UINT_UINT,
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

	return G_OBJECT (object);
}

static void
dispose (GObject *object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	g_object_unref (priv->proxy);
	if (priv->ip4_config)
		g_object_unref (priv->ip4_config);
	if (priv->dhcp4_config)
		g_object_unref (priv->dhcp4_config);
	if (priv->ip6_config)
		g_object_unref (priv->ip6_config);
	if (priv->dhcp6_config)
		g_object_unref (priv->dhcp6_config);
	if (priv->client)
		g_object_unref (priv->client);

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

	switch (prop_id) {
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
nm_device_class_init (NMDeviceClass *device_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (device_class);

	g_type_class_add_private (device_class, sizeof (NMDevicePrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
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
	 * NMDevice:udi:
	 *
	 * The Unique Device Identifier of the device.
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
				    _nm_marshal_VOID__UINT_UINT_UINT,
				    G_TYPE_NONE, 3,
				    G_TYPE_UINT, G_TYPE_UINT, G_TYPE_UINT);
}

/**
 * nm_device_new:
 * @connection: the #DBusGConnection
 * @path: the DBus object path of the device
 *
 * Creates a new #NMDevice.
 *
 * Returns: a new device
 **/
GObject *
nm_device_new (DBusGConnection *connection, const char *path)
{
	DBusGProxy *proxy;
	GError *err = NULL;
	GValue value = {0,};
	GType dtype = 0;
	NMDevice *device = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	proxy = dbus_g_proxy_new_for_name (connection,
									   NM_DBUS_SERVICE,
									   path,
									   "org.freedesktop.DBus.Properties");
	if (!proxy) {
		g_warning ("%s: couldn't create D-Bus object proxy.", __func__);
		return NULL;
	}

	if (!dbus_g_proxy_call (proxy,
						    "Get", &err,
						    G_TYPE_STRING, NM_DBUS_INTERFACE_DEVICE,
						    G_TYPE_STRING, "DeviceType",
						    G_TYPE_INVALID,
						    G_TYPE_VALUE, &value, G_TYPE_INVALID)) {
		g_warning ("Error in get_property: %s\n", err->message);
		g_error_free (err);
		goto out;
	}

	switch (g_value_get_uint (&value)) {
	case NM_DEVICE_TYPE_ETHERNET:
		dtype = NM_TYPE_DEVICE_ETHERNET;
		break;
	case NM_DEVICE_TYPE_WIFI:
		dtype = NM_TYPE_DEVICE_WIFI;
		break;
	case NM_DEVICE_TYPE_GSM:
		dtype = NM_TYPE_GSM_DEVICE;
		break;
	case NM_DEVICE_TYPE_CDMA:
		dtype = NM_TYPE_CDMA_DEVICE;
		break;
	case NM_DEVICE_TYPE_BT:
		dtype = NM_TYPE_DEVICE_BT;
		break;
	default:
		g_warning ("Unknown device type %d", g_value_get_uint (&value));
		break;
	}

	if (dtype) {
		device = (NMDevice *) g_object_new (dtype,
											NM_OBJECT_DBUS_CONNECTION, connection,
											NM_OBJECT_DBUS_PATH, path,
											NULL);
	}

out:
	g_object_unref (proxy);
	return G_OBJECT (device);
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
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->iface) {
		priv->iface = _nm_object_get_string_property (NM_OBJECT (device),
		                                             NM_DBUS_INTERFACE_DEVICE,
		                                             "Interface");
	}

	return priv->iface;
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
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->ip_iface) {
		priv->ip_iface = _nm_object_get_string_property (NM_OBJECT (device),
		                                                 NM_DBUS_INTERFACE_DEVICE,
		                                                 "IpInterface");
	}

	return priv->ip_iface;
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
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->udi) {
		priv->udi = _nm_object_get_string_property (NM_OBJECT (device),
		                                           NM_DBUS_INTERFACE_DEVICE,
		                                           "Udi");
	}

	return priv->udi;
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
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->driver) {
		priv->driver = _nm_object_get_string_property (NM_OBJECT (device),
		                                              NM_DBUS_INTERFACE_DEVICE,
		                                              "Driver");
	}

	return priv->driver;
}

/**
 * nm_device_get_capabilities:
 * @device: a #NMDevice
 *
 * Gets the device' capabilities.
 *
 * Returns: the capabilities
 **/
guint32
nm_device_get_capabilities (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->capabilities) {
		priv->capabilities = _nm_object_get_uint_property (NM_OBJECT (device),
		                                                  NM_DBUS_INTERFACE_DEVICE,
		                                                  "Capabilities");
	}

	return priv->capabilities;
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
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->managed) {
		priv->managed = _nm_object_get_boolean_property (NM_OBJECT (device),
		                                                NM_DBUS_INTERFACE_DEVICE,
		                                                "Managed");
	}

	return priv->managed;
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
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), 0);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->firmware_missing) {
		priv->firmware_missing = _nm_object_get_boolean_property (NM_OBJECT (device),
		                                                          NM_DBUS_INTERFACE_DEVICE,
		                                                          "FirmwareMissing");
	}

	return priv->firmware_missing;
}

/**
 * nm_device_get_ip4_config:
 * @device: a #NMDevice
 *
 * Gets the current #NMIP4Config associated with the #NMDevice.
 *
 * Returns: the #NMIP4Config or %NULL if the device is not activated.
 **/
NMIP4Config *
nm_device_get_ip4_config (NMDevice *device)
{
	NMDevicePrivate *priv;
	char *path;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (priv->ip4_config)
		return priv->ip4_config;
	if (priv->null_ip4_config)
		return NULL;

	path = _nm_object_get_object_path_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Ip4Config");
	if (path) {
		g_value_init (&value, DBUS_TYPE_G_OBJECT_PATH);
		g_value_take_boxed (&value, path);
		demarshal_ip4_config (NM_OBJECT (device), NULL, &value, &priv->ip4_config);
		g_value_unset (&value);
	}

	return priv->ip4_config;
}

/**
 * nm_device_get_dhcp4_config:
 * @device: a #NMDevice
 *
 * Gets the current #NMDHCP4Config associated with the #NMDevice.
 *
 * Returns: the #NMDHCPConfig or %NULL if the device is not activated or not
 * using DHCP.
 **/
NMDHCP4Config *
nm_device_get_dhcp4_config (NMDevice *device)
{
	NMDevicePrivate *priv;
	char *path;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (priv->dhcp4_config)
		return priv->dhcp4_config;
	if (priv->null_dhcp4_config)
		return NULL;

	path = _nm_object_get_object_path_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Dhcp4Config");
	if (path) {
		g_value_init (&value, DBUS_TYPE_G_OBJECT_PATH);
		g_value_take_boxed (&value, path);
		demarshal_dhcp4_config (NM_OBJECT (device), NULL, &value, &priv->dhcp4_config);
		g_value_unset (&value);
	}

	return priv->dhcp4_config;
}

/**
 * nm_device_get_ip6_config:
 * @device: a #NMDevice
 *
 * Gets the current #NMIP6Config associated with the #NMDevice.
 *
 * Returns: the #NMIP6Config or %NULL if the device is not activated.
 **/
NMIP6Config *
nm_device_get_ip6_config (NMDevice *device)
{
	NMDevicePrivate *priv;
	char *path;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (priv->ip6_config)
		return priv->ip6_config;
	if (priv->null_ip6_config)
		return NULL;

	path = _nm_object_get_object_path_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Ip6Config");
	if (path) {
		g_value_init (&value, DBUS_TYPE_G_OBJECT_PATH);
		g_value_take_boxed (&value, path);
		demarshal_ip6_config (NM_OBJECT (device), NULL, &value, &priv->ip6_config);
		g_value_unset (&value);
	}

	return priv->ip6_config;
}

/**
 * nm_device_get_dhcp6_config:
 * @device: a #NMDevice
 *
 * Gets the current #NMDHCP6Config associated with the #NMDevice.
 *
 * Returns: the #NMDHCPConfig or %NULL if the device is not activated or not
 * using DHCP.
 **/
NMDHCP6Config *
nm_device_get_dhcp6_config (NMDevice *device)
{
	NMDevicePrivate *priv;
	char *path;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (priv->dhcp6_config)
		return priv->dhcp6_config;
	if (priv->null_dhcp6_config)
		return NULL;

	path = _nm_object_get_object_path_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Dhcp6Config");
	if (path) {
		g_value_init (&value, DBUS_TYPE_G_OBJECT_PATH);
		g_value_take_boxed (&value, path);
		demarshal_dhcp6_config (NM_OBJECT (device), NULL, &value, &priv->dhcp6_config);
		g_value_unset (&value);
	}

	return priv->dhcp6_config;
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
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NM_DEVICE_STATE_UNKNOWN);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (priv->state == NM_DEVICE_STATE_UNKNOWN) {
		priv->state = _nm_object_get_uint_property (NM_OBJECT (device), 
		                                           NM_DBUS_INTERFACE_DEVICE,
		                                           "State");
	}

	return priv->state;
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
nm_device_update_description (NMDevice *device)
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

	/* Ref the device again becuase we have to unref it each iteration,
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
		nm_device_update_description (device);
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
		nm_device_update_description (device);
	return priv->vendor;
}

typedef struct {
	NMDevice *device;
	NMDeviceDeactivateFn fn;
	gpointer user_data;
} DeactivateInfo;

static void
deactivate_cb (DBusGProxy *proxy,
               GError *error,
               gpointer user_data)
{
	DeactivateInfo *info = user_data;

	if (info->fn)
		info->fn (info->device, error, info->user_data);
	else if (error) {
		g_warning ("%s: device %s deactivation failed: (%d) %s",
		           __func__,
		           nm_object_get_path (NM_OBJECT (info->device)),
		           error ? error->code : -1,
		           error && error->message ? error->message : "(unknown)");
	}

	g_object_unref (info->device);
	g_slice_free (DeactivateInfo, info);
}

/**
 * nm_device_disconnect:
 * @device: a #NMDevice
 * @callback: callback to be called when disconnect operation completes
 * @user_data: caller-specific data passed to @callback
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

	org_freedesktop_NetworkManager_Device_disconnect_async (NM_DEVICE_GET_PRIVATE (device)->proxy,
	                                                        deactivate_cb,
	                                                        info);
}

