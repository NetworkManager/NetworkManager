#include <string.h>

#include "NetworkManager.h"
#include "nm-device-ethernet.h"
#include "nm-device-wifi.h"
#include "nm-gsm-device.h"
#include "nm-cdma-device.h"
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
	char *udi;
	char *driver;
	guint32 capabilities;
	gboolean managed;
	NMIP4Config *ip4_config;
	gboolean null_ip4_config;
	NMDHCP4Config *dhcp4_config;
	gboolean null_dhcp4_config;
	NMDeviceState state;
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
	PROP_IP4_CONFIG,
	PROP_DHCP4_CONFIG,
	PROP_STATE,
	PROP_PRODUCT,
	PROP_VENDOR,

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
	priv->disposed = FALSE;
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
			config = NM_IP4_CONFIG (nm_object_cache_get (path));
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

	nm_object_queue_notify (object, NM_DEVICE_IP4_CONFIG);
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
			config = NM_DHCP4_CONFIG (nm_object_cache_get (path));
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

	nm_object_queue_notify (object, NM_DEVICE_DHCP4_CONFIG);
	return TRUE;
}

static void
register_for_property_changed (NMDevice *device)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (device);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_DEVICE_UDI,          nm_object_demarshal_generic, &priv->udi },
		{ NM_DEVICE_INTERFACE,    nm_object_demarshal_generic, &priv->iface },
		{ NM_DEVICE_DRIVER,       nm_object_demarshal_generic, &priv->driver },
		{ NM_DEVICE_CAPABILITIES, nm_object_demarshal_generic, &priv->capabilities },
		{ NM_DEVICE_MANAGED,      nm_object_demarshal_generic, &priv->managed },
		{ NM_DEVICE_IP4_CONFIG,   demarshal_ip4_config,        &priv->ip4_config },
		{ NM_DEVICE_DHCP4_CONFIG, demarshal_dhcp4_config,      &priv->dhcp4_config },
		{ NULL },
	};

	nm_object_handle_properties_changed (NM_OBJECT (device),
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
		nm_object_queue_notify (NM_OBJECT (self), "state");
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

	dbus_g_object_register_marshaller (nm_marshal_VOID__UINT_UINT_UINT,
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

	G_OBJECT_CLASS (nm_device_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDevicePrivate *priv = NM_DEVICE_GET_PRIVATE (object);

	g_free (priv->iface);
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
	case PROP_DRIVER:
		g_value_set_string (value, nm_device_get_driver (device));
		break;
	case PROP_CAPABILITIES:
		g_value_set_uint (value, nm_device_get_capabilities (device));
		break;
	case PROP_MANAGED:
		g_value_set_boolean (value, nm_device_get_managed (device));
		break;
	case PROP_IP4_CONFIG:
		g_value_set_object (value, nm_device_get_ip4_config (device));
		break;
	case PROP_DHCP4_CONFIG:
		g_value_set_object (value, nm_device_get_dhcp4_config (device));
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
	 * The HAL UDI of the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_UDI,
		 g_param_spec_string (NM_DEVICE_UDI,
						  "UDI",
						  "HAL UDI",
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
				    nm_marshal_VOID__UINT_UINT_UINT,
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
		priv->iface = nm_object_get_string_property (NM_OBJECT (device),
		                                             NM_DBUS_INTERFACE_DEVICE,
		                                             "Interface");
	}

	return priv->iface;
}

/**
 * nm_device_get_udi:
 * @device: a #NMDevice
 *
 * Gets the HAL UDI of the #NMDevice.
 *
 * Returns: the HAL UDI of the device. This is the internal string used by the
 * device, and must not be modified.
 **/
const char *
nm_device_get_udi (NMDevice *device)
{
	NMDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);

	priv = NM_DEVICE_GET_PRIVATE (device);
	if (!priv->udi) {
		priv->udi = nm_object_get_string_property (NM_OBJECT (device),
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
		priv->driver = nm_object_get_string_property (NM_OBJECT (device),
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
		priv->capabilities = nm_object_get_uint_property (NM_OBJECT (device),
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
		priv->managed = nm_object_get_boolean_property (NM_OBJECT (device),
		                                                NM_DBUS_INTERFACE_DEVICE,
		                                                "Managed");
	}

	return priv->managed;
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

	path = nm_object_get_object_path_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Ip4Config");
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

	path = nm_object_get_object_path_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Dhcp4Config");
	if (path) {
		g_value_init (&value, DBUS_TYPE_G_OBJECT_PATH);
		g_value_take_boxed (&value, path);
		demarshal_dhcp4_config (NM_OBJECT (device), NULL, &value, &priv->dhcp4_config);
		g_value_unset (&value);
	}

	return priv->dhcp4_config;
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
		priv->state = nm_object_get_uint_property (NM_OBJECT (device), 
		                                           NM_DBUS_INTERFACE_DEVICE,
		                                           "State");
	}

	return priv->state;
}

static char *
get_ancestor_device (NMDevice *device,
                     DBusGConnection *connection,
                     const char *udi,
                     gboolean want_origdev)
{
	DBusGProxy *proxy;
	GError *err = NULL;
	char *parent = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (udi != NULL, NULL);

	proxy = dbus_g_proxy_new_for_name (connection, "org.freedesktop.Hal", udi, "org.freedesktop.Hal.Device");
	if (!proxy)
		return NULL;

	if (want_origdev) {
		gboolean serial = FALSE;

		if (NM_IS_GSM_DEVICE (device) || NM_IS_CDMA_DEVICE (device))
			serial = TRUE;

		dbus_g_proxy_call (proxy, "GetPropertyString", NULL,
		                   G_TYPE_STRING, serial ? "serial.originating_device" : "net.originating_device",
		                   G_TYPE_INVALID,
		                   G_TYPE_STRING, &parent,
		                   G_TYPE_INVALID);

		if (!parent) {
			/* Older HAL uses 'physical_device' */
			dbus_g_proxy_call (proxy, "GetPropertyString", &err,
			                   G_TYPE_STRING, serial ? "serial.physical_device" : "net.physical_device",
			                   G_TYPE_INVALID,
			                   G_TYPE_STRING, &parent,
			                   G_TYPE_INVALID);
		}

		if (err || !parent) {
			g_warning ("Error getting originating device info from HAL: %s",
			           err ? err->message : "unknown error");
			if (err)
				g_error_free (err);
		}
	} else {
		if (!dbus_g_proxy_call (proxy, "GetPropertyString", &err,
								G_TYPE_STRING, "info.parent",
								G_TYPE_INVALID,
								G_TYPE_STRING, &parent,
								G_TYPE_INVALID)) {
			g_warning ("Error getting parent device info from HAL: %s", err->message);
			g_error_free (err);
	    }
	}

	g_object_unref (proxy);
	return parent;
}

static char *
proxy_get_string (DBusGProxy *proxy,
                  const char *property,
                  gboolean warn)
{
	GError *error = NULL;
	char *result = NULL;

	g_return_val_if_fail (proxy != NULL, NULL);
	g_return_val_if_fail (property != NULL, NULL);

	if (dbus_g_proxy_call (proxy, "GetPropertyString", &error,
	                       G_TYPE_STRING, property, G_TYPE_INVALID,
	                       G_TYPE_STRING, &result, G_TYPE_INVALID))
		return result;

	if (warn) {
		g_warning ("Error getting HAL property '%s' from device '%s': %s",
		           property, dbus_g_proxy_get_path (proxy),
		           error ? error->message : "unknown");
	}
	g_error_free (error);
	return NULL;
}

static gboolean
get_product_and_vendor (DBusGConnection *connection,
                        const char *udi,
                        char **product,
                        char **vendor)
{
	DBusGProxy *proxy;
	char *tmp_product = NULL;
	char *tmp_vendor = NULL;
	char *subsys = NULL;
	gboolean product_fallback = TRUE, vendor_fallback = TRUE;
	gboolean warn = FALSE;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (udi != NULL, FALSE);

	g_return_val_if_fail (product != NULL, FALSE);
	g_return_val_if_fail (*product == NULL, FALSE);

	g_return_val_if_fail (vendor != NULL, FALSE);
	g_return_val_if_fail (*vendor == NULL, FALSE);

	proxy = dbus_g_proxy_new_for_name (connection, "org.freedesktop.Hal", udi, "org.freedesktop.Hal.Device");
	if (!proxy)
		return FALSE;

	subsys = proxy_get_string (proxy, "info.subsystem", warn);
	if (subsys && !strcmp (subsys, "pci")) {
		tmp_product = proxy_get_string (proxy, "pci.subsys_product", warn);
		if (tmp_product)
			product_fallback = FALSE;

		tmp_vendor = proxy_get_string (proxy, "pci.subsys_vendor", warn);
		if (tmp_vendor)
			vendor_fallback = FALSE;
	}
	g_free (subsys);

	if (product_fallback)
		tmp_product = proxy_get_string (proxy, "info.product", warn);
	if (vendor_fallback)
		tmp_vendor = proxy_get_string (proxy, "info.vendor", warn);

	if (tmp_product && tmp_vendor) {
		*product = tmp_product;
		*vendor = tmp_vendor;
	} else {
		g_free (tmp_product);
		g_free (tmp_vendor);
	}
	g_object_unref (proxy);

	return (*product && *vendor) ? TRUE : FALSE;
}

static void
nm_device_update_description (NMDevice *device)
{
	NMDevicePrivate *priv;
	DBusGConnection *connection;
	const char *udi;
	char *orig_dev_udi = NULL;
	char *parent_udi = NULL;

	g_return_if_fail (NM_IS_DEVICE (device));
	priv = NM_DEVICE_GET_PRIVATE (device);

	g_free (priv->product);
	priv->product = NULL;
	g_free (priv->vendor);
	priv->vendor = NULL;

	connection = nm_object_get_connection (NM_OBJECT (device));
	g_return_if_fail (connection != NULL);

	/* First, get the udi of the originating device */
	udi = nm_device_get_udi (device);
	orig_dev_udi = get_ancestor_device (device, connection, udi, TRUE);

	/* Get product and vendor off the originating device if possible */
	if (!get_product_and_vendor (connection, orig_dev_udi, &priv->product, &priv->vendor)) {
		 /* Try the parent of the originating device */
		parent_udi = get_ancestor_device (device, connection, orig_dev_udi, FALSE);
		if (parent_udi)
			get_product_and_vendor (connection, parent_udi, &priv->product, &priv->vendor);
		g_free (parent_udi);
	}

	g_free (orig_dev_udi);

	nm_object_queue_notify (NM_OBJECT (device), NM_DEVICE_VENDOR);
	nm_object_queue_notify (NM_OBJECT (device), NM_DEVICE_PRODUCT);
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

