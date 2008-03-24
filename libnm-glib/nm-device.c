#include <string.h>

#include "NetworkManager.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "nm-gsm-device.h"
#include "nm-cdma-device.h"
#include "nm-device.h"
#include "nm-device-private.h"
#include "nm-object-private.h"
#include "nm-object-cache.h"

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
	NMIP4Config *ip4_config;
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
	PROP_IP4_CONFIG,
	PROP_STATE,
	PROP_PRODUCT,
	PROP_VENDOR,

	LAST_PROP
};


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

	path = g_value_get_boxed (value);
	if (strcmp (path, "/")) {
		config = NM_IP4_CONFIG (nm_object_cache_get (path));
		if (config)
			config = g_object_ref (config);
		else {
			connection = nm_object_get_connection (object);
			config = NM_IP4_CONFIG (nm_ip4_config_new (connection, path));
		}
	}

	if (priv->ip4_config) {
		g_object_unref (priv->ip4_config);
		priv->ip4_config = NULL;
	}

	if (config)
		priv->ip4_config = config;

	g_object_notify (G_OBJECT (object), NM_DEVICE_IP4_CONFIG);
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
		{ NM_DEVICE_IP4_CONFIG,   demarshal_ip4_config,        &priv->ip4_config },
		{ NM_DEVICE_STATE,        nm_object_demarshal_generic, &priv->state },
		{ NULL },
	};

	nm_object_handle_properties_changed (NM_OBJECT (device),
	                                     priv->proxy,
	                                     property_changed_info);
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
	case PROP_IP4_CONFIG:
		g_value_set_object (value, nm_device_get_ip4_config (device));
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
	g_object_class_install_property
		(object_class, PROP_INTERFACE,
		 g_param_spec_string (NM_DEVICE_INTERFACE,
						  "Interface",
						  "Interface name",
						  NULL,
						  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_UDI,
		 g_param_spec_string (NM_DEVICE_UDI,
						  "UDI",
						  "HAL UDI",
						  NULL,
						  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_DRIVER,
		 g_param_spec_string (NM_DEVICE_DRIVER,
						  "Driver",
						  "Driver",
						  NULL,
						  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_CAPABILITIES,
						  "Capabilities",
						  "Capabilities",
						  0, G_MAXUINT32, 0,
						  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_IP4_CONFIG,
		 g_param_spec_object (NM_DEVICE_IP4_CONFIG,
						  "IP4 Config",
						  "IP4 Config",
						  NM_TYPE_IP4_CONFIG,
						  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_DEVICE_STATE,
						  "State",
						  "State",
						  0, G_MAXUINT32, 0,
						  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_VENDOR,
		 g_param_spec_string (NM_DEVICE_VENDOR,
						  "Vendor",
						  "Vendor string",
						  NULL,
						  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_PRODUCT,
		 g_param_spec_string (NM_DEVICE_PRODUCT,
						  "Product",
						  "Product string",
						  NULL,
						  G_PARAM_READABLE));
}

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
	case DEVICE_TYPE_802_3_ETHERNET:
		dtype = NM_TYPE_DEVICE_802_3_ETHERNET;
		break;
	case DEVICE_TYPE_802_11_WIRELESS:
		dtype = NM_TYPE_DEVICE_802_11_WIRELESS;
		break;
	case DEVICE_TYPE_GSM:
		dtype = NM_TYPE_GSM_DEVICE;
		break;
	case DEVICE_TYPE_CDMA:
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

	path = nm_object_get_object_path_property (NM_OBJECT (device), NM_DBUS_INTERFACE_DEVICE, "Ip4Config");

	g_value_init (&value, DBUS_TYPE_G_OBJECT_PATH);
	g_value_take_boxed (&value, path);
	demarshal_ip4_config (NM_OBJECT (device), NULL, &value, &priv->ip4_config);
	g_value_unset (&value);
	return priv->ip4_config;
}

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
get_product_and_vendor (DBusGConnection *connection,
                        const char *udi,
                        gboolean want_origdev,
                        gboolean warn,
                        char **product,
                        char **vendor)
{
	DBusGProxy *proxy;
	GError *err = NULL;
	char *parent = NULL;
	char *tmp_product = NULL;
	char *tmp_vendor = NULL;

	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (udi != NULL, NULL);

	proxy = dbus_g_proxy_new_for_name (connection, "org.freedesktop.Hal", udi, "org.freedesktop.Hal.Device");
	if (!proxy)
		return NULL;

	if (!dbus_g_proxy_call (proxy, "GetPropertyString", &err,
							G_TYPE_STRING, "info.product",
							G_TYPE_INVALID,
							G_TYPE_STRING, &tmp_product,
							G_TYPE_INVALID)) {
		if (warn)
			g_warning ("Error getting device %s product from HAL: %s", udi, err->message);
		g_error_free (err);
		err = NULL;
    }

	if (!dbus_g_proxy_call (proxy, "GetPropertyString", &err,
							G_TYPE_STRING, "info.vendor",
							G_TYPE_INVALID,
							G_TYPE_STRING, &tmp_vendor,
							G_TYPE_INVALID)) {
		if (warn)
			g_warning ("Error getting device %s vendor from HAL: %s", udi, err->message);
		g_error_free (err);
		err = NULL;
    }

	if (want_origdev) {
		dbus_g_proxy_call (proxy, "GetPropertyString", NULL,
		                   G_TYPE_STRING, "net.originating_device",
		                   G_TYPE_INVALID,
		                   G_TYPE_STRING, &parent,
		                   G_TYPE_INVALID);

		if (!parent) {
			/* Older HAL uses 'physical_device' */
			dbus_g_proxy_call (proxy, "GetPropertyString", &err,
			                   G_TYPE_STRING, "net.physical_device",
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

	if (parent && tmp_product && tmp_vendor) {
		*product = tmp_product;
		*vendor = tmp_vendor;
	} else {
		g_free (tmp_product);
		g_free (tmp_vendor);
	}
	g_object_unref (proxy);

	return parent;
}

static void
nm_device_update_description (NMDevice *device)
{
	NMDevicePrivate *priv;
	DBusGConnection *connection;
	const char *udi;
	char *orig_dev_udi = NULL;
	char *pd_parent_udi = NULL;

	g_return_if_fail (NM_IS_DEVICE (device));
	priv = NM_DEVICE_GET_PRIVATE (device);

	g_free (priv->product);
	priv->product = NULL;
	g_free (priv->vendor);
	priv->vendor = NULL;

	connection = nm_object_get_connection (NM_OBJECT (device));
	g_return_if_fail (connection != NULL);

	/* First, get the originating device info */
	udi = nm_device_get_udi (device);
	orig_dev_udi = get_product_and_vendor (connection, udi, TRUE, FALSE, &priv->product, &priv->vendor);

	/* Ignore product and vendor for the Network Interface */
	if (priv->product || priv->vendor) {
		g_free (priv->product);
		priv->product = NULL;
		g_free (priv->vendor);
		priv->vendor = NULL;
	}

	/* Get product and vendor off the originating device if possible */
	pd_parent_udi = get_product_and_vendor (connection,
	                                        orig_dev_udi,
	                                        FALSE,
	                                        FALSE,
	                                        &priv->product,
	                                        &priv->vendor);
	g_free (orig_dev_udi);

	/* If one of the product/vendor isn't found on the originating device, try the
	 * parent of the originating device.
	 */
	if (!priv->product || !priv->vendor) {
		char *ignore;
		ignore = get_product_and_vendor (connection, pd_parent_udi, FALSE, TRUE,
		                                 &priv->product, &priv->vendor);
		g_free (ignore);
	}
	g_free (pd_parent_udi);

	g_object_notify (G_OBJECT (device), NM_DEVICE_VENDOR);
	g_object_notify (G_OBJECT (device), NM_DEVICE_PRODUCT);
}

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

