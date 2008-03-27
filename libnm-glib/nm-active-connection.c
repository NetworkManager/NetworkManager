/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <string.h>

#include "NetworkManager.h"
#include "nm-active-connection.h"
#include "nm-object-private.h"
#include "nm-types-private.h"
#include "nm-device.h"
#include "nm-connection.h"

#include "nm-active-connection-bindings.h"

G_DEFINE_TYPE (NMActiveConnection, nm_active_connection, NM_TYPE_OBJECT)

#define NM_ACTIVE_CONNECTION_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_ACTIVE_CONNECTION, NMActiveConnectionPrivate))

static gboolean demarshal_devices (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field);


typedef struct {
	gboolean disposed;
	DBusGProxy *proxy;

	char *service_name;
	NMConnectionScope scope;
	char *connection;
	char *specific_object;
	char *shared_service_name;
	char *shared_connection;
	GPtrArray *devices;
} NMActiveConnectionPrivate;

enum {
	PROP_0,
	PROP_SERVICE_NAME,
	PROP_CONNECTION,
	PROP_SPECIFIC_OBJECT,
	PROP_SHARED_SERVICE_NAME,
	PROP_SHARED_CONNECTION,
	PROP_DEVICES,

	LAST_PROP
};

#define DBUS_PROP_SERVICE_NAME "ServiceName"
#define DBUS_PROP_CONNECTION "Connection"
#define DBUS_PROP_SPECIFIC_OBJECT "SpecificObject"
#define DBUS_PROP_SHARED_SERVICE_NAME "SharedServiceName"
#define DBUS_PROP_SHARED_CONNECTION "SharedConnection"
#define DBUS_PROP_DEVICES "Devices"

GObject *
nm_active_connection_new (DBusGConnection *connection, const char *path)
{
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);

	return g_object_new (NM_TYPE_ACTIVE_CONNECTION,
						 NM_OBJECT_DBUS_CONNECTION, connection,
						 NM_OBJECT_DBUS_PATH, path,
						 NULL);
}

static NMConnectionScope
get_scope_for_service_name (const char *service_name)
{
	if (service_name && !strcmp (service_name, NM_DBUS_SERVICE_USER_SETTINGS))
		return NM_CONNECTION_SCOPE_USER;
	else if (service_name && !strcmp (service_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS))
		return NM_CONNECTION_SCOPE_SYSTEM;

	return NM_CONNECTION_SCOPE_UNKNOWN;
}

const char *
nm_active_connection_get_service_name (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (!priv->service_name) {
		priv->service_name = nm_object_get_string_property (NM_OBJECT (connection),
		                                                    NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
		                                                    DBUS_PROP_SERVICE_NAME);
		priv->scope = get_scope_for_service_name (priv->service_name);
	}

	return priv->service_name;
}

NMConnectionScope
nm_active_connection_get_scope (NMActiveConnection *connection)
{
	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NM_CONNECTION_SCOPE_UNKNOWN);

	/* Make sure service_name and scope are up-to-date */
	nm_active_connection_get_service_name (connection);
	return NM_ACTIVE_CONNECTION_GET_PRIVATE (connection)->scope;
}

const char *
nm_active_connection_get_connection (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (!priv->connection) {
		priv->connection = nm_object_get_string_property (NM_OBJECT (connection),
		                                                  NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
		                                                  DBUS_PROP_CONNECTION);
	}

	return priv->connection;
}

const char *
nm_active_connection_get_specific_object (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (!priv->specific_object) {
		priv->specific_object = nm_object_get_string_property (NM_OBJECT (connection),
		                                                       NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
		                                                       DBUS_PROP_SPECIFIC_OBJECT);
	}

	return priv->specific_object;
}

const char *
nm_active_connection_get_shared_service_name (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (!priv->shared_service_name) {
		priv->shared_service_name = nm_object_get_string_property (NM_OBJECT (connection),
		                                                           NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
		                                                           DBUS_PROP_SHARED_SERVICE_NAME);
	}

	return priv->shared_service_name;
}

const char *
nm_active_connection_get_shared_connection (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (!priv->shared_connection) {
		priv->shared_connection = nm_object_get_string_property (NM_OBJECT (connection),
		                                                         NM_DBUS_INTERFACE_ACTIVE_CONNECTION,
		                                                         DBUS_PROP_SHARED_CONNECTION);
	}

	return priv->shared_connection;
}

const GPtrArray *
nm_active_connection_get_devices (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_ACTIVE_CONNECTION (connection), NULL);

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	if (priv->devices)
		return handle_ptr_array_return (priv->devices);

	if (!nm_object_get_property (NM_OBJECT (connection),
	                             NM_DBUS_INTERFACE,
	                             DBUS_PROP_DEVICES,
	                             &value)) {
		return NULL;
	}

	demarshal_devices (NM_OBJECT (connection), NULL, &value, &priv->devices);
	g_value_unset (&value);

	return handle_ptr_array_return (priv->devices);
}

static void
nm_active_connection_init (NMActiveConnection *ap)
{
}

static void
dispose (GObject *object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_active_connection_parent_class)->dispose (object);
		return;
	}

	priv->disposed = TRUE;

	if (priv->devices) {
		g_ptr_array_foreach (priv->devices, (GFunc) g_object_unref, NULL);
		g_ptr_array_free (priv->devices, TRUE);
	}
	g_object_unref (priv->proxy);

	G_OBJECT_CLASS (nm_active_connection_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	g_free (priv->service_name);
	g_free (priv->connection);
	g_free (priv->specific_object);
	g_free (priv->shared_service_name);
	g_free (priv->shared_service_name);

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
	case PROP_SERVICE_NAME:
		g_value_set_string (value, nm_active_connection_get_service_name (self));
		break;
	case PROP_CONNECTION:
		g_value_set_boxed (value, nm_active_connection_get_connection (self));
		break;
	case PROP_SPECIFIC_OBJECT:
		g_value_set_boxed (value, nm_active_connection_get_specific_object (self));
		break;
	case PROP_SHARED_SERVICE_NAME:
		g_value_set_string (value, nm_active_connection_get_shared_service_name (self));
		break;
	case PROP_SHARED_CONNECTION:
		g_value_set_boxed (value, nm_active_connection_get_shared_connection (self));
		break;
	case PROP_DEVICES:
		g_value_set_boxed (value, nm_active_connection_get_devices (self));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static gboolean
demarshal_devices (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	DBusGConnection *connection;

	connection = nm_object_get_connection (object);
	if (!nm_object_array_demarshal (value, (GPtrArray **) field, connection, nm_device_new))
		return FALSE;

	nm_object_queue_notify (object, NM_ACTIVE_CONNECTION_DEVICES);
	return TRUE;
}

static gboolean
demarshal_service (NMObject *object, GParamSpec *pspec, GValue *value, gpointer field)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	if (nm_object_demarshal_generic (object, pspec, value, field)) {
		priv->scope = get_scope_for_service_name (priv->service_name);
		return TRUE;
	}
	return FALSE;
}

static void
register_for_property_changed (NMActiveConnection *connection)
{
	NMActiveConnectionPrivate *priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (connection);
	const NMPropertiesChangedInfo property_changed_info[] = {
		{ NM_ACTIVE_CONNECTION_SERVICE_NAME,        demarshal_service,           &priv->service_name },
		{ NM_ACTIVE_CONNECTION_CONNECTION,          nm_object_demarshal_generic, &priv->connection },
		{ NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT,     nm_object_demarshal_generic, &priv->specific_object },
		{ NM_ACTIVE_CONNECTION_SHARED_SERVICE_NAME, nm_object_demarshal_generic, &priv->shared_service_name },
		{ NM_ACTIVE_CONNECTION_SHARED_CONNECTION,   nm_object_demarshal_generic, &priv->shared_connection },
		{ NM_ACTIVE_CONNECTION_DEVICES,             demarshal_devices,           &priv->devices },
		{ NULL },
	};

	nm_object_handle_properties_changed (NM_OBJECT (connection),
	                                     priv->proxy,
	                                     property_changed_info);
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	NMObject *object;
	NMActiveConnectionPrivate *priv;

	object = (NMObject *) G_OBJECT_CLASS (nm_active_connection_parent_class)->constructor (type,
																	  n_construct_params,
																	  construct_params);
	if (!object)
		return NULL;

	priv = NM_ACTIVE_CONNECTION_GET_PRIVATE (object);

	priv->proxy = dbus_g_proxy_new_for_name (nm_object_get_connection (object),
									    NM_DBUS_SERVICE,
									    nm_object_get_path (object),
									    NM_DBUS_INTERFACE_ACTIVE_CONNECTION);

	register_for_property_changed (NM_ACTIVE_CONNECTION (object));

	return G_OBJECT (object);
}


static void
nm_active_connection_class_init (NMActiveConnectionClass *ap_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (ap_class);

	g_type_class_add_private (ap_class, sizeof (NMActiveConnectionPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_SERVICE_NAME,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_SERVICE_NAME,
						  "Service Name",
						  "Service Name",
						  NULL,
						  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_CONNECTION,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_CONNECTION,
						      "Connection",
						      "Connection",
						      NULL,
						      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_SPECIFIC_OBJECT,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_SPECIFIC_OBJECT,
						      "Specific object",
						      "Specific object",
						      NULL,
						      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_SHARED_SERVICE_NAME,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_SHARED_SERVICE_NAME,
						  "Shared Service Name",
						  "Shared Service Name",
						  NULL,
						  G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_SHARED_CONNECTION,
		 g_param_spec_string (NM_ACTIVE_CONNECTION_SHARED_CONNECTION,
						      "Shared Connection",
						      "Shared Connection",
						      NULL,
						      G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_DEVICES,
		 g_param_spec_boxed (NM_ACTIVE_CONNECTION_DEVICES,
						       "Devices",
						       "Devices",
						       NM_TYPE_OBJECT_ARRAY,
						       G_PARAM_READABLE));
}
