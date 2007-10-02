/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <string.h>

#include "nm-manager.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"
#include "nm-device-interface.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerSystem.h"
#include "nm-marshal.h"

static gboolean impl_manager_get_devices (NMManager *manager, GPtrArray **devices, GError **err);
static void impl_manager_activate_device (NMManager *manager,
								  char *device_path,
								  char *service_name,
								  char *connection_path,
								  char *specific_object_path,
								  DBusGMethodInvocation *context);

static gboolean impl_manager_sleep (NMManager *manager, gboolean sleep, GError **err);

/* Legacy 0.6 compatibility interface */

static gboolean impl_manager_legacy_sleep (NMManager *manager, GError **err);
static gboolean impl_manager_legacy_wake  (NMManager *manager, GError **err);
static gboolean impl_manager_legacy_state (NMManager *manager, guint32 *state, GError **err);

#include "nm-manager-glue.h"

static void nm_manager_connections_destroy (NMManager *manager, NMConnectionType type);
static void manager_set_wireless_enabled (NMManager *manager, gboolean enabled);

static void connection_added_default_handler (NMManager *manager,
									 NMConnection *connection,
									 NMConnectionType connection_type);


typedef struct {
	DBusGMethodInvocation *context;
	NMDevice *device;
	NMConnectionType connection_type;
	char *connection_path;
	char *specific_object_path;
	guint timeout_id;
} PendingConnectionInfo;

typedef struct {
	GSList *devices;
	NMState state;

	GHashTable *user_connections;
	DBusGProxy *user_proxy;

	GHashTable *system_connections;
	DBusGProxy *system_proxy;

	PendingConnectionInfo *pending_connection_info;
	gboolean wireless_enabled;
	gboolean sleeping;
} NMManagerPrivate;

#define NM_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MANAGER, NMManagerPrivate))

G_DEFINE_TYPE (NMManager, nm_manager, G_TYPE_OBJECT)

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	STATE_CHANGE,
	CONNECTION_ADDED,
	CONNECTION_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_STATE,
	PROP_WIRELESS_ENABLED,

	LAST_PROP
};

static void
nm_manager_init (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	priv->wireless_enabled = TRUE;
	priv->sleeping = FALSE;
	priv->state = NM_STATE_DISCONNECTED;

	priv->user_connections = g_hash_table_new_full (g_str_hash,
	                                                g_str_equal,
	                                                g_free,
	                                                g_object_unref);

	priv->system_connections = g_hash_table_new_full (g_str_hash,
	                                                g_str_equal,
	                                                g_free,
	                                                g_object_unref);
}

NMState
nm_manager_get_state (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NM_STATE_UNKNOWN);

	return NM_MANAGER_GET_PRIVATE (manager)->state;
}

static void
nm_manager_update_state (NMManager *manager)
{
	NMManagerPrivate *priv;
	NMState new_state = NM_STATE_DISCONNECTED;

	g_return_if_fail (NM_IS_MANAGER (manager));

	priv = NM_MANAGER_GET_PRIVATE (manager);

	if (priv->sleeping) {
		new_state = NM_STATE_ASLEEP;
	} else {
		GSList *iter;

		for (iter = priv->devices; iter; iter = iter->next) {
			NMDevice *dev = NM_DEVICE (iter->data);

			if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED) {
				new_state = NM_STATE_CONNECTED;
				break;
			} else if (nm_device_is_activating (dev)) {
				new_state = NM_STATE_CONNECTING;
			}
		}
	}

	if (priv->state != new_state) {
		priv->state = new_state;
		g_signal_emit (manager, signals[STATE_CHANGE], 0, priv->state);
	}
}

static void
pending_connection_info_destroy (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	PendingConnectionInfo *info = priv->pending_connection_info;

	if (!info)
		return;

	if (info->timeout_id)
		g_source_remove (info->timeout_id);

	g_free (info->connection_path);
	g_free (info->specific_object_path);
	g_object_unref (info->device);

	g_slice_free (PendingConnectionInfo, info);
	priv->pending_connection_info = NULL;
}

static void
finalize (GObject *object)
{
	NMManager *manager = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	pending_connection_info_destroy (manager);

	nm_manager_connections_destroy (manager, NM_CONNECTION_TYPE_USER);
	g_hash_table_destroy (priv->user_connections);
	priv->user_connections = NULL;

	nm_manager_connections_destroy (manager, NM_CONNECTION_TYPE_SYSTEM);
	g_hash_table_destroy (priv->system_connections);
	priv->system_connections = NULL;

	while (g_slist_length (priv->devices))
		nm_manager_remove_device (manager, NM_DEVICE (priv->devices->data));

	G_OBJECT_CLASS (nm_manager_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_WIRELESS_ENABLED:
		manager_set_wireless_enabled (NM_MANAGER (object), g_value_get_boolean (value));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_STATE:
		nm_manager_update_state (NM_MANAGER (object));
		g_value_set_uint (value, priv->state);
		break;
	case PROP_WIRELESS_ENABLED:
		g_value_set_boolean (value, priv->wireless_enabled);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_manager_class_init (NMManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMManagerPrivate));

	/* virtual methods */
	manager_class->connection_added = connection_added_default_handler;

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;

	/* properties */
	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_uint (NM_MANAGER_STATE,
							"State",
							"Current state",
							0, 5, 0, /* FIXME */
							G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_WIRELESS_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIRELESS_ENABLED,
							   "WirelessEnabled",
							   "Is wireless enabled",
							   TRUE,
							   G_PARAM_READWRITE));

	/* signals */
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMManagerClass, device_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMManagerClass, device_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[STATE_CHANGE] =
		g_signal_new ("state-change",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMManagerClass, state_change),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1,
					  G_TYPE_UINT);

	signals[CONNECTION_ADDED] =
		g_signal_new ("connection-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMManagerClass, connection_added),
					  NULL, NULL,
				    nm_marshal_VOID__OBJECT_UINT,
					  G_TYPE_NONE, 2,
				    G_TYPE_OBJECT, G_TYPE_UINT);

	signals[CONNECTION_REMOVED] =
		g_signal_new ("connection-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMManagerClass, connection_removed),
					  NULL, NULL,
				    nm_marshal_VOID__OBJECT_UINT,
					  G_TYPE_NONE, 2,
				    G_TYPE_OBJECT, G_TYPE_UINT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (manager_class),
									 &dbus_glib_nm_manager_object_info);
}

#define DBUS_TYPE_G_STRING_VARIANT_HASHTABLE (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))
#define DBUS_TYPE_G_DICT_OF_DICTS (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, DBUS_TYPE_G_STRING_VARIANT_HASHTABLE))

typedef struct GetSettingsInfo {
	NMManager *manager;
	NMConnection *connection;
} GetSettingsInfo;

static void
free_get_settings_info (gpointer data)
{
	GetSettingsInfo *info = (GetSettingsInfo *) data;

	if (info->manager) {
		g_object_unref (info->manager);
		info->manager = NULL;
	}
	if (info->connection) {
		g_object_unref (info->connection);
		info->connection = NULL;
	}

	g_slice_free (GetSettingsInfo, data);	
}

static void
connection_get_settings_cb  (DBusGProxy *proxy,
                             DBusGProxyCall *call_id,
                             gpointer user_data)
{
	GetSettingsInfo *info = (GetSettingsInfo *) user_data;
	GError *err = NULL;
	GHashTable *settings = NULL;
	NMConnection *connection;
	NMConnectionType connection_type;
	NMManager *manager;

	g_return_if_fail (info != NULL);

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            DBUS_TYPE_G_DICT_OF_DICTS, &settings,
	                            G_TYPE_INVALID)) {
		nm_warning ("Couldn't retrieve connection settings: %s.", err->message);
		g_error_free (err);
		goto out;
	}

	manager = info->manager;
	connection = info->connection;
 	if (connection == NULL) {
		const char *path = dbus_g_proxy_get_path (proxy);
		const char *bus_name = dbus_g_proxy_get_bus_name (proxy);
		NMManagerPrivate *priv;

		connection = nm_connection_new_from_hash (settings);
		if (connection == NULL)
			goto out;

		g_object_set_data_full (G_OBJECT (connection),
		                        NM_MANAGER_CONNECTION_PROXY_TAG,
		                        proxy,
		                        (GDestroyNotify) g_object_unref);

		priv = NM_MANAGER_GET_PRIVATE (manager);
		if (strcmp (bus_name, NM_DBUS_SERVICE_USER_SETTINGS) == 0) {
			connection_type = NM_CONNECTION_TYPE_USER;
			g_hash_table_insert (priv->user_connections,
			                     g_strdup (path),
			                     connection);
		} else if (strcmp (bus_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS) == 0) {
			connection_type = NM_CONNECTION_TYPE_SYSTEM;
			g_hash_table_insert (priv->system_connections,
			                     g_strdup (path),
			                     connection);
		} else {
			nm_warning ("Connection wasn't a user connection or a system connection.");
			g_assert_not_reached ();
		}

		g_signal_emit (manager, signals[CONNECTION_ADDED], 0, connection, connection_type);
	} else {
		// FIXME: merge settings? or just replace?
		nm_warning ("%s (#%d): implement merge settings", __func__, __LINE__);
	}

	g_hash_table_destroy (settings);

out:
	return;
}

static void
connection_removed_cb (DBusGProxy *proxy, gpointer user_data)
{
	NMManager * manager = NM_MANAGER (user_data);
	const char *path = dbus_g_proxy_get_path (proxy);
	const char *bus_name = dbus_g_proxy_get_bus_name (proxy);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMConnectionType connection_type;
	NMConnection *connection = NULL;
	GHashTable *hash = NULL;

	if (strcmp (bus_name, NM_DBUS_SERVICE_USER_SETTINGS) == 0) {
		connection_type = NM_CONNECTION_TYPE_USER;
		hash = priv->user_connections;
	} else if (strcmp (bus_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS) == 0) {
		connection_type = NM_CONNECTION_TYPE_SYSTEM;
		hash = priv->system_connections;
	}			

	if (hash == NULL)
		goto out;

	connection = g_hash_table_lookup (hash, path);
	if (connection != NULL) {
		/* Destroys the connection, then associated DBusGProxy due to the
		 * weak reference notify function placed on the connection when it
		 * was created.
		 */
		g_object_ref (connection);
		g_hash_table_remove (hash, path);
		g_signal_emit (manager, signals[CONNECTION_REMOVED], 0, connection, connection_type);
		g_object_unref (connection);
	}

out:
	return;
}

static void
new_connection_cb (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	NMManager * manager = NM_MANAGER (user_data);
	DBusGProxy *con_proxy;
	NMDBusManager * dbus_mgr;
	DBusGConnection * g_connection;
	DBusGProxyCall *call;
	struct GetSettingsInfo *info;

	dbus_mgr = nm_dbus_manager_get ();
	g_connection = nm_dbus_manager_get_connection (dbus_mgr);
	con_proxy = dbus_g_proxy_new_for_name (g_connection,
	                                       NM_DBUS_SERVICE_USER_SETTINGS,
	                                       path,
	                                       NM_DBUS_IFACE_SETTINGS_CONNECTION);
	g_object_unref (dbus_mgr);
	if (!con_proxy) {
		nm_warning ("Error: could not init user connection proxy");
		return;
	}

	dbus_g_proxy_add_signal (con_proxy, "Updated",
	                         DBUS_TYPE_G_DICT_OF_DICTS,
	                         G_TYPE_INVALID);
//	dbus_g_proxy_connect_signal (con_proxy, "Updated",
//	                             G_CALLBACK (connection_updated_cb),
//	                             manager,
//	                             NULL);

	dbus_g_proxy_add_signal (con_proxy, "Removed", G_TYPE_INVALID, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (con_proxy, "Removed",
	                             G_CALLBACK (connection_removed_cb),
	                             manager,
	                             NULL);

	info = g_slice_new0 (GetSettingsInfo);
	info->manager = g_object_ref (manager);
	call = dbus_g_proxy_begin_call (con_proxy, "GetSettings",
	                                connection_get_settings_cb,
	                                info,
	                                free_get_settings_info,
	                                G_TYPE_INVALID);
}

#define DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH (dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_OBJECT_PATH))

static void
list_connections_cb  (DBusGProxy *proxy,
                      DBusGProxyCall *call_id,
                      gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	GError *err = NULL;
	GPtrArray *ops;
	int i;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH, &ops,
	                            G_TYPE_INVALID)) {
		nm_warning ("Couldn't retrieve connections: %s.", err->message);
		g_error_free (err);
		goto out;
	}

	for (i = 0; i < ops->len; i++)
		new_connection_cb (proxy, g_ptr_array_index (ops, i), manager);

	g_ptr_array_free (ops, TRUE);

out:
	return;
}

static void
query_connections (NMManager *manager,
                   NMConnectionType type)
{
	NMManagerPrivate *priv;
	DBusGProxyCall *call;
	DBusGProxy ** proxy;
	const char * service;

	g_return_if_fail (NM_IS_MANAGER (manager));

	priv = NM_MANAGER_GET_PRIVATE (manager);
	if (type == NM_CONNECTION_TYPE_USER) {
		proxy = &priv->user_proxy;
		service = NM_DBUS_SERVICE_USER_SETTINGS;
	} else if (type == NM_CONNECTION_TYPE_SYSTEM) {
		proxy = &priv->system_proxy;
		service = NM_DBUS_SERVICE_SYSTEM_SETTINGS;
	} else {
		nm_warning ("Unknown NMConnectionType %d", type);
		return;
	}

	if (!*proxy) {
		NMDBusManager * dbus_mgr;
		DBusGConnection * g_connection;

		dbus_mgr = nm_dbus_manager_get ();
		g_connection = nm_dbus_manager_get_connection (dbus_mgr);
		*proxy = dbus_g_proxy_new_for_name (g_connection,
		                                    service,
		                                    NM_DBUS_PATH_SETTINGS,
		                                    NM_DBUS_IFACE_SETTINGS);
		g_object_unref (dbus_mgr);
		if (!*proxy) {
			nm_warning ("Error: could not init settings proxy");
			return;
		}

		dbus_g_proxy_add_signal (*proxy,
		                         "NewConnection",
		                         DBUS_TYPE_G_OBJECT_PATH,
		                         G_TYPE_INVALID);

		dbus_g_proxy_connect_signal (*proxy, "NewConnection",
		                             G_CALLBACK (new_connection_cb),
		                             manager,
		                             NULL);
	}

	/* grab connections */
	call = dbus_g_proxy_begin_call (*proxy, "ListConnections",
	                                list_connections_cb,
	                                manager,
	                                NULL,
	                                G_TYPE_INVALID);
}

static void
nm_manager_name_owner_changed (NMDBusManager *mgr,
                               const char *name,
                               const char *old,
                               const char *new,
                               gpointer user_data)
{
	NMManager * manager = NM_MANAGER (user_data);
	gboolean old_owner_good = (old && (strlen (old) > 0));
	gboolean new_owner_good = (new && (strlen (new) > 0));

	if (strcmp (name, NM_DBUS_SERVICE_USER_SETTINGS) == 0) {
		if (!old_owner_good && new_owner_good) {
			/* User Settings service appeared, update stuff */
			query_connections (manager, NM_CONNECTION_TYPE_USER);
		} else {
			/* User Settings service disappeared, throw them away (?) */
			nm_manager_connections_destroy (manager, NM_CONNECTION_TYPE_USER);
		}
	} else if (strcmp (name, NM_DBUS_SERVICE_SYSTEM_SETTINGS) == 0) {
		if (!old_owner_good && new_owner_good) {
			/* System Settings service appeared, update stuff */
			query_connections (manager, NM_CONNECTION_TYPE_SYSTEM);
		} else {
			/* System Settings service disappeared, throw them away (?) */
			nm_manager_connections_destroy (manager, NM_CONNECTION_TYPE_SYSTEM);
		}
	}
}

static gboolean
initial_get_connections (gpointer user_data)
{
	NMManager * manager = NM_MANAGER (user_data);

	if (nm_dbus_manager_name_has_owner (nm_dbus_manager_get (),
	                                    NM_DBUS_SERVICE_USER_SETTINGS))
		query_connections (manager, NM_CONNECTION_TYPE_USER);

	if (nm_dbus_manager_name_has_owner (nm_dbus_manager_get (),
	                                    NM_DBUS_SERVICE_SYSTEM_SETTINGS))
		query_connections (manager, NM_CONNECTION_TYPE_SYSTEM);

	return FALSE;
}


NMManager *
nm_manager_new (void)
{
	GObject *object;
	DBusGConnection *connection;
	NMDBusManager * dbus_mgr;

	object = g_object_new (NM_TYPE_MANAGER, NULL);

	dbus_mgr = nm_dbus_manager_get ();
	connection = nm_dbus_manager_get_connection (dbus_mgr);
	dbus_g_connection_register_g_object (connection,
	                                     NM_DBUS_PATH,
	                                     object);

	g_signal_connect (dbus_mgr,
	                  "name-owner-changed",
	                  G_CALLBACK (nm_manager_name_owner_changed),
	                  NM_MANAGER (object));

	g_idle_add ((GSourceFunc) initial_get_connections, NM_MANAGER (object));

	return NM_MANAGER (object);
}

static void
nm_manager_connections_destroy (NMManager *manager,
                                NMConnectionType type)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	if (type == NM_CONNECTION_TYPE_USER) {
		if (priv->user_connections)
			g_hash_table_remove_all (priv->user_connections);

		if (priv->user_proxy) {
			g_object_unref (priv->user_proxy);
			priv->user_proxy = NULL;
		}
	} else if (type == NM_CONNECTION_TYPE_SYSTEM) {
		if (priv->system_connections)
			g_hash_table_remove_all (priv->system_connections);

		if (priv->system_proxy) {
			g_object_unref (priv->system_proxy);
			priv->system_proxy = NULL;
		}
	} else {
		nm_warning ("Unknown NMConnectionType %d", type);
	}
}

static void
manager_set_wireless_enabled (NMManager *manager, gboolean enabled)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;

	if (priv->wireless_enabled == enabled)
		return;

	priv->wireless_enabled = enabled;

	/* Tear down all wireless devices */
	for (iter = priv->devices; iter; iter = iter->next) {
		if (NM_IS_DEVICE_802_11_WIRELESS (iter->data)) {
			if (enabled)
				nm_device_bring_up (NM_DEVICE (iter->data), FALSE);
			else
				nm_device_bring_down (NM_DEVICE (iter->data), FALSE);
		}
	}
}

static void
manager_device_added (NMManager *manager, NMDevice *device)
{
	g_signal_emit (manager, signals[DEVICE_ADDED], 0, device);
}

static void
manager_device_state_changed (NMDeviceInterface *device, NMDeviceState state, gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);

	nm_manager_update_state (manager);
}

void
nm_manager_add_device (NMManager *manager, NMDevice *device)
{
	NMManagerPrivate *priv;

	g_return_if_fail (NM_IS_MANAGER (manager));
	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_MANAGER_GET_PRIVATE (manager);

	priv->devices = g_slist_append (priv->devices, g_object_ref (device));

	g_signal_connect (device, "state-changed",
					  G_CALLBACK (manager_device_state_changed),
					  manager);

	if (!priv->sleeping) {
		if (!NM_IS_DEVICE_802_11_WIRELESS (device) || priv->wireless_enabled) {
			nm_device_bring_down (device, TRUE);
			nm_device_bring_up (device, TRUE);
		}
	}

	nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));

	manager_device_added (manager, device);
}

static void
manager_device_removed (NMManager *manager, NMDevice *device)
{
	g_signal_emit (manager, signals[DEVICE_REMOVED], 0, device);
}
 
void
nm_manager_remove_device (NMManager *manager, NMDevice *device)
{
	NMManagerPrivate *priv;
	GSList *iter;

	g_return_if_fail (NM_IS_MANAGER (manager));
	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_MANAGER_GET_PRIVATE (manager);

	for (iter = priv->devices; iter; iter = iter->next) {
		if (iter->data == device) {
			priv->devices = g_slist_delete_link (priv->devices, iter);

			nm_device_bring_down (device, FALSE);

			g_signal_handlers_disconnect_by_func (device, manager_device_state_changed, manager);

			manager_device_removed (manager, device);
			g_object_unref (device);
			break;
		}
	}
}

GSList *
nm_manager_get_devices (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	return NM_MANAGER_GET_PRIVATE (manager)->devices;
}

static gboolean
impl_manager_get_devices (NMManager *manager, GPtrArray **devices, GError **err)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;

	*devices = g_ptr_array_sized_new (g_slist_length (priv->devices));

	for (iter = priv->devices; iter; iter = iter->next)
		g_ptr_array_add (*devices, g_strdup (nm_device_get_dbus_path (NM_DEVICE (iter->data))));

	return TRUE;
}

NMDevice *
nm_manager_get_device_by_path (NMManager *manager, const char *path)
{
	GSList *iter;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (!strcmp (nm_device_get_dbus_path (device), path))
			return device;
	}

	return NULL;
}

NMDevice *
nm_manager_get_device_by_udi (NMManager *manager, const char *udi)
{
	GSList *iter;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (!strcmp (nm_device_get_udi (device), udi))
			return device;
	}

	return NULL;
}

gboolean
nm_manager_activate_device (NMManager *manager,
					   NMDevice *device,
					   NMConnection *connection,
					   const char *specific_object,
					   gboolean user_requested)
{
	NMActRequest *req;
	gboolean success;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	req = nm_act_request_new (connection, specific_object, user_requested);
	success = nm_device_interface_activate (NM_DEVICE_INTERFACE (device), req);
	g_object_unref (req);

	return success;
}

gboolean
nm_manager_activation_pending (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	return NM_MANAGER_GET_PRIVATE (manager)->pending_connection_info != NULL;
}

static GError *
nm_manager_error_new (const gchar *format, ...)
{
	GError *err;
	va_list args;
	gchar *msg;
	static GQuark domain_quark = 0;

	if (domain_quark == 0)
		domain_quark = g_quark_from_static_string ("nm_manager_error");

	va_start (args, format);
	msg = g_strdup_vprintf (format, args);
	va_end (args);

	err = g_error_new_literal (domain_quark, 1, (const gchar *) msg);

	g_free (msg);

	return err;
}

static gboolean
wait_for_connection_expired (gpointer data)
{
	NMManager *manager = NM_MANAGER (data);
	PendingConnectionInfo *info = NM_MANAGER_GET_PRIVATE (manager)->pending_connection_info;
	GError *err;

	nm_info ("%s: didn't receive connection details soon enough for activation.",
	         nm_device_get_iface (info->device));

	err = nm_manager_error_new ("Could not find connection");
	dbus_g_method_return_error (info->context, err);
	g_error_free (err);

	info->timeout_id = 0;
	pending_connection_info_destroy (manager);

	return FALSE;
}

static void
connection_added_default_handler (NMManager *manager,
						    NMConnection *connection,
						    NMConnectionType connection_type)
{
	PendingConnectionInfo *info;
	const char *path;

	if (!nm_manager_activation_pending (manager))
		return;

	info = NM_MANAGER_GET_PRIVATE (manager)->pending_connection_info;
	if (connection_type != info->connection_type)
		return;

	path = nm_manager_get_connection_dbus_path (manager, connection);
	if (strcmp (info->connection_path, path))
		return;

	if (nm_manager_activate_device (manager, info->device, connection, info->specific_object_path, TRUE)) {
		dbus_g_method_return (info->context, TRUE);
	} else {
		GError *err;

		err = nm_manager_error_new ("Error in device activation");
		dbus_g_method_return_error (info->context, err);
		g_error_free (err);
	}

	pending_connection_info_destroy (manager);
}

static void
impl_manager_activate_device (NMManager *manager,
						char *device_path,
						char *service_name,
						char *connection_path,
						char *specific_object_path,
						DBusGMethodInvocation *context)
{
	NMDevice *device;
	NMConnectionType connection_type;
	NMConnection *connection;
	GError *err = NULL;

	device = nm_manager_get_device_by_path (manager, device_path);
	if (!device) {
		err = nm_manager_error_new ("Could not find device");
		goto err;
	}

	nm_info ("User request for activation of %s.", nm_device_get_iface (device));

	if (!strcmp (service_name, NM_DBUS_SERVICE_USER_SETTINGS))
		connection_type = NM_CONNECTION_TYPE_USER;
	else if (!strcmp (service_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS))
		connection_type = NM_CONNECTION_TYPE_SYSTEM;
	else {
		err = nm_manager_error_new ("Invalid service name");
		goto err;
	}

	connection = nm_manager_get_connection_by_object_path (manager, connection_type, connection_path);
	if (connection) {
		if (nm_manager_activate_device (manager, device, connection, specific_object_path, TRUE)) {
			dbus_g_method_return (context, TRUE);
		} else {
			err = nm_manager_error_new ("Error in device activation");
			goto err;
		}
	} else {
		PendingConnectionInfo *info;

		/* Don't have the connection quite yet, probably created by
		 * the client on-the-fly.  Defer the activation until we have it
		 */

		info = g_slice_new0 (PendingConnectionInfo);
		info->context = context;
		info->device = g_object_ref (device);
		info->connection_type = connection_type;
		info->connection_path = g_strdup (connection_path);
		info->specific_object_path = g_strdup (specific_object_path);
		info->timeout_id = g_timeout_add (5000, wait_for_connection_expired, manager);

		NM_MANAGER_GET_PRIVATE (manager)->pending_connection_info = info;
	}

 err:
	if (err) {
		dbus_g_method_return_error (context, err);
		g_error_free (err);
	}
}

gboolean
nm_manager_wireless_enabled (NMManager *manager)
{
	gboolean enabled;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	g_object_get (manager, NM_MANAGER_WIRELESS_ENABLED, &enabled, NULL);

	return enabled;
}

void
nm_manager_sleep (NMManager *manager, gboolean sleep)
{
	NMManagerPrivate *priv;

	g_return_if_fail (NM_IS_MANAGER (manager));

	priv = NM_MANAGER_GET_PRIVATE (manager);

	if (priv->sleeping == sleep)
		return;

	priv->sleeping = sleep;

	if (sleep) {
		GSList *iter;

		nm_info ("Going to sleep.");

		/* Just deactivate and down all devices from the device list,
		 * we'll remove them in 'wake' for speed's sake.
		 */
		for (iter = priv->devices; iter; iter = iter->next)
			nm_device_bring_down (NM_DEVICE (iter->data), FALSE);
	} else {
		nm_info  ("Waking up from sleep.");

		while (g_slist_length (priv->devices))
			nm_manager_remove_device (manager, NM_DEVICE (priv->devices->data));

		priv->devices = NULL;
	}

	nm_manager_update_state (manager);
}

static gboolean
impl_manager_sleep (NMManager *manager, gboolean sleep, GError **err)
{
	nm_manager_sleep (manager, sleep);

	return TRUE;
}

NMDevice *
nm_manager_get_active_device (NMManager *manager)
{
	GSList *iter;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	for (iter = nm_manager_get_devices (manager); iter; iter = iter->next) {
		NMDevice *dev = NM_DEVICE (iter->data);

		if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED)
			return dev;
	}

	return NULL;
}

/* Legacy 0.6 compatibility interface */

static gboolean
impl_manager_legacy_sleep (NMManager *manager, GError **err)
{
	return impl_manager_sleep (manager, TRUE, err);
}

static gboolean
impl_manager_legacy_wake  (NMManager *manager, GError **err)
{
	return impl_manager_sleep (manager, FALSE, err);
}

static gboolean
impl_manager_legacy_state (NMManager *manager, guint32 *state, GError **err)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	nm_manager_update_state (manager);
	*state = priv->state;
	return TRUE;
}


/* Connections */

static void
connections_to_slist (gpointer key, gpointer value, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, g_object_ref (value));
}

/* Returns a GSList of referenced NMConnection objects, caller must
 * unref the connections in the list and destroy the list.
 */
GSList *
nm_manager_get_connections (NMManager *manager,
                            NMConnectionType type)
{
	NMManagerPrivate *priv;
	GSList *list = NULL;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	priv = NM_MANAGER_GET_PRIVATE (manager);
	if (type == NM_CONNECTION_TYPE_USER)
		g_hash_table_foreach (priv->user_connections, connections_to_slist, &list);
	else if (type == NM_CONNECTION_TYPE_SYSTEM)
		g_hash_table_foreach (priv->system_connections, connections_to_slist, &list);
	else
		nm_warning ("Unknown NMConnectionType %d", type);
	return list;
}

NMConnection *
nm_manager_get_connection_by_object_path (NMManager *manager,
                                          NMConnectionType type,
                                          const char *path)
{
	NMManagerPrivate *priv;
	NMConnection *connection = NULL;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	priv = NM_MANAGER_GET_PRIVATE (manager);
	if (type == NM_CONNECTION_TYPE_USER)
		connection = (NMConnection *) g_hash_table_lookup (priv->user_connections, path);
	else if (type == NM_CONNECTION_TYPE_SYSTEM)
		connection = (NMConnection *) g_hash_table_lookup (priv->system_connections, path);
	else
		nm_warning ("Unknown NMConnectionType %d", type);
	return connection;
}

const char *
nm_manager_get_connection_dbus_path (NMManager *manager,
                                     NMConnection *connection)
{
	DBusGProxy *proxy;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	proxy = g_object_get_data (G_OBJECT (connection), NM_MANAGER_CONNECTION_PROXY_TAG);
	if (!DBUS_IS_G_PROXY (proxy)) {
		nm_warning ("Couldn't get dbus proxy for connection.");
		return NULL;
	}

	return dbus_g_proxy_get_path (proxy);
}

void
nm_manager_update_connections (NMManager *manager,
                               NMConnectionType type,
                               GSList *connections,
                               gboolean reset)
{
	g_return_if_fail (NM_IS_MANAGER (manager));

	if (reset)
		nm_manager_connections_destroy (manager, type);
}

