/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <string.h>

#include "nm-manager.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"
#include "nm-device-interface.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerSystem.h"

static gboolean impl_manager_get_devices (NMManager *manager, GPtrArray **devices, GError **err);
static gboolean impl_manager_sleep (NMManager *manager, gboolean sleep, GError **err);

/* Legacy 0.6 compatibility interface */

static gboolean impl_manager_legacy_sleep (NMManager *manager, GError **err);
static gboolean impl_manager_legacy_wake  (NMManager *manager, GError **err);
static gboolean impl_manager_legacy_state (NMManager *manager, guint32 *state, GError **err);

#include "nm-manager-glue.h"

static void nm_manager_connections_destroy (NMManager *manager, NMConnectionType type);
static void manager_set_wireless_enabled (NMManager *manager, gboolean enabled);

typedef struct {
	GSList *devices;
	NMState state;

	GHashTable *user_connections;
	DBusGProxy *user_proxy;

	GHashTable *system_connections;
	DBusGProxy *system_proxy;

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

#define CONNECTION_PROXY_TAG "dbus-proxy"
#define CONNECTION_GET_SECRETS_CALL_TAG "get-secrets-call"

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
finalize (GObject *object)
{
	NMManager *manager = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

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
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[CONNECTION_REMOVED] =
		g_signal_new ("connection-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMManagerClass, connection_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

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

		g_object_set_data_full (G_OBJECT (connection), CONNECTION_PROXY_TAG, proxy,
						    (GDestroyNotify) g_object_unref);

		priv = NM_MANAGER_GET_PRIVATE (manager);
		if (strcmp (bus_name, NM_DBUS_SERVICE_USER_SETTINGS) == 0) {
			g_hash_table_insert (priv->user_connections,
			                     g_strdup (path),
			                     connection);
		} else if (strcmp (bus_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS) == 0) {
			g_hash_table_insert (priv->system_connections,
			                     g_strdup (path),
			                     connection);
		} else {
			nm_warning ("Connection wasn't a user connection or a system connection.");
			g_assert_not_reached ();
		}

		g_signal_emit (manager, signals[CONNECTION_ADDED], 0, connection);
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
	NMConnection *connection = NULL;
	GHashTable *hash = NULL;

	if (strcmp (bus_name, NM_DBUS_SERVICE_USER_SETTINGS) == 0) {
		hash = priv->user_connections;
	} else if (strcmp (bus_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS) == 0) {
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
		g_signal_emit (manager, signals[CONNECTION_REMOVED], 0, connection);
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


static NMManager *
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

NMManager *
nm_manager_get (void)
{
	static NMManager *singleton = NULL;

	if (!singleton)
		singleton = nm_manager_new ();
	else
		g_object_ref (singleton);

	g_assert (singleton);
	return singleton;
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

	if (state == NM_DEVICE_STATE_NEED_AUTH) {
		NMActRequest *req;
		NMConnection *connection;

		req = nm_device_get_act_request (NM_DEVICE (device));
		/* When device needs an auth it must be activating and thus have an act request. */
		g_assert (req);
		connection = nm_act_request_get_connection (req);

		nm_manager_get_connection_secrets (manager, device,
									connection,
									nm_connection_need_secrets (connection),
									TRUE);
	}
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
nm_manager_get_device_by_iface (NMManager *manager, const char *iface)
{
	GSList *iter;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (!strcmp (nm_device_get_iface (device), iface))
			return device;
	}

	return NULL;
}

NMDevice *
nm_manager_get_device_by_index (NMManager *manager, int idx)
{
	GSList *iter;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (nm_device_get_index (device) == idx)
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
nm_manager_get_connection_service_name (NMManager *manager,
                                        NMConnection *connection)
{
	DBusGProxy *proxy;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	proxy = g_object_get_data (G_OBJECT (connection), CONNECTION_PROXY_TAG);
	if (!DBUS_IS_G_PROXY (proxy)) {
		nm_warning ("Couldn't get dbus proxy for connection.");
		return NULL;
	}

	return dbus_g_proxy_get_bus_name (proxy);
}

const char *
nm_manager_get_connection_dbus_path (NMManager *manager,
                                     NMConnection *connection)
{
	DBusGProxy *proxy;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	proxy = g_object_get_data (G_OBJECT (connection), CONNECTION_PROXY_TAG);
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

typedef struct GetSecretsInfo {
	NMManager *manager;
	NMConnection *connection;
	NMDeviceInterface *device;
	char *setting_name;
} GetSecretsInfo;

static void
free_get_secrets_info (gpointer data)
{
	GetSecretsInfo * info = (GetSecretsInfo *) data;

	g_free (info->setting_name);
	if (info->connection)
		g_object_unref (info->connection);
	g_object_unref (info->device);
	g_slice_free (GetSecretsInfo, info);
}

static void
get_secrets_cb (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	GetSecretsInfo *info = (GetSecretsInfo *) user_data;
	GError *err = NULL;
	GHashTable *secrets = NULL;

	g_return_if_fail (info != NULL);
	g_return_if_fail (info->manager);
	g_return_if_fail (info->connection);
	g_return_if_fail (info->setting_name);
	g_return_if_fail (info->device);

	g_object_set_data (G_OBJECT (info->connection), CONNECTION_GET_SECRETS_CALL_TAG, NULL);

	if (!dbus_g_proxy_end_call (proxy, call, &err,
								dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE), &secrets,
								G_TYPE_INVALID)) {
		nm_warning ("Couldn't get connection secrets: %s.", err->message);
		g_error_free (err);
		nm_device_interface_deactivate (info->device);
		return;
	}

	if (g_hash_table_size (secrets) > 0) {
		nm_connection_update_secrets (info->connection, info->setting_name, secrets);
		// FIXME: some better way to handle invalid message?
	} else {
		nm_warning ("GetSecrets call returned but no secrets were found.");
	}

	g_hash_table_destroy (secrets);
}

gboolean
nm_manager_get_connection_secrets (NMManager *manager,
                                   NMDeviceInterface *device,
                                   NMConnection *connection,
                                   const char *setting_name,
                                   gboolean request_new)
{
	DBusGProxy *proxy;
	GetSecretsInfo *info = NULL;
	DBusGProxyCall *call;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	proxy = g_object_get_data (G_OBJECT (connection), CONNECTION_PROXY_TAG);
	if (!DBUS_IS_G_PROXY (proxy)) {
		nm_warning ("Couldn't get dbus proxy for connection.");
		goto error;
	}

	info = g_slice_new0 (GetSecretsInfo);
	if (!info) {
		nm_warning ("Not enough memory to get secrets");
		goto error;
	}

	info->setting_name = g_strdup (setting_name);
	if (!info->setting_name) {
		nm_warning ("Not enough memory to get secrets");
		goto error;
	}

	info->connection = g_object_ref (connection);
	info->manager = manager;
	info->device = g_object_ref (device);

	call = dbus_g_proxy_begin_call_with_timeout (proxy, "GetSecrets",
	                                             get_secrets_cb,
	                                             info,
	                                             free_get_secrets_info,
	                                             G_MAXINT32,
	                                             G_TYPE_STRING, setting_name,
	                                             G_TYPE_BOOLEAN, request_new,
	                                             G_TYPE_INVALID);
	if (!call) {
		nm_warning ("Could not call GetSecrets");
		goto error;
	}

	g_object_set_data (G_OBJECT (connection), CONNECTION_GET_SECRETS_CALL_TAG, call);
	return TRUE;

error:
	if (info)
		free_get_secrets_info (info);
	return FALSE;
}

void
nm_manager_cancel_get_connection_secrets (NMManager *manager,
                                          NMConnection *connection)
{
	DBusGProxyCall *call;
	DBusGProxy *proxy;

	g_return_if_fail (NM_IS_MANAGER (manager));
	g_return_if_fail (NM_IS_CONNECTION (connection));

	proxy = g_object_get_data (G_OBJECT (connection), CONNECTION_PROXY_TAG);
	if (!DBUS_IS_G_PROXY (proxy))
		return;

	call = g_object_get_data (G_OBJECT (connection), CONNECTION_GET_SECRETS_CALL_TAG);
	if (!call)
		return;

	dbus_g_proxy_cancel_call (proxy, call);
	g_object_set_data (G_OBJECT (connection), CONNECTION_GET_SECRETS_CALL_TAG, NULL);
}

