/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <netinet/ether.h>
#include <string.h>

#include "nm-manager.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"
#include "nm-device-interface.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerSystem.h"
#include "nm-properties-changed-signal.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"
#include "nm-marshal.h"

static gboolean impl_manager_get_devices (NMManager *manager, GPtrArray **devices, GError **err);
static void impl_manager_activate_device (NMManager *manager,
								  char *device_path,
								  char *service_name,
								  char *connection_path,
								  char *specific_object_path,
								  DBusGMethodInvocation *context);

static gboolean impl_manager_get_active_connections (NMManager *manager,
                                                     GPtrArray **connections,
                                                     GError **err);

static gboolean impl_manager_sleep (NMManager *manager, gboolean sleep, GError **err);

static const char * nm_manager_get_connection_dbus_path (NMManager *manager,
                                                         NMConnection *connection);

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

	NMDBusManager *dbus_mgr;

	GHashTable *user_connections;
	DBusGProxy *user_proxy;

	GHashTable *system_connections;
	DBusGProxy *system_proxy;

	PendingConnectionInfo *pending_connection_info;
	gboolean wireless_enabled;
	gboolean wireless_hw_enabled;
	gboolean sleeping;
} NMManagerPrivate;

#define NM_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MANAGER, NMManagerPrivate))

G_DEFINE_TYPE (NMManager, nm_manager, G_TYPE_OBJECT)

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	STATE_CHANGE,
	PROPERTIES_CHANGED,
	CONNECTIONS_ADDED,
	CONNECTION_ADDED,
	CONNECTION_UPDATED,
	CONNECTION_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_STATE,
	PROP_WIRELESS_ENABLED,
	PROP_WIRELESS_HARDWARE_ENABLED,

	LAST_PROP
};

typedef enum
{
	NM_MANAGER_ERROR_UNKNOWN_CONNECTION = 0,
	NM_MANAGER_ERROR_UNKNOWN_DEVICE,
	NM_MANAGER_ERROR_INVALID_SERVICE,
	NM_MANAGER_ERROR_SYSTEM_CONNECTION,
	NM_MANAGER_ERROR_PERMISSION_DENIED,
} NMManagerError;

#define NM_MANAGER_ERROR (nm_manager_error_quark ())
#define NM_TYPE_MANAGER_ERROR (nm_manager_error_get_type ()) 

static GQuark
nm_manager_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-manager-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_manager_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection was not provided by any known settings service. */
			ENUM_ENTRY (NM_MANAGER_ERROR_UNKNOWN_CONNECTION, "UnknownConnection"),
			/* Unknown device. */
			ENUM_ENTRY (NM_MANAGER_ERROR_UNKNOWN_DEVICE, "UnknownDevice"),
			/* Invalid settings service (not a recognized system or user
			 * settings service name)
			 */
			ENUM_ENTRY (NM_MANAGER_ERROR_INVALID_SERVICE, "InvalidService"),
			/* Connection was superceded by a system connection. */
			ENUM_ENTRY (NM_MANAGER_ERROR_SYSTEM_CONNECTION, "SystemConnection"),
			/* User does not have the permission to activate this connection. */
			ENUM_ENTRY (NM_MANAGER_ERROR_PERMISSION_DENIED, "PermissionDenied"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMManagerError", values);
	}
	return etype;
}

static void
nm_manager_init (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	priv->wireless_enabled = TRUE;
	priv->wireless_hw_enabled = TRUE;
	priv->sleeping = FALSE;
	priv->state = NM_STATE_DISCONNECTED;

	priv->dbus_mgr = nm_dbus_manager_get ();

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
pending_connection_info_destroy (PendingConnectionInfo *info)
{
	if (!info)
		return;

	if (info->timeout_id)
		g_source_remove (info->timeout_id);

	g_free (info->connection_path);
	g_free (info->specific_object_path);
	g_object_unref (info->device);

	g_slice_free (PendingConnectionInfo, info);
}

static void
finalize (GObject *object)
{
	NMManager *manager = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	pending_connection_info_destroy (priv->pending_connection_info);
	priv->pending_connection_info = NULL;

	nm_manager_connections_destroy (manager, NM_CONNECTION_TYPE_USER);
	g_hash_table_destroy (priv->user_connections);
	priv->user_connections = NULL;

	nm_manager_connections_destroy (manager, NM_CONNECTION_TYPE_SYSTEM);
	g_hash_table_destroy (priv->system_connections);
	priv->system_connections = NULL;

	while (g_slist_length (priv->devices))
		nm_manager_remove_device (manager, NM_DEVICE (priv->devices->data), TRUE);

	if (priv->dbus_mgr)
		g_object_unref (priv->dbus_mgr);

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
	case PROP_WIRELESS_HARDWARE_ENABLED:
		nm_manager_set_wireless_hardware_enabled (NM_MANAGER (object), g_value_get_boolean (value));
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
	case PROP_WIRELESS_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->wireless_hw_enabled);
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

	g_object_class_install_property
		(object_class, PROP_WIRELESS_HARDWARE_ENABLED,
		 g_param_spec_boolean (NM_MANAGER_WIRELESS_HARDWARE_ENABLED,
						   "WirelessHardwareEnabled",
						   "RF kill state",
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

	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class,
								    G_STRUCT_OFFSET (NMManagerClass, properties_changed));

	signals[CONNECTIONS_ADDED] =
		g_signal_new ("connections-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMManagerClass, connections_added),
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

	signals[CONNECTION_UPDATED] =
		g_signal_new ("connection-updated",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMManagerClass, connection_updated),
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

	dbus_g_error_domain_register (NM_MANAGER_ERROR, NULL, NM_TYPE_MANAGER_ERROR);
}

#define DBUS_TYPE_G_STRING_VARIANT_HASHTABLE (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, G_TYPE_VALUE))
#define DBUS_TYPE_G_DICT_OF_DICTS (dbus_g_type_get_map ("GHashTable", G_TYPE_STRING, DBUS_TYPE_G_STRING_VARIANT_HASHTABLE))

static NMConnectionType
get_type_for_proxy (DBusGProxy *proxy)
{
	const char *bus_name = dbus_g_proxy_get_bus_name (proxy);

	if (strcmp (bus_name, NM_DBUS_SERVICE_USER_SETTINGS) == 0)
		return NM_CONNECTION_TYPE_USER;
	else if (strcmp (bus_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS) == 0)
		return NM_CONNECTION_TYPE_SYSTEM;

	return NM_CONNECTION_TYPE_UNKNOWN;
}

typedef struct GetSettingsInfo {
	NMManager *manager;
	NMConnection *connection;
	DBusGProxy *proxy;
	DBusGProxyCall *call;
	DBusGProxy *secrets_proxy;
	GSList **calls;
} GetSettingsInfo;

static void
free_get_settings_info (gpointer data)
{
	GetSettingsInfo *info = (GetSettingsInfo *) data;

	/* If this was the last pending call for a batch of GetSettings calls,
	 * send out the connections-added signal.
	 */
	if (info->calls) {
		*(info->calls) = g_slist_remove (*(info->calls), info->call);
		if (g_slist_length (*(info->calls)) == 0) {
			g_slist_free (*(info->calls));
			g_signal_emit (info->manager,
			               signals[CONNECTIONS_ADDED],
			               0,
			               get_type_for_proxy (info->proxy));
		}
	}

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
	NMConnectionType type;
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
		NMManagerPrivate *priv;

		connection = nm_connection_new_from_hash (settings);
		if (connection == NULL)
			goto out;

		g_object_set_data_full (G_OBJECT (connection),
		                        NM_MANAGER_CONNECTION_PROXY_TAG,
		                        proxy,
		                        (GDestroyNotify) g_object_unref);

		g_object_set_data_full (G_OBJECT (connection),
		                        NM_MANAGER_CONNECTION_SECRETS_PROXY_TAG,
		                        info->secrets_proxy,
		                        (GDestroyNotify) g_object_unref);

		priv = NM_MANAGER_GET_PRIVATE (manager);
		type = get_type_for_proxy (proxy);
		switch (type) {
			case NM_CONNECTION_TYPE_USER:
				g_hash_table_insert (priv->user_connections,
				                     g_strdup (path),
				                     connection);
				break;
			case NM_CONNECTION_TYPE_SYSTEM:
				g_hash_table_insert (priv->system_connections,
				                     g_strdup (path),
				                     connection);
				break;
			default:
				nm_warning ("Connection wasn't a user connection or a system connection.");
				g_assert_not_reached ();
				break;
		}

		g_object_set_data (G_OBJECT (connection),
		                   NM_MANAGER_CONNECTION_TYPE_TAG,
		                   GUINT_TO_POINTER (type));

		/* If the connection-added signal is supposed to be batched, don't
		 * emit the single connection-added here.
		 */
		if (!info->calls)
			g_signal_emit (manager, signals[CONNECTION_ADDED], 0, connection, type);
	} else {
		// FIXME: merge settings? or just replace?
		nm_warning ("%s (#%d): implement merge settings", __func__, __LINE__);
	}

out:
	if (settings)
		g_hash_table_destroy (settings);

	return;
}

static NMConnection *
get_connection_for_proxy (NMManager *manager,
                          DBusGProxy *proxy,
                          GHashTable **out_hash,
                          const char **out_path)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMConnection *connection = NULL;
	const char *path = dbus_g_proxy_get_path (proxy);

	if (out_path)
		*out_path = path;

	switch (get_type_for_proxy (proxy)) {
		case NM_CONNECTION_TYPE_USER:
			*out_hash = priv->user_connections;
			connection = g_hash_table_lookup (priv->user_connections, path);
			break;
		case NM_CONNECTION_TYPE_SYSTEM:
			*out_hash = priv->system_connections;
			connection = g_hash_table_lookup (priv->system_connections, path);
			break;
		default:
			nm_warning ("Connection wasn't a user connection or a system connection.");
			g_assert_not_reached ();
			break;
	}
	return connection;
}

static void
remove_connection (NMManager *manager,
                   NMConnection *connection,
                   GHashTable *hash,
                   const char *path)
{
	NMConnectionType type;

	/* Destroys the connection, then associated DBusGProxy due to the
	 * weak reference notify function placed on the connection when it
	 * was created.
	 */
	g_object_ref (connection);
	g_hash_table_remove (hash, path);
	type = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), NM_MANAGER_CONNECTION_TYPE_TAG));
	g_signal_emit (manager, signals[CONNECTION_REMOVED], 0, connection, type);
	g_object_unref (connection);
}

static void
connection_removed_cb (DBusGProxy *proxy, gpointer user_data)
{
	NMManager * manager = NM_MANAGER (user_data);
	NMConnection *connection = NULL;
	GHashTable *hash = NULL;
	const char *path;

	connection = get_connection_for_proxy (manager, proxy, &hash, &path);
	if (connection)
		remove_connection (manager, connection, hash, path);
}

static void
connection_updated_cb (DBusGProxy *proxy, GHashTable *settings, gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMConnection *new_connection;
	NMConnection *old_connection;
	GHashTable *hash;
	const char *path;
	gboolean valid = FALSE;

	old_connection = get_connection_for_proxy (manager, proxy, &hash, &path);
	if (!old_connection)
		return;

	new_connection = nm_connection_new_from_hash (settings);
	if (!new_connection) {
		/* New connection invalid, remove existing connection */
		remove_connection (manager, old_connection, hash, path);
		return;
	}
	g_object_unref (new_connection);

	valid = nm_connection_replace_settings (old_connection, settings);
	if (valid) {
		NMConnectionType type;

		type = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (old_connection),
		                                            NM_MANAGER_CONNECTION_TYPE_TAG));
		g_signal_emit (manager, signals[CONNECTION_UPDATED], 0, old_connection, type);
	} else {
		remove_connection (manager, old_connection, hash, path);
	}
}

static void
internal_new_connection_cb (DBusGProxy *proxy,
                            const char *path,
                            NMManager *manager,
                            GSList **calls)
{
	struct GetSettingsInfo *info;
	DBusGProxy *con_proxy;
	DBusGConnection * g_connection;
	DBusGProxyCall *call;
	DBusGProxy *secrets_proxy;
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	con_proxy = dbus_g_proxy_new_for_name (g_connection,
	                                       dbus_g_proxy_get_bus_name (proxy),
	                                       path,
	                                       NM_DBUS_IFACE_SETTINGS_CONNECTION);
	if (!con_proxy) {
		nm_warning ("Error: could not init user connection proxy");
		return;
	}

	secrets_proxy = dbus_g_proxy_new_for_name (g_connection,
	                                           dbus_g_proxy_get_bus_name (proxy),
	                                           path,
	                                           NM_DBUS_IFACE_SETTINGS_CONNECTION_SECRETS);
	if (!secrets_proxy) {
		nm_warning ("Error: could not init user connection secrets proxy");
		g_object_unref (con_proxy);
		return;
	}

	dbus_g_proxy_add_signal (con_proxy, "Updated",
	                         DBUS_TYPE_G_DICT_OF_DICTS,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (con_proxy, "Updated",
	                             G_CALLBACK (connection_updated_cb),
	                             manager,
	                             NULL);

	dbus_g_proxy_add_signal (con_proxy, "Removed", G_TYPE_INVALID, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (con_proxy, "Removed",
	                             G_CALLBACK (connection_removed_cb),
	                             manager,
	                             NULL);

	info = g_slice_new0 (GetSettingsInfo);
	info->manager = g_object_ref (manager);
	info->calls = calls;
	call = dbus_g_proxy_begin_call (con_proxy, "GetSettings",
	                                connection_get_settings_cb,
	                                info,
	                                free_get_settings_info,
	                                G_TYPE_INVALID);
	info->call = call;
	info->proxy = con_proxy;
	info->secrets_proxy = secrets_proxy;
	if (info->calls)
		*(info->calls) = g_slist_prepend (*(info->calls), call);
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
	GSList **calls = NULL;
	int i;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH, &ops,
	                            G_TYPE_INVALID)) {
		nm_warning ("Couldn't retrieve connections: %s.", err->message);
		g_error_free (err);
		goto out;
	}

	/* Keep track of all calls made here; don't want to emit connection-added for
	 * each one, but emit connections-added when they are all done.
	 */
	calls = g_slice_new0 (GSList *);

	for (i = 0; i < ops->len; i++) {
		internal_new_connection_cb (proxy,
		                            g_ptr_array_index (ops, i),
		                            manager,
		                            calls);
	}

	g_ptr_array_free (ops, TRUE);

out:
	return;
}

static void
new_connection_cb (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	internal_new_connection_cb (proxy, path, NM_MANAGER (user_data), NULL);
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
		DBusGConnection * g_connection;

		g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
		*proxy = dbus_g_proxy_new_for_name (g_connection,
		                                    service,
		                                    NM_DBUS_PATH_SETTINGS,
		                                    NM_DBUS_IFACE_SETTINGS);
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
	                                    NM_DBUS_SERVICE_SYSTEM_SETTINGS))
		query_connections (manager, NM_CONNECTION_TYPE_SYSTEM);

	if (nm_dbus_manager_name_has_owner (nm_dbus_manager_get (),
	                                    NM_DBUS_SERVICE_USER_SETTINGS))
		query_connections (manager, NM_CONNECTION_TYPE_USER);

	return FALSE;
}


NMManager *
nm_manager_new (void)
{
	GObject *object;
	NMManagerPrivate *priv;

	object = g_object_new (NM_TYPE_MANAGER, NULL);
	priv = NM_MANAGER_GET_PRIVATE (object);

	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                     NM_DBUS_PATH,
	                                     object);

	g_signal_connect (priv->dbus_mgr,
	                  "name-owner-changed",
	                  G_CALLBACK (nm_manager_name_owner_changed),
	                  NM_MANAGER (object));

	g_idle_add ((GSourceFunc) initial_get_connections, NM_MANAGER (object));

	return NM_MANAGER (object);
}

static void
emit_removed (gpointer key, gpointer value, gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMConnection *connection = NM_CONNECTION (value);
	NMConnectionType type;

	type = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), NM_MANAGER_CONNECTION_TYPE_TAG));
	g_signal_emit (manager, signals[CONNECTION_REMOVED], 0, connection, type);
}

static void
nm_manager_connections_destroy (NMManager *manager,
                                NMConnectionType type)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	if (type == NM_CONNECTION_TYPE_USER) {
		if (priv->user_connections) {
			g_hash_table_foreach (priv->user_connections, emit_removed, manager);
			g_hash_table_remove_all (priv->user_connections);
		}

		if (priv->user_proxy) {
			g_object_unref (priv->user_proxy);
			priv->user_proxy = NULL;
		}
	} else if (type == NM_CONNECTION_TYPE_SYSTEM) {
		if (priv->system_connections) {
			g_hash_table_foreach (priv->system_connections, emit_removed, manager);
			g_hash_table_remove_all (priv->system_connections);
		}

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

	/* Can't set wireless enabled if it's disabled in hardware */
	if (!priv->wireless_hw_enabled && enabled)
		return;

	priv->wireless_enabled = enabled;

	g_object_notify (G_OBJECT (manager), NM_MANAGER_WIRELESS_ENABLED);

	/* Don't touch devices if asleep/networking disabled */
	if (priv->sleeping)
		return;

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

static void
manager_hidden_ap_found (NMDeviceInterface *device,
                         NMAccessPoint *ap,
                         gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	const struct ether_addr *ap_addr;
	const GByteArray *ap_ssid;
	GSList *iter;
	GSList *connections;
	gboolean done = FALSE;

	ap_ssid = nm_ap_get_ssid (ap);
	if (ap_ssid && ap_ssid->len)
		return;

	ap_addr = nm_ap_get_address (ap);
	g_assert (ap_addr);

	/* Look for this AP's BSSID in the seen-bssids list of a connection,
	 * and if a match is found, copy over the SSID */
	connections = nm_manager_get_connections (manager, NM_CONNECTION_TYPE_SYSTEM);
	connections = g_slist_concat (connections,  nm_manager_get_connections (manager, NM_CONNECTION_TYPE_USER));

	for (iter = connections; iter && !done; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingWireless *s_wireless;
		GSList *seen_iter;
		
		s_wireless = (NMSettingWireless *) nm_connection_get_setting (connection, NM_TYPE_SETTING_WIRELESS);
		if (!s_wireless || !s_wireless->seen_bssids)
			goto next;
		g_assert (s_wireless->ssid);

		for (seen_iter = s_wireless->seen_bssids; seen_iter; seen_iter = g_slist_next (seen_iter)) {
			struct ether_addr seen_addr;

			if (!ether_aton_r ((char *) seen_iter->data, &seen_addr))
				continue;

			if (memcmp (ap_addr, &seen_addr, sizeof (struct ether_addr)))
				continue;

			/* Copy the SSID from the connection to the AP */
			nm_ap_set_ssid (ap, s_wireless->ssid);
			done = TRUE;
		}

next:
		g_object_unref (connection);
	}
	g_slist_free (connections);
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

	/* Attach to the access-point-added signal so that the manager can fill
	 * non-SSID-broadcasting APs with an SSID.
	 */
	if (NM_IS_DEVICE_802_11_WIRELESS (device)) {
		g_signal_connect (device, "hidden-ap-found",
						  G_CALLBACK (manager_hidden_ap_found),
						  manager);
	}

	if (!priv->sleeping) {
		if (!NM_IS_DEVICE_802_11_WIRELESS (device) || priv->wireless_enabled) {
			nm_device_bring_down (device, TRUE);
			nm_device_bring_up (device, TRUE);
		}
	}

	nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));

	nm_info ("(%s): exported as %s",
		    nm_device_get_iface (device),
		    nm_device_get_udi (device));
	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (priv->dbus_mgr),
								  nm_device_get_udi (device),
								  G_OBJECT (device));

	manager_device_added (manager, device);
}

static void
manager_device_removed (NMManager *manager, NMDevice *device)
{
	g_signal_emit (manager, signals[DEVICE_REMOVED], 0, device);
}
 
void
nm_manager_remove_device (NMManager *manager, NMDevice *device, gboolean deactivate)
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
			if (deactivate)
				nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));

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
		g_ptr_array_add (*devices, g_strdup (nm_device_get_udi (NM_DEVICE (iter->data))));

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

		if (!strcmp (nm_device_get_udi (device), path))
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

static gboolean
check_connection_allowed (NMManager *manager,
                          NMDeviceInterface *dev_iface,
                          NMConnection *connection,
                          const char *specific_object,
                          GError **error)
{
	NMSettingConnection *s_con;
	GSList *system_connections;
	GSList *iter;
	gboolean allowed = TRUE;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_return_val_if_fail (s_con != NULL, FALSE);

	system_connections = nm_manager_get_connections (manager, NM_CONNECTION_TYPE_SYSTEM);
	for (iter = system_connections; iter; iter = g_slist_next (iter)) {
		NMConnection *system_connection = NM_CONNECTION (iter->data);

		if (connection == system_connection)
			continue;

		if (nm_device_interface_check_connection_conflicts (dev_iface,
		                                                    connection,
		                                                    system_connection)) {
			allowed = FALSE;
			break;
		}
	}

	g_slist_foreach (system_connections, (GFunc) g_object_unref, NULL);

	return allowed;
}

gboolean
nm_manager_activate_device (NMManager *manager,
					   NMDevice *device,
					   NMConnection *connection,
					   const char *specific_object,
					   gboolean user_requested,
					   GError **error)
{
	NMActRequest *req;
	NMDeviceInterface *dev_iface;
	gboolean success;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);
	g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	dev_iface = NM_DEVICE_INTERFACE (device);

	/* Ensure the requested connection is allowed to be activated */
	if (!check_connection_allowed (manager, dev_iface, connection, specific_object, error))
		return FALSE;

	req = nm_act_request_new (connection, specific_object, user_requested);
	success = nm_device_interface_activate (dev_iface, req, error);
	g_object_unref (req);

	return success;
}

gboolean
nm_manager_activation_pending (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	return NM_MANAGER_GET_PRIVATE (manager)->pending_connection_info != NULL;
}

static gboolean
wait_for_connection_expired (gpointer data)
{
	NMManager *manager = NM_MANAGER (data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	PendingConnectionInfo *info = priv->pending_connection_info;
	GError *error = NULL;

	g_return_val_if_fail (info != NULL, FALSE);

	nm_info ("%s: didn't receive connection details soon enough for activation.",
	         nm_device_get_iface (info->device));

	g_set_error (&error,
	             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
	             "%s", "Connection was not provided by any settings service");
	nm_warning ("Failed to activate device %s: (%d) %s",
	            nm_device_get_iface (info->device),
	            error->code,
	            error->message);
	dbus_g_method_return_error (info->context, error);
	g_error_free (error);

	info->timeout_id = 0;
	pending_connection_info_destroy (priv->pending_connection_info);
	priv->pending_connection_info = NULL;

	return FALSE;
}

/* ICK ICK ICK; should go away with multiple device support.  There is
 * corresponding code in NetworkManagerPolicy.c that handles this for
 * automatically activated connections.
 */
static void
deactivate_old_device (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMDevice *device = NULL;
	GSList *iter;

	switch (priv->state) {
	case NM_STATE_CONNECTED:
		device = nm_manager_get_active_device (manager);
		break;
	case NM_STATE_CONNECTING:
		for (iter = nm_manager_get_devices (manager); iter; iter = iter->next) {
			NMDevice *d = NM_DEVICE (iter->data);

			if (nm_device_is_activating (d)) {
				device = d;
				break;
			}
		}
		break;
	default:
		break;
	}

	if (device)
		nm_device_interface_deactivate (NM_DEVICE_INTERFACE (device));
}

static void
connection_added_default_handler (NMManager *manager,
						    NMConnection *connection,
						    NMConnectionType connection_type)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	PendingConnectionInfo *info = priv->pending_connection_info;
	const char *path;
	gboolean success;
	GError *error = NULL;

	if (!info)
		return;

	if (connection_type != info->connection_type)
		return;

	path = nm_manager_get_connection_dbus_path (manager, connection);
	if (strcmp (info->connection_path, path))
		return;

	/* Will destroy below; can't be valid during the initial activation start */
	priv->pending_connection_info = NULL;

	// FIXME: remove old_dev deactivation when multiple device support lands
	deactivate_old_device (manager);

	success = nm_manager_activate_device (manager,
	                                      info->device,
	                                      connection,
	                                      info->specific_object_path,
	                                      TRUE,
	                                      &error);
	if (success)
		dbus_g_method_return (info->context, TRUE);
	else {
		dbus_g_method_return_error (info->context, error);
		nm_warning ("Failed to activate device %s: (%d) %s",
		            nm_device_get_iface (info->device),
		            error->code,
		            error->message);
		g_error_free (error);
	}

	pending_connection_info_destroy (info);
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
	GError *error = NULL;
	char *real_sop = NULL;

	device = nm_manager_get_device_by_path (manager, device_path);
	if (!device) {
		g_set_error (&error,
		             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
		             "%s", "Device not found");
		goto err;
	}

	nm_info ("User request for activation of %s.", nm_device_get_iface (device));

	if (!strcmp (service_name, NM_DBUS_SERVICE_USER_SETTINGS))
		connection_type = NM_CONNECTION_TYPE_USER;
	else if (!strcmp (service_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS))
		connection_type = NM_CONNECTION_TYPE_SYSTEM;
	else {
		g_set_error (&error,
		             NM_MANAGER_ERROR, NM_MANAGER_ERROR_INVALID_SERVICE,
		             "%s", "Invalid settings service name");
		goto err;
	}

	/* "/" is special-cased to NULL to get through D-Bus */
	if (specific_object_path && strcmp (specific_object_path, "/"))
		real_sop = g_strdup (specific_object_path);

	connection = nm_manager_get_connection_by_object_path (manager, connection_type, connection_path);
	if (connection) {
		gboolean success;

		// FIXME: remove old_dev deactivation when multiple device support lands
		deactivate_old_device (manager);

		success = nm_manager_activate_device (manager,
		                                      device,
		                                      connection,
		                                      real_sop,
		                                      TRUE,
		                                      &error);
		if (success)
			dbus_g_method_return (context, TRUE);
	} else {
		PendingConnectionInfo *info;
		NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

		if (priv->pending_connection_info) {
			pending_connection_info_destroy (priv->pending_connection_info);
			priv->pending_connection_info = NULL;
		}

		/* Don't have the connection quite yet, probably created by
		 * the client on-the-fly.  Defer the activation until we have it
		 */

		info = g_slice_new0 (PendingConnectionInfo);
		info->context = context;
		info->device = g_object_ref (device);
		info->connection_type = connection_type;
		info->connection_path = g_strdup (connection_path);
		info->specific_object_path = g_strdup (real_sop);
		info->timeout_id = g_timeout_add (5000, wait_for_connection_expired, manager);

		// FIXME: should probably be per-device, not global to the manager
		NM_MANAGER_GET_PRIVATE (manager)->pending_connection_info = info;
	}

 err:
	if (error) {
		dbus_g_method_return_error (context, error);
		nm_warning ("Failed to activate device %s: (%d) %s",
		            nm_device_get_iface (device),
		            error->code,
		            error->message);
		g_error_free (error);
	}

	g_free (real_sop);
}

static GValueArray *
add_one_connection_element (NMManager *manager,
                            NMDevice *device)
{
	static GType type = 0, ao_type = 0;
	GValue entry = {0, };
	GPtrArray *dev_array = NULL;
	NMActRequest *req;
	const char *service_name = NULL;
	NMConnection *connection;
	const char *specific_object;
	gpointer type_ptr;

	req = nm_device_get_act_request (device);
 	g_assert (req);

	connection = nm_act_request_get_connection (req);
	type_ptr = g_object_get_data (G_OBJECT (connection), NM_MANAGER_CONNECTION_TYPE_TAG);
	g_return_val_if_fail (type_ptr != NULL, NULL);

	switch ((NMConnectionType) GPOINTER_TO_UINT (type_ptr)) {
		case NM_CONNECTION_TYPE_USER:
			service_name = NM_DBUS_SERVICE_USER_SETTINGS;
			break;
		case NM_CONNECTION_TYPE_SYSTEM:
			service_name = NM_DBUS_SERVICE_SYSTEM_SETTINGS;
			break;
		default:
			g_assert_not_reached ();
			break;
	}

	specific_object = nm_act_request_get_specific_object (req);

	/* dbus signature "sooao" */
	if (G_UNLIKELY (ao_type) == 0)
		ao_type = dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_OBJECT_PATH);
	if (G_UNLIKELY (type) == 0) {
		type = dbus_g_type_get_struct ("GValueArray",
		                               G_TYPE_STRING,
		                               DBUS_TYPE_G_OBJECT_PATH,
		                               DBUS_TYPE_G_OBJECT_PATH,
		                               ao_type,
		                               G_TYPE_INVALID);
	}

	dev_array = g_ptr_array_sized_new (1);
	if (!dev_array)
		return NULL;
	g_ptr_array_add (dev_array, g_strdup (nm_device_get_udi (device)));

	g_value_init (&entry, type);
	g_value_take_boxed (&entry, dbus_g_type_specialized_construct (type));
	dbus_g_type_struct_set (&entry,
	                        0, service_name,
	                        1, nm_manager_get_connection_dbus_path (manager, connection),
	                        2, specific_object ? specific_object : "/",
	                        3, dev_array,
	                        G_MAXUINT);
	return g_value_get_boxed (&entry);
}

static gboolean
impl_manager_get_active_connections (NMManager *manager,
                                     GPtrArray **connections,
                                     GError **err)
{
	NMManagerPrivate *priv;
	GSList *iter;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	priv = NM_MANAGER_GET_PRIVATE (manager);

	// GPtrArray of GValueArrays of (gchar * and GPtrArray of gchar *)
	*connections = g_ptr_array_sized_new (1);

	// FIXME: this assumes one active device per connection
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *dev = NM_DEVICE (iter->data);
		GValueArray *item;

		if (   (nm_device_get_state (dev) != NM_DEVICE_STATE_ACTIVATED)
		    && !nm_device_is_activating (dev))
			continue;

		item = add_one_connection_element (manager, dev);
		if (!item)
			continue;

		g_ptr_array_add (*connections, item);
	}

	return TRUE;
}

gboolean
nm_manager_wireless_enabled (NMManager *manager)
{
	gboolean enabled;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	g_object_get (manager, NM_MANAGER_WIRELESS_ENABLED, &enabled, NULL);

	return enabled;
}

gboolean
nm_manager_wireless_hardware_enabled (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	return NM_MANAGER_GET_PRIVATE (manager)->wireless_hw_enabled;
}

void
nm_manager_set_wireless_hardware_enabled (NMManager *manager,
								  gboolean enabled)
{
	NMManagerPrivate *priv;

	g_return_if_fail (NM_IS_MANAGER (manager));

	priv = NM_MANAGER_GET_PRIVATE (manager);

	if (priv->wireless_hw_enabled != enabled) {
		nm_info ("Wireless now %s by radio killswitch", enabled ? "enabled" : "disabled");
		priv->wireless_hw_enabled = enabled;
		g_object_notify (G_OBJECT (manager), NM_MANAGER_WIRELESS_HARDWARE_ENABLED);

		manager_set_wireless_enabled (manager, enabled);
	}
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
			nm_manager_remove_device (manager, NM_DEVICE (priv->devices->data), FALSE);

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

static int
connection_sort (gconstpointer pa, gconstpointer pb)
{
	NMConnection *a = NM_CONNECTION (pa);
	NMSettingConnection *con_a;
	NMConnection *b = NM_CONNECTION (pb);
	NMSettingConnection *con_b;

	con_a = (NMSettingConnection *) nm_connection_get_setting (a, NM_TYPE_SETTING_CONNECTION);
	g_assert (con_a);
	con_b = (NMSettingConnection *) nm_connection_get_setting (b, NM_TYPE_SETTING_CONNECTION);
	g_assert (con_b);

	if (con_a->autoconnect != con_b->autoconnect) {
		if (con_a->autoconnect)
			return -1;
		return 1;
	}

	if (con_a->timestamp > con_b->timestamp)
		return -1;
	else if (con_a->timestamp == con_b->timestamp)
		return 0;
	return 1;
}

static void
connections_to_slist (gpointer key, gpointer value, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_insert_sorted (*list, g_object_ref (value), connection_sort);
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

static const char *
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

