#include <dbus/dbus-glib.h>
#include <string.h>
#include "nm-client.h"
#include "nm-device-802-3-ethernet.h"
#include "nm-device-802-11-wireless.h"
#include "nm-device-private.h"
#include "nm-marshal.h"

#include "nm-client-bindings.h"

G_DEFINE_TYPE (NMClient, nm_client, NM_TYPE_OBJECT)

#define NM_CLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CLIENT, NMClientPrivate))

typedef struct {
	DBusGProxy *client_proxy;
	DBusGProxy *bus_proxy;
	gboolean manager_running;
	NMState state;
	gboolean have_device_list;
	GHashTable *devices;

	DBusGProxy *vpn_proxy;
	NMVPNActStage vpn_state;
	gboolean have_vpn_connections;
	GHashTable *vpn_connections;
} NMClientPrivate;

enum {
	MANAGER_RUNNING,
	DEVICE_ADDED,
	DEVICE_REMOVED,
	STATE_CHANGE,

	VPN_CONNECTION_ADDED,
	VPN_CONNECTION_REMOVED,
	VPN_STATE_CHANGE,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void proxy_name_owner_changed (DBusGProxy *proxy,
									  const char *name,
									  const char *old_owner,
									  const char *new_owner,
									  gpointer user_data);

static void client_state_change_proxy (DBusGProxy *proxy, guint state, gpointer user_data);
static void client_device_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data);
static void client_device_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data);

static void setup_vpn_proxy (NMClient *client, DBusGConnection *connection);
static void clear_vpn_connections (NMClient * client);

static void
nm_client_init (NMClient *client)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

	priv->state = NM_STATE_UNKNOWN;
	priv->devices = g_hash_table_new_full (g_str_hash, g_str_equal,
										   (GDestroyNotify) g_free,
										   (GDestroyNotify) g_object_unref);

	priv->vpn_connections = g_hash_table_new_full (g_str_hash,
	                                               g_str_equal,
	                                               (GDestroyNotify) g_free,
	                                               (GDestroyNotify) g_object_unref);

	priv->vpn_state = NM_VPN_ACT_STAGE_UNKNOWN;
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	NMObject *object;
	DBusGConnection *connection;
	NMClientPrivate *priv;
	GError *err = NULL;

	object = (NMObject *) G_OBJECT_CLASS (nm_client_parent_class)->constructor (type,
																				n_construct_params,
																				construct_params);
	if (!object)
		return NULL;

	priv = NM_CLIENT_GET_PRIVATE (object);
	connection = nm_object_get_connection (object);

	priv->client_proxy = dbus_g_proxy_new_for_name (connection,
													NM_DBUS_SERVICE,
													nm_object_get_path (object),
													NM_DBUS_INTERFACE);

	dbus_g_proxy_add_signal (priv->client_proxy, "StateChange", G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->client_proxy,
								 "StateChange",
								 G_CALLBACK (client_state_change_proxy),
								 object,
								 NULL);

	dbus_g_proxy_add_signal (priv->client_proxy, "DeviceAdded", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->client_proxy,
								 "DeviceAdded",
								 G_CALLBACK (client_device_added_proxy),
								 object,
								 NULL);

	dbus_g_proxy_add_signal (priv->client_proxy, "DeviceRemoved", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->client_proxy,
								 "DeviceRemoved",
								 G_CALLBACK (client_device_removed_proxy),
								 object,
								 NULL);

	setup_vpn_proxy (NM_CLIENT (object), connection);

	priv->bus_proxy = dbus_g_proxy_new_for_name (connection,
												 "org.freedesktop.DBus",
												 "/org/freedesktop/DBus",
												 "org.freedesktop.DBus");

	dbus_g_proxy_add_signal (priv->bus_proxy, "NameOwnerChanged",
							 G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
							 G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->bus_proxy,
								 "NameOwnerChanged",
								 G_CALLBACK (proxy_name_owner_changed),
								 object, NULL);

	if (!dbus_g_proxy_call (priv->bus_proxy,
							"NameHasOwner", &err,
							G_TYPE_STRING, NM_DBUS_SERVICE,
							G_TYPE_INVALID,
							G_TYPE_BOOLEAN, &priv->manager_running,
							G_TYPE_INVALID)) {
		g_warning ("Error on NameHasOwner DBUS call: %s", err->message);
		g_error_free (err);
	}

	return G_OBJECT (object);
}

static void
finalize (GObject *object)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (object);

	g_object_unref (priv->vpn_proxy);
	g_object_unref (priv->client_proxy);
	g_object_unref (priv->bus_proxy);
	g_hash_table_destroy (priv->devices);
	g_hash_table_destroy (priv->vpn_connections);
}

static void
manager_running (NMClient *client, gboolean running)
{
	if (!running) {
		NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

		priv->state = NM_STATE_UNKNOWN;
		g_hash_table_remove_all (priv->devices);
		priv->have_device_list = FALSE;

		clear_vpn_connections (client);
		priv->have_vpn_connections = FALSE;
	}
}

static void
nm_client_class_init (NMClientClass *client_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (client_class);

	g_type_class_add_private (client_class, sizeof (NMClientPrivate));

	/* virtual methods */
	object_class->constructor = constructor;
	object_class->finalize = finalize;

	client_class->manager_running = manager_running;

	/* signals */
	signals[MANAGER_RUNNING] =
		g_signal_new ("manager-running",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, manager_running),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__BOOLEAN,
					  G_TYPE_NONE, 1,
					  G_TYPE_BOOLEAN);
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, device_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, device_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[STATE_CHANGE] =
		g_signal_new ("state-change",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, state_change),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1,
					  G_TYPE_UINT);

	signals[VPN_CONNECTION_ADDED] =
		g_signal_new ("vpn-connection-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, vpn_connection_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[VPN_CONNECTION_REMOVED] =
		g_signal_new ("vpn-connection-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, vpn_connection_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[VPN_STATE_CHANGE] =
		g_signal_new ("vpn-state-change",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMClientClass, state_change),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1,
					  G_TYPE_UINT);
}

NMClient *
nm_client_new (void)
{
	DBusGConnection *connection;
	GError *err = NULL;

	connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!connection) {
		g_warning ("Couldn't connect to system bus: %s", err->message);
		g_error_free (err);
		return NULL;
	}

	return (NMClient *) g_object_new (NM_TYPE_CLIENT,
									  NM_OBJECT_CONNECTION, connection,
									  NM_OBJECT_PATH, NM_DBUS_PATH,
									  NULL);
}

static void
proxy_name_owner_changed (DBusGProxy *proxy,
						  const char *name,
						  const char *old_owner,
						  const char *new_owner,
						  gpointer user_data)
{
	if (name && !strcmp (name, NM_DBUS_SERVICE)) {
		NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (user_data);

		if (new_owner && strlen (new_owner) > 0)
			priv->manager_running = TRUE;
		else
			priv->manager_running = FALSE;

		g_signal_emit (NM_CLIENT (user_data), signals[MANAGER_RUNNING], 0, priv->manager_running);
	}
}

static void
client_state_change_proxy (DBusGProxy *proxy, guint state, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->state != state) {
		priv->state = state;
		g_signal_emit (client, signals[STATE_CHANGE], 0, state);
	}
}

static NMDevice *
get_device (NMClient *client, const char *path, gboolean create_if_not_found)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	NMDevice *device;

	device = g_hash_table_lookup (priv->devices, path);
	if (!device && create_if_not_found) {
		DBusGConnection *connection;
		NMDeviceType type;

		connection = nm_object_get_connection (NM_OBJECT (client));
		type = nm_device_type_for_path (connection, path);

		switch (type) {
		case DEVICE_TYPE_802_3_ETHERNET:
			device = NM_DEVICE (nm_device_802_3_ethernet_new (connection, path));
			break;
		case DEVICE_TYPE_802_11_WIRELESS:
			device = NM_DEVICE (nm_device_802_11_wireless_new (connection, path));
			break;
		default:
			device = nm_device_new (connection, path);
		}

		if (device)
			g_hash_table_insert (priv->devices, g_strdup (path), device);
	}

	return device;
}

static void
client_device_added_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMDevice *device;

	device = get_device (client, path, TRUE);
	if (device)
		g_signal_emit (client, signals[DEVICE_ADDED], 0, device);
}

static void
client_device_removed_proxy (DBusGProxy *proxy, char *path, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMDevice *device;

	device = get_device (client, path, FALSE);
	if (device) {
		g_signal_emit (client, signals[DEVICE_REMOVED], 0, device);
		g_hash_table_remove (NM_CLIENT_GET_PRIVATE (client)->devices, path);
	}
}

gboolean
nm_client_manager_is_running (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return NM_CLIENT_GET_PRIVATE (client)->manager_running;
}

static void
devices_to_slist (gpointer key, gpointer value, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, value);
}

GSList *
nm_client_get_devices (NMClient *client)
{
	NMClientPrivate *priv;
	GSList *list = NULL;
	GPtrArray *array = NULL;
	GError *err = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->have_device_list) {
		g_hash_table_foreach (priv->devices, devices_to_slist, &list);
		return list;
	}

	if (!org_freedesktop_NetworkManager_get_devices (priv->client_proxy, &array, &err)) {
		g_warning ("Error in get_devices: %s", err->message);
		g_error_free (err);
	} else {
		int i;

		for (i = 0; i < array->len; i++) {
			NMDevice *device;

			device = get_device (client, (const char *) g_ptr_array_index (array, i), TRUE);
			if (device)
				list = g_slist_append (list, device);
		}

		g_ptr_array_free (array, TRUE);

		priv->have_device_list = TRUE;
	}

	return list;
}

NMDevice *
nm_client_get_device_by_path (NMClient *client, const char *object_path)
{
	GSList *devices;
	GSList *iter;
	NMDevice *device = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);
	g_return_val_if_fail (object_path, NULL);

	devices = nm_client_get_devices (client);
	for (iter = devices; iter; iter = iter->next) {
		if (!strcmp (nm_object_get_path (NM_OBJECT (iter->data)), object_path)) {
			device = NM_DEVICE (iter->data);
			break;
		}
	}
	g_slist_free (devices);

	return device;
}

gboolean
nm_client_wireless_get_enabled (NMClient *client)
{
	g_return_val_if_fail (NM_IS_CLIENT (client), FALSE);

	return nm_object_get_boolean_property (NM_OBJECT (client), NM_DBUS_INTERFACE, "WirelessEnabled");
}

void
nm_client_wireless_set_enabled (NMClient *client, gboolean enabled)
{
	GValue value = {0,};

	g_return_if_fail (NM_IS_CLIENT (client));

	g_value_init (&value, G_TYPE_BOOLEAN);
	g_value_set_boolean (&value, enabled);

	nm_object_set_property (NM_OBJECT (client),
							NM_DBUS_INTERFACE,
							"WirelessEnabled",
							&value);
}

NMState
nm_client_get_state (NMClient *client)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_STATE_UNKNOWN);

	priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->state == NM_STATE_UNKNOWN)
		priv->state = nm_object_get_uint_property (NM_OBJECT (client), NM_DBUS_INTERFACE, "State");

	return priv->state;
}

void
nm_client_sleep (NMClient *client, gboolean sleep)
{
	GError *err = NULL;

	g_return_if_fail (NM_IS_CLIENT (client));

	if (!org_freedesktop_NetworkManager_sleep (NM_CLIENT_GET_PRIVATE (client)->client_proxy, sleep, &err)) {
		g_warning ("Error in sleep: %s", err->message);
		g_error_free (err);
	}
}

/* VPN */

/*
 * This "best" state is the summary of all states from all connections and
 * available for convenience.
 * For the exact state, each connection has it's own state which' changes
 * are also signalled.
 */
static NMVPNActStage
nm_client_get_best_vpn_state (NMClient *client)
{
	GSList *iter;
	NMVPNActStage state;
	NMVPNActStage best_state = NM_VPN_ACT_STAGE_UNKNOWN;

	for (iter = nm_client_get_vpn_connections (client); iter; iter = iter->next) {
		state = nm_vpn_connection_get_state (NM_VPN_CONNECTION (iter->data));
		if (state > best_state && state < NM_VPN_ACT_STAGE_FAILED)
			best_state = state;
	}

	return best_state;
}

static void
proxy_vpn_state_change (DBusGProxy *proxy, char *connection_name, NMVPNActStage state, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	NMVPNConnection *connection;
	NMVPNActStage best_state;

	connection = nm_client_get_vpn_connection_by_name (client, connection_name);
	if (connection)
		nm_vpn_connection_set_state (connection, state);

	best_state = nm_client_get_best_vpn_state (client);
	if (best_state != priv->vpn_state) {
		priv->vpn_state = state;
		g_signal_emit (client, signals[VPN_STATE_CHANGE], 0, best_state);
	}
}

static void
proxy_vpn_connection_added (DBusGProxy *proxy, char *name, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	NMVPNConnection *connection;

	if (g_hash_table_lookup (priv->vpn_connections, name))
		return;

	connection = nm_vpn_connection_new (proxy, name);
	if (connection == NULL) {
		g_log (G_LOG_DOMAIN,
		       G_LOG_LEVEL_WARNING,
		       "Warning: out of memory creating NMVPNConnection for '%s'\n",
		       name);
		return;
	}

	g_hash_table_insert (priv->vpn_connections, name, connection);
	g_signal_emit (client, signals[VPN_CONNECTION_ADDED], 0, connection);
}

static void
proxy_vpn_connection_removed (DBusGProxy *proxy, char *name, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMVPNConnection *connection;

	connection = nm_client_get_vpn_connection_by_name (client, name);
	if (connection)
		nm_client_remove_vpn_connection (client, connection);
}

static void
proxy_vpn_connection_update (DBusGProxy *proxy, char *name, gpointer user_data)
{
	NMClient *client = NM_CLIENT (user_data);
	NMVPNConnection *connection;

	connection = nm_client_get_vpn_connection_by_name (client, name);
	if (connection)
		nm_vpn_connection_update (connection);
}

static void
setup_vpn_proxy (NMClient *client, DBusGConnection *connection)
{
	DBusGProxy *proxy;

	proxy = dbus_g_proxy_new_for_name (connection,
									   NM_DBUS_SERVICE,
									   NM_DBUS_PATH_VPN,
									   NM_DBUS_INTERFACE_VPN);

	dbus_g_object_register_marshaller (nm_marshal_VOID__STRING_INT,
									   G_TYPE_NONE, G_TYPE_STRING, G_TYPE_UINT, G_TYPE_INVALID);

	dbus_g_proxy_add_signal (proxy, "VPNConnectionStateChange", G_TYPE_STRING, G_TYPE_UINT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy, "VPNConnectionStateChange",
								 G_CALLBACK (proxy_vpn_state_change),
								 client, NULL);

	dbus_g_proxy_add_signal (proxy, "VPNConnectionAdded", G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy, "VPNConnectionAdded",
								 G_CALLBACK (proxy_vpn_connection_added),
								 client, NULL);

	dbus_g_proxy_add_signal (proxy, "VPNConnectionRemoved", G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy, "VPNConnectionRemoved",
								 G_CALLBACK (proxy_vpn_connection_removed),
								 client, NULL);

	dbus_g_proxy_add_signal (proxy, "VPNConnectionUpdate", G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (proxy, "VPNConnectionUpdate",
								 G_CALLBACK (proxy_vpn_connection_update),
								 client, NULL);

	NM_CLIENT_GET_PRIVATE (client)->vpn_proxy = proxy;
}

static void
get_connections (NMClient *client)
{
	NMClientPrivate *priv = NM_CLIENT_GET_PRIVATE (client);
	char **name;
	char **vpn_names = NULL;
	GError *err = NULL;

	if (!dbus_g_proxy_call (priv->vpn_proxy, "getVPNConnections", &err,
							G_TYPE_INVALID,
							G_TYPE_STRV, &vpn_names,
							G_TYPE_INVALID)) {
		g_warning ("Error while getting VPN connections: %s", err->message);
		g_error_free (err);
		return;
	}

	for (name = vpn_names; *name; name++)
		proxy_vpn_connection_added (priv->vpn_proxy, *name, client);
	g_strfreev (vpn_names);
}

static void
clear_one_vpn_connection (gpointer data,
                          gpointer user_data)
{
	NMClient * client = NM_CLIENT (user_data);
	NMVPNConnection * connection = NM_VPN_CONNECTION (data);

	g_signal_emit (client, signals[VPN_CONNECTION_REMOVED], 0, connection);
}

static void
clear_vpn_connections (NMClient * client)
{
	NMClientPrivate * priv;
	GSList * list;
	
	g_return_if_fail (NM_IS_CLIENT (client));

	priv = NM_CLIENT_GET_PRIVATE (client);

	list = nm_client_get_vpn_connections (client);
	g_hash_table_steal_all (priv->vpn_connections);

	g_slist_foreach (list, clear_one_vpn_connection, client);
	g_slist_foreach (list, (GFunc) g_object_unref, NULL);
	g_slist_free (list);
}

static void
vpn_connections_to_slist (gpointer key, gpointer value, gpointer user_data)
{
	GSList **list = (GSList **) user_data;

	*list = g_slist_prepend (*list, value);
}

GSList *
nm_client_get_vpn_connections (NMClient *client)
{
	NMClientPrivate *priv;
	GSList * list = NULL;

	g_return_val_if_fail (NM_IS_CLIENT (client), NULL);

	priv = NM_CLIENT_GET_PRIVATE (client);

	if (!priv->have_vpn_connections) {
		get_connections (client);
		priv->have_vpn_connections = TRUE;
	}

	g_hash_table_foreach (priv->vpn_connections,
	                      vpn_connections_to_slist,
	                      &list);
	return list;
}

NMVPNConnection *
nm_client_get_vpn_connection_by_name (NMClient *client, const char *name)
{
	NMClientPrivate *priv;
	GSList * list;
	
	g_return_if_fail (NM_IS_CLIENT (client));

	priv = NM_CLIENT_GET_PRIVATE (client);

	/* Ensure list of VPN connections is current */
	list = nm_client_get_vpn_connections (client);
	g_slist_free (list);

	return g_hash_table_lookup (priv->vpn_connections, name);
}

struct find_info {
	char * found_key;
	NMVPNConnection * connection;
};

static void
find_connection (gpointer key,
                 gpointer value,
                 gpointer user_data)
{
	struct find_info * info = (struct find_info *) user_data;

	if (info->connection == value)
		info->found_key = key;
}

void
nm_client_remove_vpn_connection (NMClient *client, NMVPNConnection *connection)
{
	NMClientPrivate *priv;
	struct find_info info = { NULL, NULL };
	
	g_return_if_fail (NM_IS_CLIENT (client));
	g_return_if_fail (NM_IS_VPN_CONNECTION (connection));

	/* Note that the connection isn't removed from NetworkManager, it's
	   because it doesn't have DBUS API for that right now. */

	priv = NM_CLIENT_GET_PRIVATE (client);

	info.connection = connection;
	g_hash_table_foreach (priv->vpn_connections, find_connection, &info);
	if (!info.found_key) {
		g_log (G_LOG_DOMAIN,
		       G_LOG_LEVEL_WARNING,
		       "Warning: tried to remove unknown NMVPNConnection object %p\n",
		       connection);
		return;
	}

	g_hash_table_steal (priv->vpn_connections, info.found_key);
	g_signal_emit (client, signals[VPN_CONNECTION_REMOVED], 0, connection);
	g_object_unref (connection);
}

NMVPNActStage
nm_client_get_vpn_state (NMClient *client)
{
	NMClientPrivate *priv;

	g_return_val_if_fail (NM_IS_CLIENT (client), NM_VPN_ACT_STAGE_UNKNOWN);

	priv = NM_CLIENT_GET_PRIVATE (client);

	if (priv->vpn_state == NM_VPN_ACT_STAGE_UNKNOWN)
		priv->vpn_state = nm_client_get_best_vpn_state (client);

	return priv->vpn_state;
}
