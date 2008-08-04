/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <netinet/ether.h>
#include <string.h>

#include "nm-manager.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"
#include "nm-vpn-manager.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-device-wifi.h"
#include "NetworkManagerSystem.h"
#include "nm-properties-changed-signal.h"
#include "nm-setting-connection.h"
#include "nm-setting-wireless.h"
#include "nm-setting-vpn.h"
#include "nm-marshal.h"
#include "nm-dbus-glib-types.h"
#include "nm-hal-manager.h"

#define NM_AUTOIP_DBUS_SERVICE "org.freedesktop.nm_avahi_autoipd"
#define NM_AUTOIP_DBUS_IFACE   "org.freedesktop.nm_avahi_autoipd"

static gboolean impl_manager_get_devices (NMManager *manager, GPtrArray **devices, GError **err);
static void impl_manager_activate_connection (NMManager *manager,
								  const char *service_name,
								  const char *connection_path,
								  const char *device_path,
								  const char *specific_object_path,
								  DBusGMethodInvocation *context);

static gboolean impl_manager_deactivate_connection (NMManager *manager,
                                                    const char *connection_path,
                                                    GError **error);

static gboolean impl_manager_sleep (NMManager *manager, gboolean sleep, GError **err);

static gboolean poke_system_settings_daemon_cb (gpointer user_data);

/* Legacy 0.6 compatibility interface */

static gboolean impl_manager_legacy_sleep (NMManager *manager, GError **err);
static gboolean impl_manager_legacy_wake  (NMManager *manager, GError **err);
static gboolean impl_manager_legacy_state (NMManager *manager, guint32 *state, GError **err);

#include "nm-manager-glue.h"

static void nm_manager_connections_destroy (NMManager *manager, NMConnectionScope scope);
static void manager_set_wireless_enabled (NMManager *manager, gboolean enabled);

static void connection_added_default_handler (NMManager *manager,
									 NMConnection *connection,
									 NMConnectionScope scope);

static void hal_manager_udi_added_cb (NMHalManager *hal_mgr,
                                      const char *udi,
                                      const char *type_name,
                                      NMDeviceCreatorFn creator_fn,
                                      gpointer user_data);

static void hal_manager_udi_removed_cb (NMHalManager *hal_mgr,
                                        const char *udi,
                                        gpointer user_data);

static void hal_manager_rfkill_changed_cb (NMHalManager *hal_mgr,
                                           gboolean rfkilled,
                                           gpointer user_data);

static void hal_manager_hal_reappeared_cb (NMHalManager *hal_mgr,
                                           gpointer user_data);

#define SSD_POKE_INTERVAL 120000

typedef struct {
	DBusGMethodInvocation *context;
	NMConnectionScope scope;
	char *connection_path;
	char *specific_object_path;
	char *device_path;
	guint timeout_id;
} PendingConnectionInfo;

typedef struct {
	GSList *devices;
	NMState state;

	NMDBusManager *dbus_mgr;
	NMHalManager *hal_mgr;

	GHashTable *user_connections;
	DBusGProxy *user_proxy;

	GHashTable *system_connections;
	DBusGProxy *system_proxy;
	DBusGProxy *system_props_proxy;
	GSList *unmanaged_udis;

	PendingConnectionInfo *pending_connection_info;
	gboolean wireless_enabled;
	gboolean wireless_hw_enabled;
	gboolean sleeping;

	guint poke_id;
	guint sync_devices_id;

	NMVPNManager *vpn_manager;
	guint vpn_manager_id;

	DBusGProxy *aipd_proxy;

	gboolean disposed;
} NMManagerPrivate;

#define NM_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MANAGER, NMManagerPrivate))

G_DEFINE_TYPE (NMManager, nm_manager, G_TYPE_OBJECT)

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,
	STATE_CHANGED,
	STATE_CHANGE,  /* DEPRECATED */
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
	PROP_ACTIVE_CONNECTIONS,

	LAST_PROP
};

typedef enum
{
	NM_MANAGER_ERROR_UNKNOWN_CONNECTION = 0,
	NM_MANAGER_ERROR_UNKNOWN_DEVICE,
	NM_MANAGER_ERROR_UNMANAGED_DEVICE,
	NM_MANAGER_ERROR_INVALID_SERVICE,
	NM_MANAGER_ERROR_SYSTEM_CONNECTION,
	NM_MANAGER_ERROR_PERMISSION_DENIED,
	NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
	NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE,
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
			/* Unmanaged device. */
			ENUM_ENTRY (NM_MANAGER_ERROR_UNMANAGED_DEVICE, "UnmanagedDevice"),
			/* Invalid settings service (not a recognized system or user
			 * settings service name)
			 */
			ENUM_ENTRY (NM_MANAGER_ERROR_INVALID_SERVICE, "InvalidService"),
			/* Connection was superceded by a system connection. */
			ENUM_ENTRY (NM_MANAGER_ERROR_SYSTEM_CONNECTION, "SystemConnection"),
			/* User does not have the permission to activate this connection. */
			ENUM_ENTRY (NM_MANAGER_ERROR_PERMISSION_DENIED, "PermissionDenied"),
			/* The connection was not active. */
			ENUM_ENTRY (NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE, "ConnectionNotActive"),
			/* The manager is already in the requested sleep state */
			ENUM_ENTRY (NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE, "AlreadyAsleepOrAwake"),
			{ 0, 0, 0 },
		};
		etype = g_enum_register_static ("NMManagerError", values);
	}
	return etype;
}

static void
vpn_manager_connection_deactivated_cb (NMVPNManager *manager,
                                       NMVPNConnection *vpn,
                                       NMVPNConnectionState state,
                                       NMVPNConnectionStateReason reason,
                                       gpointer user_data)
{
	g_object_notify (G_OBJECT (user_data), NM_MANAGER_ACTIVE_CONNECTIONS);
}

static void
aipd_handle_event (DBusGProxy *proxy,
                   const char *event,
                   const char *iface,
                   const char *address,
                   gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;
	gboolean handled;

	if (!event || !iface) {
		nm_warning ("Incomplete message received from avahi-autoipd");
		return;
	}

	if (   (strcmp (event, "BIND") != 0)
	    && (strcmp (event, "CONFLICT") != 0)
	    && (strcmp (event, "UNBIND") != 0)
	    && (strcmp (event, "STOP") != 0)) {
		nm_warning ("Unknown event '%s' received from avahi-autoipd", event);
		return;
	}

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *candidate = NM_DEVICE (iter->data);

		if (!strcmp (nm_device_get_iface (candidate), iface)) {
			nm_device_handle_autoip4_event (candidate, event, address);
			handled = TRUE;
			break;
		}
	}

	if (!handled)
		nm_warning ("Unhandled avahi-autoipd event for '%s'", iface);
}

static void
nm_manager_init (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	DBusGConnection *g_connection;
	guint id;

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

	priv->vpn_manager = nm_vpn_manager_get ();
	id = g_signal_connect (G_OBJECT (priv->vpn_manager), "connection-deactivated",
	                       G_CALLBACK (vpn_manager_connection_deactivated_cb), manager);
	priv->vpn_manager_id = id;

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->aipd_proxy = dbus_g_proxy_new_for_name (g_connection,
	                                              NM_AUTOIP_DBUS_SERVICE,
	                                              "/",
	                                              NM_AUTOIP_DBUS_IFACE);
	if (priv->aipd_proxy) {
		dbus_g_object_register_marshaller (nm_marshal_VOID__STRING_STRING_STRING,
										   G_TYPE_NONE,
										   G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
										   G_TYPE_INVALID);

		dbus_g_proxy_add_signal (priv->aipd_proxy,
		                         "Event",
		                         G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
		                         G_TYPE_INVALID);

		dbus_g_proxy_connect_signal (priv->aipd_proxy, "Event",
									 G_CALLBACK (aipd_handle_event),
									 manager,
									 NULL);
	} else
		nm_warning ("Could not initialize avahi-autoipd D-Bus proxy");
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
		g_object_notify (G_OBJECT (manager), NM_MANAGER_STATE);

		g_signal_emit (manager, signals[STATE_CHANGED], 0, priv->state);

		/* Emit StateChange too for backwards compatibility */
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
	g_free (info->device_path);

	g_slice_free (PendingConnectionInfo, info);
}

static void
manager_device_state_changed (NMDevice *device,
                              NMDeviceState new_state,
                              NMDeviceState old_state,
                              NMDeviceStateReason reason,
                              gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);

	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_FAILED:
		g_object_notify (G_OBJECT (manager), NM_MANAGER_ACTIVE_CONNECTIONS);
		break;
	default:
		break;
	}

	nm_manager_update_state (manager);
}

static void
remove_one_device (NMManager *manager, NMDevice *device)
{
	if (nm_device_get_managed (device))
		nm_device_set_managed (device, FALSE);

	g_signal_handlers_disconnect_by_func (device, manager_device_state_changed, manager);

	g_signal_emit (manager, signals[DEVICE_REMOVED], 0, device);
	g_object_unref (device);
}

static void
dispose (GObject *object)
{
	NMManager *manager = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	pending_connection_info_destroy (priv->pending_connection_info);
	priv->pending_connection_info = NULL;

	if (priv->sync_devices_id) {
		g_source_remove (priv->sync_devices_id);
		priv->sync_devices_id = 0;
	}

	while (g_slist_length (priv->devices)) {
		remove_one_device (manager, NM_DEVICE (priv->devices->data));
		priv->devices = g_slist_remove_link (priv->devices, priv->devices);
	}

	nm_manager_connections_destroy (manager, NM_CONNECTION_SCOPE_USER);
	g_hash_table_destroy (priv->user_connections);
	priv->user_connections = NULL;

	nm_manager_connections_destroy (manager, NM_CONNECTION_SCOPE_SYSTEM);
	g_hash_table_destroy (priv->system_connections);
	priv->system_connections = NULL;

	if (priv->system_props_proxy) {
		g_object_unref (priv->system_props_proxy);
		priv->system_props_proxy = NULL;
	}
	g_slist_foreach (priv->unmanaged_udis, (GFunc) g_free, NULL);
	g_slist_free (priv->unmanaged_udis);

	if (priv->poke_id) {
		g_source_remove (priv->poke_id);
		priv->poke_id = 0;
	}

	if (priv->vpn_manager_id) {
		g_source_remove (priv->vpn_manager_id);
		priv->vpn_manager_id = 0;
	}
	g_object_unref (priv->vpn_manager);

	g_object_unref (priv->dbus_mgr);
	g_object_unref (priv->hal_mgr);

	G_OBJECT_CLASS (nm_manager_parent_class)->dispose (object);
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

static GPtrArray *
get_active_connections (NMManager *manager, NMConnection *filter)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMVPNManager *vpn_manager;
	GPtrArray *active;
	GSList *iter;

 	active = g_ptr_array_sized_new (3);

	/* Add active device connections */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMActRequest *req;
		const char *path;

		req = nm_device_get_act_request (NM_DEVICE (iter->data));
		if (!req)
			continue;

		if (!filter || (nm_act_request_get_connection (req) == filter)) {
			path = nm_act_request_get_active_connection_path (req);
			g_ptr_array_add (active, g_strdup (path));
		}
	}

	/* Add active VPN connections */
	vpn_manager = nm_vpn_manager_get ();
	nm_vpn_manager_add_active_connections (vpn_manager, filter, active);
	g_object_unref (vpn_manager);

	return active;
}

static void
get_property (GObject *object, guint prop_id,
			  GValue *value, GParamSpec *pspec)
{
	NMManager *self = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_STATE:
		nm_manager_update_state (self);
		g_value_set_uint (value, priv->state);
		break;
	case PROP_WIRELESS_ENABLED:
		g_value_set_boolean (value, priv->wireless_enabled);
		break;
	case PROP_WIRELESS_HARDWARE_ENABLED:
		g_value_set_boolean (value, priv->wireless_hw_enabled);
		break;
	case PROP_ACTIVE_CONNECTIONS:
		g_value_take_boxed (value, get_active_connections (self, NULL));
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
	object_class->dispose = dispose;

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
						   G_PARAM_READABLE));

	g_object_class_install_property
		(object_class, PROP_ACTIVE_CONNECTIONS,
		 g_param_spec_boxed (NM_MANAGER_ACTIVE_CONNECTIONS,
							  "Active connections",
							  "Active connections",
							  DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH,
							  G_PARAM_READABLE));

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

	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMManagerClass, state_changed),
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

	/* StateChange is DEPRECATED */
	signals[STATE_CHANGE] =
		g_signal_new ("state-change",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  0, NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1,
					  G_TYPE_UINT);


	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (manager_class),
									 &dbus_glib_nm_manager_object_info);

	dbus_g_error_domain_register (NM_MANAGER_ERROR, NULL, NM_TYPE_MANAGER_ERROR);
}

static NMConnectionScope
get_scope_for_proxy (DBusGProxy *proxy)
{
	const char *bus_name = dbus_g_proxy_get_bus_name (proxy);

	if (strcmp (bus_name, NM_DBUS_SERVICE_USER_SETTINGS) == 0)
		return NM_CONNECTION_SCOPE_USER;
	else if (strcmp (bus_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS) == 0)
		return NM_CONNECTION_SCOPE_SYSTEM;

	return NM_CONNECTION_SCOPE_UNKNOWN;
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
			g_slice_free (GSList, (gpointer) info->calls);
			g_signal_emit (info->manager,
			               signals[CONNECTIONS_ADDED],
			               0,
			               get_scope_for_proxy (info->proxy));
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
	NMConnectionScope scope;
	NMManager *manager;

	g_return_if_fail (info != NULL);

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT, &settings,
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
		GError *error = NULL;

		connection = nm_connection_new_from_hash (settings, &error);
		if (connection == NULL) {
			nm_warning ("%s: Invalid connection: '%s' / '%s' invalid: %d",
			            __func__,
			            g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)),
			            error->message, error->code);
			g_error_free (error);
			goto out;
		}

		scope = get_scope_for_proxy (proxy);

		nm_connection_set_path (connection, path);
		nm_connection_set_scope (connection, scope);

		g_object_set_data_full (G_OBJECT (connection),
		                        NM_MANAGER_CONNECTION_PROXY_TAG,
		                        proxy,
		                        (GDestroyNotify) g_object_unref);

		g_object_set_data_full (G_OBJECT (connection),
		                        NM_MANAGER_CONNECTION_SECRETS_PROXY_TAG,
		                        info->secrets_proxy,
		                        (GDestroyNotify) g_object_unref);

		priv = NM_MANAGER_GET_PRIVATE (manager);
		switch (scope) {
			case NM_CONNECTION_SCOPE_USER:
				g_hash_table_insert (priv->user_connections,
				                     g_strdup (path),
				                     connection);
				break;
			case NM_CONNECTION_SCOPE_SYSTEM:
				g_hash_table_insert (priv->system_connections,
				                     g_strdup (path),
				                     connection);
				break;
			default:
				nm_warning ("Connection wasn't a user connection or a system connection.");
				g_assert_not_reached ();
				break;
		}

		/* If the connection-added signal is supposed to be batched, don't
		 * emit the single connection-added here.
		 */
		if (!info->calls)
			g_signal_emit (manager, signals[CONNECTION_ADDED], 0, connection, scope);
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
                          GHashTable **out_hash)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMConnection *connection = NULL;
	const char *path = dbus_g_proxy_get_path (proxy);

	switch (get_scope_for_proxy (proxy)) {
		case NM_CONNECTION_SCOPE_USER:
			*out_hash = priv->user_connections;
			connection = g_hash_table_lookup (priv->user_connections, path);
			break;
		case NM_CONNECTION_SCOPE_SYSTEM:
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
                   GHashTable *hash)
{
	/* Destroys the connection, then associated DBusGProxy due to the
	 * weak reference notify function placed on the connection when it
	 * was created.
	 */
	g_object_ref (connection);
	g_hash_table_remove (hash, nm_connection_get_path (connection));
	g_signal_emit (manager, signals[CONNECTION_REMOVED], 0,
	               connection,
	               nm_connection_get_scope (connection));
	g_object_unref (connection);
}

static void
connection_removed_cb (DBusGProxy *proxy, gpointer user_data)
{
	NMManager * manager = NM_MANAGER (user_data);
	NMConnection *connection = NULL;
	GHashTable *hash = NULL;

	connection = get_connection_for_proxy (manager, proxy, &hash);
	if (connection)
		remove_connection (manager, connection, hash);
}

static void
connection_updated_cb (DBusGProxy *proxy, GHashTable *settings, gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMConnection *new_connection;
	NMConnection *old_connection;
	GHashTable *hash;
	gboolean valid = FALSE;
	GError *error = NULL;

	old_connection = get_connection_for_proxy (manager, proxy, &hash);
	g_return_if_fail (old_connection != NULL);

	new_connection = nm_connection_new_from_hash (settings, &error);
	if (!new_connection) {
		/* New connection invalid, remove existing connection */
		nm_warning ("%s: Invalid connection: '%s' / '%s' invalid: %d",
		            __func__,
		            g_type_name (nm_connection_lookup_setting_type_by_quark (error->domain)),
		            error->message, error->code);
		g_error_free (error);
		remove_connection (manager, old_connection, hash);
		return;
	}
	g_object_unref (new_connection);

	valid = nm_connection_replace_settings (old_connection, settings);
	if (valid) {
		g_signal_emit (manager, signals[CONNECTION_UPDATED], 0,
		               old_connection,
		               nm_connection_get_scope (old_connection));
	} else {
		remove_connection (manager, old_connection, hash);
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
	                         DBUS_TYPE_G_MAP_OF_MAP_OF_VARIANT,
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
		char *op = g_ptr_array_index (ops, i);

		internal_new_connection_cb (proxy, op, manager, calls);
		g_free (op);
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
                   NMConnectionScope scope)
{
	NMManagerPrivate *priv;
	DBusGProxyCall *call;
	DBusGProxy ** proxy;
	const char * service;

	g_return_if_fail (NM_IS_MANAGER (manager));

	priv = NM_MANAGER_GET_PRIVATE (manager);
	if (scope == NM_CONNECTION_SCOPE_USER) {
		proxy = &priv->user_proxy;
		service = NM_DBUS_SERVICE_USER_SETTINGS;
	} else if (scope == NM_CONNECTION_SCOPE_SYSTEM) {
		proxy = &priv->system_proxy;
		service = NM_DBUS_SERVICE_SYSTEM_SETTINGS;
	} else {
		nm_warning ("Unknown NMConnectionScope %d", scope);
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

static NMDevice *
nm_manager_get_device_by_udi (NMManager *manager, const char *udi)
{
	GSList *iter;

	for (iter = NM_MANAGER_GET_PRIVATE (manager)->devices; iter; iter = iter->next) {
		if (!strcmp (nm_device_get_udi (NM_DEVICE (iter->data)), udi))
			return NM_DEVICE (iter->data);
	}
	return NULL;
}

static gboolean
nm_manager_udi_is_managed (NMManager *self, const char *udi)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	for (iter = priv->unmanaged_udis; iter; iter = iter->next) {
		if (!strcmp (udi, iter->data))
			return FALSE;
	}

	return TRUE;
}

static void
handle_unmanaged_devices (NMManager *manager, GPtrArray *ops)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	int i;
	GSList *unmanaged = NULL, *iter;

	g_slist_foreach (priv->unmanaged_udis, (GFunc) g_free, NULL);
	g_slist_free (priv->unmanaged_udis);
	priv->unmanaged_udis = NULL;

	/* Mark unmanaged devices */
	for (i = 0; ops && (i < ops->len); i++) {
		NMDevice *device;
		const char *udi = g_ptr_array_index (ops, i);

		priv->unmanaged_udis = g_slist_prepend (priv->unmanaged_udis, g_strdup (udi));

		device = nm_manager_get_device_by_udi (manager, udi);
		if (device) {
			unmanaged = g_slist_prepend (unmanaged, device);
			nm_device_set_managed (device, FALSE);
		}
	}

	/* Mark managed devices */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (!g_slist_find (unmanaged, device))
			nm_device_set_managed (device, TRUE);
	}

	g_slist_free (unmanaged);
}

static void
system_settings_properties_changed_cb (DBusGProxy *proxy,
                                       GHashTable *properties,
                                       gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	GValue *value;

	value = g_hash_table_lookup (properties, "UnmanagedDevices");
	if (!value || !G_VALUE_HOLDS (value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH))
		return;

	handle_unmanaged_devices (manager, g_value_get_boxed (value));
}

static void
system_settings_get_unmanaged_devices_cb (DBusGProxy *proxy,
                                          DBusGProxyCall *call_id,
                                          gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	GError *error = NULL;
	GValue value = { 0, };

	if (!dbus_g_proxy_end_call (proxy, call_id, &error,
	                            G_TYPE_VALUE, &value,
	                            G_TYPE_INVALID)) {
		nm_warning ("%s: Error getting unmanaged devices from the system "
		            "settings service: (%d) %s",
		            __func__, error->code, error->message);
		g_error_free (error);
		return;
	}

	if (G_VALUE_HOLDS (&value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH))
		handle_unmanaged_devices (manager, g_value_get_boxed (&value));

	g_value_unset (&value);

	g_object_unref (proxy);
}

static void
query_unmanaged_devices (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	DBusGConnection *g_connection;
	DBusGProxy *get_proxy;

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	if (!priv->system_props_proxy) {
		priv->system_props_proxy = dbus_g_proxy_new_for_name (g_connection,
		                                                      NM_DBUS_SERVICE_SYSTEM_SETTINGS,
		                                                      NM_DBUS_PATH_SETTINGS,
		                                                      "org.freedesktop.NetworkManagerSettings.System");
		if (!priv->system_props_proxy) {
			nm_warning ("Error: could not init system settings properties proxy.");
			return;
		}

		dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__BOXED,
									G_TYPE_NONE, G_TYPE_VALUE, G_TYPE_INVALID);
		dbus_g_proxy_add_signal (priv->system_props_proxy, "PropertiesChanged",
		                         DBUS_TYPE_G_MAP_OF_VARIANT, G_TYPE_INVALID);
		dbus_g_proxy_connect_signal (priv->system_props_proxy, "PropertiesChanged",
		                             G_CALLBACK (system_settings_properties_changed_cb),
		                             manager,
		                             NULL);
	}

	/* Get unmanaged devices */
	get_proxy = dbus_g_proxy_new_for_name (g_connection,
		                                   NM_DBUS_SERVICE_SYSTEM_SETTINGS,
		                                   NM_DBUS_PATH_SETTINGS,
		                                   "org.freedesktop.DBus.Properties");

	dbus_g_proxy_begin_call (get_proxy, "Get",
	                         system_settings_get_unmanaged_devices_cb,
	                         manager,
	                         NULL,
	                         G_TYPE_STRING, "org.freedesktop.NetworkManagerSettings.System",
	                         G_TYPE_STRING, "UnmanagedDevices",
	                         G_TYPE_INVALID);
}

static void
nm_manager_name_owner_changed (NMDBusManager *mgr,
                               const char *name,
                               const char *old,
                               const char *new,
                               gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	gboolean old_owner_good = (old && (strlen (old) > 0));
	gboolean new_owner_good = (new && (strlen (new) > 0));

	if (strcmp (name, NM_DBUS_SERVICE_USER_SETTINGS) == 0) {
		if (!old_owner_good && new_owner_good) {
			/* User Settings service appeared, update stuff */
			query_connections (manager, NM_CONNECTION_SCOPE_USER);
		} else {
			/* User Settings service disappeared, throw them away (?) */
			nm_manager_connections_destroy (manager, NM_CONNECTION_SCOPE_USER);
		}
	} else if (strcmp (name, NM_DBUS_SERVICE_SYSTEM_SETTINGS) == 0) {
		if (!old_owner_good && new_owner_good) {
			if (priv->poke_id) {
				g_source_remove (priv->poke_id);
				priv->poke_id = 0;
			}

			/* System Settings service appeared, update stuff */
			query_unmanaged_devices (manager);
			query_connections (manager, NM_CONNECTION_SCOPE_SYSTEM);
		} else {
			/* System Settings service disappeared, throw them away (?) */
			nm_manager_connections_destroy (manager, NM_CONNECTION_SCOPE_SYSTEM);

			if (priv->system_props_proxy) {
				g_object_unref (priv->system_props_proxy);
				priv->system_props_proxy = NULL;
			}

			if (priv->poke_id)
				g_source_remove (priv->poke_id);

			/* Poke the system settings daemon so that it gets activated by dbus
			 * system bus activation.
			 */
			priv->poke_id = g_idle_add (poke_system_settings_daemon_cb, (gpointer) manager);
		}
	}
}

static gboolean
poke_system_settings_daemon_cb (gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	DBusGConnection *g_connection;
	DBusGProxy *proxy;

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	proxy = dbus_g_proxy_new_for_name (g_connection,
	                                   NM_DBUS_SERVICE_SYSTEM_SETTINGS,
	                                   NM_DBUS_PATH_SETTINGS,
	                                   NM_DBUS_IFACE_SETTINGS);
	if (!proxy) {
		nm_warning ("Error: could not init system settings daemon proxy");
		goto out;
	}

	nm_info ("Trying to start the system settings daemon...");
	dbus_g_proxy_call_no_reply (proxy, "ListConnections", G_TYPE_INVALID);
	g_object_unref (proxy);

out:
	/* Reschedule the poke */
	priv->poke_id = g_timeout_add (SSD_POKE_INTERVAL, poke_system_settings_daemon_cb, (gpointer) manager);

	return FALSE;
}

static gboolean
initial_get_connections (gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	if (nm_dbus_manager_name_has_owner (nm_dbus_manager_get (),
	                                    NM_DBUS_SERVICE_SYSTEM_SETTINGS)) {
		query_unmanaged_devices (manager);
		query_connections (manager, NM_CONNECTION_SCOPE_SYSTEM);
	} else {
		/* Try to activate the system settings daemon */
		priv->poke_id = g_idle_add (poke_system_settings_daemon_cb, (gpointer) manager);
	}

	if (nm_dbus_manager_name_has_owner (nm_dbus_manager_get (),
	                                    NM_DBUS_SERVICE_USER_SETTINGS))
		query_connections (manager, NM_CONNECTION_SCOPE_USER);

	return FALSE;
}

static void
sync_devices (NMManager *self)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *devices;
	GSList *iter;

	/* Remove devices which are no longer known to HAL */
	devices = g_slist_copy (priv->devices);
	for (iter = devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);
		const char *udi = nm_device_get_udi (device);

		if (nm_hal_manager_udi_exists (priv->hal_mgr, udi)) {
			nm_device_set_managed (device, nm_manager_udi_is_managed (self, udi));
		} else {
			priv->devices = g_slist_delete_link (priv->devices, iter);
			remove_one_device (self, device);
		}
	}

	g_slist_free (devices);

	/* Get any new ones */
	nm_hal_manager_query_devices (priv->hal_mgr);
}

static gboolean
deferred_sync_devices (gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);

	priv->sync_devices_id = 0;
	sync_devices (self);

	return FALSE;
}

NMManager *
nm_manager_get (void)
{
	static NMManager *singleton = NULL;
	NMManagerPrivate *priv;

	if (singleton)
		return g_object_ref (singleton);

	singleton = (NMManager *) g_object_new (NM_TYPE_MANAGER, NULL);
	g_assert (singleton);

	priv = NM_MANAGER_GET_PRIVATE (singleton);

	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                     NM_DBUS_PATH,
	                                     G_OBJECT (singleton));

	g_signal_connect (priv->dbus_mgr,
	                  "name-owner-changed",
	                  G_CALLBACK (nm_manager_name_owner_changed),
	                  singleton);

	g_idle_add ((GSourceFunc) initial_get_connections, singleton);

	priv->hal_mgr = nm_hal_manager_new ();
	priv->sync_devices_id = g_idle_add (deferred_sync_devices, singleton);

	g_signal_connect (priv->hal_mgr,
	                  "udi-added",
	                  G_CALLBACK (hal_manager_udi_added_cb),
	                  singleton);

	g_signal_connect (priv->hal_mgr,
	                  "udi-removed",
	                  G_CALLBACK (hal_manager_udi_removed_cb),
	                  singleton);

	g_signal_connect (priv->hal_mgr,
	                  "rfkill-changed",
	                  G_CALLBACK (hal_manager_rfkill_changed_cb),
	                  singleton);

	g_signal_connect (priv->hal_mgr,
	                  "hal-reappeared",
	                  G_CALLBACK (hal_manager_hal_reappeared_cb),
	                  singleton);

	return singleton;
}

static void
emit_removed (gpointer key, gpointer value, gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);
	NMConnection *connection = NM_CONNECTION (value);

	g_signal_emit (manager, signals[CONNECTION_REMOVED], 0,
	               connection,
	               nm_connection_get_scope (connection));
}

static void
nm_manager_connections_destroy (NMManager *manager,
                                NMConnectionScope scope)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	if (scope == NM_CONNECTION_SCOPE_USER) {
		if (priv->user_connections) {
			g_hash_table_foreach (priv->user_connections, emit_removed, manager);
			g_hash_table_remove_all (priv->user_connections);
		}

		if (priv->user_proxy) {
			g_object_unref (priv->user_proxy);
			priv->user_proxy = NULL;
		}
	} else if (scope == NM_CONNECTION_SCOPE_SYSTEM) {
		if (priv->system_connections) {
			g_hash_table_foreach (priv->system_connections, emit_removed, manager);
			g_hash_table_remove_all (priv->system_connections);
		}

		if (priv->system_proxy) {
			g_object_unref (priv->system_proxy);
			priv->system_proxy = NULL;
		}
	} else {
		nm_warning ("Unknown NMConnectionScope %d", scope);
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

	/* enable/disable wireless devices as required */
	for (iter = priv->devices; iter; iter = iter->next) {
		if (NM_IS_DEVICE_WIFI (iter->data))
			nm_device_wifi_set_enabled (NM_DEVICE_WIFI (iter->data), enabled);
	}
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
	connections = nm_manager_get_connections (manager, NM_CONNECTION_SCOPE_SYSTEM);
	connections = g_slist_concat (connections,  nm_manager_get_connections (manager, NM_CONNECTION_SCOPE_USER));

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

static void
hal_manager_udi_added_cb (NMHalManager *hal_mgr,
                          const char *udi,
                          const char *type_name,
                          NMDeviceCreatorFn creator_fn,
                          gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GObject *device;
	const char *iface;

	if (priv->sleeping)
		return;

	/* Make sure the device is not already in the device list */
	if (nm_manager_get_device_by_udi (self, udi))
		return;

	device = creator_fn (hal_mgr, udi, nm_manager_udi_is_managed (self, udi));
	if (!device)
		return;

	priv->devices = g_slist_append (priv->devices, device);

	g_signal_connect (device, "state-changed",
					  G_CALLBACK (manager_device_state_changed),
					  self);

	/* Attach to the access-point-added signal so that the manager can fill
	 * non-SSID-broadcasting APs with an SSID.
	 */
	if (NM_IS_DEVICE_WIFI (device)) {
		g_signal_connect (device, "hidden-ap-found",
						  G_CALLBACK (manager_hidden_ap_found),
						  self);

		/* Set initial rfkill state */
		nm_device_wifi_set_enabled (NM_DEVICE_WIFI (device), priv->wireless_enabled);
	}

	iface = nm_device_get_iface (NM_DEVICE (device));
	nm_info ("Found new %s device '%s'.", type_name, iface);

	dbus_g_connection_register_g_object (nm_dbus_manager_get_connection (priv->dbus_mgr),
								  nm_device_get_udi (NM_DEVICE (device)),
								  device);
	nm_info ("(%s): exported as %s", iface, udi);

	g_signal_emit (self, signals[DEVICE_ADDED], 0, device);
}

static void
hal_manager_udi_removed_cb (NMHalManager *manager,
                            const char *udi,
                            gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	GSList *iter;

	g_return_if_fail (udi != NULL);

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *device = NM_DEVICE (iter->data);

		if (!strcmp (nm_device_get_udi (device), udi)) {
			priv->devices = g_slist_delete_link (priv->devices, iter);
			remove_one_device (self, device);
			break;
		}
	}
}

static void
hal_manager_rfkill_changed_cb (NMHalManager *hal_mgr,
                               gboolean rfkilled,
                               gpointer user_data)
{
	NMManager *self = NM_MANAGER (user_data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (self);
	gboolean enabled = !rfkilled;

	if (priv->wireless_hw_enabled != enabled) {
		nm_info ("Wireless now %s by radio killswitch", enabled ? "enabled" : "disabled");
		priv->wireless_hw_enabled = enabled;
		g_object_notify (G_OBJECT (self), NM_MANAGER_WIRELESS_HARDWARE_ENABLED);

		manager_set_wireless_enabled (self, enabled);
	}
}

static void
hal_manager_hal_reappeared_cb (NMHalManager *hal_mgr,
                               gpointer user_data)
{
	sync_devices (NM_MANAGER (user_data));
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

static NMActRequest *
nm_manager_get_act_request_by_path (NMManager *manager,
                                    const char *path,
                                    NMDevice **device)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	GSList *iter;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (*device == NULL, NULL);

	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMActRequest *req;
		const char *ac_path;

		req = nm_device_get_act_request (NM_DEVICE (iter->data));
		if (!req)
			continue;

		ac_path = nm_act_request_get_active_connection_path (req);
		if (!strcmp (path, ac_path)) {
			*device = NM_DEVICE (iter->data);
			return req;
		}
	}

	return NULL;
}

static const char *
internal_activate_device (NMManager *manager,
                          NMDevice *device,
                          NMConnection *connection,
                          const char *specific_object,
                          gboolean user_requested,
                          GError **error)
{
	NMActRequest *req;
	NMDeviceInterface *dev_iface;
	gboolean success;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (NM_IS_DEVICE (device), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);

	dev_iface = NM_DEVICE_INTERFACE (device);

	/* Ensure the requested connection is compatible with the device */
	if (!nm_device_interface_check_connection_compatible (dev_iface, connection, error))
		return NULL;

	/* Tear down any existing connection */
	if (nm_device_get_act_request (device)) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_DISCONNECTED,
		                         NM_DEVICE_STATE_REASON_NONE);
	}

	req = nm_act_request_new (connection, specific_object, user_requested, (gpointer) device);
	success = nm_device_interface_activate (dev_iface, req, error);
	g_object_unref (req);

	return success ? nm_act_request_get_active_connection_path (req) : NULL;
}

static gboolean
wait_for_connection_expired (gpointer data)
{
	NMManager *manager = NM_MANAGER (data);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	PendingConnectionInfo *info = priv->pending_connection_info;
	GError *error = NULL;

	g_return_val_if_fail (info != NULL, FALSE);

	g_set_error (&error,
	             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_CONNECTION,
	             "%s", "Connection was not provided by any settings service");
	nm_warning ("Connection (%d) %s failed to activate (timeout): (%d) %s",
	            info->scope, info->connection_path, error->code, error->message);
	dbus_g_method_return_error (info->context, error);
	g_error_free (error);

	info->timeout_id = 0;
	pending_connection_info_destroy (priv->pending_connection_info);
	priv->pending_connection_info = NULL;

	return FALSE;
}

const char *
nm_manager_activate_connection (NMManager *manager,
                                NMConnection *connection,
                                const char *specific_object,
                                const char *device_path,
                                gboolean user_requested,
                                GError **error)
{
	NMDevice *device = NULL;
	char *path = NULL;
	NMSettingConnection *s_con;

	g_return_val_if_fail (manager != NULL, NULL);
	g_return_val_if_fail (connection != NULL, NULL);
	g_return_val_if_fail (error != NULL, NULL);
	g_return_val_if_fail (*error == NULL, NULL);

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (!strcmp (s_con->type, NM_SETTING_VPN_SETTING_NAME)) {
		NMActRequest *req;
		NMVPNManager *vpn_manager;

		/* VPN connection */
		req = nm_manager_get_act_request_by_path (manager, specific_object, &device);
		if (!req) {
			g_set_error (error,
			             NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
			             "%s", "Base connection for VPN connection not active.");
			return NULL;
		}

		if (!device) {
			g_set_error (error,
			             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			             "%s", "Source connection had no active device.");
			return NULL;
		}

		vpn_manager = nm_vpn_manager_get ();
		path = (char *) nm_vpn_manager_activate_connection (vpn_manager,
		                                                    connection,
		                                                    req,
		                                                    device,
		                                                    error);
		g_object_unref (vpn_manager);
	} else {
		NMDeviceState state;

		/* Device-based connection */
		device = nm_manager_get_device_by_udi (manager, device_path);
		if (!device) {
			g_set_error (error,
			             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNKNOWN_DEVICE,
			             "%s", "Device not found");
			return NULL;
		}

		state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));
		if (state < NM_DEVICE_STATE_DISCONNECTED) {
			g_set_error (error,
			             NM_MANAGER_ERROR, NM_MANAGER_ERROR_UNMANAGED_DEVICE,
			             "%s", "Device not managed by NetworkManager");
			return NULL;
		}

		path = (char *) internal_activate_device (manager,
		                                          device,
		                                          connection,
		                                          specific_object,
		                                          user_requested,
		                                          error);
	}

	return path;
}

static void
connection_added_default_handler (NMManager *manager,
						    NMConnection *connection,
						    NMConnectionScope scope)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	PendingConnectionInfo *info = priv->pending_connection_info;
	const char *path;
	GError *error = NULL;

	if (!info)
		return;

	if (scope != info->scope)
		return;

	if (strcmp (info->connection_path, nm_connection_get_path (connection)))
		return;

	/* Will destroy below; can't be valid during the initial activation start */
	priv->pending_connection_info = NULL;

	path = nm_manager_activate_connection (manager,
	                                       connection,
	                                       info->specific_object_path,
	                                       info->device_path,
	                                       TRUE,
	                                       &error);
	if (path) {
		dbus_g_method_return (info->context, path);
		g_object_notify (G_OBJECT (manager), NM_MANAGER_ACTIVE_CONNECTIONS);
	} else {
		dbus_g_method_return_error (info->context, error);
		nm_warning ("Connection (%d) %s failed to activate: (%d) %s",
		            scope, info->connection_path, error->code, error->message);
		g_error_free (error);
	}

	pending_connection_info_destroy (info);
}

static void
impl_manager_activate_connection (NMManager *manager,
						const char *service_name,
						const char *connection_path,
						const char *device_path,
						const char *specific_object_path,
						DBusGMethodInvocation *context)
{
	NMConnectionScope scope = NM_CONNECTION_SCOPE_UNKNOWN;
	NMConnection *connection;
	GError *error = NULL;
	char *real_sop = NULL;
	char *path = NULL;

	if (!strcmp (service_name, NM_DBUS_SERVICE_USER_SETTINGS))
		scope = NM_CONNECTION_SCOPE_USER;
	else if (!strcmp (service_name, NM_DBUS_SERVICE_SYSTEM_SETTINGS))
		scope = NM_CONNECTION_SCOPE_SYSTEM;
	else {
		g_set_error (&error,
		             NM_MANAGER_ERROR, NM_MANAGER_ERROR_INVALID_SERVICE,
		             "%s", "Invalid settings service name");
		goto err;
	}

	/* "/" is special-cased to NULL to get through D-Bus */
	if (specific_object_path && strcmp (specific_object_path, "/"))
		real_sop = g_strdup (specific_object_path);

	connection = nm_manager_get_connection_by_object_path (manager, scope, connection_path);
	if (connection) {
		path = (char *) nm_manager_activate_connection (manager,
		                                                connection,
		                                                real_sop,
		                                                device_path,
		                                                TRUE,
		                                                &error);
		if (path) {
			dbus_g_method_return (context, path);
			g_object_notify (G_OBJECT (manager), NM_MANAGER_ACTIVE_CONNECTIONS);
		}
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
		info->device_path = g_strdup (device_path);
		info->scope = scope;
		info->connection_path = g_strdup (connection_path);
		info->specific_object_path = g_strdup (real_sop);
		info->timeout_id = g_timeout_add (5000, wait_for_connection_expired, manager);

		// FIXME: should probably be per-device, not global to the manager
		NM_MANAGER_GET_PRIVATE (manager)->pending_connection_info = info;
	}

 err:
	if (error) {
		dbus_g_method_return_error (context, error);
		nm_warning ("Connection (%d) %s failed to activate: (%d) %s",
		            scope, connection_path, error->code, error->message);
		g_error_free (error);
	}

	g_free (real_sop);
}

gboolean
nm_manager_deactivate_connection (NMManager *manager,
                                  const char *connection_path,
                                  GError **error)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);
	NMVPNManager *vpn_manager;
	GSList *iter;
	gboolean success = FALSE;

	/* Check for device connections first */
	for (iter = priv->devices; iter; iter = g_slist_next (iter)) {
		NMDevice *device = NM_DEVICE (iter->data);
		NMActRequest *req;

		req = nm_device_get_act_request (device);
		if (!req)
			continue;

		if (!strcmp (connection_path, nm_act_request_get_active_connection_path (req))) {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_DISCONNECTED,
			                         NM_DEVICE_STATE_REASON_NONE);
			success = TRUE;
			goto done;
		}
	}

	/* Check for VPN connections next */
	vpn_manager = nm_vpn_manager_get ();
	if (nm_vpn_manager_deactivate_connection (vpn_manager, connection_path)) {
		success = TRUE;
	} else {
		g_set_error (error,
		             NM_MANAGER_ERROR, NM_MANAGER_ERROR_CONNECTION_NOT_ACTIVE,
		             "%s", "The connection was not active.");
	}
	g_object_unref (vpn_manager);

done:
	g_object_notify (G_OBJECT (manager), NM_MANAGER_ACTIVE_CONNECTIONS);
	return success;
}

static gboolean
impl_manager_deactivate_connection (NMManager *manager,
                                    const char *connection_path,
                                    GError **error)
{
	return nm_manager_deactivate_connection (manager, connection_path, error);
}

static gboolean
impl_manager_sleep (NMManager *manager, gboolean sleep, GError **error)
{
	NMManagerPrivate *priv;

	g_return_val_if_fail (NM_IS_MANAGER (manager), FALSE);

	priv = NM_MANAGER_GET_PRIVATE (manager);

	if (priv->sleeping == sleep) {
		g_set_error (error,
		             NM_MANAGER_ERROR, NM_MANAGER_ERROR_ALREADY_ASLEEP_OR_AWAKE,
		             "Already %s", sleep ? "asleep" : "awake");		
		return FALSE;
	}

	priv->sleeping = sleep;

	if (sleep) {
		GSList *iter;

		nm_info ("Sleeping...");

		/* Just deactivate and down all devices from the device list,
		 * we'll remove them in 'wake' for speed's sake.
		 */
		for (iter = priv->devices; iter; iter = iter->next)
			nm_device_set_managed (NM_DEVICE (iter->data), FALSE);
	} else {
		nm_info  ("Waking up...");

		sync_devices (manager);
		if (priv->sync_devices_id) {
			g_source_remove (priv->sync_devices_id);
			priv->sync_devices_id = 0;
		}
	}

	nm_manager_update_state (manager);
	return TRUE;
}

/* Legacy 0.6 compatibility interface */

static gboolean
impl_manager_legacy_sleep (NMManager *manager, GError **error)
{
	return impl_manager_sleep (manager, TRUE, error);
}

static gboolean
impl_manager_legacy_wake  (NMManager *manager, GError **error)
{
	return impl_manager_sleep (manager, FALSE, error);
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
                            NMConnectionScope scope)
{
	NMManagerPrivate *priv;
	GSList *list = NULL;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	priv = NM_MANAGER_GET_PRIVATE (manager);
	if (scope == NM_CONNECTION_SCOPE_USER)
		g_hash_table_foreach (priv->user_connections, connections_to_slist, &list);
	else if (scope == NM_CONNECTION_SCOPE_SYSTEM)
		g_hash_table_foreach (priv->system_connections, connections_to_slist, &list);
	else
		nm_warning ("Unknown NMConnectionScope %d", scope);	
	return list;
}

NMConnection *
nm_manager_get_connection_by_object_path (NMManager *manager,
                                          NMConnectionScope scope,
                                          const char *path)
{
	NMManagerPrivate *priv;
	NMConnection *connection = NULL;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);
	g_return_val_if_fail (path != NULL, NULL);

	priv = NM_MANAGER_GET_PRIVATE (manager);
	if (scope == NM_CONNECTION_SCOPE_USER)
		connection = (NMConnection *) g_hash_table_lookup (priv->user_connections, path);
	else if (scope == NM_CONNECTION_SCOPE_SYSTEM)
		connection = (NMConnection *) g_hash_table_lookup (priv->system_connections, path);
	else
		nm_warning ("Unknown NMConnectionScope %d", scope);
	return connection;
}

GPtrArray *
nm_manager_get_active_connections_by_connection (NMManager *manager,
                                                 NMConnection *connection)
{
	return get_active_connections (manager, connection);
}

