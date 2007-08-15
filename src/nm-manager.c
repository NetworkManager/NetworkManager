/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <string.h>

#include "nm-manager.h"
#include "nm-utils.h"
#include "nm-dbus-manager.h"
#include "nm-device-interface.h"
#include "nm-device-802-11-wireless.h"
#include "NetworkManagerSystem.h"
#include "NetworkManagerDbus.h"

static gboolean impl_manager_get_devices (NMManager *manager, GPtrArray **devices, GError **err);
static gboolean impl_manager_sleep (NMManager *manager, gboolean sleep, GError **err);

/* Legacy 0.6 compatibility interface */

static gboolean impl_manager_legacy_sleep (NMManager *manager, GError **err);
static gboolean impl_manager_legacy_wake  (NMManager *manager, GError **err);
static gboolean impl_manager_legacy_state (NMManager *manager, GError **err);

#include "nm-manager-glue.h"

static void nm_manager_connections_destroy (NMManager *manager);
static void manager_state_changed (NMManager *manager);
static void manager_set_wireless_enabled (NMManager *manager, gboolean enabled);

typedef struct {
	GSList *devices;
	GSList *connections;
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
}

static void
finalize (GObject *object)
{
	NMManager *manager = NM_MANAGER (object);
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	nm_manager_connections_destroy (manager);

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
		g_value_set_uint (value, nm_manager_get_state (NM_MANAGER (object)));
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
					  g_cclosure_marshal_VOID__POINTER,
					  G_TYPE_NONE, 1,
					  G_TYPE_POINTER);

	signals[CONNECTION_REMOVED] =
		g_signal_new ("connection-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMManagerClass, connection_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__POINTER,
					  G_TYPE_NONE, 1,
					  G_TYPE_POINTER);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (manager_class),
									 &dbus_glib_nm_manager_object_info);
}

NMManager *
nm_manager_new (void)
{
	GObject *object;
	DBusGConnection *connection;

	object = g_object_new (NM_TYPE_MANAGER, NULL);

	connection = nm_dbus_manager_get_connection (nm_dbus_manager_get ());
	dbus_g_connection_register_g_object (connection,
										 NM_DBUS_PATH,
										 object);

	return (NMManager *) object;
}

static void
nm_manager_connections_destroy (NMManager *manager)
{
	NMManagerPrivate *priv = NM_MANAGER_GET_PRIVATE (manager);

	g_slist_foreach (priv->connections, (GFunc) nm_connection_destroy, NULL);
	g_slist_free (priv->connections);
	priv->connections = NULL;
}

static void
manager_state_changed (NMManager *manager)
{
	g_signal_emit (manager, signals[STATE_CHANGE], 0, nm_manager_get_state (manager));
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
manager_device_state_changed (NMDevice *device, NMDeviceState state, gpointer user_data)
{
	NMManager *manager = NM_MANAGER (user_data);

	/* Only these state changes can modify the manager state */
	if (state == NM_DEVICE_STATE_ACTIVATED || state == NM_DEVICE_STATE_FAILED ||
		state == NM_DEVICE_STATE_CANCELLED || state == NM_DEVICE_STATE_DISCONNECTED)

		manager_state_changed (manager);
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
		if (!NM_IS_DEVICE_802_11_WIRELESS (device) || priv->wireless_enabled)
			nm_device_bring_up (device, TRUE);
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

			g_signal_handlers_disconnect_by_func (device, manager_device_state_changed, manager);

			nm_device_bring_down (device, FALSE);
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
		g_ptr_array_add (*devices, nm_dbus_get_object_path_for_device (NM_DEVICE (iter->data)));

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

NMState
nm_manager_get_state (NMManager *manager)
{
	NMManagerPrivate *priv;
	GSList *iter;
	NMState state = NM_STATE_DISCONNECTED;

	g_return_val_if_fail (NM_IS_MANAGER (manager), NM_STATE_UNKNOWN);

	priv = NM_MANAGER_GET_PRIVATE (manager);

	if (priv->sleeping)
		return NM_STATE_ASLEEP;

	for (iter = priv->devices; iter; iter = iter->next) {
		NMDevice *dev = NM_DEVICE (iter->data);

		if (nm_device_get_state (dev) == NM_DEVICE_STATE_ACTIVATED)
			return NM_STATE_CONNECTED;

		if (nm_device_is_activating (dev))
			state = NM_STATE_CONNECTING;
	}

	return state;
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

	manager_state_changed (manager);
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
impl_manager_legacy_state (NMManager *manager, GError **err)
{
	return nm_manager_get_state (manager);
}


/* Connections */

GSList *
nm_manager_get_connections (NMManager *manager)
{
	g_return_val_if_fail (NM_IS_MANAGER (manager), NULL);

	return NM_MANAGER_GET_PRIVATE (manager)->connections;
}

void
nm_manager_update_connections (NMManager *manager,
							   GSList *connections,
							   gboolean reset)
{
	g_return_if_fail (NM_IS_MANAGER (manager));

	if (reset)
		nm_manager_connections_destroy (manager);

	
}
