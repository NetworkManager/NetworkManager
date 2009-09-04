/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <string.h>
#include "nm-modem-manager.h"
#include "nm-modem.h"
#include "nm-modem-gsm.h"
#include "nm-modem-cdma.h"
#include "nm-dbus-manager.h"
#include "nm-utils.h"
#include "nm-modem-types.h"

#define MODEM_POKE_INTERVAL 120

G_DEFINE_TYPE (NMModemManager, nm_modem_manager, G_TYPE_OBJECT)

#define NM_MODEM_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_MANAGER, NMModemManagerPrivate))

typedef struct {
	NMDBusManager *dbus_mgr;
	DBusGProxy *proxy;
	GHashTable *modems;
	gboolean disposed;
	guint poke_id;
} NMModemManagerPrivate;

enum {
	DEVICE_ADDED,
	DEVICE_REMOVED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


NMModemManager *
nm_modem_manager_get (void)
{
	static NMModemManager *singleton = NULL;

	if (!singleton)
		singleton = NM_MODEM_MANAGER (g_object_new (NM_TYPE_MODEM_MANAGER, NULL));
	else
		g_object_ref (singleton);

	g_assert (singleton);
	return singleton;
}

gboolean
nm_modem_manager_has_modem_for_iface (NMModemManager *manager,
                                      const gchar *iface)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (manager);
	GList *iter;
	g_assert (manager);
	g_assert (NM_IS_MODEM_MANAGER(manager));
	g_assert (iface);

	for (iter = g_hash_table_get_values(priv->modems); iter != NULL; iter = iter->next) {
		NMDevice *device = NM_DEVICE(iter->data);
		const gchar *device_iface = nm_device_get_iface (device);
		if (!g_strcmp0 (iface, device_iface))
			return TRUE;
	}
	return FALSE;
}

static gboolean
get_modem_properties (DBusGConnection *connection,
					  const char *path,
					  char **device,
					  char **data_device,
					  char **driver,
					  guint32 *type,
					  guint32 *ip_method)
{
	DBusGProxy *proxy;
	GValue value = { 0 };
	GError *err = NULL;

	proxy = dbus_g_proxy_new_for_name (connection,
									   MM_DBUS_SERVICE,
									   path,
									   "org.freedesktop.DBus.Properties");

	if (dbus_g_proxy_call_with_timeout (proxy, "Get", 15000, &err,
	                                    G_TYPE_STRING, MM_DBUS_INTERFACE_MODEM,
	                                    G_TYPE_STRING, "Type",
	                                    G_TYPE_INVALID,
	                                    G_TYPE_VALUE, &value,
	                                    G_TYPE_INVALID)) {
		*type = g_value_get_uint (&value);
		g_value_unset (&value);
	} else {
		g_warning ("Could not get device type: %s", err->message);
		goto out;
	}

	if (dbus_g_proxy_call_with_timeout (proxy, "Get", 15000, &err,
	                                    G_TYPE_STRING, MM_DBUS_INTERFACE_MODEM,
	                                    G_TYPE_STRING, "MasterDevice",
	                                    G_TYPE_INVALID,
	                                    G_TYPE_VALUE, &value,
	                                    G_TYPE_INVALID)) {
		*device = g_value_dup_string (&value);
		g_value_unset (&value);
	} else {
		g_warning ("Could not get device: %s", err->message);
		goto out;
	}

	if (dbus_g_proxy_call_with_timeout (proxy, "Get", 15000, &err,
										G_TYPE_STRING, MM_DBUS_INTERFACE_MODEM,
										G_TYPE_STRING, "IpMethod",
										G_TYPE_INVALID,
										G_TYPE_VALUE, &value,
										G_TYPE_INVALID)) {
		*ip_method = g_value_get_uint (&value);
		g_value_unset (&value);
	} else {
		g_warning ("Could not get IP method: %s", err->message);
		goto out;
	}

	if (dbus_g_proxy_call_with_timeout (proxy, "Get", 15000, &err,
										G_TYPE_STRING, MM_DBUS_INTERFACE_MODEM,
										G_TYPE_STRING, "Device",
										G_TYPE_INVALID,
										G_TYPE_VALUE, &value,
										G_TYPE_INVALID)) {
		*data_device = g_value_dup_string (&value);
		g_value_unset (&value);
	} else {
		g_warning ("Could not get modem data device: %s", err->message);
		goto out;
	}

	if (dbus_g_proxy_call_with_timeout (proxy, "Get", 15000, &err,
										G_TYPE_STRING, MM_DBUS_INTERFACE_MODEM,
										G_TYPE_STRING, "Driver",
										G_TYPE_INVALID,
										G_TYPE_VALUE, &value,
										G_TYPE_INVALID)) {
		*driver = g_value_dup_string (&value);
		g_value_unset (&value);
	} else {
		g_warning ("Could not get modem driver: %s", err->message);
		goto out;
	}

 out:
	if (err)
		g_error_free (err);

	g_object_unref (proxy);

	return *data_device && *driver;
}

static void
create_modem (NMModemManager *manager, const char *path)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (manager);
	NMDevice *device;
	char *data_device = NULL, *driver = NULL, *master_device = NULL;
	uint modem_type = MM_MODEM_TYPE_UNKNOWN;
	uint ip_method = MM_MODEM_IP_METHOD_PPP;

	if (g_hash_table_lookup (priv->modems, path)) {
		nm_warning ("Modem with path %s already exists, ignoring", path);
		return;
	}

	if (!get_modem_properties (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                           path, &master_device, &data_device, &driver,
	                           &modem_type, &ip_method))
		return;

	if (modem_type == MM_MODEM_TYPE_UNKNOWN) {
		nm_warning ("Modem with path %s has unknown type, ignoring", path);
		return;
	}

	if (!master_device || !strlen (master_device)) {
		nm_warning ("Modem with path %s has unknown device, ignoring", path);
		return;
	}

	if (!driver || !strlen (driver)) {
		nm_warning ("Modem with path %s has unknown driver, ignoring", path);
		return;
	}

	if (!data_device || !strlen (data_device)) {
		nm_warning ("Modem with path %s has unknown data device, ignoring", path);
		return;
	}

	if (modem_type == MM_MODEM_TYPE_GSM)
		device = nm_modem_gsm_new (path, master_device, data_device, driver, ip_method);
	else if (modem_type == MM_MODEM_TYPE_CDMA)
		device = nm_modem_cdma_new (path, master_device, data_device, driver);
	else
		g_error ("Invalid modem type");

	g_free (data_device);
	g_free (driver);

	if (device) {
		g_hash_table_insert (priv->modems, g_strdup (path), device);
		g_signal_emit (manager, signals[DEVICE_ADDED], 0, device);
	}
}

static void
modem_added (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	create_modem (NM_MODEM_MANAGER (user_data), path);
}

static void
modem_removed (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (user_data);
	NMModem *modem;

	modem = (NMModem *) g_hash_table_lookup (priv->modems, path);
	if (modem) {
		g_signal_emit (user_data, signals[DEVICE_REMOVED], 0, modem);
		g_hash_table_remove (priv->modems, path);
	}
}

static gboolean
poke_modem_cb (gpointer user_data)
{
	NMModemManager *self = NM_MODEM_MANAGER (user_data);
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	DBusGConnection *g_connection;
	DBusGProxy *proxy;

	g_connection = nm_dbus_manager_get_connection (priv->dbus_mgr);
	proxy = dbus_g_proxy_new_for_name (g_connection,
									   MM_DBUS_SERVICE,
									   MM_DBUS_PATH,
									   MM_DBUS_INTERFACE);

	dbus_g_proxy_call_no_reply (proxy, "EnumerateDevices", G_TYPE_INVALID);
	g_object_unref (proxy);

	return TRUE;
}

static void
enumerate_devices_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer data)
{
	NMModemManager *manager = NM_MODEM_MANAGER (data);
	GPtrArray *modems;
	GError *error = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &error,
								dbus_g_type_get_collection ("GPtrArray", DBUS_TYPE_G_OBJECT_PATH), &modems,
								G_TYPE_INVALID)) {
		nm_warning ("Could not get modem list: %s", error->message);
		g_error_free (error);
	} else {
		int i;

		for (i = 0; i < modems->len; i++) {
			char *path = (char *) g_ptr_array_index (modems, i);

			create_modem (manager, path);
			g_free (path);
		}

		g_ptr_array_free (modems, TRUE);
	}
}

static void
modem_manager_appeared (NMModemManager *self, gboolean enumerate_devices)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	if (priv->poke_id) {
		g_source_remove (priv->poke_id);
		priv->poke_id = 0;
	}

	nm_info ("modem-manager is now available");

	priv->proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
											 MM_DBUS_SERVICE, MM_DBUS_PATH, MM_DBUS_INTERFACE);

	dbus_g_proxy_add_signal (priv->proxy, "DeviceAdded", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "DeviceAdded",
								 G_CALLBACK (modem_added), self,
								 NULL);

	dbus_g_proxy_add_signal (priv->proxy, "DeviceRemoved", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->proxy, "DeviceRemoved",
								 G_CALLBACK (modem_removed), self,
								 NULL);

	if (enumerate_devices)
		dbus_g_proxy_begin_call (priv->proxy, "EnumerateDevices", enumerate_devices_done, self, NULL, G_TYPE_INVALID);
}

static gboolean
remove_one_modem (gpointer key, gpointer value, gpointer user_data)
{
	g_signal_emit (user_data, signals[DEVICE_REMOVED], 0, value);

	return TRUE;
}

static void
modem_manager_disappeared (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	g_hash_table_foreach_remove (priv->modems, remove_one_modem, self);

	if (priv->proxy) {
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}

	/* Try to activate the modem-manager */
	nm_info ("Trying to start the modem-manager...");
	poke_modem_cb (self);
	priv->poke_id = g_timeout_add_seconds (MODEM_POKE_INTERVAL, poke_modem_cb, self);
}

static void
nm_modem_manager_name_owner_changed (NMDBusManager *dbus_mgr,
									 const char *name,
									 const char *old_owner,
									 const char *new_owner,
									 gpointer user_data)
{
	gboolean old_owner_good;
	gboolean new_owner_good;

	/* Can't handle the signal if its not from the modem service */
	if (strcmp (MM_DBUS_SERVICE, name) != 0)
		return;

	old_owner_good = (old_owner && strlen (old_owner));
	new_owner_good = (new_owner && strlen (new_owner));

	if (!old_owner_good && new_owner_good) {
		modem_manager_appeared (NM_MODEM_MANAGER (user_data), FALSE);
	} else if (old_owner_good && !new_owner_good) {
		nm_info ("modem manager disappeared");
		modem_manager_disappeared (NM_MODEM_MANAGER (user_data));
	}
}

/*******************************************************/

static void
nm_modem_manager_init (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	priv->modems = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);
	priv->dbus_mgr = nm_dbus_manager_get ();

	g_signal_connect (priv->dbus_mgr, "name-owner-changed",
					  G_CALLBACK (nm_modem_manager_name_owner_changed),
					  self);

	if (nm_dbus_manager_name_has_owner (priv->dbus_mgr, MM_DBUS_SERVICE))
		modem_manager_appeared (self, TRUE);
	else
		modem_manager_disappeared (self);
}

static void
dispose (GObject *object)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (object);

	if (priv->disposed)
		return;

	priv->disposed = TRUE;

	if (priv->poke_id) {
		g_source_remove (priv->poke_id);
		priv->poke_id = 0;
	}

	g_hash_table_foreach_remove (priv->modems, remove_one_modem, object);
	g_hash_table_destroy (priv->modems);

	if (priv->proxy) {
		g_object_unref (priv->proxy);
		priv->proxy = NULL;
	}

	if (priv->dbus_mgr) {
		g_object_unref (priv->dbus_mgr);
		priv->dbus_mgr = NULL;
	}

	/* Chain up to the parent class */
	G_OBJECT_CLASS (nm_modem_manager_parent_class)->dispose (object);
}

static void
nm_modem_manager_class_init (NMModemManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemManagerPrivate));

	object_class->dispose = dispose;

	/* signals */
	signals[DEVICE_ADDED] =
		g_signal_new ("device-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMModemManagerClass, device_added),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);

	signals[DEVICE_REMOVED] =
		g_signal_new ("device-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMModemManagerClass, device_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1,
					  G_TYPE_OBJECT);
}
