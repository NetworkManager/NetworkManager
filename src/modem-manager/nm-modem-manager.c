/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 * Copyright (C) 2009 Canonical Ltd.
 */

#include <string.h>
#include "config.h"
#include "nm-modem-manager.h"
#include "nm-logging.h"
#include "nm-modem.h"
#include "nm-modem-gsm.h"
#include "nm-modem-cdma.h"
#include "nm-dbus-manager.h"
#include "nm-modem-types.h"
#include "nm-marshal.h"
#include "nm-dbus-glib-types.h"

#if WITH_MODEM_MANAGER_1
#include <libmm-glib.h>
#include "nm-modem-broadband.h"
#endif

#define MODEM_POKE_INTERVAL 120

G_DEFINE_TYPE (NMModemManager, nm_modem_manager, G_TYPE_OBJECT)

struct _NMModemManagerPrivate {
	/* ModemManager < 0.7 */
	NMDBusManager *dbus_mgr;
	DBusGProxy *proxy;
	guint poke_id;

#if WITH_MODEM_MANAGER_1
	/* ModemManager >= 0.7 */
	GDBusConnection *dbus_connection;
	MMManager *modem_manager_1;
	guint modem_manager_1_poke_id;
	gboolean old_modem_manager_found;
	gboolean new_modem_manager_found;
#endif

	/* Common */
	GHashTable *modems;
};

enum {
	MODEM_ADDED,
	MODEM_REMOVED,

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

/************************************************************************/
/* Support for ModemManager < 0.7 */

static void
clear_modem_manager_support (NMModemManager *self)
{
	if (self->priv->poke_id) {
		g_source_remove (self->priv->poke_id);
		self->priv->poke_id = 0;
	}

	if (self->priv->proxy) {
		g_object_unref (self->priv->proxy);
		self->priv->proxy = NULL;
	}

	if (self->priv->dbus_mgr) {
		g_object_unref (self->priv->dbus_mgr);
		self->priv->dbus_mgr = NULL;
	}
}

static gboolean
get_modem_properties (DBusGConnection *connection,
					  const char *path,
					  char **device,
					  char **data_device,
					  char **driver,
					  guint32 *type,
					  guint32 *ip_method,
					  guint32 *ip_timeout,
					  NMModemState *state)
{
	DBusGProxy *proxy;
	GError *err = NULL;
	GHashTable *props = NULL;
	GHashTableIter iter;
	const char *prop;
	GValue *value;

	proxy = dbus_g_proxy_new_for_name (connection,
	                                   MM_OLD_DBUS_SERVICE,
	                                   path,
	                                   "org.freedesktop.DBus.Properties");

	if (!dbus_g_proxy_call_with_timeout (proxy, "GetAll", 15000, &err,
	                                     G_TYPE_STRING, MM_OLD_DBUS_INTERFACE_MODEM,
	                                     G_TYPE_INVALID,
	                                     DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                                     G_TYPE_INVALID)) {
		nm_log_warn (LOGD_MB, "could not get modem properties: %s %s",
		             err ? dbus_g_error_get_name (err) : "(none)",
		             err ? err->message : "(unknown)");
		g_clear_error (&err);
		goto out;
	}

	if (!props) {
		nm_log_warn (LOGD_MB, "no modem properties found");
		goto out;
	}

	g_hash_table_iter_init (&iter, props);
	while (g_hash_table_iter_next (&iter, (gpointer) &prop, (gpointer) &value)) {
		if (g_strcmp0 (prop, "Type") == 0)
			*type = g_value_get_uint (value);
		else if (g_strcmp0 (prop, "MasterDevice") == 0)
			*device = g_value_dup_string (value);
		else if (g_strcmp0 (prop, "IpMethod") == 0)
			*ip_method = g_value_get_uint (value);
		else if (g_strcmp0 (prop, "Device") == 0)
			*data_device = g_value_dup_string (value);
		else if (g_strcmp0 (prop, "Driver") == 0)
			*driver = g_value_dup_string (value);
		else if (g_strcmp0 (prop, "IpTimeout") == 0)
			*ip_timeout = g_value_get_uint (value);
		else if (g_strcmp0 (prop, "State") == 0)
			*state = g_value_get_uint (value);
	}
	g_hash_table_unref (props);

 out:
	g_object_unref (proxy);

	return *data_device && *driver;
}

static void
create_modem (NMModemManager *self, const char *path)
{
	NMModem *modem = NULL;
	char *data_device = NULL, *driver = NULL, *master_device = NULL;
	uint modem_type = MM_MODEM_TYPE_UNKNOWN;
	uint ip_method = MM_MODEM_IP_METHOD_PPP;
	uint ip_timeout = 0;
	NMModemState state = NM_MODEM_STATE_UNKNOWN;

	if (g_hash_table_lookup (self->priv->modems, path)) {
		nm_log_warn (LOGD_MB, "modem with path %s already exists, ignoring", path);
		return;
	}

	if (!get_modem_properties (nm_dbus_manager_get_connection (self->priv->dbus_mgr),
	                           path, &master_device, &data_device, &driver,
	                           &modem_type, &ip_method, &ip_timeout, &state))
		return;

	if (modem_type == MM_MODEM_TYPE_UNKNOWN) {
		nm_log_warn (LOGD_MB, "modem with path %s has unknown type, ignoring", path);
		return;
	}

	if (!master_device || !strlen (master_device)) {
		nm_log_warn (LOGD_MB, "modem with path %s has unknown device, ignoring", path);
		return;
	}

	if (!driver || !strlen (driver)) {
		nm_log_warn (LOGD_MB, "modem with path %s has unknown driver, ignoring", path);
		return;
	}

	if (!data_device || !strlen (data_device)) {
		nm_log_warn (LOGD_MB, "modem with path %s has unknown data device, ignoring", path);
		return;
	}

	if (modem_type == MM_MODEM_TYPE_GSM)
		modem = nm_modem_gsm_new (path, data_device, ip_method, state);
	else if (modem_type == MM_MODEM_TYPE_CDMA)
		modem = nm_modem_cdma_new (path, data_device, ip_method, state);
	else
		nm_log_warn (LOGD_MB, "unknown modem type '%d'", modem_type);

	g_free (data_device);

	if (modem) {
		g_object_set (G_OBJECT (modem), NM_MODEM_IP_TIMEOUT, ip_timeout, NULL);
		g_hash_table_insert (self->priv->modems, g_strdup (path), modem);
		g_signal_emit (self, signals[MODEM_ADDED], 0, modem, driver);
	}

	g_free (driver);
}

static void
modem_added (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	create_modem (NM_MODEM_MANAGER (user_data), path);
}

static void
modem_removed (DBusGProxy *proxy, const char *path, gpointer user_data)
{
	NMModemManager *self = NM_MODEM_MANAGER (user_data);
	NMModem *modem;

	modem = (NMModem *) g_hash_table_lookup (self->priv->modems, path);
	if (modem) {
		g_signal_emit (self, signals[MODEM_REMOVED], 0, modem);
		g_hash_table_remove (self->priv->modems, path);
	}
}

static void
mm_poke_cb (DBusGProxy *proxy, DBusGProxyCall *call, gpointer user_data)
{
	GPtrArray *modems;
	int i;

	if (dbus_g_proxy_end_call (proxy, call, NULL,
	                           DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH, &modems,
	                           G_TYPE_INVALID)) {
		/* Don't care about the returned value, just free it */
		for (i = 0; i < modems->len; i++)
			g_free ((char *) g_ptr_array_index (modems, i));
		g_ptr_array_free (modems, TRUE);
	}
	g_object_unref (proxy);
}

static gboolean
poke_modem_cb (gpointer user_data)
{
	NMModemManager *self = NM_MODEM_MANAGER (user_data);
	DBusGConnection *g_connection;
	DBusGProxy *proxy;
	DBusGProxyCall *call;

	g_connection = nm_dbus_manager_get_connection (self->priv->dbus_mgr);
	proxy = dbus_g_proxy_new_for_name (g_connection,
									   MM_OLD_DBUS_SERVICE,
									   MM_OLD_DBUS_PATH,
									   MM_OLD_DBUS_INTERFACE);

	nm_log_dbg (LOGD_MB, "Requesting to (re)launch modem-manager...");

	call = dbus_g_proxy_begin_call_with_timeout (proxy,
	                                             "EnumerateDevices",
	                                             mm_poke_cb,
	                                             NULL,
	                                             NULL,
	                                             5000,
	                                             G_TYPE_INVALID);
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
		nm_log_warn (LOGD_MB, "could not get modem list: %s", error->message);
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

#if WITH_MODEM_MANAGER_1
static void clear_modem_manager_1_support (NMModemManager *self);
#endif

static void
modem_manager_appeared (NMModemManager *self, gboolean enumerate_devices)
{
	if (self->priv->poke_id) {
		g_source_remove (self->priv->poke_id);
		self->priv->poke_id = 0;
	}

	nm_log_info (LOGD_MB, "modem-manager is now available");

#if WITH_MODEM_MANAGER_1
	self->priv->old_modem_manager_found = TRUE;
	if (self->priv->new_modem_manager_found)
		nm_log_warn (LOGD_MB, "Both the old and the new ModemManager were found");
	else
		clear_modem_manager_1_support (self);
#endif

	self->priv->proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (self->priv->dbus_mgr),
	                                               MM_OLD_DBUS_SERVICE, MM_OLD_DBUS_PATH, MM_OLD_DBUS_INTERFACE);

	dbus_g_proxy_add_signal (self->priv->proxy, "DeviceAdded", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (self->priv->proxy, "DeviceAdded",
								 G_CALLBACK (modem_added), self,
								 NULL);

	dbus_g_proxy_add_signal (self->priv->proxy, "DeviceRemoved", DBUS_TYPE_G_OBJECT_PATH, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (self->priv->proxy, "DeviceRemoved",
								 G_CALLBACK (modem_removed), self,
								 NULL);

	if (enumerate_devices)
		dbus_g_proxy_begin_call (self->priv->proxy, "EnumerateDevices", enumerate_devices_done, self, NULL, G_TYPE_INVALID);
}

static gboolean
remove_one_modem (gpointer key, gpointer value, gpointer user_data)
{
	g_signal_emit (user_data, signals[MODEM_REMOVED], 0, value);

	return TRUE;
}

static void
modem_manager_disappeared (NMModemManager *self)
{
	g_hash_table_foreach_remove (self->priv->modems, remove_one_modem, self);

	if (self->priv->proxy) {
		g_object_unref (self->priv->proxy);
		self->priv->proxy = NULL;
	}

	/* Try to activate the modem-manager */
	nm_log_dbg (LOGD_MB, "trying to start the modem manager...");
	poke_modem_cb (self);
	self->priv->poke_id = g_timeout_add_seconds (MODEM_POKE_INTERVAL, poke_modem_cb, self);
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
	if (strcmp (MM_OLD_DBUS_SERVICE, name) != 0)
		return;

	old_owner_good = (old_owner && strlen (old_owner));
	new_owner_good = (new_owner && strlen (new_owner));

	if (!old_owner_good && new_owner_good) {
		modem_manager_appeared (NM_MODEM_MANAGER (user_data), FALSE);
	} else if (old_owner_good && !new_owner_good) {
		nm_log_info (LOGD_MB, "the modem manager disappeared");
		modem_manager_disappeared (NM_MODEM_MANAGER (user_data));
	}
}

/************************************************************************/
/* Support for ModemManager >= 0.7 */

#if WITH_MODEM_MANAGER_1

static void
clear_modem_manager_1_support (NMModemManager *self)
{
	if (self->priv->modem_manager_1_poke_id) {
		g_source_remove (self->priv->modem_manager_1_poke_id);
		self->priv->modem_manager_1_poke_id = 0;
	}

	g_clear_object (&self->priv->modem_manager_1);
	g_clear_object (&self->priv->dbus_connection);
}

static void
modem_object_added (MMManager *modem_manager,
                    MMObject  *modem_object,
                    NMModemManager *self)
{
	const gchar *path;
	gchar *drivers;
	MMModem *modem_iface;
	NMModem *modem;

	/* Ensure we don't have the same modem already */
	path = mm_object_get_path (modem_object);
	if (g_hash_table_lookup (self->priv->modems, path)) {
		nm_log_warn (LOGD_MB, "modem with path %s already exists, ignoring", path);
		return;
	}

	/* Ensure we have the 'Modem' interface at least */
	modem_iface = mm_object_peek_modem (modem_object);
	if (!modem_iface) {
		nm_log_warn (LOGD_MB, "modem with path %s doesn't have the Modem interface, ignoring", path);
		return;
	}

	/* Ensure we have a primary port reported */
	if (!mm_modem_get_primary_port (modem_iface)) {
		nm_log_warn (LOGD_MB, "modem with path %s has unknown primary port, ignoring", path);
		return;
	}

	/* Create a new modem object */
	modem = nm_modem_broadband_new (G_OBJECT (modem_object));
	if (!modem)
		return;

	/* Build a single string with all drivers listed */
	drivers = g_strjoinv (", ", (gchar **)mm_modem_get_drivers (modem_iface));

	/* Keep track of the new modem and notify about it */
	g_hash_table_insert (self->priv->modems, g_strdup (path), modem);
	g_signal_emit (self, signals[MODEM_ADDED], 0, modem, drivers);
	g_free (drivers);
}

static void
modem_object_removed (MMManager *manager,
                      MMObject  *modem_object,
                      NMModemManager *self)
{
	NMModem *modem;
	const gchar *path;

	path = mm_object_get_path (modem_object);
	modem = (NMModem *) g_hash_table_lookup (self->priv->modems, path);
	if (!modem)
		return;

	g_signal_emit (self, signals[MODEM_REMOVED], 0, modem);
	g_hash_table_remove (self->priv->modems, path);
}

static void
modem_manager_1_available (NMModemManager *self)
{
	GList *modems, *l;

	nm_log_info (LOGD_MB, "ModemManager available in the bus");

	self->priv->new_modem_manager_found = TRUE;
	if (self->priv->old_modem_manager_found)
		nm_log_warn (LOGD_MB, "Both the old and the new ModemManager were found");
	else
		clear_modem_manager_support (self);

	/* Update initial modems list */
    modems = g_dbus_object_manager_get_objects (G_DBUS_OBJECT_MANAGER (self->priv->modem_manager_1));
    for (l = modems; l; l = g_list_next (l))
	    modem_object_added (self->priv->modem_manager_1, MM_OBJECT (l->data), self);
    g_list_free_full (modems, (GDestroyNotify) g_object_unref);
}

static void schedule_modem_manager_1_relaunch (NMModemManager *self,
                                               guint n_seconds);

static void
modem_manager_1_name_owner_changed (MMManager *modem_manager_1,
                                    GParamSpec *pspec,
                                    NMModemManager *self)
{
	gchar *name_owner;

	/* Quit poking, if any */
	if (self->priv->modem_manager_1_poke_id) {
		g_source_remove (self->priv->modem_manager_1_poke_id);
		self->priv->modem_manager_1_poke_id = 0;
	}

	name_owner = g_dbus_object_manager_client_get_name_owner (G_DBUS_OBJECT_MANAGER_CLIENT (modem_manager_1));
	if (!name_owner) {
		nm_log_info (LOGD_MB, "ModemManager disappeared from bus");
		schedule_modem_manager_1_relaunch (self, 0);
		return;
	}

	/* Available! */
	g_free (name_owner);
	modem_manager_1_available (self);
}

static void
manager_new_ready (GObject *source,
                   GAsyncResult *res,
                   NMModemManager *self)
{
	/* Note we always get an extra reference to self here */

	GError *error = NULL;

	g_assert (!self->priv->modem_manager_1);
	self->priv->modem_manager_1 = mm_manager_new_finish (res, &error);
	if (!self->priv->modem_manager_1) {
		if (   !g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN)
		    && !g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_EXEC_FAILED)
		    && !g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_FORK_FAILED)
		    && !g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_FAILED)
		    && !g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_TIMEOUT)
		    && !g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_SERVICE_NOT_FOUND)) {
			nm_log_warn (LOGD_MB, "error creating ModemManager client: %s", error->message);
		}
		g_error_free (error);
		/* Setup timeout to relaunch */
		schedule_modem_manager_1_relaunch (self, MODEM_POKE_INTERVAL);
	} else if (self->priv->old_modem_manager_found) {
		/* If we found the old MM, abort */
		clear_modem_manager_1_support (self);
	} else {
		gchar *name_owner;

		g_signal_connect (self->priv->modem_manager_1,
		                  "notify::name-owner",
		                  G_CALLBACK (modem_manager_1_name_owner_changed),
		                  self);
		g_signal_connect (self->priv->modem_manager_1,
		                  "object-added",
		                  G_CALLBACK (modem_object_added),
		                  self);
		g_signal_connect (self->priv->modem_manager_1,
		                  "object-removed",
		                  G_CALLBACK (modem_object_removed),
		                  self);

		/* If there is no current owner right away, ensure we poke until we get
		 * one */
		name_owner = g_dbus_object_manager_client_get_name_owner (G_DBUS_OBJECT_MANAGER_CLIENT (self->priv->modem_manager_1));
		if (!name_owner) {
			/* Setup timeout to wait for an owner */
			schedule_modem_manager_1_relaunch (self, MODEM_POKE_INTERVAL);
		} else {
			/* Available! */
			modem_manager_1_available (self);
			g_free (name_owner);
		}
	}

	/* Balance refcount */
	g_object_unref (self);
}

static void
recreate_client (NMModemManager *self)
{
	g_assert (self->priv->dbus_connection);

	/* Re-create the GDBusObjectManagerClient so that we request again the owner
	 * for the well-known name.
	 * Note that we pass an extra reference always */
	g_clear_object (&self->priv->modem_manager_1);
	mm_manager_new (self->priv->dbus_connection,
	                G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_NONE,
	                NULL,
	                (GAsyncReadyCallback)manager_new_ready,
	                g_object_ref (self));
}

static void
bus_get_ready (GObject *source,
               GAsyncResult *res,
               NMModemManager *self)
{
	/* Note we always get an extra reference to self here */

	GError *error = NULL;

	self->priv->dbus_connection = g_bus_get_finish (res, &error);
	if (!self->priv->dbus_connection) {
		nm_log_warn (LOGD_CORE, "error getting bus connection: %s", error->message);
		g_error_free (error);
		/* Setup timeout to relaunch */
		schedule_modem_manager_1_relaunch (self, MODEM_POKE_INTERVAL);
	} else if (self->priv->old_modem_manager_found) {
		/* If we found the old MM, abort */
		clear_modem_manager_1_support (self);
	} else {
		/* Got the bus, create new ModemManager client. */
		recreate_client (self);
	}

	/* Balance refcount */
	g_object_unref (self);
}

static gboolean
ensure_bus (NMModemManager *self)
{
	nm_log_dbg (LOGD_MB, "Requesting to (re)launch ModemManager...");

	/* Clear poke ID */
	self->priv->modem_manager_1_poke_id = 0;

	if (!self->priv->dbus_connection)
		g_bus_get (G_BUS_TYPE_SYSTEM,
		           NULL,
		           (GAsyncReadyCallback)bus_get_ready,
		           g_object_ref (self));
	else
		/* If bus is already available, launch client re-creation */
		recreate_client (self);

	return FALSE;
}

static void
schedule_modem_manager_1_relaunch (NMModemManager *self,
                                   guint n_seconds)
{
	/* No need to pass an extra reference to self; timeout/idle will be
	 * cancelled if the object gets disposed. */

	if (n_seconds)
		self->priv->modem_manager_1_poke_id = g_timeout_add_seconds (n_seconds, (GSourceFunc)ensure_bus, self);
	else
		self->priv->modem_manager_1_poke_id = g_idle_add ((GSourceFunc)ensure_bus, self);
}

#endif /* WITH_MODEM_MANAGER_1 */

/************************************************************************/

static void
nm_modem_manager_init (NMModemManager *self)
{
	self->priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_MODEM_MANAGER, NMModemManagerPrivate);

	self->priv->modems = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);

	/* ModemManager < 0.7 */
	self->priv->dbus_mgr = nm_dbus_manager_get ();
	g_signal_connect (self->priv->dbus_mgr, NM_DBUS_MANAGER_NAME_OWNER_CHANGED,
					  G_CALLBACK (nm_modem_manager_name_owner_changed),
					  self);
	if (nm_dbus_manager_name_has_owner (self->priv->dbus_mgr, MM_OLD_DBUS_SERVICE))
		modem_manager_appeared (self, TRUE);
	else
		modem_manager_disappeared (self);

#if WITH_MODEM_MANAGER_1
	/* ModemManager >= 0.7 */
	schedule_modem_manager_1_relaunch (self, 0);
#endif
}

static void
dispose (GObject *object)
{
	NMModemManager *self = NM_MODEM_MANAGER (object);

	/* ModemManager < 0.7 */
	clear_modem_manager_support (self);

#if WITH_MODEM_MANAGER_1
	/* ModemManager >= 0.7 */
	clear_modem_manager_1_support (self);
#endif

	if (self->priv->modems) {
		g_hash_table_foreach_remove (self->priv->modems, remove_one_modem, object);
		g_hash_table_destroy (self->priv->modems);
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
	signals[MODEM_ADDED] =
		g_signal_new ("modem-added",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMModemManagerClass, modem_added),
					  NULL, NULL,
					  _nm_marshal_VOID__OBJECT_STRING,
					  G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_STRING);

	signals[MODEM_REMOVED] =
		g_signal_new ("modem-removed",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMModemManagerClass, modem_removed),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__OBJECT,
					  G_TYPE_NONE, 1, G_TYPE_OBJECT);
}
