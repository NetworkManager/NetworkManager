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
 * Copyright (C) 2009 - 2014 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 * Copyright (C) 2009 - 2013 Canonical Ltd.
 */

#include "nm-default.h"

#include "nm-modem-manager.h"

#include <string.h>
#include <libmm-glib.h>

#if HAVE_LIBSYSTEMD
#include <systemd/sd-daemon.h>
#else
#define sd_booted() FALSE
#endif

#include "nm-dbus-compat.h"
#include "nm-modem.h"
#include "nm-modem-broadband.h"

#if WITH_OFONO
#include "nm-modem-ofono.h"
#endif

#define MODEM_POKE_INTERVAL 120

/*****************************************************************************/

enum {
	MODEM_ADDED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	GDBusConnection *dbus_connection;
	MMManager *modem_manager;
	guint mm_launch_id;
	gulong mm_name_owner_changed_id;
	gulong mm_object_added_id;
	gulong mm_object_removed_id;

#if WITH_OFONO
	GDBusProxy *ofono_proxy;
#endif

	GHashTable *modems;
} NMModemManagerPrivate;

struct _NMModemManager {
	GObject parent;
	NMModemManagerPrivate _priv;
};

struct _NMModemManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMModemManager, nm_modem_manager, G_TYPE_OBJECT)

#define NM_MODEM_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMModemManager, NM_IS_MODEM_MANAGER)

/*****************************************************************************/

static void
handle_new_modem (NMModemManager *self, NMModem *modem)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	const char *path;

	path = nm_modem_get_path (modem);
	if (g_hash_table_lookup (priv->modems, path)) {
		g_warn_if_reached ();
		return;
	}

	/* Track the new modem */
	g_hash_table_insert (priv->modems, g_strdup (path), modem);
	g_signal_emit (self, signals[MODEM_ADDED], 0, modem);
}

static gboolean
remove_one_modem (gpointer key, gpointer value, gpointer user_data)
{
	nm_modem_emit_removed (NM_MODEM (value));
	return TRUE;
}

static void
clear_modem_manager (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	if (!priv->modem_manager)
		return;
	nm_clear_g_signal_handler (priv->modem_manager, &priv->mm_name_owner_changed_id);
	nm_clear_g_signal_handler (priv->modem_manager, &priv->mm_object_added_id);
	nm_clear_g_signal_handler (priv->modem_manager, &priv->mm_object_removed_id);
	g_clear_object (&priv->modem_manager);
}

static void
modem_object_added (MMManager *modem_manager,
                    MMObject  *modem_object,
                    NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	const gchar *path;
	MMModem *modem_iface;
	NMModem *modem;
	GError *error = NULL;

	/* Ensure we don't have the same modem already */
	path = mm_object_get_path (modem_object);
	if (g_hash_table_lookup (priv->modems, path)) {
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
	modem = nm_modem_broadband_new (G_OBJECT (modem_object), &error);
	if (modem)
		handle_new_modem (self, modem);
	else {
		nm_log_warn (LOGD_MB, "failed to create modem: %s",
		             error->message);
	}
	g_clear_error (&error);
}

static void
modem_object_removed (MMManager *manager,
                      MMObject  *modem_object,
                      NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	NMModem *modem;
	const gchar *path;

	path = mm_object_get_path (modem_object);
	modem = (NMModem *) g_hash_table_lookup (priv->modems, path);
	if (!modem)
		return;

	nm_modem_emit_removed (modem);
	g_hash_table_remove (priv->modems, path);
}

static void
modem_manager_available (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	GList *modems, *l;

	nm_log_info (LOGD_MB, "ModemManager available in the bus");

	/* Update initial modems list */
	modems = g_dbus_object_manager_get_objects (G_DBUS_OBJECT_MANAGER (priv->modem_manager));
	for (l = modems; l; l = g_list_next (l))
		modem_object_added (priv->modem_manager, MM_OBJECT (l->data), self);
	g_list_free_full (modems, (GDestroyNotify) g_object_unref);
}

static void schedule_modem_manager_relaunch (NMModemManager *self,
                                             guint n_seconds);
static void ensure_modem_manager (NMModemManager *self);

static void
modem_manager_name_owner_changed (MMManager *modem_manager,
                                  GParamSpec *pspec,
                                  NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	gchar *name_owner;

	/* Quit poking, if any */
	nm_clear_g_source (&priv->mm_launch_id);

	name_owner = g_dbus_object_manager_client_get_name_owner (G_DBUS_OBJECT_MANAGER_CLIENT (modem_manager));
	if (!name_owner) {
		nm_log_info (LOGD_MB, "ModemManager disappeared from bus");

		/* If not managed by systemd, schedule relaunch */
		if (!sd_booted ())
			schedule_modem_manager_relaunch (self, 0);

		return;
	}

	/* Available! */
	g_free (name_owner);

	/* Hack alert: GDBusObjectManagerClient won't signal neither 'object-added'
	 * nor 'object-removed' if it was created while there was no ModemManager in
	 * the bus. This hack avoids this issue until we get a GIO with the fix
	 * included... */
	clear_modem_manager (self);
	ensure_modem_manager (self);

	/* Whenever GDBusObjectManagerClient is fixed, we can just do the following:
	 * modem_manager_available (self);
	 */
}

#if WITH_OFONO

static void
ofono_create_modem (NMModemManager *self, const char *path)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	NMModem *modem = NULL;

	/* Ensure duplicate modems aren't created.  Because we're not using the
	 * ObjectManager interface there's a race during oFono startup where we
	 * receive ModemAdded signals before GetModems() returns, so some of the
	 * modems returned from GetModems() may already have been created.
	 */
	if (!g_hash_table_lookup (priv->modems, path)) {
		modem = nm_modem_ofono_new (path);
		if (modem)
			handle_new_modem (self, modem);
		else
			nm_log_warn (LOGD_MB, "Failed to create oFono modem for %s", path);
	}
}

static void
ofono_signal_cb (GDBusProxy *proxy,
                 gchar *sender_name,
                 gchar *signal_name,
                 GVariant *parameters,
                 gpointer user_data)
{
	NMModemManager *self = NM_MODEM_MANAGER (user_data);
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	gchar *object_path;
	NMModem *modem;

	if (g_strcmp0 (signal_name, "ModemAdded") == 0) {
		g_variant_get (parameters, "(oa{sv})", &object_path, NULL);
		nm_log_info (LOGD_MB, "oFono modem appeared: %s", object_path);

		ofono_create_modem (NM_MODEM_MANAGER (user_data), object_path);
		g_free (object_path);
	} else if (g_strcmp0 (signal_name, "ModemRemoved") == 0) {
		g_variant_get (parameters, "(o)", &object_path);
		nm_log_info (LOGD_MB, "oFono modem removed: %s", object_path);

		modem = (NMModem *) g_hash_table_lookup (priv->modems, object_path);
		if (modem) {
			nm_modem_emit_removed (modem);
			g_hash_table_remove (priv->modems, object_path);
		} else {
			nm_log_warn (LOGD_MB, "could not remove modem %s, not found in table",
			             object_path);
		}
		g_free (object_path);
	}
}

static void
ofono_enumerate_devices_done (GDBusProxy *proxy, GAsyncResult *res, gpointer user_data)
{
	NMModemManager *manager = NM_MODEM_MANAGER (user_data);
	gs_free_error GError *error = NULL;
	GVariant *results;
	GVariantIter *iter;
	const char *path;

	results = g_dbus_proxy_call_finish (proxy, res, &error);
	if (results) {
		g_variant_get (results, "(a(oa{sv}))", &iter);
		while (g_variant_iter_loop (iter, "(&oa{sv})", &path, NULL))
			ofono_create_modem (manager, path);
		g_variant_iter_free (iter);
		g_variant_unref (results);
	}

	if (error) {
		nm_log_warn (LOGD_MB, "failed to enumerate oFono devices: %s",
		             error->message);
	}
}

static void
ofono_check_name_owner (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	gs_free char *name_owner = NULL;

	name_owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (priv->ofono_proxy));
	if (name_owner) {
		nm_log_info (LOGD_MB, "oFono is now available");

		g_dbus_proxy_call (priv->ofono_proxy,
		                   "GetModems",
		                   NULL,
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   NULL,
		                   (GAsyncReadyCallback) ofono_enumerate_devices_done,
		                   g_object_ref (self));
	} else {
		GHashTableIter iter;
		NMModem *modem;

		nm_log_info (LOGD_MB, "oFono disappeared from bus");

		/* Remove any oFono modems that might be left around */
		g_hash_table_iter_init (&iter, priv->modems);
		while (g_hash_table_iter_next (&iter, NULL, (gpointer) &modem)) {
			if (NM_IS_MODEM_OFONO (modem)) {
				nm_modem_emit_removed (modem);
				g_hash_table_iter_remove (&iter);
			}
		}
	}
}

static void
ofono_name_owner_changed (GDBusProxy *ofono_proxy,
                          GParamSpec *pspec,
                          NMModemManager *self)
{
	ofono_check_name_owner (self);
}

static void
ofono_proxy_new_cb (GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	gs_unref_object NMModemManager *self = NM_MODEM_MANAGER (user_data);
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;

	priv->ofono_proxy = g_dbus_proxy_new_finish (res, &error);
	if (error) {
		nm_log_warn (LOGD_MB, "error getting oFono bus proxy: %s", error->message);
		return;
	}

	g_signal_connect (priv->ofono_proxy,
	                  "notify::g-name-owner",
	                  G_CALLBACK (ofono_name_owner_changed),
	                  self);

	g_signal_connect (priv->ofono_proxy,
	                  "g-signal",
	                  G_CALLBACK (ofono_signal_cb),
	                  self);

	ofono_check_name_owner (self);
}

static void
ensure_ofono_client (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	g_assert (priv->dbus_connection);
	g_dbus_proxy_new (priv->dbus_connection,
	                  G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                  NULL,
	                  OFONO_DBUS_SERVICE,
	                  OFONO_DBUS_PATH,
	                  OFONO_DBUS_INTERFACE,
	                  NULL,
	                  (GAsyncReadyCallback) ofono_proxy_new_cb,
	                  g_object_ref (self));
}
#endif

static void
modem_manager_poke_cb (GDBusConnection *connection,
                       GAsyncResult *res,
                       NMModemManager *self)
{
	GError *error = NULL;
	GVariant *result;

	result = g_dbus_connection_call_finish (connection, res, &error);
	if (error) {
		nm_log_warn (LOGD_MB, "error poking ModemManager: %s",
					error ? error->message : "");

		/* Don't reschedule poke is MM service doesn't exist. */
		if (!g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN)
			&& !g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_SERVICE_NOT_FOUND)) {

			/* Setup timeout to relaunch */
			schedule_modem_manager_relaunch (self, MODEM_POKE_INTERVAL);
		}

		g_error_free (error);
	} else
		g_variant_unref (result);

	/* Balance refcount */
	g_object_unref (self);
}

static void
modem_manager_poke (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	/* If there is no current owner right away, ensure we poke to get one */
	g_dbus_connection_call (priv->dbus_connection,
	                        "org.freedesktop.ModemManager1",
	                        "/org/freedesktop/ModemManager1",
	                        DBUS_INTERFACE_PEER,
	                        "Ping",
	                        NULL, /* inputs */
	                        NULL, /* outputs */
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1,
	                        NULL, /* cancellable */
	                        (GAsyncReadyCallback)modem_manager_poke_cb, /* callback */
	                        g_object_ref (self)); /* user_data */
}

static void
modem_manager_check_name_owner (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	gs_free gchar *name_owner = NULL;

	name_owner = g_dbus_object_manager_client_get_name_owner (G_DBUS_OBJECT_MANAGER_CLIENT (priv->modem_manager));
	if (name_owner) {
		/* Available! */
		modem_manager_available (self);
		return;
	}

	/* If the lifecycle is not managed by systemd, poke */
	if (!sd_booted ())
		modem_manager_poke (self);
}

static void
manager_new_ready (GObject *source,
                   GAsyncResult *res,
                   NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;

	/* Note we always get an extra reference to self here */

	g_return_if_fail (!priv->modem_manager);

	priv->modem_manager = mm_manager_new_finish (res, &error);
	if (!priv->modem_manager) {
		/* We're not really supposed to get any error here. If we do get one,
		 * though, just re-schedule the MMManager creation after some time.
		 * During this period, name-owner changes won't be followed. */
		nm_log_warn (LOGD_MB, "error creating ModemManager client: %s", error->message);
		g_error_free (error);
		/* Setup timeout to relaunch */
		schedule_modem_manager_relaunch (self, MODEM_POKE_INTERVAL);
	} else {
		/* Setup signals in the GDBusObjectManagerClient */
		priv->mm_name_owner_changed_id =
		    g_signal_connect (priv->modem_manager,
		                      "notify::name-owner",
		                      G_CALLBACK (modem_manager_name_owner_changed),
		                      self);
		priv->mm_object_added_id =
		    g_signal_connect (priv->modem_manager,
		                      "object-added",
		                      G_CALLBACK (modem_object_added),
		                      self);
		priv->mm_object_removed_id =
		    g_signal_connect (priv->modem_manager,
		                      "object-removed",
		                      G_CALLBACK (modem_object_removed),
		                      self);

		modem_manager_check_name_owner (self);
	}

	/* Balance refcount */
	g_object_unref (self);
}

static void
ensure_modem_manager (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	g_assert (priv->dbus_connection);

	/* Create the GDBusObjectManagerClient. We do not request to autostart, as
	 * we don't really want the MMManager creation to fail. We can always poke
	 * later on if we want to request the autostart */
	if (!priv->modem_manager) {
		mm_manager_new (priv->dbus_connection,
		                G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_DO_NOT_AUTO_START,
		                NULL,
		                (GAsyncReadyCallback)manager_new_ready,
		                g_object_ref (self));
		return;
	}

	/* If already available, recheck name owner! */
	modem_manager_check_name_owner (self);
}

static gboolean
mm_launch_cb (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	priv->mm_launch_id = 0;
	ensure_modem_manager (self);
	return G_SOURCE_REMOVE;
}

static void
schedule_modem_manager_relaunch (NMModemManager *self,
                                 guint n_seconds)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	/* No need to pass an extra reference to self; timeout/idle will be
	 * cancelled if the object gets disposed. */
	if (n_seconds)
		priv->mm_launch_id = g_timeout_add_seconds (n_seconds, (GSourceFunc)mm_launch_cb, self);
	else
		priv->mm_launch_id = g_idle_add ((GSourceFunc)mm_launch_cb, self);
}

static void
bus_get_ready (GObject *source,
               GAsyncResult *res,
               gpointer user_data)
{
	gs_unref_object NMModemManager *self = NM_MODEM_MANAGER (user_data);
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;

	priv->dbus_connection = g_bus_get_finish (res, &error);
	if (!priv->dbus_connection) {
		nm_log_warn (LOGD_MB, "error getting bus connection: %s", error->message);
		return;
	}

	/* Got the bus, ensure clients */
	ensure_modem_manager (self);
#if WITH_OFONO
	ensure_ofono_client (self);
#endif
}

/*****************************************************************************/

static void
nm_modem_manager_init (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	priv->modems = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_object_unref);

	g_bus_get (G_BUS_TYPE_SYSTEM,
	           NULL,
	           (GAsyncReadyCallback)bus_get_ready,
	           g_object_ref (self));
}

static void
dispose (GObject *object)
{
	NMModemManager *self = NM_MODEM_MANAGER (object);
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	nm_clear_g_source (&priv->mm_launch_id);

	clear_modem_manager (self);

#if WITH_OFONO
	if (priv->ofono_proxy) {
		g_signal_handlers_disconnect_by_func (priv->ofono_proxy, ofono_name_owner_changed, self);
		g_signal_handlers_disconnect_by_func (priv->ofono_proxy, ofono_signal_cb, self);
		g_clear_object (&priv->ofono_proxy);
	}
#endif

	g_clear_object (&priv->dbus_connection);

	if (priv->modems) {
		g_hash_table_foreach_remove (priv->modems, remove_one_modem, object);
		g_hash_table_destroy (priv->modems);
	}

	G_OBJECT_CLASS (nm_modem_manager_parent_class)->dispose (object);
}

static void
nm_modem_manager_class_init (NMModemManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;

	signals[MODEM_ADDED] =
	    g_signal_new (NM_MODEM_MANAGER_MODEM_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, NM_TYPE_MODEM);
}
