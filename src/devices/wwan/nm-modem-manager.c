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

NM_GOBJECT_PROPERTIES_DEFINE (NMModemManager,
	PROP_NAME_OWNER,
);

enum {
	MODEM_ADDED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	GDBusConnection *dbus_connection;

	/* used during g_bus_get() and later during mm_manager_new(). */
	GCancellable *main_cancellable;

	struct {
		MMManager *manager;
		GCancellable *poke_cancellable;
		gulong handle_name_owner_changed_id;
		gulong handle_object_added_id;
		gulong handle_object_removed_id;
		guint relaunch_id;

		/* this only has one use: that the <info> logging line about
		 * ModemManager available distinguishes between first-time
		 * and later name-owner-changed. */
		enum {
			LOG_AVAILABLE_NOT_INITIALIZED = 0,
			LOG_AVAILABLE_YES,
			LOG_AVAILABLE_NO,
		} log_available:3;

		GDBusProxy *proxy;
		GCancellable *proxy_cancellable;
		guint proxy_ref_count;
		char *proxy_name_owner;
	} modm;

#if WITH_OFONO
	struct {
		GDBusProxy *proxy;
		GCancellable *cancellable;
	} ofono;
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

#define _NMLOG_DOMAIN      LOGD_MB
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "modem-manager", __VA_ARGS__)

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMModemManager, nm_modem_manager_get, NM_TYPE_MODEM_MANAGER);

/*****************************************************************************/

static void modm_schedule_manager_relaunch (NMModemManager *self,
                                            guint n_seconds);
static void modm_ensure_manager (NMModemManager *self);

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

/*****************************************************************************/

static void
modm_clear_manager (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	if (!priv->modm.manager)
		return;
	nm_clear_g_signal_handler (priv->modm.manager, &priv->modm.handle_name_owner_changed_id);
	nm_clear_g_signal_handler (priv->modm.manager, &priv->modm.handle_object_added_id);
	nm_clear_g_signal_handler (priv->modm.manager, &priv->modm.handle_object_removed_id);
	g_clear_object (&priv->modm.manager);
}

static void
modm_handle_object_added (MMManager *modem_manager,
                          MMObject  *modem_object,
                          NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	const char *path;
	MMModem *modem_iface;
	NMModem *modem;
	GError *error = NULL;

	/* Ensure we don't have the same modem already */
	path = mm_object_get_path (modem_object);
	if (g_hash_table_lookup (priv->modems, path)) {
		_LOGW ("modem with path %s already exists, ignoring", path);
		return;
	}

	/* Ensure we have the 'Modem' interface at least */
	modem_iface = mm_object_peek_modem (modem_object);
	if (!modem_iface) {
		_LOGW ("modem with path %s doesn't have the Modem interface, ignoring", path);
		return;
	}

	/* Ensure we have a primary port reported */
	if (!mm_modem_get_primary_port (modem_iface)) {
		_LOGW ("modem with path %s has unknown primary port, ignoring", path);
		return;
	}

	/* Create a new modem object */
	modem = nm_modem_broadband_new (G_OBJECT (modem_object), &error);
	if (modem)
		handle_new_modem (self, modem);
	else
		_LOGW ("failed to create modem: %s", error->message);
	g_clear_error (&error);
}

static void
modm_handle_object_removed (MMManager *manager,
                            MMObject  *modem_object,
                            NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	NMModem *modem;
	const char *path;

	path = mm_object_get_path (modem_object);
	modem = (NMModem *) g_hash_table_lookup (priv->modems, path);
	if (!modem)
		return;

	nm_modem_emit_removed (modem);
	g_hash_table_remove (priv->modems, path);
}

static void
modm_manager_available (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	GList *modems, *l;

	if (priv->modm.log_available != LOG_AVAILABLE_YES) {
		_LOGI ("ModemManager %savailable", priv->modm.log_available ? "now " : "");
		priv->modm.log_available = LOG_AVAILABLE_YES;
	}

	/* Update initial modems list */
	modems = g_dbus_object_manager_get_objects (G_DBUS_OBJECT_MANAGER (priv->modm.manager));
	for (l = modems; l; l = g_list_next (l))
		modm_handle_object_added (priv->modm.manager, MM_OBJECT (l->data), self);
	g_list_free_full (modems, (GDestroyNotify) g_object_unref);
}

static void
modm_handle_name_owner_changed (MMManager *modem_manager,
                                GParamSpec *pspec,
                                NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	char *name_owner;

	/* Quit poking, if any */
	nm_clear_g_source (&priv->modm.relaunch_id);

	name_owner = g_dbus_object_manager_client_get_name_owner (G_DBUS_OBJECT_MANAGER_CLIENT (modem_manager));
	if (!name_owner) {
		if (priv->modm.log_available != LOG_AVAILABLE_NO) {
			_LOGI ("ModemManager %savailable", priv->modm.log_available ? "no longer " : "not ");
			priv->modm.log_available = LOG_AVAILABLE_NO;
		}

		/* If not managed by systemd, schedule relaunch */
		if (!sd_booted ())
			modm_schedule_manager_relaunch (self, 0);

		return;
	}

	/* Available! */
	g_free (name_owner);

	/* Hack alert: GDBusObjectManagerClient won't signal neither 'object-added'
	 * nor 'object-removed' if it was created while there was no ModemManager in
	 * the bus. This hack avoids this issue until we get a GIO with the fix
	 * included... */
	modm_clear_manager (self);
	modm_ensure_manager (self);

	/* Whenever GDBusObjectManagerClient is fixed, we can just do the following:
	 * modm_manager_available (self);
	 */
}

static void
modm_manager_poke_cb (GObject *connection,
                      GAsyncResult *res,
                      gpointer user_data)
{
	NMModemManager *self;
	NMModemManagerPrivate *priv;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *result = NULL;

	result = g_dbus_connection_call_finish (G_DBUS_CONNECTION (connection), res, &error);

	if (   !result
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = user_data;
	priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->modm.poke_cancellable);

	if (error) {
		_LOGW ("error poking ModemManager: %s", error->message);

		/* Don't reschedule poke is MM service doesn't exist. */
		if (   !g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN)
			&& !g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_SERVICE_NOT_FOUND)) {

			/* Setup timeout to relaunch */
			modm_schedule_manager_relaunch (self, MODEM_POKE_INTERVAL);
		}
	}
}

static void
modm_manager_poke (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	nm_clear_g_cancellable (&priv->modm.poke_cancellable);
	priv->modm.poke_cancellable = g_cancellable_new ();

	/* If there is no current owner right away, ensure we poke to get one */
	g_dbus_connection_call (priv->dbus_connection,
	                        NM_MODEM_MANAGER_MM_DBUS_SERVICE,
	                        NM_MODEM_MANAGER_MM_DBUS_PATH,
	                        DBUS_INTERFACE_PEER,
	                        "Ping",
	                        NULL,
	                        NULL,
	                        G_DBUS_CALL_FLAGS_NONE,
	                        -1,
	                        priv->modm.poke_cancellable,
	                        modm_manager_poke_cb,
	                        self);
}

static void
modm_manager_check_name_owner (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	gs_free char *name_owner = NULL;

	name_owner = g_dbus_object_manager_client_get_name_owner (G_DBUS_OBJECT_MANAGER_CLIENT (priv->modm.manager));
	if (name_owner) {
		modm_manager_available (self);
		return;
	}

	/* If the lifecycle is not managed by systemd, poke */
	if (!sd_booted ())
		modm_manager_poke (self);
}

static void
modm_manager_new_cb (GObject *source,
                     GAsyncResult *res,
                     gpointer user_data)
{
	NMModemManager *self;
	NMModemManagerPrivate *priv;
	gs_free_error GError *error = NULL;
	MMManager *modem_manager;

	modem_manager = mm_manager_new_finish (res, &error);
	if (   !modem_manager
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = user_data;
	priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	nm_assert (!priv->modm.manager);

	g_clear_object (&priv->main_cancellable);

	if (!modem_manager) {
		/* We're not really supposed to get any error here. If we do get one,
		 * though, just re-schedule the MMManager creation after some time.
		 * During this period, name-owner changes won't be followed. */
		_LOGW ("error creating ModemManager client: %s", error->message);
		/* Setup timeout to relaunch */
		modm_schedule_manager_relaunch (self, MODEM_POKE_INTERVAL);
		return;
	}

	priv->modm.manager = modem_manager;

	/* Setup signals in the GDBusObjectManagerClient */
	priv->modm.handle_name_owner_changed_id =
	    g_signal_connect (priv->modm.manager,
	                      "notify::name-owner",
	                      G_CALLBACK (modm_handle_name_owner_changed),
	                      self);
	priv->modm.handle_object_added_id =
	    g_signal_connect (priv->modm.manager,
	                      "object-added",
	                      G_CALLBACK (modm_handle_object_added),
	                      self);
	priv->modm.handle_object_removed_id =
	    g_signal_connect (priv->modm.manager,
	                      "object-removed",
	                      G_CALLBACK (modm_handle_object_removed),
	                      self);

	modm_manager_check_name_owner (self);
}

static void
modm_ensure_manager (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	g_assert (priv->dbus_connection);

	/* Create the GDBusObjectManagerClient. We do not request to autostart, as
	 * we don't really want the MMManager creation to fail. We can always poke
	 * later on if we want to request the autostart */
	if (!priv->modm.manager) {
		if (!priv->main_cancellable)
			priv->main_cancellable = g_cancellable_new ();
		mm_manager_new (priv->dbus_connection,
		                G_DBUS_OBJECT_MANAGER_CLIENT_FLAGS_DO_NOT_AUTO_START,
		                priv->main_cancellable,
		                modm_manager_new_cb,
		                self);
		return;
	}

	/* If already available, recheck name owner! */
	modm_manager_check_name_owner (self);
}

static gboolean
modm_schedule_manager_relaunch_cb (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	priv->modm.relaunch_id = 0;
	modm_ensure_manager (self);
	return G_SOURCE_REMOVE;
}

static void
modm_schedule_manager_relaunch (NMModemManager *self,
                                guint n_seconds)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	/* No need to pass an extra reference to self; timeout/idle will be
	 * cancelled if the object gets disposed. */
	if (n_seconds)
		priv->modm.relaunch_id = g_timeout_add_seconds (n_seconds, (GSourceFunc)modm_schedule_manager_relaunch_cb, self);
	else
		priv->modm.relaunch_id = g_idle_add ((GSourceFunc)modm_schedule_manager_relaunch_cb, self);
}

/*****************************************************************************/

static void
modm_proxy_name_owner_reset (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	char *name = NULL;

	if (priv->modm.proxy)
		name = g_dbus_proxy_get_name_owner (priv->modm.proxy);

	if (nm_streq0 (priv->modm.proxy_name_owner, name)) {
		g_free (name);
		return;
	}
	g_free (priv->modm.proxy_name_owner);
	priv->modm.proxy_name_owner = name;

	_notify (self, PROP_NAME_OWNER);
}

static void
modm_proxy_name_owner_changed_cb (GObject    *object,
                                  GParamSpec *pspec,
                                  gpointer    user_data)
{
	modm_proxy_name_owner_reset (user_data);
}

static void
modm_proxy_new_cb (GObject *source_object,
                   GAsyncResult *result,
                   gpointer user_data)
{
	NMModemManager *self;
	NMModemManagerPrivate *priv;
	GDBusProxy *proxy;
	gs_free_error GError *error = NULL;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (   !proxy
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = user_data;
	priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->modm.proxy_cancellable);

	if (!proxy) {
		_LOGW ("could not obtain D-Bus proxy for ModemManager: %s", error->message);
		return;
	}

	priv->modm.proxy = proxy;
	g_signal_connect (priv->modm.proxy, "notify::g-name-owner",
	                  G_CALLBACK (modm_proxy_name_owner_changed_cb), self);

	modm_proxy_name_owner_reset (self);
}

void
nm_modem_manager_name_owner_ref (NMModemManager *self)
{
	NMModemManagerPrivate *priv;

	g_return_if_fail (NM_IS_MODEM_MANAGER (self));

	priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	if (priv->modm.proxy_ref_count++ > 0) {
		/* only try once to create the proxy. If proxy creation
		 * for the first "ref" failed, it's unclear what to do.
		 * The proxy is hosed. */
		return;
	}

	nm_assert (!priv->modm.proxy && !priv->modm.proxy_cancellable);

	priv->modm.proxy_cancellable = g_cancellable_new ();

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                            G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES
	                          | G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS
	                          | G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                          NULL,
	                          NM_MODEM_MANAGER_MM_DBUS_SERVICE,
	                          NM_MODEM_MANAGER_MM_DBUS_PATH,
	                          NM_MODEM_MANAGER_MM_DBUS_INTERFACE,
	                          priv->modm.proxy_cancellable,
	                          modm_proxy_new_cb,
	                          self);
}

void
nm_modem_manager_name_owner_unref (NMModemManager *self)
{
	NMModemManagerPrivate *priv;

	g_return_if_fail (NM_IS_MODEM_MANAGER (self));

	priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	g_return_if_fail (priv->modm.proxy_ref_count > 0);

	if (--priv->modm.proxy_ref_count > 0)
		return;

	nm_clear_g_cancellable (&priv->modm.proxy_cancellable);
	g_clear_object (&priv->modm.proxy);

	modm_proxy_name_owner_reset (self);
}

const char *
nm_modem_manager_name_owner_get (NMModemManager *self)
{
	g_return_val_if_fail (NM_IS_MODEM_MANAGER (self), NULL);
	nm_assert (NM_MODEM_MANAGER_GET_PRIVATE (self)->modm.proxy_ref_count > 0);

	return NM_MODEM_MANAGER_GET_PRIVATE (self)->modm.proxy_name_owner;
}

/*****************************************************************************/

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
			_LOGW ("Failed to create oFono modem for %s", path);
	}
}

static void
ofono_signal_cb (GDBusProxy *proxy,
                 char *sender_name,
                 char *signal_name,
                 GVariant *parameters,
                 gpointer user_data)
{
	NMModemManager *self = NM_MODEM_MANAGER (user_data);
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	char *object_path;
	NMModem *modem;

	if (g_strcmp0 (signal_name, "ModemAdded") == 0) {
		g_variant_get (parameters, "(oa{sv})", &object_path, NULL);
		_LOGI ("oFono modem appeared: %s", object_path);

		ofono_create_modem (NM_MODEM_MANAGER (user_data), object_path);
		g_free (object_path);
	} else if (g_strcmp0 (signal_name, "ModemRemoved") == 0) {
		g_variant_get (parameters, "(o)", &object_path);
		_LOGI ("oFono modem removed: %s", object_path);

		modem = (NMModem *) g_hash_table_lookup (priv->modems, object_path);
		if (modem) {
			nm_modem_emit_removed (modem);
			g_hash_table_remove (priv->modems, object_path);
		} else {
			_LOGW ("could not remove modem %s, not found in table",
			       object_path);
		}
		g_free (object_path);
	}
}

static void
ofono_enumerate_devices_done (GObject *proxy,
                              GAsyncResult *res,
                              gpointer user_data)
{
	NMModemManager *self;
	NMModemManagerPrivate *priv;
	gs_free_error GError *error = NULL;
	GVariant *results;
	GVariantIter *iter;
	const char *path;

	results = g_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), res, &error);
	if (   !results
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_MODEM_MANAGER (user_data);
	priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->ofono.cancellable);

	if (!results) {
		_LOGW ("failed to enumerate oFono devices: %s",
		       error->message);
		return;
	}

	g_variant_get (results, "(a(oa{sv}))", &iter);
	while (g_variant_iter_loop (iter, "(&oa{sv})", &path, NULL))
		ofono_create_modem (self, path);
	g_variant_iter_free (iter);
	g_variant_unref (results);
}

static void
ofono_check_name_owner (NMModemManager *self, gboolean first_invocation)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);
	gs_free char *name_owner = NULL;

	name_owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (priv->ofono.proxy));
	if (name_owner) {
		_LOGI ("oFono is %savailable", first_invocation ? "" : "now ");

		nm_clear_g_cancellable (&priv->ofono.cancellable);
		priv->ofono.cancellable = g_cancellable_new ();

		g_dbus_proxy_call (priv->ofono.proxy,
		                   "GetModems",
		                   NULL,
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->ofono.cancellable,
		                   ofono_enumerate_devices_done,
		                   self);
	} else {
		GHashTableIter iter;
		NMModem *modem;

		_LOGI ("oFono is %savailable", first_invocation ? "not " : "no longer ");

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
	ofono_check_name_owner (self, FALSE);
}

static void
ofono_proxy_new_cb (GObject *source_object,
                    GAsyncResult *res,
                    gpointer user_data)
{
	NMModemManager *self;
	NMModemManagerPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_finish (res, &error);
	if (   !proxy
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_MODEM_MANAGER (user_data);
	priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	g_clear_object (&priv->ofono.cancellable);

	if (!proxy) {
		_LOGW ("error getting oFono bus proxy: %s", error->message);
		return;
	}

	priv->ofono.proxy = proxy;

	g_signal_connect (priv->ofono.proxy,
	                  "notify::g-name-owner",
	                  G_CALLBACK (ofono_name_owner_changed),
	                  self);

	g_signal_connect (priv->ofono.proxy,
	                  "g-signal",
	                  G_CALLBACK (ofono_signal_cb),
	                  self);

	ofono_check_name_owner (self, TRUE);
}

static void
ofono_init_proxy (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	nm_assert (priv->dbus_connection);
	nm_assert (!priv->ofono.cancellable);

	priv->ofono.cancellable = g_cancellable_new ();

	g_dbus_proxy_new (priv->dbus_connection,
	                  G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                  NULL,
	                  OFONO_DBUS_SERVICE,
	                  OFONO_DBUS_PATH,
	                  OFONO_DBUS_INTERFACE,
	                  priv->ofono.cancellable,
	                  ofono_proxy_new_cb,
	                  self);
}
#endif

/*****************************************************************************/

static void
bus_get_ready (GObject *source,
               GAsyncResult *res,
               gpointer user_data)
{
	NMModemManager *self;
	NMModemManagerPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusConnection *connection;

	connection = g_bus_get_finish (res, &error);
	if (   !connection
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_MODEM_MANAGER (user_data);
	priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	if (!connection) {
		_LOGW ("error getting bus connection: %s", error->message);
		return;
	}

	priv->dbus_connection = connection;

	modm_ensure_manager (self);
#if WITH_OFONO
	ofono_init_proxy (self);
#endif
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMModemManager *self = NM_MODEM_MANAGER (object);
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_NAME_OWNER:
		g_value_set_string (value, priv->modm.proxy_name_owner);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_modem_manager_init (NMModemManager *self)
{
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	priv->modems = g_hash_table_new_full (nm_str_hash, g_str_equal, g_free, g_object_unref);

	priv->main_cancellable = g_cancellable_new ();

	g_bus_get (G_BUS_TYPE_SYSTEM,
	           priv->main_cancellable,
	           bus_get_ready,
	           self);
}

static void
dispose (GObject *object)
{
	NMModemManager *self = NM_MODEM_MANAGER (object);
	NMModemManagerPrivate *priv = NM_MODEM_MANAGER_GET_PRIVATE (self);

	nm_clear_g_cancellable (&priv->main_cancellable);
	nm_clear_g_cancellable (&priv->modm.poke_cancellable);

	nm_clear_g_source (&priv->modm.relaunch_id);

	nm_clear_g_cancellable (&priv->modm.proxy_cancellable);
	g_clear_object (&priv->modm.proxy);
	nm_clear_g_free (&priv->modm.proxy_name_owner);

	modm_clear_manager (self);

#if WITH_OFONO
	if (priv->ofono.proxy) {
		g_signal_handlers_disconnect_by_func (priv->ofono.proxy, ofono_name_owner_changed, self);
		g_signal_handlers_disconnect_by_func (priv->ofono.proxy, ofono_signal_cb, self);
		g_clear_object (&priv->ofono.proxy);
	}
	nm_clear_g_cancellable (&priv->ofono.cancellable);
#endif

	g_clear_object (&priv->dbus_connection);

	if (priv->modems) {
		g_hash_table_foreach_remove (priv->modems, remove_one_modem, object);
		g_hash_table_destroy (priv->modems);
		priv->modems = NULL;
	}

	G_OBJECT_CLASS (nm_modem_manager_parent_class)->dispose (object);
}

static void
nm_modem_manager_class_init (NMModemManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;
	object_class->get_property = get_property;

	obj_properties[PROP_NAME_OWNER] =
	     g_param_spec_string (NM_MODEM_MANAGER_NAME_OWNER, "", "",
	                          NULL,
	                          G_PARAM_READABLE
	                          | G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[MODEM_ADDED] =
	    g_signal_new (NM_MODEM_MANAGER_MODEM_ADDED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, NM_TYPE_MODEM);
}
