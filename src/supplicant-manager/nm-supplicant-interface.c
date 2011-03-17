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
 * Copyright (C) 2006 - 2010 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "nm-supplicant-interface.h"
#include "nm-supplicant-manager.h"
#include "nm-logging.h"
#include "nm-marshal.h"
#include "nm-supplicant-config.h"
#include "nm-dbus-manager.h"
#include "nm-call-store.h"
#include "nm-dbus-glib-types.h"
#include "nm-glib-compat.h"

#define WPAS_DBUS_IFACE_INTERFACE   WPAS_DBUS_INTERFACE ".Interface"
#define WPAS_DBUS_IFACE_BSS         WPAS_DBUS_INTERFACE ".BSS"
#define WPAS_DBUS_IFACE_NETWORK	    WPAS_DBUS_INTERFACE ".Network"
#define WPAS_ERROR_INVALID_IFACE    WPAS_DBUS_INTERFACE ".InvalidInterface"
#define WPAS_ERROR_EXISTS_ERROR     WPAS_DBUS_INTERFACE ".InterfaceExists"

G_DEFINE_TYPE (NMSupplicantInterface, nm_supplicant_interface, G_TYPE_OBJECT)

static void wpas_iface_properties_changed (DBusGProxy *proxy,
                                           GHashTable *props,
                                           gpointer user_data);

static void wpas_iface_scan_done (DBusGProxy *proxy,
                                  gboolean success,
                                  gpointer user_data);

#define NM_SUPPLICANT_INTERFACE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                 NM_TYPE_SUPPLICANT_INTERFACE, \
                                                 NMSupplicantInterfacePrivate))

/* Signals */
enum {
	STATE,             /* change in the interface's state */
	REMOVED,           /* interface was removed by the supplicant */
	NEW_BSS,           /* interface saw a new access point from a scan */
	SCAN_DONE,         /* wifi scan is complete */
	CONNECTION_ERROR,  /* an error occurred during a connection request */
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };


/* Properties */
enum {
	PROP_0 = 0,
	PROP_SCANNING,
	LAST_PROP
};


typedef struct {
	NMSupplicantManager * smgr;
	gulong                smgr_avail_id;
	NMDBusManager *       dbus_mgr;
	char *                dev;
	gboolean              is_wireless;

	char *                object_path;
	guint32               state;
	NMCallStore *         assoc_pcalls;
	NMCallStore *         other_pcalls;

	gboolean              scanning;

	DBusGProxy *          wpas_proxy;
	DBusGProxy *          iface_proxy;
	DBusGProxy *          props_proxy;
	char *                net_path;
	guint32               blobs_left;

	guint32               last_scan;

	NMSupplicantConfig *  cfg;

	gboolean              disposed;
} NMSupplicantInterfacePrivate;

static gboolean
cancel_all_cb (GObject *object, gpointer call_id, gpointer user_data)
{
	dbus_g_proxy_cancel_call (DBUS_G_PROXY (object), (DBusGProxyCall *) call_id);

	return TRUE;
}

static void
cancel_all_callbacks (NMCallStore *store)
{
	nm_call_store_foreach (store, NULL, cancel_all_cb, NULL);
	nm_call_store_clear (store);
}

typedef struct {
	NMSupplicantInterface *interface;
	DBusGProxy *proxy;
	NMCallStore *store;
	DBusGProxyCall *call;
	gboolean disposing;
} NMSupplicantInfo;

static NMSupplicantInfo *
nm_supplicant_info_new (NMSupplicantInterface *interface,
                        DBusGProxy *proxy,
                        NMCallStore *store)
{
	NMSupplicantInfo *info;

	info = g_slice_new0 (NMSupplicantInfo);
	info->interface = g_object_ref (interface);
	info->proxy = g_object_ref (proxy);
	info->store = store;

	return info;
}

static void
nm_supplicant_info_set_call (NMSupplicantInfo *info, DBusGProxyCall *call)
{
	g_return_if_fail (info != NULL);
	g_return_if_fail (call != NULL);

	nm_call_store_add (info->store, G_OBJECT (info->proxy), (gpointer) call);
	info->call = call;
}

static void
nm_supplicant_info_destroy (gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;

	/* Guard against double-disposal; since DBusGProxy doesn't guard against
	 * double-disposal, we could infinite loop here if we're in the middle of
	 * some wpa_supplicant D-Bus calls.  When the supplicant dies we'll dispose
	 * of the proxy, which kills all its pending calls, which brings us here.
	 * Then when we unref the proxy here, its dispose() function will get called
	 * again, and we get right back here until we segfault because our callstack
	 * is too long.
	 */
	if (!info->disposing) {
		info->disposing = TRUE;

		if (info->call) {
			nm_call_store_remove (info->store, G_OBJECT (info->proxy), info->call);
			info->call = NULL;
		}

		g_object_unref (info->proxy);
		info->proxy = NULL;
		g_object_unref (info->interface);
		info->interface = NULL;

		memset (info, 0, sizeof (NMSupplicantInfo));
		g_slice_free (NMSupplicantInfo, info);
	}
}

static void
emit_error_helper (NMSupplicantInterface *self,
				   GError *err)
{
	const char *name = NULL;

	if (err->domain == DBUS_GERROR && err->code == DBUS_GERROR_REMOTE_EXCEPTION)
		name = dbus_g_error_get_name (err);

	g_signal_emit (self, signals[CONNECTION_ERROR], 0, name, err->message);
}

static void
bssid_properties_cb  (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	GError *error = NULL;
	GHashTable *props = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error,
	                           DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                           G_TYPE_INVALID)) {
		g_signal_emit (info->interface, signals[NEW_BSS], 0, props);
		g_hash_table_destroy (props);
	} else {
		if (!strstr (error->message, "The BSSID requested was invalid")) {
			nm_log_warn (LOGD_SUPPLICANT, "Couldn't retrieve BSSID properties: %s.",
			             error->message);
		}
		g_error_free (error);
	}
}

static void
request_bss_properties (NMSupplicantInterface *self,
                        GPtrArray *paths)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	int i;

	/* Fire off a "properties" call for each returned BSSID */
	for (i = 0; i < paths->len; i++) {
		NMSupplicantInfo *info;
		DBusGProxy *proxy;
		DBusGProxyCall *call;

		proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
			                               WPAS_DBUS_SERVICE,
			                               g_ptr_array_index (paths, i),
			                               DBUS_INTERFACE_PROPERTIES);
		info = nm_supplicant_info_new (self, proxy, priv->other_pcalls);
		call = dbus_g_proxy_begin_call (proxy, "GetAll",
			                            bssid_properties_cb,
			                            info,
			                            nm_supplicant_info_destroy,
			                            G_TYPE_STRING, WPAS_DBUS_IFACE_BSS,
			                            G_TYPE_INVALID);
		nm_supplicant_info_set_call (info, call);
		g_object_unref (proxy);
	}
}

static void
wpas_iface_bss_added (DBusGProxy *proxy,
                      const char *object_path,
                      GHashTable *props,
                      gpointer user_data)
{
	g_signal_emit (NM_SUPPLICANT_INTERFACE (user_data), signals[NEW_BSS], 0, props);
}

static int
wpas_state_string_to_enum (const char *str_state)
{
	if (!strcmp (str_state, "disconnected"))
		return NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED;
	else if (!strcmp (str_state, "inactive"))
		return NM_SUPPLICANT_INTERFACE_STATE_INACTIVE;
	else if (!strcmp (str_state, "scanning"))
		return NM_SUPPLICANT_INTERFACE_STATE_SCANNING;
	else if (!strcmp (str_state, "authenticating"))
		return NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING;
	else if (!strcmp (str_state, "associating"))
		return NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING;
	else if (!strcmp (str_state, "associated"))
		return NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED;
	else if (!strcmp (str_state, "4way_handshake"))
		return NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE;
	else if (!strcmp (str_state, "group_handshake"))
		return NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE;
	else if (!strcmp (str_state, "completed"))
		return NM_SUPPLICANT_INTERFACE_STATE_COMPLETED;

	nm_log_warn (LOGD_SUPPLICANT, "Unknown supplicant state '%s'", str_state);
	return -1;
}

static void
set_state (NMSupplicantInterface *self, guint32 new_state)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	guint32 old_state = priv->state;

	g_return_if_fail (new_state < NM_SUPPLICANT_INTERFACE_STATE_LAST);

	if (new_state == priv->state)
		return;

	/* DOWN is a terminal state */
	g_return_if_fail (priv->state != NM_SUPPLICANT_INTERFACE_STATE_DOWN);

	/* Cannot regress to READY, STARTING, or INIT from higher states */
	if (priv->state >= NM_SUPPLICANT_INTERFACE_STATE_READY)
		g_return_if_fail (new_state > NM_SUPPLICANT_INTERFACE_STATE_READY);

	if (new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		/* Cancel all pending calls when going down */
		cancel_all_callbacks (priv->other_pcalls);
		cancel_all_callbacks (priv->assoc_pcalls);

		/* Disconnect supplicant manager state listeners since we're done */
		if (priv->smgr_avail_id) {
			g_signal_handler_disconnect (priv->smgr, priv->smgr_avail_id);
			priv->smgr_avail_id = 0;
		}

		if (priv->iface_proxy) {
			dbus_g_proxy_disconnect_signal (priv->iface_proxy,
			                                "PropertiesChanged",
			                                G_CALLBACK (wpas_iface_properties_changed),
			                                self);
			dbus_g_proxy_disconnect_signal (priv->iface_proxy,
			                                "ScanDone",
			                                G_CALLBACK (wpas_iface_scan_done),
			                                self);
			dbus_g_proxy_disconnect_signal (priv->iface_proxy,
			                                "BSSAdded",
			                                G_CALLBACK (wpas_iface_bss_added),
			                                self);
		}
	}

	priv->state = new_state;
	g_signal_emit (self, signals[STATE], 0, priv->state, old_state);
}

static void
set_state_from_string (NMSupplicantInterface *self, const char *new_state)
{
	int state;

	state = wpas_state_string_to_enum (new_state);
	g_warn_if_fail (state > 0);
	if (state > 0)
		set_state (self, (guint32) state);
}

static void
set_scanning (NMSupplicantInterface *self, gboolean new_scanning)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GTimeVal cur_time;

	if (priv->scanning != new_scanning) {
		priv->scanning = new_scanning;

		/* Cache time of last scan completion */
		if (priv->scanning == FALSE) {
			g_get_current_time (&cur_time);
			priv->last_scan = cur_time.tv_sec;
		}

		g_object_notify (G_OBJECT (self), "scanning");
	}
}

gboolean
nm_supplicant_interface_get_scanning (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_val_if_fail (self != NULL, FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	if (priv->scanning)
		return TRUE;
	if (priv->state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING)
		return TRUE;
	return FALSE;
}

static void
wpas_iface_scan_done (DBusGProxy *proxy,
                      gboolean success,
                      gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GTimeVal cur_time;

	/* Cache last scan completed time */
	g_get_current_time (&cur_time);
	priv->last_scan = cur_time.tv_sec;

	g_signal_emit (self, signals[SCAN_DONE], 0, success);
}

static void
wpas_iface_properties_changed (DBusGProxy *proxy,
                               GHashTable *props,
                               gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	GValue *value;

	value = g_hash_table_lookup (props, "Scanning");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		set_scanning (self, g_value_get_boolean (value));

	value = g_hash_table_lookup (props, "State");
	if (value && G_VALUE_HOLDS_STRING (value))
		set_state_from_string (self, g_value_get_string (value));

	value = g_hash_table_lookup (props, "BSSs");
	if (value && G_VALUE_HOLDS (value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH))
		request_bss_properties (self, g_value_get_boxed (value));
}

static void
iface_get_props_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	GHashTable *props = NULL;
	GError *error = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error,
	                           DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                           G_TYPE_INVALID)) {
		wpas_iface_properties_changed (NULL, props, info->interface);
		g_hash_table_destroy (props);
	} else {
		nm_log_warn (LOGD_SUPPLICANT, "could not get interface properties: %s.",
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}
}

static void
wpas_iface_get_props (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantInfo *info;
	DBusGProxyCall *call;

	info = nm_supplicant_info_new (self, priv->props_proxy, priv->other_pcalls);
	call = dbus_g_proxy_begin_call (priv->props_proxy, "GetAll",
	                                iface_get_props_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                G_TYPE_STRING, WPAS_DBUS_IFACE_INTERFACE,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);
}

static void
interface_add_done (NMSupplicantInterface *self, char *path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	nm_log_dbg (LOGD_SUPPLICANT, "(%s): interface added to supplicant", priv->dev);

	priv->object_path = path;

	priv->iface_proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                               WPAS_DBUS_SERVICE,
	                                               path,
	                                               WPAS_DBUS_IFACE_INTERFACE);

	dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__BOXED,
	                                   G_TYPE_NONE,
	                                   DBUS_TYPE_G_MAP_OF_VARIANT,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->iface_proxy, "PropertiesChanged",
	                         DBUS_TYPE_G_MAP_OF_VARIANT, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->iface_proxy, "PropertiesChanged",
	                             G_CALLBACK (wpas_iface_properties_changed),
	                             self, NULL);

	dbus_g_proxy_add_signal (priv->iface_proxy, "ScanDone", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->iface_proxy, "ScanDone",
	                             G_CALLBACK (wpas_iface_scan_done),
	                             self,
	                             NULL);

	dbus_g_object_register_marshaller (_nm_marshal_VOID__STRING_BOXED,
	                                   G_TYPE_NONE,
	                                   G_TYPE_STRING, DBUS_TYPE_G_MAP_OF_VARIANT,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->iface_proxy, "BSSAdded", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->iface_proxy, "BSSAdded",
	                             G_CALLBACK (wpas_iface_bss_added),
	                             self,
	                             NULL);

	priv->props_proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                               WPAS_DBUS_SERVICE,
	                                               path,
	                                               DBUS_INTERFACE_PROPERTIES);
	/* Get initial properties */
	wpas_iface_get_props (self);

	set_state (self, NM_SUPPLICANT_INTERFACE_STATE_READY);
}

static void
interface_get_cb (DBusGProxy *proxy,
                  DBusGProxyCall *call_id,
                  gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
	GError *error = NULL;
	char *path = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error,
	                           DBUS_TYPE_G_OBJECT_PATH, &path,
	                           G_TYPE_INVALID)) {
		interface_add_done (info->interface, path);
	} else {
		nm_log_err (LOGD_SUPPLICANT, "(%s): error getting interface: %s",
		            priv->dev, error->message);
		g_clear_error (&error);
		set_state (info->interface, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
	}
}

static void
interface_get (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantInfo *info;
	DBusGProxyCall *call;

	info = nm_supplicant_info_new (self, priv->wpas_proxy, priv->other_pcalls);
	call = dbus_g_proxy_begin_call (priv->wpas_proxy, "GetInterface",
	                                interface_get_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                G_TYPE_STRING, priv->dev,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);
}

static void
interface_add_cb (DBusGProxy *proxy,
                  DBusGProxyCall *call_id,
                  gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
	GError *error = NULL;
	char *path = NULL;

	if (dbus_g_proxy_end_call (proxy, call_id, &error,
	                           DBUS_TYPE_G_OBJECT_PATH, &path,
	                           G_TYPE_INVALID)) {
		interface_add_done (info->interface, path);
	} else {
		if (dbus_g_error_has_name (error, WPAS_ERROR_EXISTS_ERROR)) {
			/* Interface already added, just get its object path */
			interface_get (info->interface);
		} else if (   g_error_matches (error, DBUS_GERROR, DBUS_GERROR_SERVICE_UNKNOWN)
		           || dbus_g_error_has_name (error, DBUS_ERROR_SPAWN_SERVICE_NOT_FOUND)) {
			/* Supplicant wasn't running and could be launched via service
			 * activation.  Wait for it to start by moving back to the INIT
			 * state.
			 */
			nm_log_dbg (LOGD_SUPPLICANT, "(%s): failed to activate supplicant: %s",
			            priv->dev, error->message);
			set_state (info->interface, NM_SUPPLICANT_INTERFACE_STATE_INIT);
		} else {
			nm_log_err (LOGD_SUPPLICANT, "(%s): error adding interface: %s",
			            priv->dev, error->message);
			set_state (info->interface, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
		}
		g_clear_error (&error);
	}
}

static void
interface_add (NMSupplicantInterface *self, gboolean is_wireless)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	DBusGProxyCall *call;
	NMSupplicantInfo *info;
	GHashTable *hash;
	GValue *driver, *ifname;

	/* Can only start the interface from INIT state */
	g_return_if_fail (priv->state == NM_SUPPLICANT_INTERFACE_STATE_INIT);

	nm_log_dbg (LOGD_SUPPLICANT, "(%s): adding interface to supplicant", priv->dev);

	/* Move to starting to prevent double-calls of interface_add() */
	set_state (self, NM_SUPPLICANT_INTERFACE_STATE_STARTING);

	/* Try to add the interface to the supplicant.  If the supplicant isn't
	 * running, this will start it via D-Bus activation and return the response
	 * when the supplicant has started.
	 */

	info = nm_supplicant_info_new (self, priv->wpas_proxy, priv->other_pcalls);

	hash = g_hash_table_new (g_str_hash, g_str_equal);

	driver = g_new0 (GValue, 1);
	g_value_init (driver, G_TYPE_STRING);
	g_value_set_string (driver, is_wireless ? "nl80211,wext" : "wired");
	g_hash_table_insert (hash, "Driver", driver);

	ifname = g_new0 (GValue, 1);
	g_value_init (ifname, G_TYPE_STRING);
	g_value_set_string (ifname, priv->dev);
	g_hash_table_insert (hash, "Ifname", ifname);

	call = dbus_g_proxy_begin_call (priv->wpas_proxy, "CreateInterface",
	                                interface_add_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                DBUS_TYPE_G_MAP_OF_VARIANT, hash,
	                                G_TYPE_INVALID);

	g_hash_table_destroy (hash);
	g_value_unset (driver);
	g_free (driver);
	g_value_unset (ifname);
	g_free (ifname);

	nm_supplicant_info_set_call (info, call);
}

static void
smgr_avail_cb (NMSupplicantManager *smgr,
               GParamSpec *pspec,
               gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (user_data);

	if (nm_supplicant_manager_available (smgr)) {
		/* This can happen if the supplicant couldn't be activated but
		 * for some reason was started after the activation failure.
		 */
		if (priv->state == NM_SUPPLICANT_INTERFACE_STATE_INIT)
			interface_add (self, priv->is_wireless);
	} else {
		/* The supplicant stopped; so we must tear down the interface */
		set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
	}
}

static void
remove_network_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	GError *error = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID)) {
		nm_log_dbg (LOGD_SUPPLICANT, "Couldn't remove network from supplicant interface: %s.",
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}
}

static void
disconnect_cb  (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	GError *error = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't disconnect supplicant interface: %s.",
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}
}

void
nm_supplicant_interface_disconnect (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Clear and cancel all pending calls related to a prior
	 * connection attempt.
	 */
	cancel_all_callbacks (priv->assoc_pcalls);

	/* Don't do anything if there is no connection to the supplicant yet. */
	if (!priv->iface_proxy)
		return;

	/* Don't try to disconnect if the supplicant interface is already disconnected */
	if (   priv->state == NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED
	    || priv->state == NM_SUPPLICANT_INTERFACE_STATE_INACTIVE) {
		g_free (priv->net_path);
		priv->net_path = NULL;
		return;
	}

	/* Remove any network that was added by NetworkManager */
	if (priv->net_path) {
		dbus_g_proxy_begin_call (priv->iface_proxy, "RemoveNetwork",
		                         remove_network_cb,
		                         NULL, NULL,
		                         DBUS_TYPE_G_OBJECT_PATH, priv->net_path,
		                         G_TYPE_INVALID);
		g_free (priv->net_path);
		priv->net_path = NULL;
	}

	dbus_g_proxy_begin_call (priv->iface_proxy, "Disconnect",
	                         disconnect_cb,
	                         NULL, NULL,
	                         G_TYPE_INVALID);
}

static void
select_network_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	GError *err = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't select network config: %s.", err->message);
		emit_error_helper (info->interface, err);
		g_error_free (err);
	}
}

static void
call_select_network (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	DBusGProxyCall *call;
	NMSupplicantInfo *info;

	/* We only select the network after all blobs (if any) have been set */
	if (priv->blobs_left > 0)
		return;

	info = nm_supplicant_info_new (self, priv->iface_proxy, priv->assoc_pcalls);
	call = dbus_g_proxy_begin_call (priv->iface_proxy, "SelectNetwork",
	                                select_network_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                DBUS_TYPE_G_OBJECT_PATH, priv->net_path,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);
}

static void
add_blob_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
	GError *err = NULL;
	guint tmp;

	priv->blobs_left--;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_UINT, &tmp, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't set network certificates: %s.", err->message);
		emit_error_helper (info->interface, err);
		g_error_free (err);
	} else
		call_select_network (info->interface);
}

static void
add_network_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
	GError *err = NULL;
	GHashTable *blobs;
	GHashTableIter iter;
	gpointer name, data;
	DBusGProxyCall *call;
	NMSupplicantInfo *blob_info;

	g_free (priv->net_path);
	priv->net_path = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            DBUS_TYPE_G_OBJECT_PATH, &priv->net_path,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't add a network to the supplicant interface: %s.",
		             err->message);
		emit_error_helper (info->interface, err);
		g_error_free (err);
		return;
	}

	/* Send blobs first; otherwise jump to sending the config settings */
	blobs = nm_supplicant_config_get_blobs (priv->cfg);
	priv->blobs_left = g_hash_table_size (blobs);
	g_hash_table_iter_init (&iter, blobs);
	while (g_hash_table_iter_next (&iter, &name, &data)) {
		blob_info = nm_supplicant_info_new (info->interface, priv->iface_proxy, priv->assoc_pcalls);
		call = dbus_g_proxy_begin_call (priv->iface_proxy, "AddBlob",
			                            add_blob_cb,
			                            blob_info,
			                            nm_supplicant_info_destroy,
			                            DBUS_TYPE_STRING, name,
			                            DBUS_TYPE_G_UCHAR_ARRAY, blobs,
			                            G_TYPE_INVALID);
		nm_supplicant_info_set_call (blob_info, call);
	}

	call_select_network (info->interface);
}

static void
set_ap_scan_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
	GError *err = NULL;
	DBusGProxyCall *call;
	GHashTable *config_hash;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't send AP scan mode to the supplicant interface: %s.",
		             err->message);
		emit_error_helper (info->interface, err);
		g_error_free (err);
		return;
	}

	nm_log_info (LOGD_SUPPLICANT, "Config: set interface ap_scan to %d",
	             nm_supplicant_config_get_ap_scan (priv->cfg));

	info = nm_supplicant_info_new (info->interface, priv->iface_proxy, info->store);
	config_hash = nm_supplicant_config_get_hash (priv->cfg);
	call = dbus_g_proxy_begin_call (priv->iface_proxy, "AddNetwork",
	                                add_network_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                DBUS_TYPE_G_MAP_OF_VARIANT, config_hash,
	                                G_TYPE_INVALID);
	g_hash_table_destroy (config_hash);
	nm_supplicant_info_set_call (info, call);
}

gboolean
nm_supplicant_interface_set_config (NMSupplicantInterface * self,
                                    NMSupplicantConfig * cfg)
{
	NMSupplicantInterfacePrivate *priv;
	NMSupplicantInfo *info;
	DBusGProxyCall *call;
	GValue value = { 0, };

	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	nm_supplicant_interface_disconnect (self);
	
	if (priv->cfg)
		g_object_unref (priv->cfg);
	priv->cfg = cfg;

	if (cfg == NULL)
		return TRUE;

	g_object_ref (priv->cfg);

	g_value_init (&value, G_TYPE_UINT);
	g_value_set_uint (&value, nm_supplicant_config_get_ap_scan (priv->cfg));

	info = nm_supplicant_info_new (self, priv->props_proxy, priv->other_pcalls);
	call = dbus_g_proxy_begin_call (priv->props_proxy, "Set",
	                                set_ap_scan_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                G_TYPE_STRING, WPAS_DBUS_IFACE_INTERFACE,
	                                G_TYPE_STRING, "ApScan",
	                                G_TYPE_VALUE, &value,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);

	g_value_unset (&value);
	return call != NULL;
}

static void
scan_request_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	GError *err = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Could not get scan request result: %s", err->message);
	} 
	g_signal_emit (info->interface, signals[SCAN_DONE], 0, err ? FALSE : TRUE);
	g_clear_error (&err);
}

static void
destroy_gvalue (gpointer data)
{
	GValue *value = (GValue *) data;

	g_value_unset (value);
	g_slice_free (GValue, value);
}

static GValue *
string_to_gvalue (const char *str)
{
	GValue *val = g_slice_new0 (GValue);

	g_value_init (val, G_TYPE_STRING);
	g_value_set_string (val, str);
	return val;
}

gboolean
nm_supplicant_interface_request_scan (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv;
	NMSupplicantInfo *info;
	DBusGProxyCall *call;
	GHashTable *hash;

	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Scan parameters */
	hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, destroy_gvalue);
	g_hash_table_insert (hash, "Type", string_to_gvalue ("active"));

	info = nm_supplicant_info_new (self, priv->iface_proxy, priv->other_pcalls);
	call = dbus_g_proxy_begin_call (priv->iface_proxy, "Scan",
	                                scan_request_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                DBUS_TYPE_G_MAP_OF_VARIANT, hash,
	                                G_TYPE_INVALID);
	g_hash_table_destroy (hash);
	nm_supplicant_info_set_call (info, call);

	return call != NULL;
}

guint32
nm_supplicant_interface_get_state (NMSupplicantInterface * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NM_SUPPLICANT_INTERFACE_STATE_DOWN);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->state;
}

const char *
nm_supplicant_interface_state_to_string (guint32 state)
{
	switch (state) {
	case NM_SUPPLICANT_INTERFACE_STATE_INIT:
		return "init";
	case NM_SUPPLICANT_INTERFACE_STATE_STARTING:
		return "starting";
	case NM_SUPPLICANT_INTERFACE_STATE_READY:
		return "ready";
	case NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED:
		return "disconnected";
	case NM_SUPPLICANT_INTERFACE_STATE_INACTIVE:
		return "inactive";
	case NM_SUPPLICANT_INTERFACE_STATE_SCANNING:
		return "scanning";
	case NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING:
		return "authenticating";
	case NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING:
		return "associating";
	case NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED:
		return "associated";
	case NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE:
		return "4-way handshake";
	case NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE:
		return "group handshake";
	case NM_SUPPLICANT_INTERFACE_STATE_COMPLETED:
		return "completed";
	case NM_SUPPLICANT_INTERFACE_STATE_DOWN:
		return "down";
	default:
		break;
	}
	return "unknown";
}

const char *
nm_supplicant_interface_get_device (NMSupplicantInterface * self)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->dev;
}

const char *
nm_supplicant_interface_get_object_path (NMSupplicantInterface *self)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->object_path;
}

const char *
nm_supplicant_interface_get_ifname (NMSupplicantInterface *self)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->dev;
}

/*******************************************************************/

NMSupplicantInterface *
nm_supplicant_interface_new (NMSupplicantManager *smgr,
                             const char *ifname,
                             gboolean is_wireless,
                             gboolean start_now)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	guint id;

	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (smgr), NULL);
	g_return_val_if_fail (ifname != NULL, NULL);

	self = g_object_new (NM_TYPE_SUPPLICANT_INTERFACE, NULL);
	if (self) {
		priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

		priv->smgr = g_object_ref (smgr);
		id = g_signal_connect (priv->smgr,
		                       "notify::" NM_SUPPLICANT_MANAGER_AVAILABLE,
		                       G_CALLBACK (smgr_avail_cb),
		                       self);
		priv->smgr_avail_id = id;

		priv->dev = g_strdup (ifname);
		priv->is_wireless = is_wireless;

		if (start_now)
			interface_add (self, priv->is_wireless);
	}

	return self;
}

static void
nm_supplicant_interface_init (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	DBusGConnection *bus;

	priv->state = NM_SUPPLICANT_INTERFACE_STATE_INIT;
	priv->assoc_pcalls = nm_call_store_new ();
	priv->other_pcalls = nm_call_store_new ();
	priv->dbus_mgr = nm_dbus_manager_get ();

	bus = nm_dbus_manager_get_connection (priv->dbus_mgr);
	priv->wpas_proxy = dbus_g_proxy_new_for_name (bus,
	                                              WPAS_DBUS_SERVICE,
	                                              WPAS_DBUS_PATH,
	                                              WPAS_DBUS_INTERFACE);
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	switch (prop_id) {
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_SCANNING:
		g_value_set_boolean (value, NM_SUPPLICANT_INTERFACE_GET_PRIVATE (object)->scanning);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_supplicant_interface_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	/* Cancel pending calls before unrefing the dbus manager */
	cancel_all_callbacks (priv->other_pcalls);
	nm_call_store_destroy (priv->other_pcalls);

	cancel_all_callbacks (priv->assoc_pcalls);
	nm_call_store_destroy (priv->assoc_pcalls);

	if (priv->props_proxy)
		g_object_unref (priv->props_proxy);

	if (priv->iface_proxy)
		g_object_unref (priv->iface_proxy);

	g_free (priv->net_path);

	if (priv->wpas_proxy)
		g_object_unref (priv->wpas_proxy);

	if (priv->smgr) {
		if (priv->smgr_avail_id)
			g_signal_handler_disconnect (priv->smgr, priv->smgr_avail_id);
		g_object_unref (priv->smgr);
	}

	g_free (priv->dev);

	if (priv->dbus_mgr)
		g_object_unref (priv->dbus_mgr);

	if (priv->cfg)
		g_object_unref (priv->cfg);

	g_free (priv->object_path);

	/* Chain up to the parent class */
	G_OBJECT_CLASS (nm_supplicant_interface_parent_class)->dispose (object);
}

static void
nm_supplicant_interface_class_init (NMSupplicantInterfaceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMSupplicantInterfacePrivate));

	object_class->dispose = dispose;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	/* Properties */
	g_object_class_install_property (object_class, PROP_SCANNING,
		g_param_spec_boolean ("scanning",
		                      "Scanning",
		                      "Scanning",
		                      FALSE,
		                      G_PARAM_READABLE));

	/* Signals */
	signals[STATE] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_STATE,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, state),
		              NULL, NULL,
		              _nm_marshal_VOID__UINT_UINT,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);

	signals[REMOVED] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, removed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	signals[NEW_BSS] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_NEW_BSS,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, new_bss),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__POINTER,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[SCAN_DONE] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_SCAN_DONE,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, scan_done),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__BOOLEAN,
		              G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[CONNECTION_ERROR] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_CONNECTION_ERROR,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, connection_error),
		              NULL, NULL,
		              _nm_marshal_VOID__STRING_STRING,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);
}

