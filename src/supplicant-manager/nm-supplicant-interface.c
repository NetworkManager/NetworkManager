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
#define WPAS_DBUS_IFACE_BSSID       WPAS_DBUS_INTERFACE ".BSSID"
#define WPAS_DBUS_IFACE_NETWORK	    WPAS_DBUS_INTERFACE ".Network"
#define WPAS_ERROR_INVALID_IFACE    WPAS_DBUS_INTERFACE ".InvalidInterface"
#define WPAS_ERROR_EXISTS_ERROR     WPAS_DBUS_INTERFACE ".ExistsError"


static void wpas_iface_handle_state_change (DBusGProxy *proxy,
                                            const char *str_new_state,
                                            const char *str_old_state,
                                            gpointer user_data);

static void wpas_iface_handle_scanning (DBusGProxy *proxy,
                                        gboolean scanning,
                                        gpointer user_data);


G_DEFINE_TYPE (NMSupplicantInterface, nm_supplicant_interface, G_TYPE_OBJECT)

#define NM_SUPPLICANT_INTERFACE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                 NM_TYPE_SUPPLICANT_INTERFACE, \
                                                 NMSupplicantInterfacePrivate))

/* Signals */
enum {
	STATE,             /* change in the interface's state */
	REMOVED,           /* interface was removed by the supplicant */
	SCANNED_AP,        /* interface saw a new access point from a scan */
	SCAN_REQ_RESULT,   /* result of a wireless scan request */
	SCAN_RESULTS,      /* scan results returned from supplicant */
	CONNECTION_ERROR,  /* an error occurred during a connection request */
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };


/* Properties */
enum {
	PROP_0 = 0,
	PROP_STATE,
	PROP_SCANNING,
	LAST_PROP
};


typedef struct {
	NMSupplicantManager * smgr;
	gulong                smgr_running_id;
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
	DBusGProxy *          net_proxy;

	guint                 scan_results_timeout;
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
	GError *err = NULL;
	GHashTable *hash = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            DBUS_TYPE_G_MAP_OF_VARIANT, &hash,
	                            G_TYPE_INVALID)) {
		if (!strstr (err->message, "The BSSID requested was invalid")) {
			nm_log_warn (LOGD_SUPPLICANT, "Couldn't retrieve BSSID properties: %s.",
			             err->message);
		}
		g_error_free (err);
	} else {
		g_signal_emit (info->interface, signals[SCANNED_AP], 0, hash);
		g_hash_table_destroy (hash);
	}
}

static void
request_bssid_properties (NMSupplicantInterface * self,
                          const char * op)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantInfo *info;
	DBusGProxy *proxy;
	DBusGProxyCall *call;

	proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                   WPAS_DBUS_SERVICE,
	                                   op,
	                                   WPAS_DBUS_IFACE_BSSID);
	info = nm_supplicant_info_new (self, proxy, priv->other_pcalls);
	call = dbus_g_proxy_begin_call (proxy, "properties",
	                                bssid_properties_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);
	g_object_unref (proxy);
}

static void
scan_results_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	GError *err = NULL;
	GPtrArray *array = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH, &array,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "could not get scan results: %s.", err->message);
		g_error_free (err);
	} else {
		int i;
		NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;

		/* Notify listeners of the result of the scan */
		g_signal_emit (info->interface, signals[SCAN_RESULTS], 0, array->len);

		/* Fire off a "properties" call for each returned BSSID */
		for (i = 0; i < array->len; i++) {
			char *op = g_ptr_array_index (array, i);

			request_bssid_properties (info->interface, op);
			g_free (op);
		}

		g_ptr_array_free (array, TRUE);
	}
}

static gboolean
request_scan_results (gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantInfo *info;
	DBusGProxyCall *call;
	GTimeVal cur_time;

	priv->scan_results_timeout = 0;

	g_return_val_if_fail (priv->iface_proxy != NULL, FALSE);

	info = nm_supplicant_info_new (self, priv->iface_proxy, priv->other_pcalls);
	call = dbus_g_proxy_begin_call (priv->iface_proxy, "scanResults",
	                                scan_results_cb, 
	                                info,
	                                nm_supplicant_info_destroy,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);

	g_get_current_time (&cur_time);
	priv->last_scan = cur_time.tv_sec;
	return FALSE;
}

static void
wpas_iface_query_scan_results (DBusGProxy *proxy, gpointer user_data)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (user_data);
	GTimeVal cur_time;

	/* Only query scan results if a query is not queued */
	if (priv->scan_results_timeout)
		return;

	g_get_current_time (&cur_time);

	/* Only fetch scan results every 4s max, but initially do it right away */
	if (priv->last_scan + 4 < cur_time.tv_sec) {
		priv->scan_results_timeout = g_idle_add (request_scan_results,
		                                         user_data);
	} else {
		priv->scan_results_timeout =
			g_timeout_add_seconds ((4 - (cur_time.tv_sec - priv->last_scan)),
			               request_scan_results, user_data);
	}
}

static int
wpas_state_string_to_enum (const char *str_state)
{
	if (!strcmp (str_state, "DISCONNECTED"))
		return NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED;
	else if (!strcmp (str_state, "INACTIVE"))
		return NM_SUPPLICANT_INTERFACE_STATE_INACTIVE;
	else if (!strcmp (str_state, "SCANNING"))
		return NM_SUPPLICANT_INTERFACE_STATE_SCANNING;
	else if (!strcmp (str_state, "ASSOCIATING"))
		return NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING;
	else if (!strcmp (str_state, "ASSOCIATED"))
		return NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED;
	else if (!strcmp (str_state, "4WAY_HANDSHAKE"))
		return NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE;
	else if (!strcmp (str_state, "GROUP_HANDSHAKE"))
		return NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE;
	else if (!strcmp (str_state, "COMPLETED"))
		return NM_SUPPLICANT_INTERFACE_STATE_COMPLETED;

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

	/* Cannot regress to READY or INIT from higher states */
	if (priv->state <= NM_SUPPLICANT_INTERFACE_STATE_READY)
		g_return_if_fail (new_state > priv->state);

	if (new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		/* Cancel all pending calls when going down */
		cancel_all_callbacks (priv->other_pcalls);
		cancel_all_callbacks (priv->assoc_pcalls);

		/* Disconnect supplicant manager state listeners since we're done */
		if (priv->smgr_running_id) {
			g_signal_handler_disconnect (priv->smgr, priv->smgr_running_id);
			priv->smgr_running_id = 0;
		}

		if (priv->iface_proxy) {
			dbus_g_proxy_disconnect_signal (priv->iface_proxy,
			                                "StateChange",
			                                G_CALLBACK (wpas_iface_handle_state_change),
			                                self);

			dbus_g_proxy_disconnect_signal (priv->iface_proxy,
			                                "ScanResultsAvailable",
			                                G_CALLBACK (wpas_iface_query_scan_results),
			                                self);

			dbus_g_proxy_disconnect_signal (priv->iface_proxy,
			                                "Scanning",
			                                G_CALLBACK (wpas_iface_handle_scanning),
			                                self);
		}
	}

	priv->state = new_state;
	g_signal_emit (self, signals[STATE], 0, priv->state, old_state);
}

/* Supplicant state signal handler */
static void
wpas_iface_handle_state_change (DBusGProxy *proxy,
                                const char *str_new_state,
                                const char *str_old_state,
                                gpointer user_data)
{
	int enum_state = wpas_state_string_to_enum (str_new_state);

	g_return_if_fail (enum_state > 0);

	set_state (NM_SUPPLICANT_INTERFACE (user_data), (guint32) enum_state);
}

/* Explicit state request reply handler */
static void
iface_state_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	GError *err = NULL;
	char *state_str = NULL;
	int enum_state;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            G_TYPE_STRING, &state_str,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "could not get interface state: %s.", err->message);
		g_error_free (err);
	} else {
		enum_state = wpas_state_string_to_enum (state_str);
		g_warn_if_fail (enum_state > 0);

		if (enum_state > 0)
			set_state (info->interface, (guint32) enum_state);
		g_free (state_str);
	}
}

static void
wpas_iface_get_state (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantInfo *info;
	DBusGProxyCall *call;

	info = nm_supplicant_info_new (self, priv->iface_proxy, priv->other_pcalls);
	call = dbus_g_proxy_begin_call (priv->iface_proxy, "state",
	                                iface_state_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);
}

static void
iface_scanning_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
	gboolean scanning = FALSE;

	if (dbus_g_proxy_end_call (proxy, call_id, NULL,
	                            G_TYPE_BOOLEAN, &scanning,
	                            G_TYPE_INVALID)) {
		if (scanning != priv->scanning) {
			priv->scanning = scanning;
			g_object_notify (G_OBJECT (info->interface), "scanning");
		}
	}
}

static void
wpas_iface_get_scanning (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantInfo *info;
	DBusGProxyCall *call;

	info = nm_supplicant_info_new (self, priv->iface_proxy, priv->other_pcalls);
	call = dbus_g_proxy_begin_call (priv->iface_proxy, "scanning",
	                                iface_scanning_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);
}

static void
wpas_iface_handle_scanning (DBusGProxy *proxy,
                            gboolean scanning,
                            gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (scanning != priv->scanning) {
		priv->scanning = scanning;
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
interface_add_done (NMSupplicantInterface *self, char *path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	nm_log_dbg (LOGD_SUPPLICANT, "(%s): interface added to supplicant", priv->dev);

	priv->object_path = path;

	priv->iface_proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                               WPAS_DBUS_SERVICE,
	                                               path,
	                                               WPAS_DBUS_IFACE_INTERFACE);

	dbus_g_object_register_marshaller (_nm_marshal_VOID__STRING_STRING,
	                                   G_TYPE_NONE,
	                                   G_TYPE_STRING, G_TYPE_STRING,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->iface_proxy, "StateChange", G_TYPE_STRING, G_TYPE_STRING, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->iface_proxy, "StateChange",
	                             G_CALLBACK (wpas_iface_handle_state_change),
	                             self,
	                             NULL);

	dbus_g_proxy_add_signal (priv->iface_proxy, "ScanResultsAvailable", G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->iface_proxy, "ScanResultsAvailable",
	                             G_CALLBACK (wpas_iface_query_scan_results),
	                             self,
	                             NULL);

	dbus_g_proxy_add_signal (priv->iface_proxy, "Scanning", G_TYPE_BOOLEAN, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->iface_proxy, "Scanning",
	                             G_CALLBACK (wpas_iface_handle_scanning),
	                             self,
	                             NULL);

	/* Interface added to the supplicant; get its initial state. */
	wpas_iface_get_state (self);
	wpas_iface_get_scanning (self);

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
		nm_log_err (LOGD_SUPPLICANT, "(%s): error adding interface: %s",
		            priv->dev, error->message);
		g_clear_error (&error);
	}
}

static void
interface_get (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantInfo *info;
	DBusGProxyCall *call;

	info = nm_supplicant_info_new (self, priv->wpas_proxy, priv->other_pcalls);
	call = dbus_g_proxy_begin_call (priv->wpas_proxy, "getInterface",
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
		} else {
			nm_log_err (LOGD_SUPPLICANT, "(%s): error adding interface: %s",
			            priv->dev, error->message);
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
	GValue *driver;

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

	driver = g_new0 (GValue, 1);
	g_value_init (driver, G_TYPE_STRING);
	g_value_set_string (driver, is_wireless ? "wext" : "wired");

	hash = g_hash_table_new (g_str_hash, g_str_equal);
	g_hash_table_insert (hash, "driver", driver);

	call = dbus_g_proxy_begin_call (priv->wpas_proxy, "addInterface",
	                                interface_add_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                G_TYPE_STRING, priv->dev,
	                                DBUS_TYPE_G_MAP_OF_VARIANT, hash,
	                                G_TYPE_INVALID);

	g_hash_table_destroy (hash);
	g_value_unset (driver);
	g_free (driver);

	nm_supplicant_info_set_call (info, call);
}

static void
smgr_running_cb (NMSupplicantManager *smgr,
                 GParamSpec *pspec,
                 gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (user_data);

	if (nm_supplicant_manager_running (smgr)) {
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
	GError *err = NULL;
	guint tmp;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_UINT, &tmp, G_TYPE_INVALID)) {
		nm_log_dbg (LOGD_SUPPLICANT, "Couldn't remove network from supplicant interface: %s.",
		            err->message);
		g_error_free (err);
	}
}

static void
disconnect_cb  (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	GError *err = NULL;
	guint tmp;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_UINT, &tmp, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't disconnect supplicant interface: %s.",
		             err->message);
		g_error_free (err);
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
		if (priv->net_proxy) {
			g_object_unref (priv->net_proxy);
			priv->net_proxy = NULL;
		}
		return;
	}

	/* Remove any network that was added by NetworkManager */
	if (priv->net_proxy) {
		dbus_g_proxy_begin_call (priv->iface_proxy, "removeNetwork",
		                         remove_network_cb,
		                         NULL, NULL,
		                         DBUS_TYPE_G_OBJECT_PATH, dbus_g_proxy_get_path (priv->net_proxy),
		                         G_TYPE_INVALID);

		g_object_unref (priv->net_proxy);
		priv->net_proxy = NULL;
	}

	dbus_g_proxy_begin_call (priv->iface_proxy, "disconnect",
	                         disconnect_cb,
	                         NULL, NULL,
	                         G_TYPE_INVALID);
}

static void
select_network_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	GError *err = NULL;
	guint tmp;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_UINT, &tmp, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't select network config: %s.", err->message);
		emit_error_helper (info->interface, err);
		g_error_free (err);
	}
}

static void
set_network_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
	GError *err = NULL;
	guint tmp;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_UINT, &tmp, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't set network config: %s.", err->message);
		emit_error_helper (info->interface, err);
		g_error_free (err);
	} else {
		DBusGProxyCall *call;

		info = nm_supplicant_info_new (info->interface, priv->iface_proxy, priv->assoc_pcalls);
		call = dbus_g_proxy_begin_call (priv->iface_proxy, "selectNetwork",
		                                select_network_cb,
		                                info,
		                                nm_supplicant_info_destroy,
		                                DBUS_TYPE_G_OBJECT_PATH, dbus_g_proxy_get_path (proxy),
		                                G_TYPE_INVALID);
		nm_supplicant_info_set_call (info, call);
	}
}

static void
call_set_network (NMSupplicantInfo *info)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
	GHashTable *config_hash;
	DBusGProxyCall *call;

	config_hash = nm_supplicant_config_get_hash (priv->cfg);
	call = dbus_g_proxy_begin_call (priv->net_proxy, "set",
	                                set_network_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                DBUS_TYPE_G_MAP_OF_VARIANT, config_hash,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);
	g_hash_table_destroy (config_hash);
}

static void
set_blobs_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
	GError *err = NULL;
	guint tmp;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_UINT, &tmp, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't set network certificates: %s.", err->message);
		emit_error_helper (info->interface, err);
		g_error_free (err);
	} else {
		info = nm_supplicant_info_new (info->interface, priv->iface_proxy, priv->assoc_pcalls);
		call_set_network (info);
	}
}

static GValue *
byte_array_to_gvalue (const GByteArray *array)
{
	GValue *val;

	val = g_slice_new0 (GValue);
	g_value_init (val, DBUS_TYPE_G_UCHAR_ARRAY);
	g_value_set_boxed (val, array);

	return val;
}

static void
blob_free (GValue *val)
{
	g_value_unset (val);
	g_slice_free (GValue, val);
}

static void
convert_blob (const char *key, const GByteArray *value, GHashTable *hash)
{
	GValue *val;

	val = byte_array_to_gvalue (value);
	g_hash_table_insert (hash, g_strdup (key), val);
}

static void
call_set_blobs (NMSupplicantInfo *info, GHashTable *orig_blobs)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
	DBusGProxyCall *call;
	GHashTable *blobs;

	blobs = g_hash_table_new_full (g_str_hash, g_str_equal,
	                               (GDestroyNotify) g_free,
	                               (GDestroyNotify) blob_free);
	if (!blobs) {
		const char *msg = "Not enough memory to create blob table.";

		nm_log_warn (LOGD_SUPPLICANT, "%s", msg);
		g_signal_emit (info->interface, signals[CONNECTION_ERROR], 0, "SendBlobError", msg);
		return;
	}

	g_hash_table_foreach (orig_blobs, (GHFunc) convert_blob, blobs);

	call = dbus_g_proxy_begin_call (priv->iface_proxy, "setBlobs",
	                                set_blobs_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                DBUS_TYPE_G_MAP_OF_VARIANT, blobs,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);
	g_hash_table_destroy (blobs);
}

static void
add_network_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	GError *err = NULL;
	char *path = NULL;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            DBUS_TYPE_G_OBJECT_PATH, &path,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't add a network to the supplicant interface: %s.",
		             err->message);
		emit_error_helper (info->interface, err);
		g_error_free (err);
	} else {
		NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
		GHashTable *blobs;

		priv->net_proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
		                                             WPAS_DBUS_SERVICE,
		                                             path,
		                                             WPAS_DBUS_IFACE_NETWORK);
		g_free (path);

		info = nm_supplicant_info_new (info->interface,
		                               priv->net_proxy,
		                               priv->assoc_pcalls);
		/* Send any blobs first; if there aren't any jump to sending the
		 * config settings.
		 */
		blobs = nm_supplicant_config_get_blobs (priv->cfg);
		if (g_hash_table_size (blobs) > 0)
			call_set_blobs (info, blobs);
		else
			call_set_network (info);
	}
}

static void
set_ap_scan_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (info->interface);
	GError *err = NULL;
	guint32 tmp;
	DBusGProxyCall *call;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_UINT, &tmp, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't send AP scan mode to the supplicant interface: %s.",
		             err->message);
		emit_error_helper (info->interface, err);
		g_error_free (err);
		return;
	}

	nm_log_info (LOGD_SUPPLICANT, "Config: set interface ap_scan to %d",
	             nm_supplicant_config_get_ap_scan (priv->cfg));

	info = nm_supplicant_info_new (info->interface, proxy, info->store);
	call = dbus_g_proxy_begin_call (proxy, "addNetwork",
	                                add_network_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);
}

gboolean
nm_supplicant_interface_set_config (NMSupplicantInterface * self,
                                    NMSupplicantConfig * cfg)
{
	NMSupplicantInterfacePrivate *priv;
	NMSupplicantInfo *info;
	DBusGProxyCall *call;
	guint32 ap_scan;

	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	nm_supplicant_interface_disconnect (self);
	
	if (priv->cfg)
		g_object_unref (priv->cfg);
	priv->cfg = cfg;

	if (cfg == NULL)
		return TRUE;

	g_object_ref (priv->cfg);

	info = nm_supplicant_info_new (self, priv->iface_proxy, priv->other_pcalls);
	ap_scan = nm_supplicant_config_get_ap_scan (priv->cfg);
	call = dbus_g_proxy_begin_call (priv->iface_proxy, "setAPScan",
	                                set_ap_scan_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                G_TYPE_UINT, ap_scan,
	                                G_TYPE_INVALID);
	nm_supplicant_info_set_call (info, call);

	return call != NULL;
}

static void
scan_request_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInfo *info = (NMSupplicantInfo *) user_data;
	GError *err = NULL;
	guint32 success = 0;

	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            G_TYPE_UINT, &success,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Could not get scan request result: %s", err->message);
		g_error_free (err);
	} 

	/* Notify listeners of the result of the scan */
	g_signal_emit (info->interface, signals[SCAN_REQ_RESULT], 0, !!success);
}

gboolean
nm_supplicant_interface_request_scan (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv;
	NMSupplicantInfo *info;
	DBusGProxyCall *call;

	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	info = nm_supplicant_info_new (self, priv->iface_proxy, priv->other_pcalls);
	call = dbus_g_proxy_begin_call (priv->iface_proxy, "scan",
	                                scan_request_cb,
	                                info,
	                                nm_supplicant_info_destroy,
	                                G_TYPE_INVALID);
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
	g_return_val_if_fail (self != NULL, FALSE);
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->dev;
}

/*******************************************************************/

NMSupplicantInterface *
nm_supplicant_interface_new (NMSupplicantManager *smgr,
                             const char *ifname,
                             gboolean is_wireless)
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
		                       "notify::" NM_SUPPLICANT_MANAGER_RUNNING,
		                       G_CALLBACK (smgr_running_cb),
		                       self);
		priv->smgr_running_id = id;

		priv->dev = g_strdup (ifname);
		priv->is_wireless = is_wireless;

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
	case PROP_STATE:
		g_value_set_uint (value, NM_SUPPLICANT_INTERFACE_GET_PRIVATE (object)->state);
		break;
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

	if (priv->iface_proxy)
		g_object_unref (priv->iface_proxy);

	if (priv->net_proxy)
		g_object_unref (priv->net_proxy);

	if (priv->wpas_proxy)
		g_object_unref (priv->wpas_proxy);

	if (priv->scan_results_timeout)
		g_source_remove (priv->scan_results_timeout);

	if (priv->smgr) {
		if (priv->smgr_running_id)
			g_signal_handler_disconnect (priv->smgr, priv->smgr_running_id);
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
	g_object_class_install_property (object_class, PROP_STATE,
		g_param_spec_uint ("state",
		                   "State",
		                   "State of the supplicant interface",
		                   NM_SUPPLICANT_INTERFACE_STATE_INIT,
		                   NM_SUPPLICANT_INTERFACE_STATE_LAST - 1,
		                   NM_SUPPLICANT_INTERFACE_STATE_INIT,
		                   G_PARAM_READABLE));

	g_object_class_install_property (object_class, PROP_SCANNING,
		g_param_spec_boolean ("scanning",
		                      "Scanning",
		                      "Scanning",
		                      FALSE,
		                      G_PARAM_READABLE));

	/* Signals */
	signals[STATE] =
		g_signal_new ("state",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, state),
		              NULL, NULL,
		              _nm_marshal_VOID__UINT_UINT,
		              G_TYPE_NONE, 2, G_TYPE_UINT, G_TYPE_UINT);

	signals[REMOVED] =
		g_signal_new ("removed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, removed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	signals[SCANNED_AP] =
		g_signal_new ("scanned-ap",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, scanned_ap),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__POINTER,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[SCAN_REQ_RESULT] =
		g_signal_new ("scan-req-result",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, scan_req_result),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__BOOLEAN,
		              G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[SCAN_RESULTS] =
		g_signal_new ("scan-results",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, scan_results),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[CONNECTION_ERROR] =
		g_signal_new ("connection-error",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, connection_error),
		              NULL, NULL,
		              _nm_marshal_VOID__STRING_STRING,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);
}

