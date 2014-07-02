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
 * Copyright (C) 2006 - 2012 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include <config.h>
#include <stdio.h>
#include <string.h>
#include <glib.h>

#include "NetworkManagerUtils.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-manager.h"
#include "nm-logging.h"
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

static void wpas_iface_get_props (NMSupplicantInterface *self);

#define NM_SUPPLICANT_INTERFACE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                                 NM_TYPE_SUPPLICANT_INTERFACE, \
                                                 NMSupplicantInterfacePrivate))

/* Signals */
enum {
	STATE,               /* change in the interface's state */
	REMOVED,             /* interface was removed by the supplicant */
	NEW_BSS,             /* interface saw a new access point from a scan */
	BSS_UPDATED,         /* a BSS property changed */
	BSS_REMOVED,         /* supplicant removed BSS from its scan list */
	SCAN_DONE,           /* wifi scan is complete */
	CONNECTION_ERROR,    /* an error occurred during a connection request */
	CREDENTIALS_REQUEST, /* 802.1x identity or password requested */
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
	gboolean              has_credreq;  /* Whether querying 802.1x credentials is supported */
	ApSupport             ap_support;   /* Lightweight AP mode support */
	gboolean              fast_supported;
	guint32               max_scan_ssids;
	guint32               ready_count;

	char *                object_path;
	guint32               state;
	int                   disconnect_reason;
	NMCallStore *         assoc_pcalls;
	NMCallStore *         other_pcalls;

	gboolean              scanning;

	DBusGProxy *          wpas_proxy;
	DBusGProxy *          introspect_proxy;
	DBusGProxy *          iface_proxy;
	DBusGProxy *          props_proxy;
	char *                net_path;
	guint32               blobs_left;
	GHashTable *          bss_proxies;

	gint32                last_scan; /* timestamp as returned by nm_utils_get_monotonic_timestamp_s() */

	NMSupplicantConfig *  cfg;

	gboolean              disposed;
} NMSupplicantInterfacePrivate;

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
signal_new_bss (NMSupplicantInterface *self,
                const char *object_path,
                GHashTable *props)
{
	g_signal_emit (self, signals[NEW_BSS], 0, object_path, props);
}

static void
bssid_properties_cb  (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GError *error = NULL;
	GHashTable *props = NULL;

	nm_call_store_remove (priv->other_pcalls, proxy, call_id);
	if (dbus_g_proxy_end_call (proxy, call_id, &error,
	                           DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                           G_TYPE_INVALID)) {
		signal_new_bss (self, dbus_g_proxy_get_path (proxy), props);
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
bss_properties_changed (DBusGProxy *proxy,
                        const char *interface,
                        GHashTable *props,
                        const char **unused,
                        gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->scanning)
		priv->last_scan = nm_utils_get_monotonic_timestamp_s ();

	if (g_strcmp0 (interface, WPAS_DBUS_IFACE_BSS) == 0)
		g_signal_emit (self, signals[BSS_UPDATED], 0, dbus_g_proxy_get_path (proxy), props);
}

static void
handle_new_bss (NMSupplicantInterface *self,
                const char *object_path,
                GHashTable *props)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	DBusGProxy *bss_proxy;
	DBusGProxyCall *call;

	g_return_if_fail (object_path != NULL);

	if (g_hash_table_lookup (priv->bss_proxies, object_path))
		return;

	bss_proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                       WPAS_DBUS_SERVICE,
	                                       object_path,
	                                       DBUS_INTERFACE_PROPERTIES);
	g_hash_table_insert (priv->bss_proxies,
	                     (gpointer) dbus_g_proxy_get_path (bss_proxy),
	                     bss_proxy);

	/* Standard D-Bus PropertiesChanged signal */
	dbus_g_object_register_marshaller (g_cclosure_marshal_generic,
	                                   G_TYPE_NONE,
	                                   G_TYPE_STRING, DBUS_TYPE_G_MAP_OF_VARIANT, G_TYPE_STRV,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (bss_proxy, "PropertiesChanged",
	                         G_TYPE_STRING, DBUS_TYPE_G_MAP_OF_VARIANT, G_TYPE_STRV,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (bss_proxy, "PropertiesChanged",
	                             G_CALLBACK (bss_properties_changed),
	                             self, NULL);

	if (props) {
		signal_new_bss (self, object_path, props);
	} else {
		call = dbus_g_proxy_begin_call (bss_proxy, "GetAll",
		                                bssid_properties_cb,
		                                self,
		                                NULL,
		                                G_TYPE_STRING, WPAS_DBUS_IFACE_BSS,
		                                G_TYPE_INVALID);
		nm_call_store_add (priv->other_pcalls, bss_proxy, call);
	}
}

static void
wpas_iface_bss_added (DBusGProxy *proxy,
                      const char *object_path,
                      GHashTable *props,
                      gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->scanning)
		priv->last_scan = nm_utils_get_monotonic_timestamp_s ();

	handle_new_bss (self, object_path, props);
}

static void
wpas_iface_bss_removed (DBusGProxy *proxy,
                        const char *object_path,
                        gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_signal_emit (self, signals[BSS_REMOVED], 0, object_path);

	g_hash_table_remove (priv->bss_proxies, object_path);
}

static int
wpas_state_string_to_enum (const char *str_state)
{
	if (!strcmp (str_state, "interface_disabled"))
		return NM_SUPPLICANT_INTERFACE_STATE_DISABLED;
	else if (!strcmp (str_state, "disconnected"))
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

	if (new_state == NM_SUPPLICANT_INTERFACE_STATE_READY) {
		/* Get properties again to update to the actual wpa_supplicant
		 * interface state.
		 */
		wpas_iface_get_props (self);
	} else if (new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		/* Cancel all pending calls when going down */
		nm_call_store_clear (priv->other_pcalls);
		nm_call_store_clear (priv->assoc_pcalls);

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
			dbus_g_proxy_disconnect_signal (priv->iface_proxy,
			                                "BSSRemoved",
			                                G_CALLBACK (wpas_iface_bss_removed),
			                                self);
		}
	}

	priv->state = new_state;

	if (   priv->state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING
	    || old_state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING)
		priv->last_scan = nm_utils_get_monotonic_timestamp_s ();

	/* Disconnect reason is no longer relevant when not in the DISCONNECTED state */
	if (priv->state != NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED)
		priv->disconnect_reason = 0;

	g_signal_emit (self, signals[STATE], 0,
	               priv->state,
	               old_state,
	               priv->disconnect_reason);
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

	if (priv->scanning != new_scanning) {
		priv->scanning = new_scanning;

		/* Cache time of last scan completion */
		if (priv->scanning == FALSE)
			priv->last_scan = nm_utils_get_monotonic_timestamp_s ();

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

gint32
nm_supplicant_interface_get_last_scan_time (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->last_scan;
}

static void
wpas_iface_scan_done (DBusGProxy *proxy,
                      gboolean success,
                      gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Cache last scan completed time */
	priv->last_scan = nm_utils_get_monotonic_timestamp_s ();
	g_signal_emit (self, signals[SCAN_DONE], 0, success);
}

static void
parse_capabilities (NMSupplicantInterface *self, GHashTable *props)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GValue *value;
	gboolean have_active = FALSE, have_ssid = FALSE;

	g_return_if_fail (props != NULL);

	value = g_hash_table_lookup (props, "Scan");
	if (value && G_VALUE_HOLDS (value, G_TYPE_STRV)) {
		const char **vals = g_value_get_boxed (value);
		const char **iter = vals;

		while (iter && *iter && (!have_active || !have_ssid)) {
			if (g_strcmp0 (*iter, "active") == 0)
				have_active = TRUE;
			else if (g_strcmp0 (*iter, "ssid") == 0)
				have_ssid = TRUE;
			iter++;
		}
	}

	value = g_hash_table_lookup (props, "MaxScanSSID");
	if (value && G_VALUE_HOLDS (value, G_TYPE_INT)) {
		/* We need active scan and SSID probe capabilities to care about MaxScanSSIDs */
		if (have_active && have_ssid) {
			/* wpa_supplicant's WPAS_MAX_SCAN_SSIDS value is 16, but for speed
			 * and to ensure we don't disclose too many SSIDs from the hidden
			 * list, we'll limit to 5.
			 */
			priv->max_scan_ssids = CLAMP (g_value_get_int (value), 0, 5);
			nm_log_info (LOGD_SUPPLICANT, "(%s) supports %d scan SSIDs",
			             priv->dev, priv->max_scan_ssids);
		}
	}
}

static void
wpas_iface_properties_changed (DBusGProxy *proxy,
                               GHashTable *props,
                               gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GValue *value;

	value = g_hash_table_lookup (props, "Scanning");
	if (value && G_VALUE_HOLDS_BOOLEAN (value))
		set_scanning (self, g_value_get_boolean (value));

	value = g_hash_table_lookup (props, "State");
	if (value && G_VALUE_HOLDS_STRING (value)) {
		if (priv->state >= NM_SUPPLICANT_INTERFACE_STATE_READY) {
			/* Only transition to actual wpa_supplicant interface states (ie,
			 * anything > READY) after the NMSupplicantInterface has had a
			 * chance to initialize, which is signalled by entering the READY
			 * state.
			 */
			set_state_from_string (self, g_value_get_string (value));
		}
	}

	value = g_hash_table_lookup (props, "BSSs");
	if (value && G_VALUE_HOLDS (value, DBUS_TYPE_G_ARRAY_OF_OBJECT_PATH)) {
		GPtrArray *paths = g_value_get_boxed (value);
		int i;

		for (i = 0; paths && (i < paths->len); i++)
			handle_new_bss (self, g_ptr_array_index (paths, i), NULL);
	}

	value = g_hash_table_lookup (props, "Capabilities");
	if (value && G_VALUE_HOLDS (value, DBUS_TYPE_G_MAP_OF_VARIANT))
		parse_capabilities (self, g_value_get_boxed (value));

	/* Disconnect reason is currently only given for deauthentication events,
	 * not disassociation; currently they are IEEE 802.11 "reason codes",
	 * defined by (IEEE 802.11-2007, 7.3.1.7, Table 7-22).  Any locally caused
	 * deauthentication will be negative, while authentications caused by the
	 * AP will be positive.
	 */
	value = g_hash_table_lookup (props, "DisconnectReason");
	if (value && G_VALUE_HOLDS (value, G_TYPE_INT)) {
		priv->disconnect_reason = g_value_get_int (value);
		if (priv->disconnect_reason != 0) {
			nm_log_warn (LOGD_SUPPLICANT, "Connection disconnected (reason %d)",
			             priv->disconnect_reason);
		}
	}
}

static void
iface_check_ready (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->ready_count && priv->state < NM_SUPPLICANT_INTERFACE_STATE_READY) {
		priv->ready_count--;
		if (priv->ready_count == 0)
			set_state (self, NM_SUPPLICANT_INTERFACE_STATE_READY);
	}
}

static void
iface_get_props_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GHashTable *props = NULL;
	GError *error = NULL;

	nm_call_store_remove (priv->other_pcalls, proxy, call_id);
	if (dbus_g_proxy_end_call (proxy, call_id, &error,
	                           DBUS_TYPE_G_MAP_OF_VARIANT, &props,
	                           G_TYPE_INVALID)) {
		wpas_iface_properties_changed (NULL, props, self);
		g_hash_table_destroy (props);
	} else {
		nm_log_warn (LOGD_SUPPLICANT, "could not get interface properties: %s.",
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}
	iface_check_ready (self);
}

static void
wpas_iface_get_props (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	DBusGProxyCall *call;

	call = dbus_g_proxy_begin_call (priv->props_proxy, "GetAll",
	                                iface_get_props_cb,
	                                self,
	                                NULL,
	                                G_TYPE_STRING, WPAS_DBUS_IFACE_INTERFACE,
	                                G_TYPE_INVALID);
	nm_call_store_add (priv->other_pcalls, priv->props_proxy, call);
}

gboolean
nm_supplicant_interface_credentials_reply (NMSupplicantInterface *self,
                                           const char *field,
                                           const char *value,
                                           GError **error)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	g_return_val_if_fail (priv->has_credreq == TRUE, FALSE);

	/* Need a network block object path */
	g_return_val_if_fail (priv->net_path, FALSE);
	return dbus_g_proxy_call_with_timeout (priv->iface_proxy, "NetworkReply",
	                                       5000,
	                                       error,
	                                       DBUS_TYPE_G_OBJECT_PATH, priv->net_path,
	                                       G_TYPE_STRING, field,
	                                       G_TYPE_STRING, value,
	                                       G_TYPE_INVALID);
}

static void
wpas_iface_network_request (DBusGProxy *proxy,
                            const char *object_path,
                            const char *field,
                            const char *message,
                            gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_return_if_fail (priv->has_credreq == TRUE);
	g_return_if_fail (priv->net_path != NULL);
	g_return_if_fail (g_strcmp0 (object_path, priv->net_path) == 0);

	g_signal_emit (self, signals[CREDENTIALS_REQUEST], 0, field, message);
}

static void
iface_check_netreply_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GError *error = NULL;

	nm_call_store_remove (priv->other_pcalls, proxy, call_id);
	if (   dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID)
	    || dbus_g_error_has_name (error, "fi.w1.wpa_supplicant1.InvalidArgs")) {
		/* We know NetworkReply is supported if the NetworkReply method returned
		 * successfully (which is unexpected since we sent a bogus network
		 * object path) or if we got an "InvalidArgs" (which indicates NetworkReply
		 * is supported).  We know it's not supported if we get an
		 * "UnknownMethod" error.
		 */
		priv->has_credreq = TRUE;

		nm_log_dbg (LOGD_SUPPLICANT, "Supplicant %s network credentials requests",
			        priv->has_credreq ? "supports" : "does not support");
	}
	g_clear_error (&error);

	iface_check_ready (self);
}

static void
wpas_iface_check_network_reply (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	DBusGProxyCall *call;

	priv->ready_count++;
	call = dbus_g_proxy_begin_call (priv->iface_proxy, "NetworkReply",
	                                iface_check_netreply_cb,
	                                self,
	                                NULL,
	                                DBUS_TYPE_G_OBJECT_PATH, "/foobaraasdfasdf",
	                                G_TYPE_STRING, "foobar",
	                                G_TYPE_STRING, "foobar",
	                                G_TYPE_INVALID);
	nm_call_store_add (priv->other_pcalls, priv->iface_proxy, call);
}

ApSupport
nm_supplicant_interface_get_ap_support (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->ap_support;
}

void
nm_supplicant_interface_set_ap_support (NMSupplicantInterface *self,
                                        ApSupport ap_support)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Use the best indicator of support between the supplicant global
	 * Capabilities property and the interface's introspection data.
	 */
	if (ap_support > priv->ap_support)
		priv->ap_support = ap_support;
}

static void
iface_check_ap_mode_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	char *data;

	/* The ProbeRequest method only exists if AP mode has been enabled */
	nm_call_store_remove (priv->other_pcalls, proxy, call_id);
	if (dbus_g_proxy_end_call (proxy, call_id, NULL,
	                           G_TYPE_STRING,
	                           &data,
	                           G_TYPE_INVALID)) {
		if (data && strstr (data, "ProbeRequest"))
			priv->ap_support = AP_SUPPORT_YES;
		g_free (data);
	}

	iface_check_ready (self);
}

static void
wpas_iface_check_ap_mode (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	DBusGProxyCall *call;

	priv->ready_count++;

	/* If the global supplicant capabilities property is not present, we can
	 * fall back to checking whether the ProbeRequest method is supported.  If
	 * neither of these works we have no way of determining if AP mode is
	 * supported or not.  hostap 1.0 and earlier don't support either of these.
	 */
	call = dbus_g_proxy_begin_call (priv->introspect_proxy, "Introspect",
	                                iface_check_ap_mode_cb,
	                                self,
	                                NULL,
	                                G_TYPE_INVALID);
	nm_call_store_add (priv->other_pcalls, priv->introspect_proxy, call);
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

	dbus_g_proxy_add_signal (priv->iface_proxy, "ScanDone",
	                         G_TYPE_BOOLEAN, G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->iface_proxy, "ScanDone",
	                             G_CALLBACK (wpas_iface_scan_done),
	                             self,
	                             NULL);

	dbus_g_object_register_marshaller (g_cclosure_marshal_generic,
	                                   G_TYPE_NONE,
	                                   DBUS_TYPE_G_OBJECT_PATH, DBUS_TYPE_G_MAP_OF_VARIANT,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->iface_proxy, "BSSAdded", 
	                         DBUS_TYPE_G_OBJECT_PATH, DBUS_TYPE_G_MAP_OF_VARIANT,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->iface_proxy, "BSSAdded",
	                             G_CALLBACK (wpas_iface_bss_added),
	                             self,
	                             NULL);

	dbus_g_object_register_marshaller (g_cclosure_marshal_VOID__BOXED,
	                                   G_TYPE_NONE,
	                                   DBUS_TYPE_G_OBJECT_PATH,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->iface_proxy, "BSSRemoved",
	                         DBUS_TYPE_G_OBJECT_PATH,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->iface_proxy, "BSSRemoved",
	                             G_CALLBACK (wpas_iface_bss_removed),
	                             self,
	                             NULL);

	dbus_g_object_register_marshaller (g_cclosure_marshal_generic,
	                                   G_TYPE_NONE,
	                                   DBUS_TYPE_G_OBJECT_PATH, G_TYPE_STRING, G_TYPE_STRING,
	                                   G_TYPE_INVALID);
	dbus_g_proxy_add_signal (priv->iface_proxy, "NetworkRequest",
	                         DBUS_TYPE_G_OBJECT_PATH, G_TYPE_STRING, G_TYPE_STRING,
	                         G_TYPE_INVALID);
	dbus_g_proxy_connect_signal (priv->iface_proxy, "NetworkRequest",
	                             G_CALLBACK (wpas_iface_network_request),
	                             self,
	                             NULL);

	priv->introspect_proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                                    WPAS_DBUS_SERVICE,
	                                                    priv->object_path,
	                                                    DBUS_INTERFACE_INTROSPECTABLE);

	priv->props_proxy = dbus_g_proxy_new_for_name (nm_dbus_manager_get_connection (priv->dbus_mgr),
	                                               WPAS_DBUS_SERVICE,
	                                               path,
	                                               DBUS_INTERFACE_PROPERTIES);
	/* Get initial properties and check whether NetworkReply is supported */
	priv->ready_count = 1;
	wpas_iface_get_props (self);

	/* These two increment ready_count themselves */
	wpas_iface_check_network_reply (self);
	if (priv->ap_support == AP_SUPPORT_UNKNOWN)
		wpas_iface_check_ap_mode (self);
}

static void
interface_get_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GError *error = NULL;
	char *path = NULL;

	nm_call_store_remove (priv->other_pcalls, proxy, call_id);
	if (dbus_g_proxy_end_call (proxy, call_id, &error,
	                           DBUS_TYPE_G_OBJECT_PATH, &path,
	                           G_TYPE_INVALID)) {
		interface_add_done (self, path);
	} else {
		nm_log_err (LOGD_SUPPLICANT, "(%s): error getting interface: %s",
		            priv->dev, error->message);
		g_clear_error (&error);
		set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
	}
}

static void
interface_get (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	DBusGProxyCall *call;

	call = dbus_g_proxy_begin_call (priv->wpas_proxy, "GetInterface",
	                                interface_get_cb,
	                                self,
	                                NULL,
	                                G_TYPE_STRING, priv->dev,
	                                G_TYPE_INVALID);
	nm_call_store_add (priv->other_pcalls, priv->wpas_proxy, call);
}

static void
interface_add_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GError *error = NULL;
	char *path = NULL;

	nm_call_store_remove (priv->other_pcalls, proxy, call_id);
	if (dbus_g_proxy_end_call (proxy, call_id, &error,
	                           DBUS_TYPE_G_OBJECT_PATH, &path,
	                           G_TYPE_INVALID)) {
		interface_add_done (self, path);
	} else {
		if (dbus_g_error_has_name (error, WPAS_ERROR_EXISTS_ERROR)) {
			/* Interface already added, just get its object path */
			interface_get (self);
		} else if (   g_error_matches (error, DBUS_GERROR, DBUS_GERROR_SERVICE_UNKNOWN)
		           || g_error_matches (error, DBUS_GERROR, DBUS_GERROR_SPAWN_EXEC_FAILED)
		           || g_error_matches (error, DBUS_GERROR, DBUS_GERROR_SPAWN_FORK_FAILED)
		           || g_error_matches (error, DBUS_GERROR, DBUS_GERROR_SPAWN_FAILED)
		           || g_error_matches (error, DBUS_GERROR, DBUS_GERROR_TIMEOUT)
		           || g_error_matches (error, DBUS_GERROR, DBUS_GERROR_NO_REPLY)
		           || g_error_matches (error, DBUS_GERROR, DBUS_GERROR_TIMED_OUT)
		           || dbus_g_error_has_name (error, DBUS_ERROR_SPAWN_SERVICE_NOT_FOUND)) {
			/* Supplicant wasn't running and could not be launched via service
			 * activation.  Wait for it to start by moving back to the INIT
			 * state.
			 */
			nm_log_dbg (LOGD_SUPPLICANT, "(%s): failed to activate supplicant: %s",
			            priv->dev, error->message);
			set_state (self, NM_SUPPLICANT_INTERFACE_STATE_INIT);
		} else {
			nm_log_err (LOGD_SUPPLICANT, "(%s): error adding interface: %s",
			            priv->dev, error->message);
			set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
		}
		g_clear_error (&error);
	}
}

#if HAVE_WEXT
#define DEFAULT_WIFI_DRIVER "nl80211,wext"
#else
#define DEFAULT_WIFI_DRIVER "nl80211"
#endif

static void
interface_add (NMSupplicantInterface *self, gboolean is_wireless)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	DBusGProxyCall *call;
	GHashTable *hash;
	GValue driver = G_VALUE_INIT;
	GValue ifname = G_VALUE_INIT;

	/* Can only start the interface from INIT state */
	g_return_if_fail (priv->state == NM_SUPPLICANT_INTERFACE_STATE_INIT);

	nm_log_dbg (LOGD_SUPPLICANT, "(%s): adding interface to supplicant", priv->dev);

	/* Move to starting to prevent double-calls of interface_add() */
	set_state (self, NM_SUPPLICANT_INTERFACE_STATE_STARTING);

	/* Try to add the interface to the supplicant.  If the supplicant isn't
	 * running, this will start it via D-Bus activation and return the response
	 * when the supplicant has started.
	 */

	hash = g_hash_table_new (g_str_hash, g_str_equal);

	g_value_init (&driver, G_TYPE_STRING);
	g_value_set_string (&driver, is_wireless ? DEFAULT_WIFI_DRIVER : "wired");
	g_hash_table_insert (hash, "Driver", &driver);

	g_value_init (&ifname, G_TYPE_STRING);
	g_value_set_string (&ifname, priv->dev);
	g_hash_table_insert (hash, "Ifname", &ifname);

	call = dbus_g_proxy_begin_call (priv->wpas_proxy, "CreateInterface",
	                                interface_add_cb,
	                                self,
	                                NULL,
	                                DBUS_TYPE_G_MAP_OF_VARIANT, hash,
	                                G_TYPE_INVALID);
	nm_call_store_add (priv->other_pcalls, priv->wpas_proxy, call);

	g_hash_table_destroy (hash);
	g_value_unset (&driver);
	g_value_unset (&ifname);
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
	nm_call_store_clear (priv->assoc_pcalls);

	/* Don't do anything if there is no connection to the supplicant yet. */
	if (!priv->iface_proxy)
		return;

	/* Disconnect from the current AP */
	if (   (priv->state >= NM_SUPPLICANT_INTERFACE_STATE_SCANNING)
	    && (priv->state <= NM_SUPPLICANT_INTERFACE_STATE_COMPLETED)) {
		dbus_g_proxy_begin_call (priv->iface_proxy, "Disconnect",
			                     disconnect_cb,
			                     NULL, NULL,
			                     G_TYPE_INVALID);
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
}

static void
select_network_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GError *err = NULL;

	nm_call_store_remove (priv->assoc_pcalls, proxy, call_id);
	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't select network config: %s.", err->message);
		emit_error_helper (self, err);
		g_error_free (err);
	}
}

static void
call_select_network (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	DBusGProxyCall *call;

	/* We only select the network after all blobs (if any) have been set */
	if (priv->blobs_left == 0) {
		call = dbus_g_proxy_begin_call (priv->iface_proxy, "SelectNetwork",
		                                select_network_cb,
		                                self,
		                                NULL,
		                                DBUS_TYPE_G_OBJECT_PATH, priv->net_path,
		                                G_TYPE_INVALID);
		nm_call_store_add (priv->assoc_pcalls, priv->iface_proxy, call);
	}
}

static void
add_blob_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GError *err = NULL;
	guint tmp;

	priv->blobs_left--;

	nm_call_store_remove (priv->assoc_pcalls, proxy, call_id);
	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_UINT, &tmp, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't set network certificates: %s.", err->message);
		emit_error_helper (self, err);
		g_error_free (err);
	} else
		call_select_network (self);
}

static void
add_network_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GError *err = NULL;
	GHashTable *blobs;
	GHashTableIter iter;
	gpointer name, data;
	DBusGProxyCall *call;

	g_free (priv->net_path);
	priv->net_path = NULL;

	nm_call_store_remove (priv->assoc_pcalls, proxy, call_id);
	if (!dbus_g_proxy_end_call (proxy, call_id, &err,
	                            DBUS_TYPE_G_OBJECT_PATH, &priv->net_path,
	                            G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't add a network to the supplicant interface: %s.",
		             err->message);
		emit_error_helper (self, err);
		g_error_free (err);
		return;
	}

	/* Send blobs first; otherwise jump to sending the config settings */
	blobs = nm_supplicant_config_get_blobs (priv->cfg);
	priv->blobs_left = g_hash_table_size (blobs);
	g_hash_table_iter_init (&iter, blobs);
	while (g_hash_table_iter_next (&iter, &name, &data)) {
		call = dbus_g_proxy_begin_call (priv->iface_proxy, "AddBlob",
			                            add_blob_cb,
			                            self,
			                            NULL,
			                            DBUS_TYPE_STRING, name,
			                            DBUS_TYPE_G_UCHAR_ARRAY, data,
			                            G_TYPE_INVALID);
		nm_call_store_add (priv->assoc_pcalls, priv->iface_proxy, call);
	}

	call_select_network (self);
}

static void
set_ap_scan_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GError *err = NULL;
	DBusGProxyCall *call;
	GHashTable *config_hash;

	nm_call_store_remove (priv->assoc_pcalls, proxy, call_id);
	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_INVALID)) {
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't send AP scan mode to the supplicant interface: %s.",
		             err->message);
		emit_error_helper (self, err);
		g_error_free (err);
		return;
	}

	nm_log_info (LOGD_SUPPLICANT, "Config: set interface ap_scan to %d",
	             nm_supplicant_config_get_ap_scan (priv->cfg));

	config_hash = nm_supplicant_config_get_hash (priv->cfg);
	call = dbus_g_proxy_begin_call (priv->iface_proxy, "AddNetwork",
	                                add_network_cb,
	                                self,
	                                NULL,
	                                DBUS_TYPE_G_MAP_OF_VARIANT, config_hash,
	                                G_TYPE_INVALID);
	g_hash_table_destroy (config_hash);
	nm_call_store_add (priv->assoc_pcalls, priv->iface_proxy, call);
}

gboolean
nm_supplicant_interface_set_config (NMSupplicantInterface *self,
                                    NMSupplicantConfig *cfg)
{
	NMSupplicantInterfacePrivate *priv;
	DBusGProxyCall *call;
	GValue value = G_VALUE_INIT;

	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	nm_supplicant_interface_disconnect (self);

	/* Make sure the supplicant supports EAP-FAST before trying to send
	 * it an EAP-FAST configuration.
	 */
	if (nm_supplicant_config_fast_required (cfg) && !priv->fast_supported) {
		nm_log_warn (LOGD_SUPPLICANT, "EAP-FAST is not supported by the supplicant");
		return FALSE;
	}

	if (priv->cfg)
		g_object_unref (priv->cfg);
	priv->cfg = cfg;

	if (cfg == NULL)
		return TRUE;

	g_object_ref (priv->cfg);

	g_value_init (&value, G_TYPE_UINT);
	g_value_set_uint (&value, nm_supplicant_config_get_ap_scan (priv->cfg));

	call = dbus_g_proxy_begin_call (priv->props_proxy, "Set",
	                                set_ap_scan_cb,
	                                self,
	                                NULL,
	                                G_TYPE_STRING, WPAS_DBUS_IFACE_INTERFACE,
	                                G_TYPE_STRING, "ApScan",
	                                G_TYPE_VALUE, &value,
	                                G_TYPE_INVALID);
	nm_call_store_add (priv->assoc_pcalls, priv->props_proxy, call);

	g_value_unset (&value);
	return call != NULL;
}

static void
scan_request_cb (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GError *err = NULL;

	nm_call_store_remove (priv->other_pcalls, proxy, call_id);
	if (!dbus_g_proxy_end_call (proxy, call_id, &err, G_TYPE_INVALID))
		nm_log_warn (LOGD_SUPPLICANT, "Could not get scan request result: %s", err->message);

	g_signal_emit (self, signals[SCAN_DONE], 0, err ? FALSE : TRUE);
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

static GValue *
byte_array_array_to_gvalue (const GPtrArray *array)
{
	GValue *val = g_slice_new0 (GValue);

	g_value_init (val, DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR);
	g_value_set_boxed (val, array);
	return val;
}

gboolean
nm_supplicant_interface_request_scan (NMSupplicantInterface *self, const GPtrArray *ssids)
{
	NMSupplicantInterfacePrivate *priv;
	DBusGProxyCall *call;
	GHashTable *hash;

	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Scan parameters */
	hash = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, destroy_gvalue);
	g_hash_table_insert (hash, "Type", string_to_gvalue ("active"));
	if (ssids)
		g_hash_table_insert (hash, "SSIDs", byte_array_array_to_gvalue (ssids));

	call = dbus_g_proxy_begin_call (priv->iface_proxy, "Scan",
	                                scan_request_cb,
	                                self,
	                                NULL,
	                                DBUS_TYPE_G_MAP_OF_VARIANT, hash,
	                                G_TYPE_INVALID);
	g_hash_table_destroy (hash);
	nm_call_store_add (priv->other_pcalls, priv->iface_proxy, call);

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
	case NM_SUPPLICANT_INTERFACE_STATE_DISABLED:
		return "disabled";
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
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->dev;
}

const char *
nm_supplicant_interface_get_object_path (NMSupplicantInterface *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->object_path;
}

const char *
nm_supplicant_interface_get_ifname (NMSupplicantInterface *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->dev;
}

guint
nm_supplicant_interface_get_max_scan_ssids (NMSupplicantInterface *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), 0);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->max_scan_ssids;
}

/*******************************************************************/

NMSupplicantInterface *
nm_supplicant_interface_new (NMSupplicantManager *smgr,
                             const char *ifname,
                             gboolean is_wireless,
                             gboolean fast_supported,
                             ApSupport ap_support,
                             gboolean start_now)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	guint id;

	g_return_val_if_fail (NM_IS_SUPPLICANT_MANAGER (smgr), NULL);
	g_return_val_if_fail (ifname != NULL, NULL);

	self = g_object_new (NM_TYPE_SUPPLICANT_INTERFACE, NULL);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->smgr = g_object_ref (smgr);
	id = g_signal_connect (priv->smgr,
	                       "notify::" NM_SUPPLICANT_MANAGER_AVAILABLE,
	                       G_CALLBACK (smgr_avail_cb),
	                       self);
	priv->smgr_avail_id = id;

	priv->dev = g_strdup (ifname);
	priv->is_wireless = is_wireless;
	priv->fast_supported = fast_supported;
	priv->ap_support = ap_support;

	if (start_now)
		interface_add (self, priv->is_wireless);

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

	priv->bss_proxies = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
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
	nm_call_store_clear (priv->other_pcalls);
	nm_call_store_destroy (priv->other_pcalls);

	nm_call_store_clear (priv->assoc_pcalls);
	nm_call_store_destroy (priv->assoc_pcalls);

	if (priv->props_proxy)
		g_object_unref (priv->props_proxy);

	if (priv->iface_proxy)
		g_object_unref (priv->iface_proxy);

	g_free (priv->net_path);

	if (priv->introspect_proxy)
		g_object_unref (priv->introspect_proxy);

	if (priv->wpas_proxy)
		g_object_unref (priv->wpas_proxy);

	g_hash_table_destroy (priv->bss_proxies);

	if (priv->smgr) {
		if (priv->smgr_avail_id)
			g_signal_handler_disconnect (priv->smgr, priv->smgr_avail_id);
		g_object_unref (priv->smgr);
	}

	g_free (priv->dev);

	priv->dbus_mgr = NULL;

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
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 3, G_TYPE_UINT, G_TYPE_UINT, G_TYPE_INT);

	signals[REMOVED] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	signals[NEW_BSS] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_NEW_BSS,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, new_bss),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_POINTER);

	signals[BSS_UPDATED] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_BSS_UPDATED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, bss_updated),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_POINTER);

	signals[BSS_REMOVED] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_BSS_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, bss_removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_STRING);

	signals[SCAN_DONE] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_SCAN_DONE,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, scan_done),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[CONNECTION_ERROR] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_CONNECTION_ERROR,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, connection_error),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);

	signals[CREDENTIALS_REQUEST] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_CREDENTIALS_REQUEST,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, credentials_request),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);
}

