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

#include "config.h"

#include <stdio.h>
#include <string.h>

#include "nm-default.h"
#include "NetworkManagerUtils.h"
#include "nm-supplicant-interface.h"
#include "nm-supplicant-config.h"
#include "nm-core-internal.h"
#include "nm-dbus-compat.h"

#define WPAS_DBUS_IFACE_INTERFACE   WPAS_DBUS_INTERFACE ".Interface"
#define WPAS_DBUS_IFACE_BSS         WPAS_DBUS_INTERFACE ".BSS"
#define WPAS_DBUS_IFACE_NETWORK	    WPAS_DBUS_INTERFACE ".Network"
#define WPAS_ERROR_INVALID_IFACE    WPAS_DBUS_INTERFACE ".InvalidInterface"
#define WPAS_ERROR_EXISTS_ERROR     WPAS_DBUS_INTERFACE ".InterfaceExists"

G_DEFINE_TYPE (NMSupplicantInterface, nm_supplicant_interface, G_TYPE_OBJECT)

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
	PROP_CURRENT_BSS,
	LAST_PROP
};


typedef struct {
	char *         dev;
	gboolean       is_wireless;
	gboolean       has_credreq;  /* Whether querying 802.1x credentials is supported */
	ApSupport      ap_support;   /* Lightweight AP mode support */
	gboolean       fast_supported;
	guint32        max_scan_ssids;
	guint32        ready_count;

	char *         object_path;
	guint32        state;
	int            disconnect_reason;

	gboolean       scanning;

	GDBusProxy *   wpas_proxy;
	GCancellable * init_cancellable;
	GDBusProxy *   iface_proxy;
	GCancellable * other_cancellable;
	GCancellable * assoc_cancellable;
	char *         net_path;
	guint32        blobs_left;
	GHashTable *   bss_proxies;
	char *         current_bss;

	gint32         last_scan; /* timestamp as returned by nm_utils_get_monotonic_timestamp_s() */

	NMSupplicantConfig *cfg;
} NMSupplicantInterfacePrivate;

/***************************************************************/

static void
emit_error_helper (NMSupplicantInterface *self, GError *error)
{
	char *name = NULL;

	if (g_dbus_error_is_remote_error (error))
		name = g_dbus_error_get_remote_error (error);

	g_signal_emit (self, signals[CONNECTION_ERROR], 0, name, error->message);
	g_free (name);
}

static void
bss_props_changed_cb (GDBusProxy *proxy,
                      GVariant *changed_properties,
                      char **invalidated_properties,
                      gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->scanning)
		priv->last_scan = nm_utils_get_monotonic_timestamp_s ();

	g_signal_emit (self, signals[BSS_UPDATED], 0,
	               g_dbus_proxy_get_object_path (proxy),
	               changed_properties);
}

static GVariant *
_get_bss_proxy_properties (NMSupplicantInterface *self, GDBusProxy *proxy)
{
	gs_strfreev char **properties = NULL;
	GVariantBuilder builder;
	char **iter;

	iter = properties = g_dbus_proxy_get_cached_property_names (proxy);
	if (!iter)
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	while (*iter) {
		GVariant *copy = g_dbus_proxy_get_cached_property (proxy, *iter);

		g_variant_builder_add (&builder, "{sv}", *iter++, copy);
		g_variant_unref (copy);
	}

	return g_variant_builder_end (&builder);
}

#define BSS_PROXY_INITED "bss-proxy-inited"

static void
on_bss_proxy_acquired (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *props = NULL;

	if (!g_async_initable_init_finish (G_ASYNC_INITABLE (proxy), result, &error)) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			nm_log_dbg (LOGD_SUPPLICANT, "Failed to acquire BSS proxy: (%s)", error->message);
			g_hash_table_remove (NM_SUPPLICANT_INTERFACE_GET_PRIVATE (user_data)->bss_proxies,
			                     g_dbus_proxy_get_object_path (proxy));
		}
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	props = _get_bss_proxy_properties (self, proxy);
	if (!props)
		return;

	g_object_set_data (G_OBJECT (proxy), BSS_PROXY_INITED, GUINT_TO_POINTER (TRUE));

	g_signal_emit (self, signals[NEW_BSS], 0,
	               g_dbus_proxy_get_object_path (proxy),
	               g_variant_ref_sink (props));
}

static void
handle_new_bss (NMSupplicantInterface *self, const char *object_path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GDBusProxy *bss_proxy;

	g_return_if_fail (object_path != NULL);

	if (g_hash_table_lookup (priv->bss_proxies, object_path))
		return;

	bss_proxy = g_object_new (G_TYPE_DBUS_PROXY,
	                          "g-bus-type", G_BUS_TYPE_SYSTEM,
	                          "g-flags", G_DBUS_PROXY_FLAGS_NONE,
	                          "g-name", WPAS_DBUS_SERVICE,
	                          "g-object-path", object_path,
	                          "g-interface-name", WPAS_DBUS_IFACE_BSS,
	                          NULL);
	g_hash_table_insert (priv->bss_proxies,
	                     (char *) g_dbus_proxy_get_object_path (bss_proxy),
	                     bss_proxy);
	g_signal_connect (bss_proxy, "g-properties-changed", G_CALLBACK (bss_props_changed_cb), self);
	g_async_initable_init_async (G_ASYNC_INITABLE (bss_proxy),
	                             G_PRIORITY_DEFAULT,
	                             priv->other_cancellable,
	                             (GAsyncReadyCallback) on_bss_proxy_acquired,
	                             self);
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
		if (priv->other_cancellable) {
			g_warn_if_fail (priv->other_cancellable == NULL);
			g_cancellable_cancel (priv->other_cancellable);
			g_clear_object (&priv->other_cancellable);
		}
		priv->other_cancellable = g_cancellable_new ();
	} else if (new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		if (priv->init_cancellable)
			g_cancellable_cancel (priv->init_cancellable);
		g_clear_object (&priv->init_cancellable);

		if (priv->other_cancellable)
			g_cancellable_cancel (priv->other_cancellable);
		g_clear_object (&priv->other_cancellable);

		if (priv->iface_proxy)
			g_signal_handlers_disconnect_by_data (priv->iface_proxy, self);
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

const char *
nm_supplicant_interface_get_current_bss (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_val_if_fail (self != NULL, FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	return priv->state >= NM_SUPPLICANT_INTERFACE_STATE_READY ? priv->current_bss : NULL;
}

gint32
nm_supplicant_interface_get_last_scan_time (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->last_scan;
}

#define MATCH_PROPERTY(p, n, v, t) (!strcmp (p, n) && g_variant_is_of_type (v, t))

static void
parse_capabilities (NMSupplicantInterface *self, GVariant *capabilities)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gboolean have_active = FALSE, have_ssid = FALSE;
	gint32 max_scan_ssids = -1;
	const char **array;

	g_return_if_fail (capabilities && g_variant_is_of_type (capabilities, G_VARIANT_TYPE_VARDICT));

	if (g_variant_lookup (capabilities, "Scan", "^a&s", &array)) {
		if (_nm_utils_string_in_list ("active", array))
			have_active = TRUE;
		if (_nm_utils_string_in_list ("ssid", array))
			have_ssid = TRUE;
		g_free (array);
	}

	if (g_variant_lookup (capabilities, "MaxScanSSID", "i", &max_scan_ssids)) {
		/* We need active scan and SSID probe capabilities to care about MaxScanSSIDs */
		if (max_scan_ssids > 0 && have_active && have_ssid) {
			/* wpa_supplicant's WPAS_MAX_SCAN_SSIDS value is 16, but for speed
			 * and to ensure we don't disclose too many SSIDs from the hidden
			 * list, we'll limit to 5.
			 */
			priv->max_scan_ssids = CLAMP (max_scan_ssids, 0, 5);
			nm_log_info (LOGD_SUPPLICANT, "(%s) supports %d scan SSIDs",
				         priv->dev, priv->max_scan_ssids);
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

gboolean
nm_supplicant_interface_credentials_reply (NMSupplicantInterface *self,
                                           const char *field,
                                           const char *value,
                                           GError **error)
{
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *reply = NULL;

	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);
	g_return_val_if_fail (field != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	g_return_val_if_fail (priv->has_credreq == TRUE, FALSE);

	/* Need a network block object path */
	g_return_val_if_fail (priv->net_path, FALSE);
	reply = g_dbus_proxy_call_sync (priv->iface_proxy,
	                                "NetworkReply",
	                                g_variant_new ("(oss)",
	                                               priv->net_path,
	                                               field,
	                                               value),
	                                G_DBUS_CALL_FLAGS_NONE,
	                                5000,
	                                NULL,
	                                error);
	if (error && *error)
		g_dbus_error_strip_remote_error (*error);

	return !!reply;
}

static void
iface_check_netreply_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;

	/* We know NetworkReply is supported if the NetworkReply method returned
	 * successfully (which is unexpected since we sent a bogus network
	 * object path) or if we got an "InvalidArgs" (which indicates NetworkReply
	 * is supported).  We know it's not supported if we get an
	 * "UnknownMethod" error.
	 */

	variant = g_dbus_proxy_call_finish (proxy, result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (variant || _nm_dbus_error_has_name (error, "fi.w1.wpa_supplicant1.InvalidArgs"))
		priv->has_credreq = TRUE;

	nm_log_dbg (LOGD_SUPPLICANT, "Supplicant %s network credentials requests",
	            priv->has_credreq ? "supports" : "does not support");

	iface_check_ready (self);
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
iface_check_ap_mode_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;
	const char *data;

	/* The ProbeRequest method only exists if AP mode has been enabled */
	variant = _nm_dbus_proxy_call_finish (proxy, result,
	                                      G_VARIANT_TYPE ("(s)"),
	                                      &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (variant) {
		g_variant_get (variant, "(&s)", &data);
		if (strstr (data, "ProbeRequest"))
			priv->ap_support = AP_SUPPORT_YES;
	}

	iface_check_ready (self);
}

static void
wpas_iface_scan_done (GDBusProxy *proxy,
                      gboolean success,
                      gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GVariant *props;
	GHashTableIter iter;
	char *bss_path;
	GDBusProxy *bss_proxy;

	/* Cache last scan completed time */
	priv->last_scan = nm_utils_get_monotonic_timestamp_s ();

	g_signal_emit (self, signals[SCAN_DONE], 0, success);

	/* Emit NEW_BSS so that wifi device has the APs (in case it removed them) */
	g_hash_table_iter_init (&iter, priv->bss_proxies);
	while (g_hash_table_iter_next (&iter, (gpointer) &bss_path, (gpointer) &bss_proxy)) {
		if (g_object_get_data (G_OBJECT (bss_proxy), BSS_PROXY_INITED)) {
			props = _get_bss_proxy_properties (self, bss_proxy);
			if (props) {
				g_signal_emit (self, signals[NEW_BSS], 0,
				               bss_path,
				               g_variant_ref_sink (props));
				g_variant_unref (props);
			}
		}
	}
}

static void
wpas_iface_bss_added (GDBusProxy *proxy,
                      const char *path,
                      GVariant *props,
                      gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->scanning)
		priv->last_scan = nm_utils_get_monotonic_timestamp_s ();

	handle_new_bss (self, path);
}

static void
wpas_iface_bss_removed (GDBusProxy *proxy,
                        const char *path,
                        gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_signal_emit (self, signals[BSS_REMOVED], 0, path);
	g_hash_table_remove (priv->bss_proxies, path);
}

static void
wpas_iface_network_request (GDBusProxy *proxy,
                            const char *path,
                            const char *field,
                            const char *message,
                            gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->has_credreq && priv->net_path && !g_strcmp0 (path, priv->net_path))
		g_signal_emit (self, signals[CREDENTIALS_REQUEST], 0, field, message);
}

static void
props_changed_cb (GDBusProxy *proxy,
                  GVariant *changed_properties,
                  GStrv invalidated_properties,
                  gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	const char *s, **array, **iter;
	gboolean b = FALSE;
	gint32 i32;
	GVariant *v;

	g_object_freeze_notify (G_OBJECT (self));

	if (g_variant_lookup (changed_properties, "Scanning", "b", &b))
		set_scanning (self, b);

	if (   g_variant_lookup (changed_properties, "State", "&s", &s)
	    && priv->state >= NM_SUPPLICANT_INTERFACE_STATE_READY) {
		/* Only transition to actual wpa_supplicant interface states (ie,
		 * anything > READY) after the NMSupplicantInterface has had a
		 * chance to initialize, which is signalled by entering the READY
		 * state.
		 */
		set_state_from_string (self, s);
	}

	if (g_variant_lookup (changed_properties, "BSSs", "^a&o", &array)) {
		iter = array;
		while (*iter)
			handle_new_bss (self, *iter++);
		g_free (array);
	}

	if (g_variant_lookup (changed_properties, "CurrentBSS", "&o", &s)) {
		if (strcmp (s, "/") == 0)
			s = NULL;
		if (g_strcmp0 (s, priv->current_bss) != 0) {
			g_free (priv->current_bss);
			priv->current_bss = g_strdup (s);
			g_object_notify (G_OBJECT (self), NM_SUPPLICANT_INTERFACE_CURRENT_BSS);
		}
	}

	v = g_variant_lookup_value (changed_properties, "Capabilities", G_VARIANT_TYPE_VARDICT);
	if (v) {
		parse_capabilities (self, v);
		g_variant_unref (v);
	}

	if (g_variant_lookup (changed_properties, "DisconnectReason", "i", &i32)) {
		/* Disconnect reason is currently only given for deauthentication events,
		 * not disassociation; currently they are IEEE 802.11 "reason codes",
		 * defined by (IEEE 802.11-2007, 7.3.1.7, Table 7-22).  Any locally caused
		 * deauthentication will be negative, while authentications caused by the
		 * AP will be positive.
		 */
		priv->disconnect_reason = i32;
		if (priv->disconnect_reason != 0) {
			nm_log_warn (LOGD_SUPPLICANT, "Connection disconnected (reason %d)",
				         priv->disconnect_reason);
		}
	}

	g_object_thaw_notify (G_OBJECT (self));
}

static void
on_iface_proxy_acquired (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_free_error GError *error = NULL;

	if (!g_async_initable_init_finish (G_ASYNC_INITABLE (proxy), result, &error)) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			nm_log_warn (LOGD_SUPPLICANT, "Failed to acquire wpa_supplicant interface proxy: (%s)", error->message);
			set_state (NM_SUPPLICANT_INTERFACE (user_data), NM_SUPPLICANT_INTERFACE_STATE_DOWN);
		}
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	_nm_dbus_signal_connect (priv->iface_proxy, "ScanDone", G_VARIANT_TYPE ("(b)"),
	                         G_CALLBACK (wpas_iface_scan_done), self);
	_nm_dbus_signal_connect (priv->iface_proxy, "BSSAdded", G_VARIANT_TYPE ("(oa{sv})"),
	                         G_CALLBACK (wpas_iface_bss_added), self);
	_nm_dbus_signal_connect (priv->iface_proxy, "BSSRemoved", G_VARIANT_TYPE ("(o)"),
	                         G_CALLBACK (wpas_iface_bss_removed), self);
	_nm_dbus_signal_connect (priv->iface_proxy, "NetworkRequest", G_VARIANT_TYPE ("(oss)"),
	                         G_CALLBACK (wpas_iface_network_request), self);

	/* Scan result aging parameters */
	g_dbus_proxy_call (priv->iface_proxy,
	                   "org.freedesktop.DBus.Properties.Set",
	                   g_variant_new ("(ssv)",
	                                  WPAS_DBUS_IFACE_INTERFACE,
	                                  "BSSExpireAge",
	                                  g_variant_new_uint32 (250)),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->init_cancellable,
	                   NULL,
	                   NULL);
	g_dbus_proxy_call (priv->iface_proxy,
	                   "org.freedesktop.DBus.Properties.Set",
	                   g_variant_new ("(ssv)",
	                                  WPAS_DBUS_IFACE_INTERFACE,
	                                  "BSSExpireCount",
	                                  g_variant_new_uint32 (2)),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->init_cancellable,
	                   NULL,
	                   NULL);

	/* Check whether NetworkReply and AP mode are supported */
	priv->ready_count = 1;
	g_dbus_proxy_call (priv->iface_proxy,
	                   "NetworkReply",
	                   g_variant_new ("(oss)",
	                                  "/fff",
	                                  "foobar",
	                                  "foobar"),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->init_cancellable,
	                   (GAsyncReadyCallback) iface_check_netreply_cb,
	                   self);

	if (priv->ap_support == AP_SUPPORT_UNKNOWN) {
		/* If the global supplicant capabilities property is not present, we can
		 * fall back to checking whether the ProbeRequest method is supported.  If
		 * neither of these works we have no way of determining if AP mode is
		 * supported or not.  hostap 1.0 and earlier don't support either of these.
		 */
		priv->ready_count++;
		g_dbus_proxy_call (priv->iface_proxy,
		                   DBUS_INTERFACE_INTROSPECTABLE ".Introspect",
		                   NULL,
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->init_cancellable,
		                   (GAsyncReadyCallback) iface_check_ap_mode_cb,
		                   self);
	}
}

static void
interface_add_done (NMSupplicantInterface *self, const char *path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	nm_log_dbg (LOGD_SUPPLICANT, "(%s): interface added to supplicant", priv->dev);

	priv->object_path = g_strdup (path);
	priv->iface_proxy = g_object_new (G_TYPE_DBUS_PROXY,
	                                  "g-bus-type", G_BUS_TYPE_SYSTEM,
	                                  "g-flags", G_DBUS_PROXY_FLAGS_NONE,
	                                  "g-name", WPAS_DBUS_SERVICE,
	                                  "g-object-path", priv->object_path,
	                                  "g-interface-name", WPAS_DBUS_IFACE_INTERFACE,
	                                  NULL);
	g_signal_connect (priv->iface_proxy, "g-properties-changed", G_CALLBACK (props_changed_cb), self);
	g_async_initable_init_async (G_ASYNC_INITABLE (priv->iface_proxy),
	                             G_PRIORITY_DEFAULT,
	                             priv->init_cancellable,
	                             (GAsyncReadyCallback) on_iface_proxy_acquired,
	                             self);
}

static void
interface_get_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;
	const char *path;

	variant = _nm_dbus_proxy_call_finish (proxy, result,
	                                      G_VARIANT_TYPE ("(o)"),
	                                      &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (variant) {
		g_variant_get (variant, "(&o)", &path);
		interface_add_done (self, path);
	} else {
		g_dbus_error_strip_remote_error (error);
		nm_log_err (LOGD_SUPPLICANT, "(%s): error getting interface: %s", priv->dev, error->message);
		set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
	}
}

static void
interface_add_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *variant = NULL;
	const char *path;

	variant = _nm_dbus_proxy_call_finish (proxy, result,
	                                      G_VARIANT_TYPE ("(o)"),
	                                      &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (variant) {
		g_variant_get (variant, "(&o)", &path);
		interface_add_done (self, path);
	} else if (_nm_dbus_error_has_name (error, WPAS_ERROR_EXISTS_ERROR)) {
		/* Interface already added, just get its object path */
		g_dbus_proxy_call (priv->wpas_proxy,
		                   "GetInterface",
		                   g_variant_new ("(s)", priv->dev),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->init_cancellable,
		                   (GAsyncReadyCallback) interface_get_cb,
		                   self);
	} else if (   g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SERVICE_UNKNOWN)
	           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_EXEC_FAILED)
	           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_FORK_FAILED)
	           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_FAILED)
	           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_TIMEOUT)
	           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_NO_REPLY)
	           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_TIMED_OUT)
	           || g_error_matches (error, G_DBUS_ERROR, G_DBUS_ERROR_SPAWN_SERVICE_NOT_FOUND)) {
		/* Supplicant wasn't running and could not be launched via service
		 * activation.  Wait for it to start by moving back to the INIT
		 * state.
		 */
		g_dbus_error_strip_remote_error (error);
		nm_log_dbg (LOGD_SUPPLICANT, "(%s): failed to activate supplicant: %s",
		            priv->dev, error->message);
		set_state (self, NM_SUPPLICANT_INTERFACE_STATE_INIT);
	} else {
		g_dbus_error_strip_remote_error (error);
		nm_log_err (LOGD_SUPPLICANT, "(%s): error adding interface: %s", priv->dev, error->message);
		set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
	}
}

#if HAVE_WEXT
#define DEFAULT_WIFI_DRIVER "nl80211,wext"
#else
#define DEFAULT_WIFI_DRIVER "nl80211"
#endif

static void
on_wpas_proxy_acquired (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *wpas_proxy;
	GVariantBuilder props;

	wpas_proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (!wpas_proxy) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			nm_log_warn (LOGD_SUPPLICANT, "Failed to acquire wpa_supplicant proxy: (%s)",
			             error ? error->message : "unknown");
			set_state (NM_SUPPLICANT_INTERFACE (user_data), NM_SUPPLICANT_INTERFACE_STATE_DOWN);
		}
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->wpas_proxy = wpas_proxy;

	/* Try to add the interface to the supplicant.  If the supplicant isn't
	 * running, this will start it via D-Bus activation and return the response
	 * when the supplicant has started.
	 */

	g_variant_builder_init (&props, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&props, "{sv}",
	                       "Driver",
	                       g_variant_new_string (priv->is_wireless ? DEFAULT_WIFI_DRIVER : "wired"));
	g_variant_builder_add (&props, "{sv}",
	                       "Ifname",
	                       g_variant_new_string (priv->dev));

	g_dbus_proxy_call (priv->wpas_proxy,
	                   "CreateInterface",
	                   g_variant_new ("(a{sv})", &props),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->init_cancellable,
	                   (GAsyncReadyCallback) interface_add_cb,
	                   self);
}

static void
interface_add (NMSupplicantInterface *self, gboolean is_wireless)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Can only start the interface from INIT state */
	g_return_if_fail (priv->state == NM_SUPPLICANT_INTERFACE_STATE_INIT);

	nm_log_dbg (LOGD_SUPPLICANT, "(%s): adding interface to supplicant", priv->dev);

	priv->is_wireless = is_wireless;

	/* Move to starting to prevent double-calls of interface_add() */
	set_state (self, NM_SUPPLICANT_INTERFACE_STATE_STARTING);

	g_warn_if_fail (priv->init_cancellable == NULL);
	g_clear_object (&priv->init_cancellable);
	priv->init_cancellable = g_cancellable_new ();

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                            G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                          NULL,
	                          WPAS_DBUS_SERVICE,
	                          WPAS_DBUS_PATH,
	                          WPAS_DBUS_INTERFACE,
	                          priv->init_cancellable,
	                          (GAsyncReadyCallback) on_wpas_proxy_acquired,
	                          self);
}

void
nm_supplicant_interface_set_supplicant_available (NMSupplicantInterface *self,
                                                  gboolean available)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (available) {
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
log_result_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &error);
	if (   !reply
	    && !g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)
	    && !strstr (error->message, "fi.w1.wpa_supplicant1.NotConnected")) {
		g_dbus_error_strip_remote_error (error);
		nm_log_warn (LOGD_SUPPLICANT, "Failed to %s: %s.", (char *) user_data, error->message);
	}
}

void
nm_supplicant_interface_disconnect (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Cancel all pending calls related to a prior connection attempt */
	if (priv->assoc_cancellable) {
		g_cancellable_cancel (priv->assoc_cancellable);
		g_clear_object (&priv->assoc_cancellable);
	}

	/* Don't do anything if there is no connection to the supplicant yet. */
	if (!priv->iface_proxy)
		return;

	/* Disconnect from the current AP */
	if (   (priv->state >= NM_SUPPLICANT_INTERFACE_STATE_SCANNING)
	    && (priv->state <= NM_SUPPLICANT_INTERFACE_STATE_COMPLETED)) {
		g_dbus_proxy_call (priv->iface_proxy,
		                   "Disconnect",
		                   NULL,
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   NULL,
		                   (GAsyncReadyCallback) log_result_cb,
		                   "disconnect");
	}

	/* Remove any network that was added by NetworkManager */
	if (priv->net_path) {
		g_dbus_proxy_call (priv->iface_proxy,
		                   "RemoveNetwork",
		                   g_variant_new ("(o)", priv->net_path),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->other_cancellable,
		                   (GAsyncReadyCallback) log_result_cb,
		                   "remove network");
		g_free (priv->net_path);
		priv->net_path = NULL;
	}
}

static void
select_network_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *err = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &err);
	if (!reply && !g_error_matches (err, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		g_dbus_error_strip_remote_error (err);
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't select network config: %s.", err->message);
		emit_error_helper (NM_SUPPLICANT_INTERFACE (user_data), err);
	}
}

static void
call_select_network (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* We only select the network after all blobs (if any) have been set */
	if (priv->blobs_left == 0) {
		g_dbus_proxy_call (priv->iface_proxy,
		                   "SelectNetwork",
		                   g_variant_new ("(o)", priv->net_path),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->assoc_cancellable,
		                   (GAsyncReadyCallback) select_network_cb,
		                   self);
	}
}

static void
add_blob_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *err = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &err);
	if (g_error_matches (err, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->blobs_left--;
	if (reply)
		call_select_network (self);
	else {
		g_dbus_error_strip_remote_error (err);
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't set network certificates: %s.", err->message);
		emit_error_helper (self, err);
	}
}

static void
add_network_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;
	GHashTable *blobs;
	GHashTableIter iter;
	const char *blob_name;
	GByteArray *blob_data;

	reply = _nm_dbus_proxy_call_finish (proxy, result,
	                                    G_VARIANT_TYPE ("(o)"),
	                                    &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_free (priv->net_path);
	priv->net_path = NULL;

	if (error) {
		g_dbus_error_strip_remote_error (error);
		nm_log_warn (LOGD_SUPPLICANT, "Adding network to supplicant failed: %s.", error->message);
		emit_error_helper (self, error);
		return;
	}

	g_variant_get (reply, "(o)", &priv->net_path);

	/* Send blobs first; otherwise jump to selecting the network */
	blobs = nm_supplicant_config_get_blobs (priv->cfg);
	priv->blobs_left = g_hash_table_size (blobs);

	g_hash_table_iter_init (&iter, blobs);
	while (g_hash_table_iter_next (&iter, (gpointer) &blob_name, (gpointer) &blob_data)) {
		g_dbus_proxy_call (priv->iface_proxy,
		                   "AddBlob",
		                   g_variant_new ("(s@ay)",
		                                  blob_name,
		                                  g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                                             blob_data->data, blob_data->len, 1)),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->assoc_cancellable,
		                   (GAsyncReadyCallback) add_blob_cb,
		                   self);
	}

	call_select_network (self);
}

static void
set_ap_scan_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (!reply) {
		g_dbus_error_strip_remote_error (error);
		nm_log_warn (LOGD_SUPPLICANT, "Couldn't send AP scan mode to the supplicant interface: %s.",
		             error->message);
		emit_error_helper (self, error);
		return;
	}

	nm_log_info (LOGD_SUPPLICANT, "Config: set interface ap_scan to %d",
	             nm_supplicant_config_get_ap_scan (priv->cfg));

	g_dbus_proxy_call (priv->iface_proxy,
	                   "AddNetwork",
	                   g_variant_new ("(@a{sv})", nm_supplicant_config_to_variant (priv->cfg)),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->assoc_cancellable,
	                   (GAsyncReadyCallback) add_network_cb,
	                   self);
}

gboolean
nm_supplicant_interface_set_config (NMSupplicantInterface *self,
                                    NMSupplicantConfig *cfg)
{
	NMSupplicantInterfacePrivate *priv;

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

	g_clear_object (&priv->cfg);
	if (cfg) {
		priv->cfg = g_object_ref (cfg);
		g_dbus_proxy_call (priv->iface_proxy,
		                   DBUS_INTERFACE_PROPERTIES ".Set",
		                   g_variant_new ("(ssv)",
		                                  WPAS_DBUS_IFACE_INTERFACE,
		                                  "ApScan",
		                                  g_variant_new_uint32 (nm_supplicant_config_get_ap_scan (priv->cfg))),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->assoc_cancellable,
		                   (GAsyncReadyCallback) set_ap_scan_cb,
		                   self);
	}
	return TRUE;
}

static void
scan_request_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	if (error) {
		if (_nm_dbus_error_has_name (error, "fi.w1.wpa_supplicant1.Interface.ScanError"))
			nm_log_dbg (LOGD_SUPPLICANT, "Could not get scan request result: %s", error->message);
		else {
			g_dbus_error_strip_remote_error (error);
			nm_log_warn (LOGD_SUPPLICANT, "Could not get scan request result: %s", error->message);
		}
	}
	g_signal_emit (NM_SUPPLICANT_INTERFACE (user_data), signals[SCAN_DONE], 0, error ? FALSE : TRUE);
}

gboolean
nm_supplicant_interface_request_scan (NMSupplicantInterface *self, const GPtrArray *ssids)
{
	NMSupplicantInterfacePrivate *priv;
	GVariantBuilder builder;
	guint i;

	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Scan parameters */
	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&builder, "{sv}", "Type", g_variant_new_string ("active"));
	if (ssids) {
		GVariantBuilder ssids_builder;

		g_variant_builder_init (&ssids_builder, G_VARIANT_TYPE_BYTESTRING_ARRAY);
		for (i = 0; i < ssids->len; i++) {
			GByteArray *ssid = g_ptr_array_index (ssids, i);
			g_variant_builder_add (&ssids_builder, "@ay",
			                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
			                                                  ssid->data, ssid->len, 1));
		}
		g_variant_builder_add (&builder, "{sv}", "SSIDs", g_variant_builder_end (&ssids_builder));
	}

	g_dbus_proxy_call (priv->iface_proxy,
	                   "Scan",
	                   g_variant_new ("(a{sv})", &builder),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->other_cancellable,
	                   (GAsyncReadyCallback) scan_request_cb,
	                   self);
	return TRUE;
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
nm_supplicant_interface_new (const char *ifname,
                             gboolean is_wireless,
                             gboolean fast_supported,
                             ApSupport ap_support,
                             gboolean start_now)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;

	g_return_val_if_fail (ifname != NULL, NULL);

	self = g_object_new (NM_TYPE_SUPPLICANT_INTERFACE, NULL);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

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

	priv->state = NM_SUPPLICANT_INTERFACE_STATE_INIT;
	priv->bss_proxies = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, g_object_unref);
}

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
}

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SCANNING:
		g_value_set_boolean (value, priv->scanning);
		break;
	case PROP_CURRENT_BSS:
		g_value_set_string (value, priv->current_bss);
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

	if (priv->iface_proxy)
		g_signal_handlers_disconnect_by_data (priv->iface_proxy, NM_SUPPLICANT_INTERFACE (object));
	g_clear_object (&priv->iface_proxy);

	if (priv->init_cancellable)
		g_cancellable_cancel (priv->init_cancellable);
	g_clear_object (&priv->init_cancellable);

	if (priv->other_cancellable)
		g_cancellable_cancel (priv->other_cancellable);
	g_clear_object (&priv->other_cancellable);

	g_clear_object (&priv->wpas_proxy);
	g_clear_pointer (&priv->bss_proxies, (GDestroyNotify) g_hash_table_destroy);

	g_clear_pointer (&priv->net_path, g_free);
	g_clear_pointer (&priv->dev, g_free);
	g_clear_pointer (&priv->object_path, g_free);
	g_clear_pointer (&priv->current_bss, g_free);

	g_clear_object (&priv->cfg);

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
	g_object_class_install_property
		(object_class, PROP_SCANNING,
		 g_param_spec_boolean ("scanning", "", "",
		                       FALSE,
		                       G_PARAM_READABLE |
		                       G_PARAM_STATIC_STRINGS));

	g_object_class_install_property
		(object_class, PROP_CURRENT_BSS,
		 g_param_spec_string (NM_SUPPLICANT_INTERFACE_CURRENT_BSS, "", "",
		                      NULL,
		                      G_PARAM_READABLE |
		                      G_PARAM_STATIC_STRINGS));

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
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_VARIANT);

	signals[BSS_UPDATED] =
		g_signal_new (NM_SUPPLICANT_INTERFACE_BSS_UPDATED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_LAST,
		              G_STRUCT_OFFSET (NMSupplicantInterfaceClass, bss_updated),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_VARIANT);

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

