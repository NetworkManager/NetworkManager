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

#include "nm-default.h"

#include "nm-supplicant-interface.h"

#include <stdio.h>
#include <string.h>

#include "NetworkManagerUtils.h"
#include "nm-supplicant-config.h"
#include "nm-core-internal.h"
#include "nm-dbus-compat.h"

#define WPAS_DBUS_IFACE_INTERFACE   WPAS_DBUS_INTERFACE ".Interface"
#define WPAS_DBUS_IFACE_BSS         WPAS_DBUS_INTERFACE ".BSS"
#define WPAS_DBUS_IFACE_NETWORK	    WPAS_DBUS_INTERFACE ".Network"
#define WPAS_ERROR_INVALID_IFACE    WPAS_DBUS_INTERFACE ".InvalidInterface"
#define WPAS_ERROR_EXISTS_ERROR     WPAS_DBUS_INTERFACE ".InterfaceExists"

/*****************************************************************************/

typedef struct {
	GDBusProxy *proxy;
	gulong change_id;
} BssData;

struct _AddNetworkData;

typedef struct {
	NMSupplicantInterface *self;
	NMSupplicantConfig *cfg;
	GCancellable *cancellable;
	NMSupplicantInterfaceAssocCb callback;
	gpointer user_data;
	guint fail_on_idle_id;
	guint blobs_left;
	struct _AddNetworkData *add_network_data;
} AssocData;

typedef struct _AddNetworkData {
	/* the assoc_data at the time when doing the call. */
	AssocData *assoc_data;
} AddNetworkData;

enum {
	STATE,               /* change in the interface's state */
	REMOVED,             /* interface was removed by the supplicant */
	BSS_UPDATED,         /* a new BSS appeared or an existing had properties changed */
	BSS_REMOVED,         /* supplicant removed BSS from its scan list */
	SCAN_DONE,           /* wifi scan is complete */
	CREDENTIALS_REQUEST, /* 802.1x identity or password requested */
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

NM_GOBJECT_PROPERTIES_DEFINE (NMSupplicantInterface,
	PROP_IFACE,
	PROP_SCANNING,
	PROP_CURRENT_BSS,
	PROP_DRIVER,
	PROP_FAST_SUPPORT,
	PROP_AP_SUPPORT,
);

typedef struct {
	char *         dev;
	NMSupplicantDriver driver;
	gboolean       has_credreq;  /* Whether querying 802.1x credentials is supported */
	NMSupplicantFeature fast_support;
	NMSupplicantFeature ap_support;   /* Lightweight AP mode support */
	guint32        max_scan_ssids;
	guint32        ready_count;

	char *         object_path;
	NMSupplicantInterfaceState state;
	int            disconnect_reason;

	gboolean       scanning:1;

	bool           scan_done_pending:1;
	bool           scan_done_success:1;

	GDBusProxy *   wpas_proxy;
	GCancellable * init_cancellable;
	GDBusProxy *   iface_proxy;
	GCancellable * other_cancellable;

	AssocData *    assoc_data;

	char *         net_path;
	GHashTable *   bss_proxies;
	char *         current_bss;

	gint32         last_scan; /* timestamp as returned by nm_utils_get_monotonic_timestamp_s() */

} NMSupplicantInterfacePrivate;

struct _NMSupplicantInterface {
	GObject parent;
	NMSupplicantInterfacePrivate _priv;
};

struct _NMSupplicantInterfaceClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMSupplicantInterface, nm_supplicant_interface, G_TYPE_OBJECT)

#define NM_SUPPLICANT_INTERFACE_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSupplicantInterface, NM_IS_SUPPLICANT_INTERFACE)

/*****************************************************************************/

#define _NMLOG_DOMAIN           LOGD_SUPPLICANT
#define _NMLOG_PREFIX_NAME      "sup-iface"
#define _NMLOG(level, ...) \
    G_STMT_START { \
         char _sbuf[64]; \
         \
         nm_log ((level), _NMLOG_DOMAIN, \
                 "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                 _NMLOG_PREFIX_NAME, \
                 ((self) \
                      ? nm_sprintf_buf (_sbuf, \
                                        "[%p,%s]", \
                                        (self), \
                                        NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->dev) \
                      : "") \
                 _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

static void scan_done_emit_signal (NMSupplicantInterface *self);

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE (nm_supplicant_interface_state_to_string, NMSupplicantInterfaceState,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_INVALID,         "invalid"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_INIT,            "init"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_STARTING,        "starting"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_READY,           "ready"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_DISABLED,        "disabled"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED,    "disconnected"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_INACTIVE,        "inactive"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_SCANNING,        "scanning"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING,  "authenticating"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING,     "associating"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED,      "associated"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE,  "4-way handshake"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE, "group handshake"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_COMPLETED,       "completed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_DOWN,            "down"),
);

/*****************************************************************************/

static void
bss_data_destroy (gpointer user_data)
{
	BssData *bss_data = user_data;

	nm_clear_g_signal_handler (bss_data->proxy, &bss_data->change_id);
	g_object_unref (bss_data->proxy);
	g_slice_free (BssData, bss_data);
}

static void
bss_proxy_properties_changed_cb (GDBusProxy *proxy,
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
bss_proxy_get_properties (NMSupplicantInterface *self, GDBusProxy *proxy)
{
	gs_strfreev char **properties = NULL;
	GVariantBuilder builder;
	char **iter;

	iter = properties = g_dbus_proxy_get_cached_property_names (proxy);

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));
	if (iter) {
		while (*iter) {
			GVariant *copy = g_dbus_proxy_get_cached_property (proxy, *iter);

			g_variant_builder_add (&builder, "{sv}", *iter++, copy);
			g_variant_unref (copy);
		}
	}
	return g_variant_builder_end (&builder);
}

#define BSS_PROXY_INITED "bss-proxy-inited"

static void
bss_proxy_acquired_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_free_error GError *error = NULL;
	GVariant *props = NULL;
	const char *object_path;
	BssData *bss_data;

	g_async_initable_init_finish (G_ASYNC_INITABLE (proxy), result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (error) {
		_LOGD ("failed to acquire BSS proxy: (%s)", error->message);
		g_hash_table_remove (priv->bss_proxies,
		                     g_dbus_proxy_get_object_path (proxy));
		return;
	}

	object_path = g_dbus_proxy_get_object_path (proxy);
	bss_data = g_hash_table_lookup (priv->bss_proxies, object_path);
	if (!bss_data)
		return;

	bss_data->change_id = g_signal_connect (proxy, "g-properties-changed", G_CALLBACK (bss_proxy_properties_changed_cb), self);

	props = bss_proxy_get_properties (self, proxy);
	g_signal_emit (self, signals[BSS_UPDATED], 0,
	               g_dbus_proxy_get_object_path (proxy),
	               g_variant_ref_sink (props));
	g_variant_unref (props);

	if (priv->scan_done_pending)
		scan_done_emit_signal (self);
}

static void
bss_add_new (NMSupplicantInterface *self, const char *object_path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GDBusProxy *bss_proxy;
	BssData *bss_data;

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
	bss_data = g_slice_new0 (BssData);
	bss_data->proxy = bss_proxy;
	g_hash_table_insert (priv->bss_proxies,
	                     (char *) g_dbus_proxy_get_object_path (bss_proxy),
	                     bss_data);
	g_async_initable_init_async (G_ASYNC_INITABLE (bss_proxy),
	                             G_PRIORITY_DEFAULT,
	                             priv->other_cancellable,
	                             (GAsyncReadyCallback) bss_proxy_acquired_cb,
	                             self);
}

/*****************************************************************************/

static void
set_state (NMSupplicantInterface *self, NMSupplicantInterfaceState new_state)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantInterfaceState old_state = priv->state;

	if (new_state == priv->state)
		return;

	/* DOWN is a terminal state */
	g_return_if_fail (priv->state != NM_SUPPLICANT_INTERFACE_STATE_DOWN);

	/* Cannot regress to READY, STARTING, or INIT from higher states */
	if (priv->state >= NM_SUPPLICANT_INTERFACE_STATE_READY)
		g_return_if_fail (new_state > NM_SUPPLICANT_INTERFACE_STATE_READY);

	if (new_state == NM_SUPPLICANT_INTERFACE_STATE_READY) {
		nm_clear_g_cancellable (&priv->other_cancellable);
		priv->other_cancellable = g_cancellable_new ();
	} else if (new_state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
		nm_clear_g_cancellable (&priv->init_cancellable);
		nm_clear_g_cancellable (&priv->other_cancellable);

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
	               (int) priv->state,
	               (int) old_state,
	               (int) priv->disconnect_reason);
}

static NMSupplicantInterfaceState
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

	return NM_SUPPLICANT_INTERFACE_STATE_INVALID;
}

static void
set_state_from_string (NMSupplicantInterface *self, const char *new_state)
{
	NMSupplicantInterfaceState state;

	state = wpas_state_string_to_enum (new_state);
	if (state == NM_SUPPLICANT_INTERFACE_STATE_INVALID) {
		_LOGW ("unknown supplicant state '%s'", new_state);
		return;
	}
	set_state (self, state);
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

		_notify (self, PROP_SCANNING);
	}
}

gboolean
nm_supplicant_interface_get_scanning (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_val_if_fail (self, FALSE);

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

	if (   g_variant_lookup (capabilities, "Scan", "^a&s", &array)
	    && array) {
		if (g_strv_contains (array, "active"))
			have_active = TRUE;
		if (g_strv_contains (array, "ssid"))
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
			_LOGI ("supports %d scan SSIDs", priv->max_scan_ssids);
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

	_LOGD ("supplicant %s network credentials requests",
	       priv->has_credreq ? "supports" : "does not support");

	iface_check_ready (self);
}

NMSupplicantFeature
nm_supplicant_interface_get_ap_support (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->ap_support;
}

void
nm_supplicant_interface_set_ap_support (NMSupplicantInterface *self,
                                        NMSupplicantFeature ap_support)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Use the best indicator of support between the supplicant global
	 * Capabilities property and the interface's introspection data.
	 */
	if (ap_support > priv->ap_support)
		priv->ap_support = ap_support;
}

void
nm_supplicant_interface_set_fast_support (NMSupplicantInterface *self,
                                          NMSupplicantFeature fast_support)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->fast_support = fast_support;
}

static void
iface_introspect_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;
	const char *data;

	variant = _nm_dbus_proxy_call_finish (proxy, result,
	                                      G_VARIANT_TYPE ("(s)"),
	                                      &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (variant) {
		g_variant_get (variant, "(&s)", &data);

		/* The ProbeRequest method only exists if AP mode has been enabled */
		if (strstr (data, "ProbeRequest"))
			priv->ap_support = NM_SUPPLICANT_FEATURE_YES;
	}

	iface_check_ready (self);
}

static void
scan_done_emit_signal (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	const char *object_path;
	BssData *bss_data;
	gboolean success;
	GHashTableIter iter;

	g_hash_table_iter_init (&iter, priv->bss_proxies);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &bss_data)) {
		/* we have some BSS' that need to be initialized first. Delay
		 * emitting signal. */
		if (!bss_data->change_id) {
			priv->scan_done_pending = TRUE;
			return;
		}
	}

	/* Emit BSS_UPDATED so that wifi device has the APs (in case it removed them) */
	g_hash_table_iter_init (&iter, priv->bss_proxies);
	while (g_hash_table_iter_next (&iter, (gpointer *) &object_path, (gpointer *) &bss_data)) {
		gs_unref_variant GVariant *props = NULL;

		props = bss_proxy_get_properties (self, bss_data->proxy);
		g_signal_emit (self, signals[BSS_UPDATED], 0,
		               object_path,
		               g_variant_ref_sink (props));
	}

	success = priv->scan_done_success;
	priv->scan_done_success = FALSE;
	priv->scan_done_pending = FALSE;
	g_signal_emit (self, signals[SCAN_DONE], 0, success);
}

static void
wpas_iface_scan_done (GDBusProxy *proxy,
                      gboolean success,
                      gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Cache last scan completed time */
	priv->last_scan = nm_utils_get_monotonic_timestamp_s ();
	priv->scan_done_success |= success;
	scan_done_emit_signal (self);
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

	bss_add_new (self, path);
}

static void
wpas_iface_bss_removed (GDBusProxy *proxy,
                        const char *path,
                        gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	BssData *bss_data;

	bss_data = g_hash_table_lookup (priv->bss_proxies, path);
	if (!bss_data)
		return;
	g_hash_table_steal (priv->bss_proxies, path);
	g_signal_emit (self, signals[BSS_REMOVED], 0, path);
	bss_data_destroy (bss_data);
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
			bss_add_new (self, *iter++);
		g_free (array);
	}

	if (g_variant_lookup (changed_properties, "CurrentBSS", "&o", &s)) {
		if (strcmp (s, "/") == 0)
			s = NULL;
		if (g_strcmp0 (s, priv->current_bss) != 0) {
			g_free (priv->current_bss);
			priv->current_bss = g_strdup (s);
			_notify (self, PROP_CURRENT_BSS);
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
		if (priv->disconnect_reason != 0)
			_LOGW ("connection disconnected (reason %d)", priv->disconnect_reason);
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
			self = NM_SUPPLICANT_INTERFACE (user_data);
			_LOGW ("failed to acquire wpa_supplicant interface proxy: (%s)", error->message);
			set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
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

	if (priv->ap_support == NM_SUPPLICANT_FEATURE_UNKNOWN) {
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
		                   (GAsyncReadyCallback) iface_introspect_cb,
		                   self);
	}
}

static void
interface_add_done (NMSupplicantInterface *self, const char *path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	_LOGD ("interface added to supplicant");

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
		_LOGE ("error getting interface: %s", error->message);
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
		_LOGD ("failed to activate supplicant: %s", error->message);
		set_state (self, NM_SUPPLICANT_INTERFACE_STATE_INIT);
	} else {
		g_dbus_error_strip_remote_error (error);
		_LOGE ("error adding interface: %s", error->message);
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
	const char *driver_name = NULL;

	wpas_proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (!wpas_proxy) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
			self = NM_SUPPLICANT_INTERFACE (user_data);
			_LOGW ("failed to acquire wpa_supplicant proxy: (%s)", error->message);
			set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
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

	switch (priv->driver) {
	case NM_SUPPLICANT_DRIVER_WIRELESS:
		driver_name = DEFAULT_WIFI_DRIVER;
		break;
	case NM_SUPPLICANT_DRIVER_WIRED:
		driver_name = "wired";
		break;
	case NM_SUPPLICANT_DRIVER_MACSEC:
		driver_name = "macsec_linux";
		break;
	}

	g_return_if_fail (driver_name);

	g_variant_builder_init (&props, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&props, "{sv}",
	                       "Driver",
	                       g_variant_new_string (driver_name));
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
interface_add (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Can only start the interface from INIT state */
	g_return_if_fail (priv->state == NM_SUPPLICANT_INTERFACE_STATE_INIT);

	_LOGD ("adding interface to supplicant");

	/* Move to starting to prevent double-calls of interface_add() */
	set_state (self, NM_SUPPLICANT_INTERFACE_STATE_STARTING);

	nm_clear_g_cancellable (&priv->init_cancellable);
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
	NMSupplicantInterfacePrivate *priv;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (available) {
		/* This can happen if the supplicant couldn't be activated but
		 * for some reason was started after the activation failure.
		 */
		if (priv->state == NM_SUPPLICANT_INTERFACE_STATE_INIT)
			interface_add (self);
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
		nm_log_warn (_NMLOG_DOMAIN, "%s: failed to %s: %s",
		             _NMLOG_PREFIX_NAME, (const char *) user_data, error->message);
	}
}

/*****************************************************************************/

static void
assoc_return (NMSupplicantInterface *self, GError *error, const char *message)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	AssocData *assoc_data;

	assoc_data = g_steal_pointer (&priv->assoc_data);
	if (!assoc_data)
		return;

	if (error) {
		g_dbus_error_strip_remote_error (error);
		_LOGW ("assoc[%p]: %s: %s", assoc_data, message, error->message);
	} else
		_LOGD ("assoc[%p]: association request successful", assoc_data);

	if (assoc_data->add_network_data) {
		/* signal that this request already completed */
		assoc_data->add_network_data->assoc_data = NULL;
	}

	nm_clear_g_source (&assoc_data->fail_on_idle_id);
	nm_clear_g_cancellable (&assoc_data->cancellable);

	if (assoc_data->callback)
		assoc_data->callback (self, error, assoc_data->user_data);

	g_object_unref (assoc_data->cfg);
	g_slice_free (AssocData, assoc_data);
}

void
nm_supplicant_interface_disconnect (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Cancel all pending calls related to a prior connection attempt */
	if (priv->assoc_data) {
		gs_free GError *error = NULL;

		nm_utils_error_set_cancelled (&error, FALSE, "NMSupplicantInterface");
		assoc_return (self, error, "abort due to disconnect");
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
assoc_select_network_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	if (error)
		assoc_return (self, error, "failure to select network config");
	else
		assoc_return (self, NULL, NULL);
}

static void
assoc_call_select_network (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_dbus_proxy_call (priv->iface_proxy,
	                   "SelectNetwork",
	                   g_variant_new ("(o)", priv->net_path),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->assoc_data->cancellable,
	                   (GAsyncReadyCallback) assoc_select_network_cb,
	                   self);
}

static void
assoc_add_blob_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
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

	if (error) {
		assoc_return (self, error, "failure to set network certificates");
		return;
	}

	priv->assoc_data->blobs_left--;
	_LOGT ("assoc[%p]: blob added (%u left)", priv->assoc_data, priv->assoc_data->blobs_left);
	if (priv->assoc_data->blobs_left == 0)
		assoc_call_select_network (self);
}

static void
assoc_add_network_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	AddNetworkData *add_network_data = user_data;
	AssocData *assoc_data;
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;
	GHashTable *blobs;
	GHashTableIter iter;
	const char *blob_name;
	GByteArray *blob_data;

	assoc_data = add_network_data->assoc_data;
	if (assoc_data)
		assoc_data->add_network_data = NULL;
	g_slice_free (AddNetworkData, add_network_data);

	reply = _nm_dbus_proxy_call_finish (proxy, result,
	                                    G_VARIANT_TYPE ("(o)"),
	                                    &error);

	if (!assoc_data) {
		if (!error) {
			gs_free char *net_path = NULL;

			/* the assoc-request was already cancelled, but the AddNetwork request succeeded.
			 * Cleanup the created network.
			 *
			 * This cleanup action does not work when NetworkManager is about to exit
			 * and leaves the mainloop. During program shutdown, we may orphan networks. */
			g_variant_get (reply, "(o)", &net_path);
			g_dbus_proxy_call (proxy,
			                   "RemoveNetwork",
			                   g_variant_new ("(o)", net_path),
			                   G_DBUS_CALL_FLAGS_NONE,
			                   -1,
			                   NULL,
			                   NULL,
			                   NULL);
		}
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (assoc_data->self);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (error) {
		assoc_return (self, error, "failure to add network");
		return;
	}

	g_variant_get (reply, "(o)", &priv->net_path);

	/* Send blobs first; otherwise jump to selecting the network */
	blobs = nm_supplicant_config_get_blobs (priv->assoc_data->cfg);
	priv->assoc_data->blobs_left = g_hash_table_size (blobs);

	_LOGT ("assoc[%p]: network added (%s) (%u blobs left)", priv->assoc_data, priv->net_path, priv->assoc_data->blobs_left);

	if (priv->assoc_data->blobs_left == 0)
		assoc_call_select_network (self);
	else {
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
			                   priv->assoc_data->cancellable,
			                   (GAsyncReadyCallback) assoc_add_blob_cb,
			                   self);
		}
	}
}

static void
assoc_set_ap_scan_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;
	AddNetworkData *add_network_data;

	reply = g_dbus_proxy_call_finish (proxy, result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (error) {
		assoc_return (self, error, "failure to set AP scan mode");
		return;
	}

	_LOGT ("assoc[%p]: set interface ap_scan to %d",
	       priv->assoc_data,
	       nm_supplicant_config_get_ap_scan (priv->assoc_data->cfg));

	add_network_data = g_slice_new0 (AddNetworkData);
	priv->assoc_data->add_network_data = add_network_data;

	add_network_data->assoc_data = priv->assoc_data;

	g_dbus_proxy_call (priv->iface_proxy,
	                   "AddNetwork",
	                   g_variant_new ("(@a{sv})", nm_supplicant_config_to_variant (priv->assoc_data->cfg)),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   NULL,
	                   (GAsyncReadyCallback) assoc_add_network_cb,
	                   add_network_data);
}

static gboolean
assoc_fail_on_idle_cb (gpointer user_data)
{
	NMSupplicantInterface *self = user_data;
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gs_free_error GError *error = NULL;

	priv->assoc_data->fail_on_idle_id = 0;
	g_set_error (&error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
	             "EAP-FAST is not supported by the supplicant");
	assoc_return (self, error, "failure due to missing supplicant support");
	return G_SOURCE_REMOVE;
}

/**
 * nm_supplicant_interface_assoc:
 * @self: the supplicant interface instance
 * @cfg: the configuration with the data for the association
 * @callback: callback invoked when the association completes or fails.
 * @user_data: data for the callback.
 *
 * Calls AddNetwork and SelectNetwork to start associating according to @cfg.
 *
 * The callback is invoked exactly once (always) and always asynchronously.
 * The pending association can be aborted via nm_supplicant_interface_disconnect()
 * or by destroying @self. In that case, the @callback is invoked synchornously with
 * an error reason indicating cancellation/disposing (see nm_utils_error_is_cancelled()).
 */
void
nm_supplicant_interface_assoc (NMSupplicantInterface *self,
                               NMSupplicantConfig *cfg,
                               NMSupplicantInterfaceAssocCb callback,
                               gpointer user_data)
{
	NMSupplicantInterfacePrivate *priv;
	AssocData *assoc_data;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));
	g_return_if_fail (NM_IS_SUPPLICANT_CONFIG (cfg));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	nm_supplicant_interface_disconnect (self);

	assoc_data = g_slice_new0 (AssocData);
	priv->assoc_data = assoc_data;

	assoc_data->self = self;
	assoc_data->cfg = g_object_ref (cfg);
	assoc_data->callback = callback;
	assoc_data->user_data = user_data;

	_LOGD ("assoc[%p]: starting association...", assoc_data);

	/* Make sure the supplicant supports EAP-FAST before trying to send
	 * it an EAP-FAST configuration.
	 */
	if (   priv->fast_support == NM_SUPPLICANT_FEATURE_NO
	    && nm_supplicant_config_fast_required (cfg)) {
		assoc_data->fail_on_idle_id = g_idle_add (assoc_fail_on_idle_cb, self);
		return;
	}

	assoc_data->cancellable = g_cancellable_new();
	g_dbus_proxy_call (priv->iface_proxy,
	                   DBUS_INTERFACE_PROPERTIES ".Set",
	                   g_variant_new ("(ssv)",
	                                  WPAS_DBUS_IFACE_INTERFACE,
	                                  "ApScan",
	                                  g_variant_new_uint32 (nm_supplicant_config_get_ap_scan (priv->assoc_data->cfg))),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->assoc_data->cancellable,
	                   (GAsyncReadyCallback) assoc_set_ap_scan_cb,
	                   self);
}

/*****************************************************************************/

static void
scan_request_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	if (error) {
		if (_nm_dbus_error_has_name (error, "fi.w1.wpa_supplicant1.Interface.ScanError"))
			_LOGD ("could not get scan request result: %s", error->message);
		else {
			g_dbus_error_strip_remote_error (error);
			_LOGW ("could not get scan request result: %s", error->message);
		}
	}
}

void
nm_supplicant_interface_request_scan (NMSupplicantInterface *self, const GPtrArray *ssids)
{
	NMSupplicantInterfacePrivate *priv;
	GVariantBuilder builder;
	guint i;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

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
}

/*****************************************************************************/

NMSupplicantInterfaceState
nm_supplicant_interface_get_state (NMSupplicantInterface * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NM_SUPPLICANT_INTERFACE_STATE_DOWN);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->state;
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

/*****************************************************************************/

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE ((NMSupplicantInterface *) object);

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
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE ((NMSupplicantInterface *) object);

	switch (prop_id) {
	case PROP_IFACE:
		/* construct-only */
		priv->dev = g_value_dup_string (value);
		g_return_if_fail (priv->dev);
		break;
	case PROP_DRIVER:
		/* construct-only */
		priv->driver = g_value_get_uint (value);
		break;
	case PROP_FAST_SUPPORT:
		/* construct-only */
		priv->fast_support = g_value_get_int (value);
		break;
	case PROP_AP_SUPPORT:
		/* construct-only */
		priv->ap_support = g_value_get_int (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_supplicant_interface_init (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->state = NM_SUPPLICANT_INTERFACE_STATE_INIT;
	priv->bss_proxies = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, bss_data_destroy);
}

NMSupplicantInterface *
nm_supplicant_interface_new (const char *ifname,
                             NMSupplicantDriver driver,
                             NMSupplicantFeature fast_support,
                             NMSupplicantFeature ap_support)
{
	g_return_val_if_fail (ifname != NULL, NULL);

	return g_object_new (NM_TYPE_SUPPLICANT_INTERFACE,
	                     NM_SUPPLICANT_INTERFACE_IFACE, ifname,
	                     NM_SUPPLICANT_INTERFACE_DRIVER, (guint) driver,
	                     NM_SUPPLICANT_INTERFACE_FAST_SUPPORT, (int) fast_support,
	                     NM_SUPPLICANT_INTERFACE_AP_SUPPORT, (int) ap_support,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (object);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->assoc_data) {
		gs_free GError *error = NULL;

		nm_utils_error_set_cancelled (&error, TRUE, "NMSupplicantInterface");
		assoc_return (self, error, "cancelled due to dispose of supplicant interface");
	}

	if (priv->iface_proxy)
		g_signal_handlers_disconnect_by_data (priv->iface_proxy, object);
	g_clear_object (&priv->iface_proxy);

	nm_clear_g_cancellable (&priv->init_cancellable);
	nm_clear_g_cancellable (&priv->other_cancellable);

	g_clear_object (&priv->wpas_proxy);
	g_clear_pointer (&priv->bss_proxies, (GDestroyNotify) g_hash_table_destroy);

	g_clear_pointer (&priv->net_path, g_free);
	g_clear_pointer (&priv->dev, g_free);
	g_clear_pointer (&priv->object_path, g_free);
	g_clear_pointer (&priv->current_bss, g_free);

	G_OBJECT_CLASS (nm_supplicant_interface_parent_class)->dispose (object);
}

static void
nm_supplicant_interface_class_init (NMSupplicantInterfaceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	obj_properties[PROP_SCANNING] =
	    g_param_spec_boolean (NM_SUPPLICANT_INTERFACE_SCANNING, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_CURRENT_BSS] =
	    g_param_spec_string (NM_SUPPLICANT_INTERFACE_CURRENT_BSS, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IFACE] =
	    g_param_spec_string (NM_SUPPLICANT_INTERFACE_IFACE, "", "",
	                         NULL,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DRIVER] =
	    g_param_spec_uint (NM_SUPPLICANT_INTERFACE_DRIVER, "", "",
	                       0, G_MAXUINT, NM_SUPPLICANT_DRIVER_WIRELESS,
	                       G_PARAM_WRITABLE |
	                       G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_FAST_SUPPORT] =
	    g_param_spec_int (NM_SUPPLICANT_INTERFACE_FAST_SUPPORT, "", "",
	                      NM_SUPPLICANT_FEATURE_UNKNOWN,
	                      NM_SUPPLICANT_FEATURE_YES,
	                      NM_SUPPLICANT_FEATURE_UNKNOWN,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_AP_SUPPORT] =
	    g_param_spec_int (NM_SUPPLICANT_INTERFACE_AP_SUPPORT, "", "",
	                      NM_SUPPLICANT_FEATURE_UNKNOWN,
	                      NM_SUPPLICANT_FEATURE_YES,
	                      NM_SUPPLICANT_FEATURE_UNKNOWN,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[STATE] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_STATE,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 3, G_TYPE_INT, G_TYPE_INT, G_TYPE_INT);

	signals[REMOVED] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);

	signals[BSS_UPDATED] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_BSS_UPDATED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_VARIANT);

	signals[BSS_REMOVED] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_BSS_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_STRING);

	signals[SCAN_DONE] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_SCAN_DONE,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_BOOLEAN);

	signals[CREDENTIALS_REQUEST] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_CREDENTIALS_REQUEST,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_STRING);
}

