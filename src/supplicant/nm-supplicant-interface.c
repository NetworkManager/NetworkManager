// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2006 - 2017 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-supplicant-interface.h"
#include "nm-supplicant-manager.h"

#include <stdio.h>

#include "NetworkManagerUtils.h"
#include "nm-supplicant-config.h"
#include "nm-core-internal.h"
#include "nm-std-aux/nm-dbus-compat.h"

/*****************************************************************************/

typedef struct {
	GDBusProxy *proxy;
	gulong change_id;
} BssData;

typedef struct {
	GDBusProxy *proxy;
	gulong change_id;
} PeerData;

struct _AddNetworkData;

typedef struct {
	NMSupplicantInterface *self;
	char *type;
	char *bssid;
	char *pin;
	GDBusProxy *proxy;
	GCancellable *cancellable;
	bool is_cancelling;
} WpsData;

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

typedef struct {
	NMSupplicantInterface *self;
	NMSupplicantInterfaceDisconnectCb callback;
	gpointer user_data;
} DisconnectData;

enum {
	STATE,                   /* change in the interface's state */
	REMOVED,                 /* interface was removed by the supplicant */
	BSS_UPDATED,             /* a new BSS appeared or an existing had properties changed */
	BSS_REMOVED,             /* supplicant removed BSS from its scan list */
	PEER_UPDATED,            /* a new Peer appeared or an existing had properties changed */
	PEER_REMOVED,            /* supplicant removed Peer from its scan list */
	SCAN_DONE,               /* wifi scan is complete */
	WPS_CREDENTIALS,         /* WPS credentials received */
	GROUP_STARTED,           /* a new Group (interface) was created */
	GROUP_FINISHED,          /* a Group (interface) has been finished */
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

NM_GOBJECT_PROPERTIES_DEFINE (NMSupplicantInterface,
	PROP_IFACE,
	PROP_OBJECT_PATH,
	PROP_P2P_GROUP_JOINED,
	PROP_P2P_GROUP_PATH,
	PROP_P2P_GROUP_OWNER,
	PROP_SCANNING,
	PROP_CURRENT_BSS,
	PROP_DRIVER,
	PROP_P2P_AVAILABLE,
	PROP_GLOBAL_CAPABILITIES,
	PROP_AUTH_STATE,
);

typedef struct _NMSupplicantInterfacePrivate {
	char *         dev;
	NMSupplicantDriver driver;
	NMSupplCapMask global_capabilities;
	NMSupplCapMask iface_capabilities;
	guint32        max_scan_ssids;
	guint32        ready_count;

	char *         object_path;
	NMSupplicantInterfaceState state;
	int            disconnect_reason;

	GDBusProxy *   wpas_proxy;
	GCancellable * init_cancellable;
	GDBusProxy *   iface_proxy;
	GCancellable * other_cancellable;
	GDBusProxy *   p2p_proxy;
	GDBusProxy *   group_proxy;

	WpsData *wps_data;

	AssocData *    assoc_data;

	char *         net_path;
	GHashTable *   bss_proxies;
	char *         current_bss;

	GHashTable *   peer_proxies;

	gint64         last_scan; /* timestamp as returned by nm_utils_get_monotonic_timestamp_msec() */

	NMSupplicantAuthState auth_state;

	bool           scanning:1;

	bool           scan_done_pending:1;
	bool           scan_done_success:1;

	bool           p2p_proxy_acquired:1;
	bool           group_proxy_acquired:1;
	bool           p2p_capable:1;

	bool           p2p_group_owner:1;

} NMSupplicantInterfacePrivate;

struct _NMSupplicantInterfaceClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMSupplicantInterface, nm_supplicant_interface, G_TYPE_OBJECT)

#define NM_SUPPLICANT_INTERFACE_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR (self, NMSupplicantInterface, NM_IS_SUPPLICANT_INTERFACE)

/*****************************************************************************/

#define _NMLOG_DOMAIN           LOGD_SUPPLICANT
#define _NMLOG_PREFIX_NAME      "sup-iface"
#define _NMLOG(level, ...) \
    G_STMT_START { \
         char _sbuf[64]; \
         const char *__ifname = self ?  NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->dev : NULL; \
         \
         nm_log ((level), _NMLOG_DOMAIN, __ifname, NULL, \
                 "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                 _NMLOG_PREFIX_NAME, \
                 ((self) ? nm_sprintf_buf (_sbuf, "[%p,%s]", (self), __ifname) : "") \
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

NM_UTILS_STRING_TABLE_LOOKUP_DEFINE_STATIC (
	wpas_state_string_to_enum,
	NMSupplicantInterfaceState,
	{ nm_assert (name); },
	{ return NM_SUPPLICANT_INTERFACE_STATE_INVALID; },
	{ "4way_handshake",     NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE  },
	{ "associated",         NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED      },
	{ "associating",        NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING     },
	{ "authenticating",     NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING  },
	{ "completed",          NM_SUPPLICANT_INTERFACE_STATE_COMPLETED       },
	{ "disconnected",       NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED    },
	{ "group_handshake",    NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE },
	{ "inactive",           NM_SUPPLICANT_INTERFACE_STATE_INACTIVE        },
	{ "interface_disabled", NM_SUPPLICANT_INTERFACE_STATE_DISABLED        },
	{ "scanning",           NM_SUPPLICANT_INTERFACE_STATE_SCANNING        },
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
		priv->last_scan = nm_utils_get_monotonic_timestamp_msec ();

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

static void
bss_proxy_acquired_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_free_error GError *error = NULL;
	GVariant *props = NULL;
	const char *object_path;
	BssData *bss_data;
	gboolean success;

	success = g_async_initable_init_finish (G_ASYNC_INITABLE (proxy), result, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (!success) {
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
	                          "g-name", NM_WPAS_DBUS_SERVICE,
	                          "g-object-path", object_path,
	                          "g-interface-name", NM_WPAS_DBUS_IFACE_BSS,
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

static void
peer_data_destroy (gpointer user_data)
{
	PeerData *peer_data = user_data;

	nm_clear_g_signal_handler (peer_data->proxy, &peer_data->change_id);
	g_object_unref (peer_data->proxy);
	g_slice_free (PeerData, peer_data);
}

static void
peer_proxy_properties_changed_cb (GDBusProxy *proxy,
                                  GVariant *changed_properties,
                                  char **invalidated_properties,
                                  gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);

	g_signal_emit (self, signals[PEER_UPDATED], 0,
	               g_dbus_proxy_get_object_path (proxy),
	               changed_properties);
}

static GVariant *
peer_proxy_get_properties (NMSupplicantInterface *self, GDBusProxy *proxy)
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

static void
peer_proxy_acquired_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_free_error GError *error = NULL;
	GVariant *props = NULL;
	const char *object_path;
	PeerData *peer_data;
	gboolean success;

	success = g_async_initable_init_finish (G_ASYNC_INITABLE (proxy), result, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (!success) {
		_LOGD ("failed to acquire Peer proxy: (%s)", error->message);
		g_hash_table_remove (priv->peer_proxies,
		                     g_dbus_proxy_get_object_path (proxy));
		return;
	}

	object_path = g_dbus_proxy_get_object_path (proxy);
	peer_data = g_hash_table_lookup (priv->peer_proxies, object_path);
	if (!peer_data)
		return;

	peer_data->change_id = g_signal_connect (proxy, "g-properties-changed", G_CALLBACK (peer_proxy_properties_changed_cb), self);

	props = peer_proxy_get_properties (self, proxy);

	g_signal_emit (self, signals[PEER_UPDATED], 0,
	               g_dbus_proxy_get_object_path (proxy),
	               g_variant_ref_sink (props));
	g_variant_unref (props);
}

static void
peer_add_new (NMSupplicantInterface *self, const char *object_path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	GDBusProxy *peer_proxy;
	PeerData *peer_data;

	g_return_if_fail (object_path != NULL);

	if (g_hash_table_lookup (priv->peer_proxies, object_path))
		return;

	peer_proxy = g_object_new (G_TYPE_DBUS_PROXY,
	                           "g-bus-type", G_BUS_TYPE_SYSTEM,
	                           "g-flags", G_DBUS_PROXY_FLAGS_NONE,
	                           "g-name", NM_WPAS_DBUS_SERVICE,
	                           "g-object-path", object_path,
	                           "g-interface-name", NM_WPAS_DBUS_IFACE_PEER,
	                           NULL);
	peer_data = g_slice_new0 (PeerData);
	peer_data->proxy = peer_proxy;
	g_hash_table_insert (priv->peer_proxies,
	                     (char *) g_dbus_proxy_get_object_path (peer_proxy),
	                     peer_data);
	g_async_initable_init_async (G_ASYNC_INITABLE (peer_proxy),
	                             G_PRIORITY_DEFAULT,
	                             priv->other_cancellable,
	                             (GAsyncReadyCallback) peer_proxy_acquired_cb,
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
		priv->last_scan = nm_utils_get_monotonic_timestamp_msec ();

	/* Disconnect reason is no longer relevant when not in the DISCONNECTED state */
	if (priv->state != NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED)
		priv->disconnect_reason = 0;

	g_signal_emit (self, signals[STATE], 0,
	               (int) priv->state,
	               (int) old_state,
	               (int) priv->disconnect_reason);
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
			priv->last_scan = nm_utils_get_monotonic_timestamp_msec ();

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

gint64
nm_supplicant_interface_get_last_scan (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->last_scan;
}

#define MATCH_PROPERTY(p, n, v, t) (!strcmp (p, n) && g_variant_is_of_type (v, t))

static void
parse_capabilities (NMSupplicantInterface *self, GVariant *capabilities)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gboolean have_active = FALSE;
	gboolean have_ssid = FALSE;
	gboolean have_p2p = FALSE;
	gboolean have_ft = FALSE;
	gint32 max_scan_ssids = -1;
	const char **array;

	g_return_if_fail (capabilities && g_variant_is_of_type (capabilities, G_VARIANT_TYPE_VARDICT));

	if (g_variant_lookup (capabilities, "KeyMgmt", "^a&s", &array)) {
		have_ft = g_strv_contains (array, "wpa-ft-psk");
		g_free (array);
	}

	priv->iface_capabilities = NM_SUPPL_CAP_MASK_SET (priv->iface_capabilities,
	                                                  NM_SUPPL_CAP_TYPE_FT,
	                                                    have_ft
	                                                  ? NM_TERNARY_TRUE
	                                                  : NM_TERNARY_FALSE);

	if (g_variant_lookup (capabilities, "Modes", "^a&s", &array)) {
		if (g_strv_contains (array, "p2p"))
			have_p2p = TRUE;
		g_free (array);
	}

	if (priv->p2p_capable != have_p2p) {
		priv->p2p_capable = have_p2p;
		_notify (self, PROP_P2P_AVAILABLE);
	}

	if (g_variant_lookup (capabilities, "Scan", "^a&s", &array)) {
		if (g_strv_contains (array, "active"))
			have_active = TRUE;
		if (g_strv_contains (array, "ssid"))
			have_ssid = TRUE;
		g_free (array);
	}

	if (g_variant_lookup (capabilities, "MaxScanSSID", "i", &max_scan_ssids)) {
		/* We need active scan and SSID probe capabilities to care about MaxScanSSIDs */
		if (max_scan_ssids > 0 && have_active && have_ssid) {
			/* wpa_supplicant's NM_WPAS_MAX_SCAN_SSIDS value is 16, but for speed
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

static void
iface_set_pmf_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;

	variant = g_dbus_proxy_call_finish (proxy, result, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);

	if (error)
		_LOGW ("failed to set Pmf=1: %s", error->message);

	iface_check_ready (self);
}

gboolean
nm_supplicant_interface_get_p2p_group_joined (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->group_proxy_acquired;
}

const char*
nm_supplicant_interface_get_p2p_group_path (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->group_proxy_acquired)
		return g_dbus_proxy_get_object_path (priv->group_proxy);
	else
		return NULL;
}

gboolean
nm_supplicant_interface_get_p2p_group_owner (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->p2p_group_owner;
}

static NMTernary
_get_capability (NMSupplicantInterfacePrivate *priv,
                 NMSupplCapType type)
{
	NMTernary value;
	NMTernary iface_value;

	switch (type) {
	case NM_SUPPL_CAP_TYPE_AP:
		iface_value = NM_SUPPL_CAP_MASK_GET (priv->iface_capabilities, type);
		value = NM_SUPPL_CAP_MASK_GET (priv->global_capabilities, type);
		value = MAX (iface_value, value);
		break;
	case NM_SUPPL_CAP_TYPE_FT:
		value = NM_SUPPL_CAP_MASK_GET (priv->global_capabilities, type);
		if (value != NM_TERNARY_FALSE) {
			iface_value = NM_SUPPL_CAP_MASK_GET (priv->iface_capabilities, type);
			if (iface_value != NM_TERNARY_DEFAULT)
				value = iface_value;
		}
		break;
	default:
		nm_assert (NM_SUPPL_CAP_MASK_GET (priv->iface_capabilities, type) == NM_TERNARY_DEFAULT);
		value = NM_SUPPL_CAP_MASK_GET (priv->global_capabilities, type);
		break;
	}
	return value;
}

NMTernary
nm_supplicant_interface_get_capability (NMSupplicantInterface *self,
                                        NMSupplCapType type)
{
	return _get_capability (NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self), type);
}

NMSupplCapMask
nm_supplicant_interface_get_capabilities (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplCapMask caps;

	caps = priv->global_capabilities;
	caps = NM_SUPPL_CAP_MASK_SET (caps, NM_SUPPL_CAP_TYPE_AP, _get_capability (priv, NM_SUPPL_CAP_TYPE_AP));
	caps = NM_SUPPL_CAP_MASK_SET (caps, NM_SUPPL_CAP_TYPE_FT, _get_capability (priv, NM_SUPPL_CAP_TYPE_FT));

	nm_assert (!NM_FLAGS_ANY (priv->iface_capabilities,
	                          ~(  NM_SUPPL_CAP_MASK_T_AP_MASK
	                            | NM_SUPPL_CAP_MASK_T_FT_MASK)));

#if NM_MORE_ASSERTS > 10
	{
		NMSupplCapType type;

		for (type = 0; type < _NM_SUPPL_CAP_TYPE_NUM; type++)
			nm_assert (NM_SUPPL_CAP_MASK_GET (caps, type) == _get_capability (priv, type));
	}
#endif

	return caps;
}

void
nm_supplicant_interface_set_global_capabilities (NMSupplicantInterface *self,
                                                 NMSupplCapMask value)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->global_capabilities = value;
}

NMSupplicantAuthState
nm_supplicant_interface_get_auth_state (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->auth_state;
}

/*****************************************************************************/

static void
_wps_data_free (WpsData *data)
{
	g_free (data->type);
	g_free (data->pin);
	g_free (data->bssid);
	g_clear_object (&data->cancellable);
	if (data->proxy && data->self)
		g_signal_handlers_disconnect_by_data (data->proxy, data->self);
	g_clear_object (&data->proxy);
	g_slice_free (WpsData, data);
}

static void
_wps_credentials_changed_cb (GDBusProxy *proxy,
                             GVariant *props,
                             gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);

	_LOGT ("wps: new credentials");
	g_signal_emit (self, signals[WPS_CREDENTIALS], 0, props);
}

static void
_wps_handle_start_cb (GObject *source_object,
                      GAsyncResult *res,
                      gpointer user_data)
{
	NMSupplicantInterface *self;
	WpsData *data;
	gs_unref_variant GVariant *result = NULL;
	gs_free_error GError *error = NULL;

	result = g_dbus_proxy_call_finish (G_DBUS_PROXY (source_object), res, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	data = user_data;
	self = data->self;

	if (result)
		_LOGT ("wps: started with success");
	else
		_LOGW ("wps: start failed with %s", error->message);

	g_clear_object (&data->cancellable);
	nm_clear_g_free (&data->type);
	nm_clear_g_free (&data->pin);
	nm_clear_g_free (&data->bssid);
}

static void
_wps_handle_set_pc_cb (GObject *source_object,
                       GAsyncResult *res,
                       gpointer user_data)
{
	WpsData *data;
	NMSupplicantInterface *self;
	gs_unref_variant GVariant *result = NULL;
	gs_free_error GError *error = NULL;
	GVariantBuilder start_args;
	guint8 bssid_buf[ETH_ALEN];

	result = g_dbus_proxy_call_finish (G_DBUS_PROXY (source_object), res, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	data = user_data;
	self = data->self;

	if (result)
		_LOGT ("wps: ProcessCredentials successfully set, starting...");
	else
		_LOGW ("wps: ProcessCredentials failed to set (%s), starting...", error->message);

	_nm_dbus_signal_connect (data->proxy, "Credentials", G_VARIANT_TYPE ("(a{sv})"),
	                         G_CALLBACK (_wps_credentials_changed_cb), self);

	g_variant_builder_init (&start_args, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&start_args, "{sv}", "Role", g_variant_new_string ("enrollee"));
	g_variant_builder_add (&start_args, "{sv}", "Type", g_variant_new_string (data->type));
	if (data->pin)
		g_variant_builder_add (&start_args, "{sv}", "Pin", g_variant_new_string (data->pin));

	if (data->bssid) {
		/* The BSSID is in fact not mandatory. If it is not set the supplicant would
		 * enroll with any BSS in range. */
		if (!nm_utils_hwaddr_aton (data->bssid, bssid_buf, sizeof (bssid_buf)))
			nm_assert_not_reached ();
		g_variant_builder_add (&start_args, "{sv}", "Bssid",
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, bssid_buf,
		                                                  ETH_ALEN, sizeof (guint8)));
	}

	g_dbus_proxy_call (data->proxy,
	                   "Start",
	                   g_variant_new ("(a{sv})", &start_args),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   data->cancellable,
	                   _wps_handle_start_cb,
	                   data);
}

static void
_wps_call_set_pc (WpsData *data)
{
	g_dbus_proxy_call (data->proxy,
	                   "org.freedesktop.DBus.Properties.Set",
	                   g_variant_new ("(ssv)",
	                                  NM_WPAS_DBUS_IFACE_INTERFACE_WPS,
	                                  "ProcessCredentials",
	                                  g_variant_new_boolean (TRUE)),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   data->cancellable,
	                   _wps_handle_set_pc_cb,
	                   data);
}

static void
_wps_handle_proxy_cb (GObject *source_object,
                      GAsyncResult *res,
                      gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	WpsData *data;
	gs_free_error GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (res, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	data = user_data;
	self = data->self;
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (!proxy) {
		_LOGW ("wps: failure to create D-Bus proxy: %s", error->message);
		_wps_data_free (data);
		priv->wps_data = NULL;
		return;
	}

	data->proxy = proxy;
	_LOGT ("wps: D-Bus proxy created. set ProcessCredentials...");
	_wps_call_set_pc (data);
}

static void
_wps_handle_cancel_cb (GObject *source_object,
                       GAsyncResult *res,
                       gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	WpsData *data;
	gs_unref_variant GVariant *result = NULL;
	gs_free_error GError *error = NULL;

	result = g_dbus_proxy_call_finish (G_DBUS_PROXY (source_object), res, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	data = user_data;
	self = data->self;

	if (!self) {
		_wps_data_free (data);
		if (result)
			_LOGT ("wps: cancel completed successfully, after supplicant interface is gone");
		else
			_LOGW ("wps: cancel failed (%s), after supplicant interface is gone", error->message);
		return;
	}

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	data->is_cancelling = FALSE;

	if (!data->type) {
		priv->wps_data = NULL;
		_wps_data_free (data);
		if (result)
			_LOGT ("wps: cancel completed successfully");
		else
			_LOGW ("wps: cancel failed (%s)", error->message);
		return;
	}

	if (result)
		_LOGT ("wps: cancel completed successfully, setting ProcessCredentials now...");
	else
		_LOGW ("wps: cancel failed (%s), setting ProcessCredentials now...", error->message);
	_wps_call_set_pc (data);
}

static void
_wps_start (NMSupplicantInterface *self,
            const char *type,
            const char *bssid,
            const char *pin)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	WpsData *data = priv->wps_data;

	if (type)
		_LOGI ("wps: type %s start...", type);

	if (!data) {
		if (!type)
			return;

		data = g_slice_new0 (WpsData);
		data->self = self;
		data->type = g_strdup (type);
		data->bssid = g_strdup (bssid);
		data->pin = g_strdup (pin);
		data->cancellable = g_cancellable_new ();

		priv->wps_data = data;

		_LOGT ("wps: create D-Bus proxy...");

		g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
		                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
		                          NULL,
		                          NM_WPAS_DBUS_SERVICE,
		                          priv->object_path,
		                          NM_WPAS_DBUS_IFACE_INTERFACE_WPS,
		                          data->cancellable,
		                          _wps_handle_proxy_cb,
		                          data);
		return;
	}

	g_free (data->type);
	g_free (data->bssid);
	g_free (data->pin);
	data->type = g_strdup (type);
	data->bssid = g_strdup (bssid);
	data->pin = g_strdup (pin);

	if (!data->proxy) {
		if (!type) {
			nm_clear_g_cancellable (&data->cancellable);
			priv->wps_data = NULL;
			_wps_data_free (data);

			_LOGT ("wps: abort creation of D-Bus proxy");
		} else
			_LOGT ("wps: new enrollment. Wait for D-Bus proxy...");
		return;
	}

	if (data->is_cancelling)
		return;

	_LOGT ("wps: cancel previous enrollment...");

	data->is_cancelling = TRUE;
	nm_clear_g_cancellable (&data->cancellable);
	data->cancellable = g_cancellable_new ();
	g_signal_handlers_disconnect_by_data (data->proxy, self);
	g_dbus_proxy_call (data->proxy,
	                   "Cancel",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   data->cancellable,
	                   _wps_handle_cancel_cb,
	                   data);
}

void
nm_supplicant_interface_enroll_wps (NMSupplicantInterface *self,
                                    const char *type,
                                    const char *bssid,
                                    const char *pin)
{
	_wps_start (self, type, bssid, pin);
}

void
nm_supplicant_interface_cancel_wps (NMSupplicantInterface *self)
{
	_wps_start (self, NULL, NULL, NULL);
}

/*****************************************************************************/

static void
iface_introspect_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;
	const char *data;
	NMTernary value;

	variant = _nm_dbus_proxy_call_finish (proxy, result,
	                                      G_VARIANT_TYPE ("(s)"),
	                                      &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (NM_SUPPL_CAP_MASK_GET (priv->global_capabilities, NM_SUPPL_CAP_TYPE_AP) == NM_TERNARY_DEFAULT) {
		/* if the global value is set, we trust it and ignore whatever we get from introspection. */
	} else {
		value = NM_TERNARY_DEFAULT;
		if (variant) {
			g_variant_get (variant, "(&s)", &data);

			/* The ProbeRequest method only exists if AP mode has been enabled */
			value =   strstr (data, "ProbeRequest")
			        ? NM_TERNARY_TRUE
			        : NM_TERNARY_FALSE;
		}
		priv->iface_capabilities = NM_SUPPL_CAP_MASK_SET (priv->iface_capabilities, NM_SUPPL_CAP_TYPE_AP, value);
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
	priv->last_scan = nm_utils_get_monotonic_timestamp_msec ();
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
		priv->last_scan = nm_utils_get_monotonic_timestamp_msec ();

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
eap_changed (GDBusProxy *proxy,
             const char *status,
             const char *parameter,
             gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantAuthState auth_state = NM_SUPPLICANT_AUTH_STATE_UNKNOWN;

	if (nm_streq0 (status, "started"))
		auth_state = NM_SUPPLICANT_AUTH_STATE_STARTED;
	else if (nm_streq0 (status, "completion")) {
		if (nm_streq0 (parameter, "success"))
			auth_state = NM_SUPPLICANT_AUTH_STATE_SUCCESS;
		else if (nm_streq0 (parameter, "failure"))
			auth_state = NM_SUPPLICANT_AUTH_STATE_FAILURE;
	}

	/* the state eventually reaches one of started, success or failure
	 * so ignore any other intermediate (unknown) state change. */
	if (   auth_state != NM_SUPPLICANT_AUTH_STATE_UNKNOWN
	    && auth_state != priv->auth_state) {
		priv->auth_state = auth_state;
		_notify (self, PROP_AUTH_STATE);
	}
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
		s = nm_dbus_path_not_empty (s);
		if (!nm_streq0 (s, priv->current_bss)) {
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

	/* We may not have priv->dev set yet if this interface was created from a
	 * known wpa_supplicant interface without knowing the device name.
	 */
	if (priv->dev == NULL && g_variant_lookup (changed_properties, "Ifname", "&s", &s)) {
		priv->dev = g_strdup (s);
		_notify (self, PROP_IFACE);
	}

	g_object_thaw_notify (G_OBJECT (self));
}

static void
group_props_changed_cb (GDBusProxy *proxy,
                        GVariant *changed_properties,
                        char **invalidated_properties,
                        gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	char *s;

	g_object_freeze_notify (G_OBJECT (self));

#if 0
	v = g_variant_lookup_value (properties, "BSSID", G_VARIANT_TYPE_BYTESTRING);
	if (v) {
		bytes = g_variant_get_fixed_array (v, &len, 1);
		if (   len == ETH_ALEN
		    && memcmp (bytes, nm_ip_addr_zero.addr_eth, ETH_ALEN) != 0
		    && memcmp (bytes, (char[ETH_ALEN]) { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, ETH_ALEN) != 0)
			nm_wifi_p2p_group_set_bssid_bin (group, bytes);
		g_variant_unref (v);
	}

	v = g_variant_lookup_value (properties, "SSID", G_VARIANT_TYPE_BYTESTRING);
	if (v) {
		bytes = g_variant_get_fixed_array (v, &len, 1);
		len = MIN (32, len);

		/* Stupid ieee80211 layer uses <hidden> */
		if (   bytes && len
		    && !(((len == 8) || (len == 9)) && !memcmp (bytes, "<hidden>", 8))
		    && !nm_utils_is_empty_ssid (bytes, len))
			nm_wifi_p2p_group_set_ssid (group, bytes, len);

		g_variant_unref (v);
	}
#endif

	if (g_variant_lookup (changed_properties, "Role", "s", &s)) {
		priv->p2p_group_owner = g_strcmp0 (s, "GO") == 0;
		_notify (self, PROP_P2P_GROUP_OWNER);
		g_free (s);
	}

	/* NOTE: We do not seem to get any property change notifications for the Members
	 *       property. However, we can keep track of these indirectly either by querying
	 *       the groups that each peer is in or listening to the Join/Disconnect
	 *       notifications.
	 */

	g_object_thaw_notify (G_OBJECT (self));
}

static void
group_proxy_acquired_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_free_error GError *error = NULL;
	gboolean success;

	success = g_async_initable_init_finish (G_ASYNC_INITABLE (proxy), result, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (!success) {
		_LOGD ("failed to acquire Group proxy: (%s)", error->message);
		g_clear_object (&priv->group_proxy);
		return;
	}

	priv->group_proxy_acquired = TRUE;
	_notify (self, PROP_P2P_GROUP_JOINED);
	_notify (self, PROP_P2P_GROUP_PATH);

	iface_check_ready (self);
}

static void
p2p_props_changed_cb (GDBusProxy *proxy,
                      GVariant *changed_properties,
                      GStrv invalidated_properties,
                      gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	const char **array, **iter;
	const char *path = NULL;

	g_object_freeze_notify (G_OBJECT (self));

	if (g_variant_lookup (changed_properties, "Peers", "^a&o", &array)) {
		iter = array;
		while (*iter)
			peer_add_new (self, *iter++);
		g_free (array);
	}

	if (g_variant_lookup (changed_properties, "Group", "&o", &path)) {
		if (priv->group_proxy && g_strcmp0 (path, g_dbus_proxy_get_object_path (priv->group_proxy)) == 0) {
			/* We already have the proxy, nothing to do. */
		} else if (nm_dbus_path_not_empty (path)) {
			if (priv->group_proxy != NULL) {
				_LOGW ("P2P: Unexpected update of the group object path");
				priv->group_proxy_acquired = FALSE;
				_notify (self, PROP_P2P_GROUP_JOINED);
				_notify (self, PROP_P2P_GROUP_PATH);
				g_clear_object (&priv->group_proxy);
			}

			/* Delay ready state if we have not reached it yet. */
			if (priv->ready_count)
				priv->ready_count++;

			priv->group_proxy = g_object_new (G_TYPE_DBUS_PROXY,
			                                  "g-bus-type", G_BUS_TYPE_SYSTEM,
			                                  "g-flags", G_DBUS_PROXY_FLAGS_NONE,
			                                  "g-name", NM_WPAS_DBUS_SERVICE,
			                                  "g-object-path", path,
			                                  "g-interface-name", NM_WPAS_DBUS_IFACE_GROUP,
			                                  NULL);
			g_signal_connect (priv->group_proxy, "g-properties-changed", G_CALLBACK (group_props_changed_cb), self);
			g_async_initable_init_async (G_ASYNC_INITABLE (priv->group_proxy),
			                             G_PRIORITY_DEFAULT,
			                             priv->other_cancellable,
			                             (GAsyncReadyCallback) group_proxy_acquired_cb,
			                             self);
		} else {
			priv->group_proxy_acquired = FALSE;
			_notify (self, PROP_P2P_GROUP_JOINED);
			_notify (self, PROP_P2P_GROUP_PATH);
			g_clear_object (&priv->group_proxy);
		}
	}

	g_object_thaw_notify (G_OBJECT (self));
}

static void
p2p_device_found (GDBusProxy *proxy,
                  const char *path,
                  gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);

	peer_add_new (self, path);
}

static void
p2p_device_lost (GDBusProxy *proxy,
                 const char *path,
                 gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	PeerData *peer_data;

	peer_data = g_hash_table_lookup (priv->peer_proxies, path);
	if (!peer_data)
		return;
	g_hash_table_steal (priv->peer_proxies, path);
	g_signal_emit (self, signals[PEER_REMOVED], 0, path);
	peer_data_destroy (peer_data);
}

static void
p2p_group_started (GDBusProxy *proxy,
                   GVariant *params,
                   gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantInterface *iface = NULL;
	char *group_path = NULL;
	char *iface_path = NULL;

	/* There is one more parameter: the role, but we don't really care about that here. */
	if (!g_variant_lookup (params, "group_object", "&o", &group_path)) {
		_LOGW ("P2P: GroupStarted signal is missing the \"group_object\" parameter");
		return;
	}

	if (!g_variant_lookup (params, "interface_object", "&o", &iface_path)) {
		_LOGW ("P2P: GroupStarted signal is missing the \"interface\" parameter");
		return;
	}

	if (g_strcmp0 (iface_path, priv->object_path) == 0) {
		_LOGW ("P2P: GroupStarted on existing interface");
		iface = g_object_ref (self);
	} else {
		iface = nm_supplicant_manager_create_interface_from_path (nm_supplicant_manager_get (),
		                                                          iface_path);
		if (iface == NULL) {
			_LOGW ("P2P: Group interface already exists in GroupStarted handler, aborting further processing.");
			return;
		}
	}

	/* Signal existence of the (new) interface. */
	g_signal_emit (self, signals[GROUP_STARTED], 0, iface);
	g_object_unref (iface);
}

static void
p2p_group_finished (GDBusProxy *proxy,
                    GVariant *params,
                    gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	const char *iface_path = NULL;
	/* TODO: Group finished is called on the management interface!
	 *       This means the signal consumer will currently need to assume which
	 *       interface is finishing or it needs to match the object paths.
	 */

	if (!g_variant_lookup (params, "interface_object", "&o", &iface_path)) {
		_LOGW ("P2P: GroupFinished signal is missing the \"interface\" parameter");
		return;
	}

	_LOGD ("P2P: GroupFinished signal on interface %s for interface %s", priv->object_path, iface_path);

	/* Signal group finish interface (on management interface). */
	g_signal_emit (self, signals[GROUP_FINISHED], 0, iface_path);
}

static void
on_iface_proxy_acquired (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_free_error GError *error = NULL;

	if (!g_async_initable_init_finish (G_ASYNC_INITABLE (proxy), result, &error)) {
		if (!nm_utils_error_is_cancelled (error)) {
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
	_nm_dbus_signal_connect (priv->iface_proxy, "EAP", G_VARIANT_TYPE ("(ss)"),
	                         G_CALLBACK (eap_changed), self);

	/* Scan result aging parameters */
	g_dbus_proxy_call (priv->iface_proxy,
	                   DBUS_INTERFACE_PROPERTIES ".Set",
	                   g_variant_new ("(ssv)",
	                                  NM_WPAS_DBUS_IFACE_INTERFACE,
	                                  "BSSExpireAge",
	                                  g_variant_new_uint32 (250)),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->init_cancellable,
	                   NULL,
	                   NULL);
	g_dbus_proxy_call (priv->iface_proxy,
	                   DBUS_INTERFACE_PROPERTIES ".Set",
	                   g_variant_new ("(ssv)",
	                                  NM_WPAS_DBUS_IFACE_INTERFACE,
	                                  "BSSExpireCount",
	                                  g_variant_new_uint32 (2)),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->init_cancellable,
	                   NULL,
	                   NULL);

	if (_get_capability (priv, NM_SUPPL_CAP_TYPE_PMF) == NM_TERNARY_TRUE) {
		/* Initialize global PMF setting to 'optional' */
		priv->ready_count++;
		g_dbus_proxy_call (priv->iface_proxy,
		                   DBUS_INTERFACE_PROPERTIES ".Set",
		                   g_variant_new ("(ssv)",
		                                  NM_WPAS_DBUS_IFACE_INTERFACE,
		                                  "Pmf",
		                                  g_variant_new_string ("1")),
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->init_cancellable,
		                   (GAsyncReadyCallback) iface_set_pmf_cb,
		                   self);
	}

	if (_get_capability (priv, NM_SUPPL_CAP_TYPE_AP) == NM_TERNARY_DEFAULT) {
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

	iface_check_ready (self);
}

static void
on_p2p_proxy_acquired (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_free_error GError *error = NULL;

	if (!g_async_initable_init_finish (G_ASYNC_INITABLE (proxy), result, &error)) {
		if (!nm_utils_error_is_cancelled (error)) {
			self = NM_SUPPLICANT_INTERFACE (user_data);
			priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
			_LOGW ("failed to acquire wpa_supplicant p2p proxy: (%s)", error->message);

			g_clear_object (&priv->p2p_proxy);

			iface_check_ready (self);
		}
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	_nm_dbus_signal_connect (priv->p2p_proxy, "DeviceFound", G_VARIANT_TYPE ("(o)"),
	                         G_CALLBACK (p2p_device_found), self);
	_nm_dbus_signal_connect (priv->p2p_proxy, "DeviceLost", G_VARIANT_TYPE ("(o)"),
	                         G_CALLBACK (p2p_device_lost), self);
	_nm_dbus_signal_connect (priv->p2p_proxy, "GroupStarted", G_VARIANT_TYPE ("(a{sv})"),
	                         G_CALLBACK (p2p_group_started), self);
	_nm_dbus_signal_connect (priv->p2p_proxy, "GroupFinished", G_VARIANT_TYPE ("(a{sv})"),
	                         G_CALLBACK (p2p_group_finished), self);
	/* TODO:
	 *  * WpsFailed
	 *  * FindStopped
	 *  * GONegotationFailure
	 *  * InvitationReceived
	 */

	priv->p2p_proxy_acquired = TRUE;
	_notify (self, PROP_P2P_AVAILABLE);

	iface_check_ready (self);
}

static void
interface_add_done (NMSupplicantInterface *self, const char *path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	_LOGD ("interface added to supplicant");

	priv->ready_count = 1;

	priv->object_path = g_strdup (path);
	_notify (self, PROP_OBJECT_PATH);
	priv->iface_proxy = g_object_new (G_TYPE_DBUS_PROXY,
	                                  "g-bus-type", G_BUS_TYPE_SYSTEM,
	                                  "g-flags", G_DBUS_PROXY_FLAGS_NONE,
	                                  "g-name", NM_WPAS_DBUS_SERVICE,
	                                  "g-object-path", priv->object_path,
	                                  "g-interface-name", NM_WPAS_DBUS_IFACE_INTERFACE,
	                                  NULL);
	g_signal_connect (priv->iface_proxy, "g-properties-changed", G_CALLBACK (props_changed_cb), self);
	g_async_initable_init_async (G_ASYNC_INITABLE (priv->iface_proxy),
	                             G_PRIORITY_DEFAULT,
	                             priv->init_cancellable,
	                             (GAsyncReadyCallback) on_iface_proxy_acquired,
	                             self);

	if (_get_capability (priv, NM_SUPPL_CAP_TYPE_P2P) == NM_TERNARY_TRUE) {
		priv->ready_count++;
		priv->p2p_proxy = g_object_new (G_TYPE_DBUS_PROXY,
		                                "g-bus-type", G_BUS_TYPE_SYSTEM,
		                                "g-flags", G_DBUS_PROXY_FLAGS_NONE,
		                                "g-name", NM_WPAS_DBUS_SERVICE,
		                                "g-object-path", priv->object_path,
		                                "g-interface-name", NM_WPAS_DBUS_IFACE_INTERFACE_P2P_DEVICE,
		                                NULL);
		g_signal_connect (priv->p2p_proxy, "g-properties-changed", G_CALLBACK (p2p_props_changed_cb), self);
		g_async_initable_init_async (G_ASYNC_INITABLE (priv->p2p_proxy),
		                             G_PRIORITY_DEFAULT,
		                             priv->init_cancellable,
		                             (GAsyncReadyCallback) on_p2p_proxy_acquired,
		                             self);
	}
}

static void
interface_get_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	gs_unref_variant GVariant *variant = NULL;
	gs_free_error GError *error = NULL;
	const char *path;

	variant = _nm_dbus_proxy_call_finish (proxy, result,
	                                      G_VARIANT_TYPE ("(o)"),
	                                      &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);

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
	if (nm_utils_error_is_cancelled (error))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (variant) {
		g_variant_get (variant, "(&o)", &path);
		interface_add_done (self, path);
	} else if (_nm_dbus_error_has_name (error, NM_WPAS_ERROR_EXISTS_ERROR)) {
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

static void
interface_removed_cb (GDBusProxy *proxy,
                      const char *path,
                      gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (g_strcmp0 (priv->object_path, path) != 0)
		return;

	_LOGD ("Received interface removed signal");

	/* The interface may lose its last reference during signal handling otherwise. */
	g_object_ref (self);

	/* Invalidate the object path to prevent the manager from trying to remove
	 * a non-existing interface. */
	g_clear_pointer (&priv->object_path, g_free);
	_notify (self, PROP_OBJECT_PATH);

	/* No need to clean up everything now, that will happen at dispose time. */

	/* Interface is down and has been removed. */
	set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
	g_signal_emit (self, signals[REMOVED], 0);

	g_object_unref (self);
}

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
		if (!nm_utils_error_is_cancelled (error)) {
			self = NM_SUPPLICANT_INTERFACE (user_data);
			_LOGW ("failed to acquire wpa_supplicant proxy: (%s)", error->message);
			set_state (self, NM_SUPPLICANT_INTERFACE_STATE_DOWN);
		}
		return;
	}

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->wpas_proxy = wpas_proxy;

	/* Watch for interface removal. */
	_nm_dbus_signal_connect (priv->wpas_proxy, "InterfaceRemoved", G_VARIANT_TYPE ("(o)"),
	                         G_CALLBACK (interface_removed_cb), self);

	/* Try to add the interface to the supplicant.  If the supplicant isn't
	 * running, this will start it via D-Bus activation and return the response
	 * when the supplicant has started.
	 */

	if (priv->dev != NULL) {
		const char *driver_name = NULL;

		switch (priv->driver) {
		case NM_SUPPLICANT_DRIVER_WIRELESS:
			driver_name = NM_WPAS_DEFAULT_WIFI_DRIVER;
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
	} else if (priv->object_path) {
		interface_add_done (self, priv->object_path);
	} else {
		g_assert_not_reached ();
	}
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
	                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
	                          NULL,
	                          NM_WPAS_DBUS_SERVICE,
	                          NM_WPAS_DBUS_PATH,
	                          NM_WPAS_DBUS_INTERFACE,
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
	    && !nm_utils_error_is_cancelled (error)
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
		gs_free_error GError *error = NULL;

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

	/* Cancel any WPS enrollment, if any */
	nm_supplicant_interface_cancel_wps (self);
}

static void
disconnect_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	DisconnectData *disconnect_data = user_data;
	gs_unref_object NMSupplicantInterface *self = disconnect_data->self;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &error);

	/* an already disconnected interface is not an error*/
	if (   !reply
	    && !strstr (error->message, "fi.w1.wpa_supplicant1.NotConnected")) {
		g_clear_error(&error);
	}

	disconnect_data->callback(self, error, disconnect_data->user_data);
	g_slice_free (DisconnectData, disconnect_data);
}

void
nm_supplicant_interface_disconnect_async ( NMSupplicantInterface * self,
                                           GCancellable * cancellable,
                                           NMSupplicantInterfaceDisconnectCb callback,
                                           gpointer user_data)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	DisconnectData *disconnect_data;

	/* Don't do anything if there is no connection to the supplicant yet. */
	if (!priv->iface_proxy)
		return;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));
	g_return_if_fail (NULL != callback);

	disconnect_data = g_slice_new0(DisconnectData);

	/* Keep interface alive until disconnect finishes */
	disconnect_data->self = g_object_ref (self);
	disconnect_data->callback = callback;
	disconnect_data->user_data = user_data;

	/* Disconnect the interface */
	g_dbus_proxy_call (priv->iface_proxy,
	                   "Disconnect",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   cancellable,
	                   (GAsyncReadyCallback) disconnect_cb,
	                   disconnect_data);
}

static void
assoc_select_network_cb (GDBusProxy *proxy, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	gs_unref_variant GVariant *reply = NULL;
	gs_free_error GError *error = NULL;

	reply = g_dbus_proxy_call_finish (proxy, result, &error);
	if (nm_utils_error_is_cancelled (error))
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
	if (nm_utils_error_is_cancelled (error))
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
	GBytes *blob_data;

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
			                                  nm_utils_gbytes_to_variant_ay (blob_data)),
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
	if (nm_utils_error_is_cancelled (error))
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
	if (   _get_capability (priv, NM_SUPPL_CAP_TYPE_FAST) == NM_TERNARY_FALSE
	    && nm_supplicant_config_fast_required (cfg)) {
		assoc_data->fail_on_idle_id = g_idle_add (assoc_fail_on_idle_cb, self);
		return;
	}

	assoc_data->cancellable = g_cancellable_new();
	g_dbus_proxy_call (priv->iface_proxy,
	                   DBUS_INTERFACE_PROPERTIES ".Set",
	                   g_variant_new ("(ssv)",
	                                  NM_WPAS_DBUS_IFACE_INTERFACE,
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
	if (nm_utils_error_is_cancelled (error))
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
nm_supplicant_interface_request_scan (NMSupplicantInterface *self,
                                      GBytes *const*ssids,
                                      guint ssids_len)
{
	NMSupplicantInterfacePrivate *priv;
	GVariantBuilder builder;
	guint i;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Scan parameters */
	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&builder, "{sv}", "Type", g_variant_new_string ("active"));
	g_variant_builder_add (&builder, "{sv}", "AllowRoam", g_variant_new_boolean (FALSE));
	if (ssids_len > 0) {
		GVariantBuilder ssids_builder;

		g_variant_builder_init (&ssids_builder, G_VARIANT_TYPE_BYTESTRING_ARRAY);
		for (i = 0; i < ssids_len; i++) {
			nm_assert (ssids[i]);
			g_variant_builder_add (&ssids_builder, "@ay",
			                       nm_utils_gbytes_to_variant_ay (ssids[i]));
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

void
nm_supplicant_interface_p2p_start_find (NMSupplicantInterface *self,
                                        guint timeout)
{
	NMSupplicantInterfacePrivate *priv;
	GVariantBuilder builder;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));
	g_return_if_fail (timeout > 0 && timeout <= 600);

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&builder, "{sv}", "Timeout", g_variant_new_int32 (timeout));

	g_dbus_proxy_call (priv->p2p_proxy,
	                   "Find",
	                   g_variant_new ("(a{sv})", &builder),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->other_cancellable,
	                   (GAsyncReadyCallback) log_result_cb,
	                   self);
}

void
nm_supplicant_interface_p2p_stop_find (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_dbus_proxy_call (priv->p2p_proxy,
	                   "StopFind",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->other_cancellable,
	                   (GAsyncReadyCallback) scan_request_cb,
	                   self);
}

/*****************************************************************************/

void
nm_supplicant_interface_p2p_connect (NMSupplicantInterface * self,
                                     const char * peer,
                                     const char * wps_method,
                                     const char * wps_pin)
{
	NMSupplicantInterfacePrivate *priv;
	GVariantBuilder builder;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Don't do anything if there is no connection to the supplicant yet. */
	if (!priv->p2p_proxy || !priv->object_path)
		return;

	/* Connect parameters */
	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	g_variant_builder_add (&builder, "{sv}", "wps_method", g_variant_new_string (wps_method));

	if (wps_pin)
		g_variant_builder_add (&builder, "{sv}", "pin", g_variant_new_string (wps_pin));

	g_variant_builder_add (&builder, "{sv}", "peer", g_variant_new_object_path (peer));

	g_variant_builder_add (&builder, "{sv}", "join", g_variant_new_boolean (FALSE));
	g_variant_builder_add (&builder, "{sv}", "persistent", g_variant_new_boolean (FALSE));
	g_variant_builder_add (&builder, "{sv}", "go_intent", g_variant_new_int32 (7));

	g_dbus_proxy_call (priv->p2p_proxy,
	                   "Connect",
	                   g_variant_new ("(a{sv})", &builder),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->other_cancellable,
	                   (GAsyncReadyCallback) log_result_cb,
	                   "p2p connect");
}

void
nm_supplicant_interface_p2p_cancel_connect (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Don't do anything if there is no connection to the supplicant yet. */
	if (!priv->p2p_proxy || !priv->object_path)
		return;

	g_dbus_proxy_call (priv->p2p_proxy,
	                   "Cancel",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->other_cancellable,
	                   (GAsyncReadyCallback) log_result_cb,
	                   "cancel p2p connect");
}

void
nm_supplicant_interface_p2p_disconnect (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	/* Don't do anything if there is no connection to the supplicant. */
	if (!priv->p2p_proxy || !priv->object_path)
		return;

	g_dbus_proxy_call (priv->p2p_proxy,
	                   "Disconnect",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1,
	                   priv->other_cancellable,
	                   (GAsyncReadyCallback) log_result_cb,
	                   "p2p disconnect");
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
	case PROP_P2P_GROUP_JOINED:
		g_value_set_boolean (value, priv->p2p_capable && priv->group_proxy_acquired);
		break;
	case PROP_P2P_GROUP_PATH:
		g_value_set_string (value, nm_supplicant_interface_get_p2p_group_path (NM_SUPPLICANT_INTERFACE (object)));
		break;
	case PROP_P2P_GROUP_OWNER:
		g_value_set_boolean (value, priv->p2p_group_owner);
		break;
	case PROP_P2P_AVAILABLE:
		g_value_set_boolean (value, priv->p2p_capable && priv->p2p_proxy_acquired);
		break;
	case PROP_AUTH_STATE:
		g_value_set_uint (value, priv->auth_state);
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
		break;
	case PROP_OBJECT_PATH:
		/* construct-only */
		priv->object_path = g_value_dup_string (value);
		break;
	case PROP_DRIVER:
		/* construct-only */
		priv->driver = g_value_get_uint (value);
		break;
	case PROP_GLOBAL_CAPABILITIES:
		/* construct-only */
		priv->global_capabilities = g_value_get_uint64 (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_supplicant_interface_init (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_SUPPLICANT_INTERFACE, NMSupplicantInterfacePrivate);

	self->_priv = priv;

	c_list_init (&self->supp_lst);

	nm_assert (priv->global_capabilities == NM_SUPPL_CAP_MASK_NONE);
	nm_assert (priv->iface_capabilities == NM_SUPPL_CAP_MASK_NONE);

	priv->state = NM_SUPPLICANT_INTERFACE_STATE_INIT;
	priv->bss_proxies = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, bss_data_destroy);
	priv->peer_proxies = g_hash_table_new_full (nm_str_hash, g_str_equal, NULL, peer_data_destroy);
}

NMSupplicantInterface *
nm_supplicant_interface_new (const char *ifname,
                             const char *object_path,
                             NMSupplicantDriver driver,
                             NMSupplCapMask global_capabilities)
{
	/* One of ifname or path need to be set */
	g_return_val_if_fail ((ifname != NULL) != (object_path != NULL), NULL);

	return g_object_new (NM_TYPE_SUPPLICANT_INTERFACE,
	                     NM_SUPPLICANT_INTERFACE_IFACE, ifname,
	                     NM_SUPPLICANT_INTERFACE_OBJECT_PATH, object_path,
	                     NM_SUPPLICANT_INTERFACE_DRIVER, (guint) driver,
	                     NM_SUPPLICANT_INTERFACE_GLOBAL_CAPABILITIES, (guint64) global_capabilities,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (object);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	nm_assert (c_list_is_empty (&self->supp_lst));

	nm_supplicant_interface_cancel_wps (self);
	if (priv->wps_data) {
		/* we shut down, but an asynchronous Cancel request is pending.
		 * We don't want to cancel it, so mark wps-data that @self is gone.
		 * This way, _wps_handle_cancel_cb() knows it must no longer touch
		 * @self */
		priv->wps_data->self = NULL;
		priv->wps_data = NULL;
	}

	if (priv->assoc_data) {
		gs_free_error GError *error = NULL;

		nm_utils_error_set_cancelled (&error, TRUE, "NMSupplicantInterface");
		assoc_return (self, error, "cancelled due to dispose of supplicant interface");
	}

	if (priv->iface_proxy)
		g_signal_handlers_disconnect_by_data (priv->iface_proxy, object);
	g_clear_object (&priv->iface_proxy);
	if (priv->p2p_proxy)
		g_signal_handlers_disconnect_by_data (priv->p2p_proxy, object);
	g_clear_object (&priv->p2p_proxy);
	if (priv->group_proxy)
		g_signal_handlers_disconnect_by_data (priv->group_proxy, object);
	g_clear_object (&priv->group_proxy);

	nm_clear_g_cancellable (&priv->init_cancellable);
	nm_clear_g_cancellable (&priv->other_cancellable);

	if (priv->wpas_proxy)
		g_signal_handlers_disconnect_by_data (priv->wpas_proxy, object);
	g_clear_object (&priv->wpas_proxy);
	g_clear_pointer (&priv->bss_proxies, g_hash_table_destroy);
	g_clear_pointer (&priv->peer_proxies, g_hash_table_destroy);

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

	g_type_class_add_private (object_class, sizeof (NMSupplicantInterfacePrivate));

	object_class->dispose      = dispose;
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
	obj_properties[PROP_OBJECT_PATH] =
	    g_param_spec_string (NM_SUPPLICANT_INTERFACE_OBJECT_PATH, "", "",
	                         NULL,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_P2P_GROUP_JOINED] =
	    g_param_spec_boolean (NM_SUPPLICANT_INTERFACE_P2P_GROUP_JOINED, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_P2P_GROUP_PATH] =
	    g_param_spec_string (NM_SUPPLICANT_INTERFACE_P2P_GROUP_PATH, "", "",
	                         NULL,
	                         G_PARAM_READABLE |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_P2P_GROUP_OWNER] =
	    g_param_spec_boolean (NM_SUPPLICANT_INTERFACE_P2P_GROUP_OWNER, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DRIVER] =
	    g_param_spec_uint (NM_SUPPLICANT_INTERFACE_DRIVER, "", "",
	                       0, G_MAXUINT, NM_SUPPLICANT_DRIVER_WIRELESS,
	                       G_PARAM_WRITABLE |
	                       G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_P2P_AVAILABLE] =
	    g_param_spec_boolean (NM_SUPPLICANT_INTERFACE_P2P_AVAILABLE, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_GLOBAL_CAPABILITIES] =
	    g_param_spec_uint64 (NM_SUPPLICANT_INTERFACE_GLOBAL_CAPABILITIES, "", "",
	                         0,
	                         NM_SUPPL_CAP_MASK_ALL,
	                         0,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_AUTH_STATE] =
	    g_param_spec_uint (NM_SUPPLICANT_INTERFACE_AUTH_STATE, "", "",
	                       NM_SUPPLICANT_AUTH_STATE_UNKNOWN,
	                       _NM_SUPPLICANT_AUTH_STATE_NUM - 1,
	                       NM_SUPPLICANT_AUTH_STATE_UNKNOWN,
	                       G_PARAM_READABLE |
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

	signals[PEER_UPDATED] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_PEER_UPDATED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_STRING, G_TYPE_VARIANT);

	signals[PEER_REMOVED] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_PEER_REMOVED,
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

	signals[WPS_CREDENTIALS] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_WPS_CREDENTIALS,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_VARIANT);

	signals[GROUP_STARTED] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_GROUP_STARTED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, NM_TYPE_SUPPLICANT_INTERFACE);

	signals[GROUP_FINISHED] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_GROUP_FINISHED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_STRING);
}
