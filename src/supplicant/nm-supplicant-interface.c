// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2006 - 2017 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-supplicant-interface.h"

#include <stdio.h>

#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"
#include "nm-glib-aux/nm-c-list.h"
#include "nm-glib-aux/nm-ref-string.h"
#include "nm-std-aux/nm-dbus-compat.h"
#include "nm-supplicant-config.h"
#include "nm-supplicant-manager.h"
#include "shared/nm-glib-aux/nm-dbus-aux.h"

#define DBUS_TIMEOUT_MSEC 20000

/*****************************************************************************/

typedef struct {
	NMSupplicantInterface *self;
	char *type;
	char *bssid;
	char *pin;
	guint signal_id;
	GCancellable *cancellable;
	bool needs_cancelling:1;
	bool is_cancelling:1;
} WpsData;

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
	NMRefString *name_owner;
	NMRefString *object_path;
	GObject *shutdown_wait_obj;
} AddNetworkData;

enum {
	STATE,                   /* change in the interface's state */
	BSS_CHANGED,             /* a new BSS appeared, was updated, or was removed. */
	PEER_CHANGED,            /* a new Peer appeared, was updated, or was removed */
	WPS_CREDENTIALS,         /* WPS credentials received */
	GROUP_STARTED,           /* a new Group (interface) was created */
	GROUP_FINISHED,          /* a Group (interface) has been finished */
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

NM_GOBJECT_PROPERTIES_DEFINE (NMSupplicantInterface,
	PROP_SUPPLICANT_MANAGER,
	PROP_DBUS_OBJECT_PATH,
	PROP_IFINDEX,
	PROP_P2P_GROUP_JOINED,
	PROP_P2P_GROUP_PATH,
	PROP_P2P_GROUP_OWNER,
	PROP_SCANNING,
	PROP_CURRENT_BSS,
	PROP_DRIVER,
	PROP_P2P_AVAILABLE,
	PROP_AUTH_STATE,
);

typedef struct _NMSupplicantInterfacePrivate {

	NMSupplicantManager *supplicant_manager;

	GDBusConnection *dbus_connection;
	NMRefString *name_owner;
	NMRefString *object_path;

	char          *ifname;

	GCancellable  *main_cancellable;

	NMRefString   *p2p_group_path;

	GCancellable  *p2p_group_properties_cancellable;

	WpsData       *wps_data;

	AssocData     *assoc_data;

	char          *net_path;

	char          *driver;

	GHashTable    *bss_idx;
	CList          bss_lst_head;
	CList          bss_initializing_lst_head;

	NMRefString   *current_bss;

	GHashTable    *peer_idx;
	CList          peer_lst_head;
	CList          peer_initializing_lst_head;

	gint64         last_scan_msec;

	NMSupplicantAuthState auth_state;

	NMSupplicantDriver requested_driver;
	NMSupplCapMask global_capabilities;
	NMSupplCapMask iface_capabilities;

	guint          properties_changed_id;
	guint          signal_id;
	guint          bss_properties_changed_id;
	guint          peer_properties_changed_id;
	guint          p2p_group_properties_changed_id;

	int            ifindex;

	int            starting_pending_count;

	guint32        max_scan_ssids;

	gint32         disconnect_reason;

	NMSupplicantInterfaceState state;
	NMSupplicantInterfaceState supp_state;

	bool           scanning_property:1;
	bool           scanning_cached:1;

	bool           p2p_capable_property:1;
	bool           p2p_capable_cached:1;

	bool           p2p_group_owner_property:1;
	bool           p2p_group_owner_cached:1;

	bool           p2p_group_joined_cached:1;

	bool           is_ready_main:1;
	bool           is_ready_p2p_device:1;

} NMSupplicantInterfacePrivate;

struct _NMSupplicantInterfaceClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMSupplicantInterface, nm_supplicant_interface, G_TYPE_OBJECT)

#define NM_SUPPLICANT_INTERFACE_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR (self, NMSupplicantInterface, NM_IS_SUPPLICANT_INTERFACE)

/*****************************************************************************/

static const char *
_log_pretty_object_path (NMSupplicantInterfacePrivate *priv)
{
	const char *s;

	nm_assert (priv);
	nm_assert (NM_IS_REF_STRING (priv->object_path));

	s = priv->object_path->str;
	if (NM_STR_HAS_PREFIX (s, "/fi/w1/wpa_supplicant1/Interfaces/")) {
		s += NM_STRLEN ("/fi/w1/wpa_supplicant1/Interfaces/");
		if (   s[0]
		    && s[0] != '/')
			return s;
	}
	return priv->object_path->str;
}

#define _NMLOG_DOMAIN           LOGD_SUPPLICANT
#define _NMLOG_PREFIX_NAME      "sup-iface"
#define _NMLOG(level, ...) \
    G_STMT_START { \
         NMSupplicantInterface *_self = (self); \
         NMSupplicantInterfacePrivate *_priv = _self ? NM_SUPPLICANT_INTERFACE_GET_PRIVATE (_self) : NULL; \
         char _sbuf[255]; \
         const char *_ifname = _priv ? _priv->ifname : NULL; \
         \
         nm_log ((level), _NMLOG_DOMAIN, _ifname, NULL, \
                 "%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                 _NMLOG_PREFIX_NAME, \
                 (  _self \
                  ? nm_sprintf_buf (_sbuf, \
                                    "["NM_HASH_OBFUSCATE_PTR_FMT",%s,%s]", \
                                    NM_HASH_OBFUSCATE_PTR (_self), \
                                    _log_pretty_object_path (_priv), \
                                    _ifname ?: "???") \
                  : "") \
                 _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

static void _starting_check_ready (NMSupplicantInterface *self);

static void assoc_return (NMSupplicantInterface *self,
                          GError *error,
                          const char *message);

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE (nm_supplicant_interface_state_to_string, NMSupplicantInterfaceState,
	NM_UTILS_LOOKUP_DEFAULT_WARN ("internal-unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_INVALID,         "internal-invalid"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_STARTING,        "internal-starting"),

	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_4WAY_HANDSHAKE,  "4way_handshake"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATED,      "associated"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_ASSOCIATING,     "associating"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_AUTHENTICATING,  "authenticating"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_COMPLETED,       "completed"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED,    "disconnected"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_GROUP_HANDSHAKE, "group_handshake"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_INACTIVE,        "inactive"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_DISABLED,        "interface_disabled"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_SCANNING,        "scanning"),

	NM_UTILS_LOOKUP_STR_ITEM (NM_SUPPLICANT_INTERFACE_STATE_DOWN,            "internal-down"),
);

static
NM_UTILS_STRING_TABLE_LOOKUP_DEFINE (
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

static NM80211ApSecurityFlags
security_from_vardict (GVariant *security)
{
	NM80211ApSecurityFlags flags = NM_802_11_AP_SEC_NONE;
	const char **array;
	const char *tmp;

	nm_assert (g_variant_is_of_type (security, G_VARIANT_TYPE_VARDICT));

	if (g_variant_lookup (security, "KeyMgmt", "^a&s", &array)) {
		if (g_strv_contains (array, "wpa-psk") ||
		    g_strv_contains (array, "wpa-ft-psk"))
			flags |= NM_802_11_AP_SEC_KEY_MGMT_PSK;
		if (g_strv_contains (array, "wpa-eap") ||
		    g_strv_contains (array, "wpa-ft-eap") ||
		    g_strv_contains (array, "wpa-fils-sha256") ||
		    g_strv_contains (array, "wpa-fils-sha384"))
			flags |= NM_802_11_AP_SEC_KEY_MGMT_802_1X;
		if (g_strv_contains (array, "sae"))
			flags |= NM_802_11_AP_SEC_KEY_MGMT_SAE;
		if (g_strv_contains (array, "owe"))
			flags |= NM_802_11_AP_SEC_KEY_MGMT_OWE;
		g_free (array);
	}

	if (g_variant_lookup (security, "Pairwise", "^a&s", &array)) {
		if (g_strv_contains (array, "tkip"))
			flags |= NM_802_11_AP_SEC_PAIR_TKIP;
		if (g_strv_contains (array, "ccmp"))
			flags |= NM_802_11_AP_SEC_PAIR_CCMP;
		g_free (array);
	}

	if (g_variant_lookup (security, "Group", "&s", &tmp)) {
		if (nm_streq (tmp, "wep40"))
			flags |= NM_802_11_AP_SEC_GROUP_WEP40;
		else if (nm_streq (tmp, "wep104"))
			flags |= NM_802_11_AP_SEC_GROUP_WEP104;
		else if (nm_streq (tmp, "tkip"))
			flags |= NM_802_11_AP_SEC_GROUP_TKIP;
		else if (nm_streq (tmp, "ccmp"))
			flags |= NM_802_11_AP_SEC_GROUP_CCMP;
	}

	return flags;
}

/*****************************************************************************/

/* Various conditions prevent _starting_check_ready() from completing. For example,
 * bss_initializing_lst_head, peer_initializing_lst_head and p2p_group_properties_cancellable.
 * At some places, these conditions might toggle, and it would seems we would have
 * to call _starting_check_ready() at that point, to ensure we don't miss a state
 * change that we are ready. However, these places are deep in the call stack and
 * not suitable to perform this state change. Instead, the callers *MUST* have
 * added their own starting_pending_count to delay _starting_check_ready().
 *
 * Assert that is the case. */
#define nm_assert_starting_has_pending_count(v) nm_assert ((v) > 0)

/*****************************************************************************/

static void
_dbus_connection_call (NMSupplicantInterface *self,
                       const char *interface_name,
                       const char *method_name,
                       GVariant *parameters,
                       const GVariantType *reply_type,
                       GDBusCallFlags flags,
                       int timeout_msec,
                       GCancellable *cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_dbus_connection_call (priv->dbus_connection,
	                        priv->name_owner->str,
	                        priv->object_path->str,
	                        interface_name,
	                        method_name,
	                        parameters,
	                        reply_type,
	                        flags,
	                        timeout_msec,
	                        cancellable,
	                        callback,
	                        user_data);
}

static void
_dbus_connection_call_simple_cb (GObject *source,
                                 GAsyncResult *result,
                                 gpointer user_data)
{
	NMSupplicantInterface *self;
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;
	const char *log_reason;
	gs_free char *remote_error = NULL;

	nm_utils_user_data_unpack (user_data, &self, &log_reason);

	res = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	if (res) {
		_LOGT ("call-%s: success", log_reason);
		return;
	}

	remote_error = g_dbus_error_get_remote_error (error);
	if (!nm_streq0 (remote_error, "fi.w1.wpa_supplicant1.NotConnected")) {
		g_dbus_error_strip_remote_error (error);
		_LOGW ("call-%s: failed with %s", log_reason, error->message);
		return;
	}

	_LOGT ("call-%s: failed with %s", log_reason, error->message);
}

static void
_dbus_connection_call_simple (NMSupplicantInterface *self,
                              const char *interface_name,
                              const char *method_name,
                              GVariant *parameters,
                              const GVariantType *reply_type,
                              const char *log_reason)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	_dbus_connection_call (self,
	                       interface_name,
	                       method_name,
	                       parameters,
	                       reply_type,
	                       G_DBUS_CALL_FLAGS_NONE,
	                       DBUS_TIMEOUT_MSEC,
	                       priv->main_cancellable,
	                       _dbus_connection_call_simple_cb,
	                       nm_utils_user_data_pack (self, log_reason));
}

/*****************************************************************************/

static void
_emit_signal_state (NMSupplicantInterface *self,
                    NMSupplicantInterfaceState new_state,
                    NMSupplicantInterfaceState old_state,
                    gint32 disconnect_reason)
{
	g_signal_emit (self,
	               signals[STATE],
	               0,
	               (int) new_state,
	               (int) old_state,
	               (int) disconnect_reason);
}

/*****************************************************************************/

static void
_remove_network (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gs_free char *net_path = NULL;

	if (!priv->net_path)
		return;

	net_path = g_steal_pointer (&priv->net_path);
	_dbus_connection_call_simple (self,
	                              NM_WPAS_DBUS_IFACE_INTERFACE,
	                              "RemoveNetwork",
	                              g_variant_new ("(o)", net_path),
	                              G_VARIANT_TYPE ("()"),
	                              "remove-network");
}

/*****************************************************************************/

static void
_notify_maybe_scanning (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gboolean scanning;

	scanning =   nm_supplicant_interface_state_is_operational (priv->state)
	          && (   priv->scanning_property
	              || priv->supp_state == NM_SUPPLICANT_INTERFACE_STATE_SCANNING);

	if (priv->scanning_cached == scanning)
		return;

	if (   !scanning
	    && !c_list_is_empty (&priv->bss_initializing_lst_head)) {
		/* we would change state to indicate we no longer scan. However,
		 * we still have BSS instances to be initialized. Delay the
		 * state change further. */
		return;
	}

	_LOGT ("scanning: %s", scanning ? "yes" : "no");

	if (!scanning)
		priv->last_scan_msec = nm_utils_get_monotonic_timestamp_msec ();
	else {
		/* while we are scanning, we set the timestamp to -1. */
		priv->last_scan_msec = -1;
	}
	priv->scanning_cached = scanning;
	_notify (self, PROP_SCANNING);
}

static void
_notify_maybe_p2p_available (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gboolean value;

	value =    priv->is_ready_p2p_device
	        && priv->p2p_capable_property;

	if (priv->p2p_capable_cached == value)
		return;

	priv->p2p_capable_cached = value;
	_notify (self, PROP_P2P_AVAILABLE);
}

static void
_notify_maybe_p2p_group (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gboolean value_joined;
	gboolean value_owner;
	gboolean joined_changed;
	gboolean owner_changed;

	value_joined =    priv->p2p_group_path
	               && !priv->p2p_group_properties_cancellable;
	value_owner =    value_joined
	              && priv->p2p_group_owner_property;

	if ((joined_changed = (priv->p2p_group_joined_cached != value_joined)))
		priv->p2p_group_joined_cached = value_joined;

	if ((owner_changed = (priv->p2p_group_owner_cached != value_owner)))
		priv->p2p_group_owner_cached = value_owner;

	if (joined_changed)
		_notify (self, PROP_P2P_GROUP_JOINED);
	if (owner_changed)
		_notify (self, PROP_P2P_GROUP_OWNER);
}

/*****************************************************************************/

static void
_bss_info_destroy (NMSupplicantBssInfo *bss_info)
{
	c_list_unlink_stale (&bss_info->_bss_lst);
	nm_clear_g_cancellable (&bss_info->_init_cancellable);
	g_bytes_unref (bss_info->ssid);
	nm_ref_string_unref (bss_info->bss_path);
	nm_g_slice_free (bss_info);
}

static void
_bss_info_changed_emit (NMSupplicantInterface *self,
                        NMSupplicantBssInfo *bss_info,
                        gboolean is_present)
{
	_LOGT ("BSS %s %s",
	       bss_info->bss_path->str,
	       is_present ? "updated" : "deleted");
	g_signal_emit (self,
	               signals[BSS_CHANGED],
	               0,
	               bss_info,
	               is_present);
}

static void
_bss_info_properties_changed (NMSupplicantInterface *self,
                              NMSupplicantBssInfo *bss_info,
                              GVariant *properties,
                              gboolean initial)
{
	gboolean v_b;
	GVariant *v_v;
	const char *v_s;
	gint16 v_i16;
	guint16 v_u16;
	guint32 v_u32;
	NM80211ApFlags p_ap_flags;
	NM80211Mode p_mode;
	guint8 p_signal_percent;
	const guint8 *arr_data;
	gsize arr_len;
	guint32 p_max_rate;
	gboolean p_max_rate_has;
	gint64 now_msec = 0;

	if (nm_g_variant_lookup (properties, "Age", "u", &v_u32)) {
		bss_info->last_seen_msec =   nm_utils_get_monotonic_timestamp_msec_cached (&now_msec)
		                           - (((gint64) v_u32) * 1000);
	} else if (initial) {
		/* Unknown Age. Assume we just received it. */
		bss_info->last_seen_msec = nm_utils_get_monotonic_timestamp_msec_cached (&now_msec);
	}

	p_ap_flags = bss_info->ap_flags;
	if (nm_g_variant_lookup (properties, "Privacy", "b", &v_b))
		p_ap_flags = NM_FLAGS_ASSIGN (p_ap_flags, NM_802_11_AP_FLAGS_PRIVACY, v_b);
	else {
		nm_assert (  !initial
		           || !NM_FLAGS_HAS (p_ap_flags, NM_802_11_AP_FLAGS_PRIVACY));
	}
	v_v = nm_g_variant_lookup_value (properties, "WPS", G_VARIANT_TYPE_VARDICT);
	if (   v_v
	    || initial) {
		NM80211ApFlags f = NM_802_11_AP_FLAGS_NONE;

		if (v_v) {
			if (g_variant_lookup (v_v, "Type", "&s", &v_s)) {
				p_ap_flags = NM_802_11_AP_FLAGS_WPS;
				if (nm_streq (v_s, "pcb"))
					f |= NM_802_11_AP_FLAGS_WPS_PBC;
				else if (nm_streq (v_s, "pin"))
					f |= NM_802_11_AP_FLAGS_WPS_PIN;
			}
			g_variant_unref (v_v);
		}
		p_ap_flags = NM_FLAGS_ASSIGN_MASK (p_ap_flags,
		                                     NM_802_11_AP_FLAGS_WPS
		                                   | NM_802_11_AP_FLAGS_WPS_PBC
		                                   | NM_802_11_AP_FLAGS_WPS_PIN,
		                                   f);
	}
	if (bss_info->ap_flags != p_ap_flags) {
		bss_info->ap_flags = p_ap_flags;
		nm_assert (bss_info->ap_flags == p_ap_flags);
	}

	if (nm_g_variant_lookup (properties, "Mode", "&s", &v_s)) {
		if (nm_streq (v_s, "infrastructure"))
			p_mode = NM_802_11_MODE_INFRA;
		else if (nm_streq (v_s, "ad-hoc"))
			p_mode = NM_802_11_MODE_ADHOC;
		else if (nm_streq (v_s, "mesh"))
			p_mode = NM_802_11_MODE_MESH;
		else
			p_mode = NM_802_11_MODE_UNKNOWN;
	} else if (initial)
		p_mode = NM_802_11_MODE_UNKNOWN;
	else
		p_mode = bss_info->mode;
	if (bss_info->mode != p_mode) {
		bss_info->mode = p_mode;
		nm_assert (bss_info->mode == p_mode);
	}

	if (nm_g_variant_lookup (properties, "Signal", "n", &v_i16))
		p_signal_percent = nm_wifi_utils_level_to_quality (v_i16);
	else if (initial)
		p_signal_percent = 0;
	else
		p_signal_percent = bss_info->signal_percent;
	bss_info->signal_percent = p_signal_percent;

	if (nm_g_variant_lookup (properties, "Frequency", "q", &v_u16))
		bss_info->frequency = v_u16;

	v_v = nm_g_variant_lookup_value (properties, "SSID", G_VARIANT_TYPE_BYTESTRING);
	if (v_v) {
		arr_data = g_variant_get_fixed_array (v_v, &arr_len, 1);
		arr_len = MIN (32, arr_len);

		/* Stupid ieee80211 layer uses <hidden> */
		if (   arr_data
		    && arr_len
		    && !(   NM_IN_SET (arr_len, 8, 9)
		         && memcmp (arr_data, "<hidden>", arr_len) == 0)
		    && !nm_utils_is_empty_ssid (arr_data, arr_len)) {
			/* good */
		} else
			arr_len = 0;

		if (!nm_utils_gbytes_equal_mem (bss_info->ssid, arr_data, arr_len)) {
			_nm_unused gs_unref_bytes GBytes *old_free = g_steal_pointer (&bss_info->ssid);

			bss_info->ssid =   (arr_len == 0)
			                 ? NULL
			                 : g_bytes_new (arr_data, arr_len);
		}

		g_variant_unref (v_v);
	} else {
		nm_assert (   !initial
		           || !bss_info->ssid);
	}

	v_v = nm_g_variant_lookup_value (properties, "BSSID", G_VARIANT_TYPE_BYTESTRING);
	if (v_v) {
		arr_data = g_variant_get_fixed_array (v_v, &arr_len, 1);
		if (   arr_len == ETH_ALEN
		    && memcmp (arr_data, nm_ip_addr_zero.addr_eth, ETH_ALEN) != 0
		    && memcmp (arr_data, (char[ETH_ALEN]) { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, ETH_ALEN) != 0) {
			/* pass */
		} else
			arr_len = 0;

		if (arr_len != 0) {
			nm_assert (arr_len == sizeof (bss_info->bssid));
			bss_info->bssid_valid = TRUE;
			memcpy (bss_info->bssid, arr_data, sizeof (bss_info->bssid));
		} else if (bss_info->bssid_valid) {
			bss_info->bssid_valid = FALSE;
			memset (bss_info->bssid, 0, sizeof (bss_info->bssid));
		}
		g_variant_unref (v_v);
	} else {
		nm_assert (   !initial
		           || !bss_info->bssid_valid);
	}
	nm_assert (   (   bss_info->bssid_valid
	               && !nm_utils_memeqzero (bss_info->bssid, sizeof (bss_info->bssid)))
	           || (  !bss_info->bssid_valid
	               && nm_utils_memeqzero (bss_info->bssid, sizeof (bss_info->bssid))));

	p_max_rate_has = FALSE;
	p_max_rate = 0;
	v_v = nm_g_variant_lookup_value (properties, "Rates", G_VARIANT_TYPE ("au"));
	if (v_v) {
		const guint32 *rates = g_variant_get_fixed_array (v_v, &arr_len, sizeof (guint32));
		gsize i;

		for (i = 0; i < arr_len; i++)
			p_max_rate = NM_MAX (p_max_rate, rates[i]);
		p_max_rate_has = TRUE;
		g_variant_unref (v_v);
	}
	v_v = nm_g_variant_lookup_value (properties, "IEs", G_VARIANT_TYPE_BYTESTRING);
	if (v_v) {
		gboolean p_owe_transition_mode;
		gboolean p_metered;
		guint32 rate;

		arr_data = g_variant_get_fixed_array (v_v, &arr_len, 1);
		nm_wifi_utils_parse_ies (arr_data, arr_len, &rate, &p_metered, &p_owe_transition_mode);
		p_max_rate = NM_MAX (p_max_rate, rate);
		p_max_rate_has = TRUE;
		g_variant_unref (v_v);

		if (p_owe_transition_mode)
			bss_info->rsn_flags |= NM_802_11_AP_SEC_KEY_MGMT_OWE;
		else
			bss_info->rsn_flags &= ~NM_802_11_AP_SEC_KEY_MGMT_OWE;

		bss_info->metered = p_metered;
	}
	if (p_max_rate_has)
		bss_info->max_rate = p_max_rate / 1000u;

	v_v = nm_g_variant_lookup_value (properties, "WPA", G_VARIANT_TYPE_VARDICT);
	if (v_v) {
		bss_info->wpa_flags = security_from_vardict (v_v);
		g_variant_unref (v_v);
	}

	v_v = nm_g_variant_lookup_value (properties, "RSN", G_VARIANT_TYPE_VARDICT);
	if (v_v) {
		bss_info->rsn_flags = security_from_vardict (v_v);
		g_variant_unref (v_v);
	}

	_bss_info_changed_emit (self, bss_info, TRUE);
}

static void
_bss_info_get_all_cb (GVariant *result,
                      GError *error,
                      gpointer user_data)
{
	NMSupplicantBssInfo *bss_info;
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *properties = NULL;

	if (nm_utils_error_is_cancelled (error))
		return;

	bss_info = user_data;
	self = bss_info->_self;
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_clear_object (&bss_info->_init_cancellable);
	nm_c_list_move_tail (&priv->bss_lst_head, &bss_info->_bss_lst);

	if (result)
		g_variant_get (result, "(@a{sv})", &properties);

	_bss_info_properties_changed (self, bss_info, properties, TRUE);

	_starting_check_ready (self);

	_notify_maybe_scanning (self);
}

static void
_bss_info_add (NMSupplicantInterface *self, const char *object_path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	nm_auto_ref_string NMRefString *bss_path = NULL;
	NMSupplicantBssInfo *bss_info;

	bss_path = nm_ref_string_new (nm_dbus_path_not_empty (object_path));
	if (!bss_path)
		return;

	bss_info = g_hash_table_lookup (priv->bss_idx, &bss_path);
	if (bss_info) {
		bss_info->_bss_dirty = FALSE;
		return;
	}

	bss_info = g_slice_new (NMSupplicantBssInfo);
	*bss_info = (NMSupplicantBssInfo) {
		._self             = self,
		.bss_path          = g_steal_pointer (&bss_path),
		._init_cancellable = g_cancellable_new (),
	};
	c_list_link_tail (&priv->bss_initializing_lst_head, &bss_info->_bss_lst);
	g_hash_table_add (priv->bss_idx, bss_info);

	nm_dbus_connection_call_get_all (priv->dbus_connection,
	                                 priv->name_owner->str,
	                                 bss_info->bss_path->str,
	                                 NM_WPAS_DBUS_IFACE_BSS,
	                                 5000,
	                                 bss_info->_init_cancellable,
	                                 _bss_info_get_all_cb,
	                                 bss_info);
}

static gboolean
_bss_info_remove (NMSupplicantInterface *self,
                  NMRefString **p_bss_path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantBssInfo *bss_info;
	gpointer unused_but_required;

	if (!g_hash_table_steal_extended (priv->bss_idx,
	                                  p_bss_path,
	                                  (gpointer *) &bss_info,
	                                  &unused_but_required))
		return FALSE;

	c_list_unlink (&bss_info->_bss_lst);
	if (!bss_info->_init_cancellable)
		_bss_info_changed_emit (self, bss_info, FALSE);
	_bss_info_destroy (bss_info);

	nm_assert_starting_has_pending_count (priv->starting_pending_count);

	return TRUE;
}

/*****************************************************************************/

static void
_peer_info_destroy (NMSupplicantPeerInfo *peer_info)
{
	c_list_unlink (&peer_info->_peer_lst);
	nm_clear_g_cancellable (&peer_info->_init_cancellable);

	g_free (peer_info->device_name);
	g_free (peer_info->manufacturer);
	g_free (peer_info->model);
	g_free (peer_info->model_number);
	g_free (peer_info->serial);
	g_bytes_unref (peer_info->ies);

	nm_g_slice_free (peer_info);
}

static void
_peer_info_changed_emit (NMSupplicantInterface *self,
                         NMSupplicantPeerInfo *peer_info,
                         gboolean is_present)
{
	g_signal_emit (self,
	               signals[PEER_CHANGED],
	               0,
	               peer_info,
	               is_present);
}

static void
_peer_info_properties_changed (NMSupplicantInterface *self,
                               NMSupplicantPeerInfo *peer_info,
                               GVariant *properties,
                               gboolean initial)
{
	GVariant *v_v;
	const char *v_s;
	gint32 v_i32;
	const guint8 *arr_data;
	gsize arr_len;

	peer_info->last_seen_msec = nm_utils_get_monotonic_timestamp_msec ();

	if (nm_g_variant_lookup (properties, "level", "i", &v_i32))
		peer_info->signal_percent = nm_wifi_utils_level_to_quality (v_i32);

	if (nm_g_variant_lookup (properties, "DeviceName", "&s", &v_s))
		nm_utils_strdup_reset (&peer_info->device_name, v_s);

	if (nm_g_variant_lookup (properties, "Manufacturer", "&s", &v_s))
		nm_utils_strdup_reset (&peer_info->manufacturer, v_s);

	if (nm_g_variant_lookup (properties, "Model", "&s", &v_s))
		nm_utils_strdup_reset (&peer_info->model, v_s);

	if (nm_g_variant_lookup (properties, "ModelNumber", "&s", &v_s))
		nm_utils_strdup_reset (&peer_info->model_number, v_s);

	if (nm_g_variant_lookup (properties, "Serial", "&s", &v_s))
		nm_utils_strdup_reset (&peer_info->serial, v_s);

	v_v = nm_g_variant_lookup_value (properties, "DeviceAddress", G_VARIANT_TYPE_BYTESTRING);
	if (v_v) {
		arr_data = g_variant_get_fixed_array (v_v, &arr_len, 1);
		if (   arr_len == ETH_ALEN
		    && memcmp (arr_data, nm_ip_addr_zero.addr_eth, ETH_ALEN) != 0
		    && memcmp (arr_data, (char[ETH_ALEN]) { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF }, ETH_ALEN) != 0) {
			/* pass */
		} else
			arr_len = 0;

		if (arr_len != 0) {
			nm_assert (arr_len == sizeof (peer_info->address));
			peer_info->address_valid = TRUE;
			memcpy (peer_info->address, arr_data, sizeof (peer_info->address));
		} else if (peer_info->address_valid) {
			peer_info->address_valid = FALSE;
			memset (peer_info->address, 0, sizeof (peer_info->address));
		}
		g_variant_unref (v_v);
	} else {
		nm_assert (   !initial
		           || !peer_info->address_valid);
	}
	nm_assert (   (   peer_info->address_valid
	               && !nm_utils_memeqzero (peer_info->address, sizeof (peer_info->address)))
	           || (  !peer_info->address_valid
	               && nm_utils_memeqzero (peer_info->address, sizeof (peer_info->address))));

	/* The IEs property contains the WFD R1 subelements */
	v_v = nm_g_variant_lookup_value (properties, "IEs", G_VARIANT_TYPE_BYTESTRING);
	if (v_v) {
		arr_data = g_variant_get_fixed_array (v_v, &arr_len, 1);
		if (!nm_utils_gbytes_equal_mem (peer_info->ies, arr_data, arr_len)) {
			_nm_unused gs_unref_bytes GBytes *old_free = g_steal_pointer (&peer_info->ies);

			peer_info->ies = g_bytes_new (arr_data, arr_len);
		} else if (   arr_len == 0
		           && !peer_info->ies)
			peer_info->ies = g_bytes_new (NULL, 0);
		g_variant_unref (v_v);
	}

	_peer_info_changed_emit (self, peer_info, TRUE);
}

static void
_peer_info_get_all_cb (GVariant *result,
                       GError *error,
                       gpointer user_data)
{
	NMSupplicantPeerInfo *peer_info;
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *properties = NULL;

	if (nm_utils_error_is_cancelled (error))
		return;

	peer_info = user_data;
	self = peer_info->_self;
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_clear_object (&peer_info->_init_cancellable);
	nm_c_list_move_tail (&priv->peer_lst_head, &peer_info->_peer_lst);

	if (result)
		g_variant_get (result, "(@a{sv})", &properties);

	_peer_info_properties_changed (self, peer_info, properties, TRUE);

	_starting_check_ready (self);
}

static void
_peer_info_add (NMSupplicantInterface *self, const char *object_path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	nm_auto_ref_string NMRefString *peer_path = NULL;
	NMSupplicantPeerInfo *peer_info;

	peer_path = nm_ref_string_new (nm_dbus_path_not_empty (object_path));
	if (!peer_path)
		return;

	peer_info = g_hash_table_lookup (priv->peer_idx, &peer_path);

	if (peer_info) {
		peer_info->_peer_dirty = FALSE;
		return;
	}

	peer_info = g_slice_new (NMSupplicantPeerInfo);
	*peer_info = (NMSupplicantPeerInfo) {
		._self             = self,
		.peer_path         = g_steal_pointer (&peer_path),
		._init_cancellable = g_cancellable_new (),
	};
	c_list_link_tail (&priv->peer_initializing_lst_head, &peer_info->_peer_lst);
	g_hash_table_add (priv->peer_idx, peer_info);

	nm_dbus_connection_call_get_all (priv->dbus_connection,
	                                 priv->name_owner->str,
	                                 peer_info->peer_path->str,
	                                 NM_WPAS_DBUS_IFACE_PEER,
	                                 5000,
	                                 peer_info->_init_cancellable,
	                                 _peer_info_get_all_cb,
	                                 peer_info);
}

static gboolean
_peer_info_remove (NMSupplicantInterface *self,
                   NMRefString **p_peer_path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantPeerInfo *peer_info;
	gpointer unused_but_required;

	if (!g_hash_table_steal_extended (priv->peer_idx,
	                                  p_peer_path,
	                                  (gpointer *) &peer_info,
	                                  &unused_but_required))
		return FALSE;

	c_list_unlink (&peer_info->_peer_lst);
	if (!peer_info->_init_cancellable)
		_peer_info_changed_emit (self, peer_info, FALSE);
	_peer_info_destroy (peer_info);

	nm_assert_starting_has_pending_count (priv->starting_pending_count);

	return TRUE;
}

/*****************************************************************************/

static void
set_state_down (NMSupplicantInterface *self,
                gboolean force_remove_from_supplicant,
                const char *reason)
{
	_nm_unused gs_unref_object NMSupplicantInterface *self_keep_alive = g_object_ref (self);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantBssInfo *bss_info;
	NMSupplicantPeerInfo *peer_info;
	NMSupplicantInterfaceState old_state;

	nm_assert (priv->state != NM_SUPPLICANT_INTERFACE_STATE_DOWN);
	nm_assert (!c_list_is_empty (&self->supp_lst));

	_LOGD ("remove interface \"%s\" on %s (%s)%s",
	       priv->object_path->str,
	       priv->name_owner->str,
	       reason,
	       force_remove_from_supplicant ? " (remove in wpa_supplicant)" : "");

	old_state = priv->state;

	priv->state = NM_SUPPLICANT_INTERFACE_STATE_DOWN;

	_nm_supplicant_manager_unregister_interface (priv->supplicant_manager, self);

	nm_assert (c_list_is_empty (&self->supp_lst));

	if (force_remove_from_supplicant) {
		_nm_supplicant_manager_dbus_call_remove_interface (priv->supplicant_manager,
		                                                   priv->name_owner->str,
		                                                   priv->object_path->str);
	}

	_emit_signal_state (self, priv->state, old_state, 0);

	nm_clear_g_dbus_connection_signal (priv->dbus_connection, &priv->properties_changed_id);
	nm_clear_g_dbus_connection_signal (priv->dbus_connection, &priv->signal_id);
	nm_clear_g_dbus_connection_signal (priv->dbus_connection, &priv->bss_properties_changed_id);
	nm_clear_g_dbus_connection_signal (priv->dbus_connection, &priv->peer_properties_changed_id);
	nm_clear_g_dbus_connection_signal (priv->dbus_connection, &priv->p2p_group_properties_changed_id);

	nm_supplicant_interface_cancel_wps (self);

	if (priv->assoc_data) {
		gs_free_error GError *error = NULL;

		nm_utils_error_set_cancelled (&error, TRUE, "NMSupplicantInterface");
		assoc_return (self, error, "cancelled because supplicant interface is going down");
	}

	while ((bss_info = c_list_first_entry (&priv->bss_initializing_lst_head, NMSupplicantBssInfo, _bss_lst))) {
		g_hash_table_remove (priv->bss_idx, bss_info);
		_bss_info_destroy (bss_info);
	}
	while ((bss_info = c_list_first_entry (&priv->bss_lst_head, NMSupplicantBssInfo, _bss_lst))) {
		g_hash_table_remove (priv->bss_idx, bss_info);
		_bss_info_destroy (bss_info);
	}
	nm_assert (g_hash_table_size (priv->bss_idx) == 0);

	while ((peer_info = c_list_first_entry (&priv->peer_initializing_lst_head, NMSupplicantPeerInfo, _peer_lst))) {
		g_hash_table_remove (priv->peer_idx, peer_info);
		_peer_info_destroy (peer_info);
	}
	while ((peer_info = c_list_first_entry (&priv->peer_lst_head, NMSupplicantPeerInfo, _peer_lst))) {
		g_hash_table_remove (priv->peer_idx, peer_info);
		_peer_info_destroy (peer_info);
	}
	nm_assert (g_hash_table_size (priv->peer_idx) == 0);

	nm_clear_g_cancellable (&priv->main_cancellable);
	nm_clear_g_cancellable (&priv->p2p_group_properties_cancellable);

	nm_clear_pointer (&priv->p2p_group_path, nm_ref_string_unref);

	_remove_network (self);

	nm_clear_pointer (&priv->current_bss, nm_ref_string_unref);

	_notify_maybe_scanning (self);
}

static void
set_state (NMSupplicantInterface *self, NMSupplicantInterfaceState new_state)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	NMSupplicantInterfaceState old_state = priv->state;

	nm_assert (new_state > NM_SUPPLICANT_INTERFACE_STATE_STARTING);
	nm_assert (new_state < NM_SUPPLICANT_INTERFACE_STATE_DOWN);
	nm_assert (nm_supplicant_interface_state_is_operational (new_state));

	nm_assert (priv->state >= NM_SUPPLICANT_INTERFACE_STATE_STARTING);
	nm_assert (priv->state < NM_SUPPLICANT_INTERFACE_STATE_DOWN);

	if (new_state == priv->state)
		return;

	_LOGT ("state: set state \"%s\" (was \"%s\")",
	       nm_supplicant_interface_state_to_string (new_state),
	       nm_supplicant_interface_state_to_string (priv->state));

	priv->state = new_state;

	_emit_signal_state (self,
	                    priv->state,
	                    old_state,
	                      priv->state != NM_SUPPLICANT_INTERFACE_STATE_DISCONNECTED
	                    ? 0u
	                    : priv->disconnect_reason);
}

NMRefString *
nm_supplicant_interface_get_current_bss (NMSupplicantInterface *self)
{
	g_return_val_if_fail (self != NULL, FALSE);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->current_bss;
}

gboolean
nm_supplicant_interface_get_scanning (NMSupplicantInterface *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->scanning_cached;
}

gint64
nm_supplicant_interface_get_last_scan (NMSupplicantInterface *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), FALSE);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->last_scan_msec;
}

#define MATCH_PROPERTY(p, n, v, t) (!strcmp (p, n) && g_variant_is_of_type (v, t))

static void
parse_capabilities (NMSupplicantInterface *self, GVariant *capabilities)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gboolean have_active = FALSE;
	gboolean have_ssid = FALSE;
	gboolean have_ft = FALSE;
	gint32 max_scan_ssids = -1;
	const char **array;

	nm_assert (capabilities && g_variant_is_of_type (capabilities, G_VARIANT_TYPE_VARDICT));

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
		/* Setting p2p_capable might toggle _prop_p2p_available_get(). However,
		 * we don't need to check for a property changed notification, because
		 * the caller did g_object_freeze_notify() and will perform the check. */
		priv->p2p_capable_property = g_strv_contains (array, "p2p");
		g_free (array);
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
		if (   max_scan_ssids > 0
		    && have_active
		    && have_ssid) {
			/* wpa_supplicant's NM_WPAS_MAX_SCAN_SSIDS value is 16, but for speed
			 * and to ensure we don't disclose too many SSIDs from the hidden
			 * list, we'll limit to 5.
			 */
			max_scan_ssids = CLAMP (max_scan_ssids, 0, 5);
			if (max_scan_ssids != priv->max_scan_ssids) {
				priv->max_scan_ssids = max_scan_ssids;
				_LOGD ("supports %d scan SSIDs", priv->max_scan_ssids);
			}
		}
	}
}

static void
_starting_check_ready (NMSupplicantInterface *self)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->state != NM_SUPPLICANT_INTERFACE_STATE_STARTING)
		return;

	if (priv->starting_pending_count > 0)
		return;

	if (!c_list_is_empty (&priv->bss_initializing_lst_head))
		return;

	if (!c_list_is_empty (&priv->peer_initializing_lst_head))
		return;

	if (priv->p2p_group_properties_cancellable)
		return;

	nm_assert (priv->state == NM_SUPPLICANT_INTERFACE_STATE_STARTING);

	if (!nm_supplicant_interface_state_is_operational (priv->supp_state)) {
		_LOGW ("Supplicant state is unknown during initialization. Destroy the interface");
		set_state_down (self, TRUE, "failure to get valid interface state");
		return;
	}

	set_state (self, priv->supp_state);
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
_p2p_group_properties_changed (NMSupplicantInterface *self,
                               GVariant *properties)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	const char *s;

	if (!properties)
		priv->p2p_group_owner_property = FALSE;
	else if (g_variant_lookup (properties, "Role", "&s", &s))
		priv->p2p_group_owner_property = nm_streq (s, "GO");

	_notify_maybe_p2p_group (self);
}

static void
_p2p_group_properties_changed_cb (GDBusConnection *connection,
                                  const char *sender_name,
                                  const char *object_path,
                                  const char *signal_interface_name,
                                  const char *signal_name,
                                  GVariant *parameters,
                                  gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gs_unref_variant GVariant *changed_properties = NULL;

	if (priv->p2p_group_properties_cancellable)
		return;
	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sa{sv}as)")))
		return;

	g_variant_get (parameters,
	               "(&s@a{sv}^a&s)",
	               NULL,
	               &changed_properties,
	               NULL);

	_p2p_group_properties_changed (self, changed_properties);
}

static void
_p2p_group_properties_get_all_cb (GVariant *result,
                                  GError *error,
                                  gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *properties = NULL;

	if (nm_utils_error_is_cancelled (error))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	g_object_freeze_notify (G_OBJECT (self));

	nm_clear_g_cancellable (&priv->p2p_group_properties_cancellable);

	if (result)
		g_variant_get (result, "(@a{sv})", &properties);

	_p2p_group_properties_changed (self, properties);

	_starting_check_ready (self);

	_notify_maybe_p2p_group (self);

	g_object_thaw_notify (G_OBJECT (self));
}

static void
_p2p_group_set_path (NMSupplicantInterface *self,
                     const char *path)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	nm_auto_ref_string NMRefString *group_path = NULL;

	group_path = nm_ref_string_new (nm_dbus_path_not_empty (path));

	if (priv->p2p_group_path == group_path)
		return;

	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->p2p_group_properties_changed_id);
	nm_clear_g_cancellable (&priv->p2p_group_properties_cancellable);

	nm_ref_string_unref (priv->p2p_group_path);
	priv->p2p_group_path = g_steal_pointer (&group_path);

	if (priv->p2p_group_path) {
		priv->p2p_group_properties_cancellable = g_cancellable_new ();
		priv->p2p_group_properties_changed_id = nm_dbus_connection_signal_subscribe_properties_changed (priv->dbus_connection,
		                                                                                                priv->name_owner->str,
		                                                                                                priv->p2p_group_path->str,
		                                                                                                NM_WPAS_DBUS_IFACE_GROUP,
		                                                                                                _p2p_group_properties_changed_cb,
		                                                                                                self,
		                                                                                                NULL);
		nm_dbus_connection_call_get_all (priv->dbus_connection,
		                                 priv->name_owner->str,
		                                 priv->p2p_group_path->str,
		                                 NM_WPAS_DBUS_IFACE_GROUP,
		                                 5000,
		                                 priv->p2p_group_properties_cancellable,
		                                 _p2p_group_properties_get_all_cb,
		                                 self);
	}

	_notify (self, PROP_P2P_GROUP_PATH);
	_notify_maybe_p2p_group (self);

	nm_assert_starting_has_pending_count (priv->starting_pending_count);
}

/*****************************************************************************/

static void
_wps_data_free (WpsData *wps_data,
                GDBusConnection *dbus_connection)
{
	nm_clear_g_dbus_connection_signal (dbus_connection,
	                                   &wps_data->signal_id);
	nm_clear_g_cancellable (&wps_data->cancellable);
	g_free (wps_data->type);
	g_free (wps_data->pin);
	g_free (wps_data->bssid);
	nm_g_slice_free (wps_data);
}

static void
_wps_credentials_changed_cb (GDBusConnection *connection,
                             const char *sender_name,
                             const char *object_path,
                             const char *signal_interface_name,
                             const char *signal_name,
                             GVariant *parameters,
                             gpointer user_data)
{
	NMSupplicantInterface *self = user_data;
	gs_unref_variant GVariant *props = NULL;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(a{sv})")))
		return;

	g_variant_get (parameters, "(@a{sv})", &props);

	_LOGT ("wps: new credentials");
	g_signal_emit (self, signals[WPS_CREDENTIALS], 0, props);
}

static void
_wps_handle_start_cb (GObject *source,
                      GAsyncResult *result,
                      gpointer user_data)
{
	NMSupplicantInterface *self;
	WpsData *wps_data;
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;

	res = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	wps_data = user_data;
	self = wps_data->self;

	if (res)
		_LOGT ("wps: started with success");
	else
		_LOGW ("wps: start failed with %s", error->message);

	g_clear_object (&wps_data->cancellable);
	nm_clear_g_free (&wps_data->type);
	nm_clear_g_free (&wps_data->pin);
	nm_clear_g_free (&wps_data->bssid);
}

static void
_wps_handle_set_pc_cb (GVariant *res,
                       GError *error,
                       gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	WpsData *wps_data;
	GVariantBuilder start_args;
	guint8 bssid_buf[ETH_ALEN];

	if (nm_utils_error_is_cancelled (error))
		return;

	wps_data = user_data;
	self = wps_data->self;
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (res)
		_LOGT ("wps: ProcessCredentials successfully set, starting...");
	else
		_LOGW ("wps: ProcessCredentials failed to set (%s), starting...", error->message);

	wps_data->signal_id = g_dbus_connection_signal_subscribe (priv->dbus_connection,
	                                                          priv->name_owner->str,
	                                                          NM_WPAS_DBUS_IFACE_INTERFACE_WPS,
	                                                          "Credentials",
	                                                          priv->object_path->str,
	                                                          NULL,
	                                                          G_DBUS_SIGNAL_FLAGS_NONE,
	                                                          _wps_credentials_changed_cb,
	                                                          self,
	                                                          NULL);

	g_variant_builder_init (&start_args, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&start_args, "{sv}", "Role", g_variant_new_string ("enrollee"));
	g_variant_builder_add (&start_args, "{sv}", "Type", g_variant_new_string (wps_data->type));
	if (wps_data->pin)
		g_variant_builder_add (&start_args, "{sv}", "Pin", g_variant_new_string (wps_data->pin));
	if (wps_data->bssid) {
		/* The BSSID is in fact not mandatory. If it is not set the supplicant would
		 * enroll with any BSS in range. */
		if (!nm_utils_hwaddr_aton (wps_data->bssid, bssid_buf, sizeof (bssid_buf)))
			nm_assert_not_reached ();
		g_variant_builder_add (&start_args, "{sv}", "Bssid",
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, bssid_buf,
		                                                  ETH_ALEN, sizeof (guint8)));
	}

	wps_data->needs_cancelling = TRUE;
	if (!wps_data->cancellable)
		wps_data->cancellable = g_cancellable_new ();

	_dbus_connection_call (self,
	                       NM_WPAS_DBUS_IFACE_INTERFACE_WPS,
	                       "Start",
	                       g_variant_new ("(a{sv})", &start_args),
	                       G_VARIANT_TYPE ("(a{sv})"),
	                       G_DBUS_CALL_FLAGS_NONE,
	                       5000,
	                       wps_data->cancellable,
	                       _wps_handle_start_cb,
	                       wps_data);
}

static void
_wps_call_set_pc (NMSupplicantInterface *self,
                  WpsData *wps_data)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (!wps_data->cancellable)
		wps_data->cancellable = g_cancellable_new ();

	nm_dbus_connection_call_set (priv->dbus_connection,
	                             priv->name_owner->str,
	                             priv->object_path->str,
	                             NM_WPAS_DBUS_IFACE_INTERFACE_WPS,
	                             "ProcessCredentials",
	                             g_variant_new_boolean (TRUE),
	                             5000,
	                             wps_data->cancellable,
	                             _wps_handle_set_pc_cb,
	                             wps_data);
}

static void
_wps_handle_cancel_cb (GObject *source,
                       GAsyncResult *result,
                       gpointer user_data)
{
	GDBusConnection *dbus_connection = G_DBUS_CONNECTION (source);
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	WpsData *wps_data;
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;

	res = g_dbus_connection_call_finish (dbus_connection, result, &error);
	nm_assert (!nm_utils_error_is_cancelled (error));

	wps_data = user_data;
	self = wps_data->self;

	if (!self) {
		_wps_data_free (wps_data, dbus_connection);
		if (res)
			_LOGT ("wps: cancel completed successfully, after supplicant interface is gone");
		else
			_LOGW ("wps: cancel failed (%s), after supplicant interface is gone", error->message);
		return;
	}

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	wps_data->is_cancelling = FALSE;

	if (!wps_data->type) {
		priv->wps_data = NULL;
		_wps_data_free (wps_data, dbus_connection);
		if (res)
			_LOGT ("wps: cancel completed successfully");
		else
			_LOGW ("wps: cancel failed (%s)", error->message);
		return;
	}

	if (res)
		_LOGT ("wps: cancel completed successfully, setting ProcessCredentials now...");
	else
		_LOGW ("wps: cancel failed (%s), setting ProcessCredentials now...", error->message);

	_wps_call_set_pc (self, wps_data);
}

static void
_wps_start (NMSupplicantInterface *self,
            const char *type,
            const char *bssid,
            const char *pin)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	WpsData *wps_data;

	if (type)
		_LOGI ("wps: type %s start...", type);

	wps_data = priv->wps_data;

	if (!wps_data) {
		if (!type)
			return;

		if (priv->state == NM_SUPPLICANT_INTERFACE_STATE_DOWN) {
			_LOGD ("wps: interface is down. Cannot start with WPS");
			return;
		}

		wps_data = g_slice_new (WpsData);
		*wps_data = (WpsData) {
			.self        = self,
			.type        = g_strdup (type),
			.bssid       = g_strdup (bssid),
			.pin         = g_strdup (pin),
		};
		priv->wps_data = wps_data;
	} else {
		g_free (wps_data->type);
		g_free (wps_data->bssid);
		g_free (wps_data->pin);
		wps_data->type = g_strdup (type);
		wps_data->bssid = g_strdup (bssid);
		wps_data->pin = g_strdup (pin);
	}

	if (wps_data->is_cancelling) {
		/* we wait for cancellation to complete. */
		return;
	}

	if (   !type
	    || wps_data->needs_cancelling) {

		_LOGT ("wps: cancel %senrollment...",
		       wps_data->needs_cancelling ? "previous " : "");

		wps_data->is_cancelling = TRUE;
		wps_data->needs_cancelling = FALSE;
		nm_clear_g_cancellable (&wps_data->cancellable);
		nm_clear_g_dbus_connection_signal (priv->dbus_connection,
		                                   &wps_data->signal_id);

		_dbus_connection_call (self,
		                       NM_WPAS_DBUS_IFACE_INTERFACE_WPS,
		                       "Cancel",
		                       NULL,
		                       G_VARIANT_TYPE ("()"),
		                       G_DBUS_CALL_FLAGS_NONE,
		                       5000,
		                       NULL,
		                       _wps_handle_cancel_cb,
		                       wps_data);
		return;
	}

	_LOGT ("wps: setting ProcessCredentials...");
	_wps_call_set_pc (self, wps_data);
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
iface_introspect_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;
	const char *data;
	NMTernary value;

	res = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	nm_assert (NM_SUPPL_CAP_MASK_GET (priv->global_capabilities, NM_SUPPL_CAP_TYPE_AP) == NM_TERNARY_DEFAULT);

	value = NM_TERNARY_DEFAULT;
	if (res) {
		g_variant_get (res, "(&s)", &data);

		/* The ProbeRequest method only exists if AP mode has been enabled */
		value =   strstr (data, "ProbeRequest")
		        ? NM_TERNARY_TRUE
		        : NM_TERNARY_FALSE;
	}

	priv->iface_capabilities = NM_SUPPL_CAP_MASK_SET (priv->iface_capabilities, NM_SUPPL_CAP_TYPE_AP, value);

	priv->starting_pending_count--;
	_starting_check_ready (self);
}

static void
_properties_changed_main (NMSupplicantInterface *self,
                          GVariant *properties)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	const char **v_strv;
	const char *v_s;
	gboolean v_b;
	gint32 v_i32;
	GVariant *v_v;
	gboolean do_log_driver_info = FALSE;
	gboolean do_set_state = FALSE;
	gboolean do_notify_current_bss = FALSE;

	nm_assert (properties || g_variant_is_of_type (properties, G_VARIANT_TYPE ("a{sv}")));

	v_v = g_variant_lookup_value (properties, "Capabilities", G_VARIANT_TYPE_VARDICT);
	if (v_v) {
		parse_capabilities (self, v_v);
		g_variant_unref (v_v);
	}

	if (nm_g_variant_lookup (properties, "Scanning", "b", &v_b)) {
		if (priv->scanning_property != (!!v_b)) {
			_LOGT ("scanning: %s (plain property)", v_b ? "yes" : "no");
			priv->scanning_property = v_b;
		}
	}

	if (nm_g_variant_lookup (properties, "Ifname", "&s", &v_s)) {
		if (nm_utils_strdup_reset (&priv->ifname, v_s))
			do_log_driver_info = TRUE;
	}
	if (nm_g_variant_lookup (properties, "Driver", "&s", &v_s)) {
		if (nm_utils_strdup_reset (&priv->driver, v_s))
			do_log_driver_info = TRUE;
	}

	if (nm_g_variant_lookup (properties, "DisconnectReason", "i", &v_i32)) {
		/* Disconnect reason is currently only given for deauthentication events,
		 * not disassociation; currently they are IEEE 802.11 "reason codes",
		 * defined by (IEEE 802.11-2007, 7.3.1.7, Table 7-22).  Any locally caused
		 * deauthentication will be negative, while authentications caused by the
		 * AP will be positive.
		 */
		priv->disconnect_reason = v_i32;
	}

	if (nm_g_variant_lookup (properties, "State", "&s", &v_s)) {
		NMSupplicantInterfaceState state;

		state = wpas_state_string_to_enum (v_s);
		if (state == NM_SUPPLICANT_INTERFACE_STATE_INVALID)
			_LOGT ("state: ignore unknown supplicant state '%s' (is %s, plain property)",
			       v_s,
			       nm_supplicant_interface_state_to_string (priv->supp_state));
		else if (priv->supp_state != state) {
			_LOGT ("state: %s (was %s, plain property)",
			       nm_supplicant_interface_state_to_string (state),
			       nm_supplicant_interface_state_to_string (priv->supp_state));
			priv->supp_state = state;
			if (priv->state > NM_SUPPLICANT_INTERFACE_STATE_STARTING) {
				/* Only transition to actual wpa_supplicant interface states (ie,
				 * anything > STARTING) after the NMSupplicantInterface has had a
				 * chance to initialize, which is signalled by entering the STARTING
				 * state.
				 */
				do_set_state = TRUE;
			}
		}
	}

	if (nm_g_variant_lookup (properties, "CurrentBSS", "&o", &v_s)) {
		v_s = nm_dbus_path_not_empty (v_s);
		if (!nm_ref_string_equals_str (priv->current_bss, v_s)) {
			nm_ref_string_unref (priv->current_bss);
			priv->current_bss = nm_ref_string_new (v_s);
			do_notify_current_bss = TRUE;
		}
	}

	if (do_log_driver_info) {
		_LOGD ("supplicant interface for ifindex=%d, ifname=%s%s%s, driver=%s%s%s (requested %s)",
		       priv->ifindex,
		       NM_PRINT_FMT_QUOTE_STRING (priv->ifname),
		       NM_PRINT_FMT_QUOTE_STRING (priv->driver),
		       nm_supplicant_driver_to_string (priv->requested_driver));
	}

	if (nm_g_variant_lookup (properties, "BSSs", "^a&o", &v_strv)) {
		NMSupplicantBssInfo *bss_info;
		NMSupplicantBssInfo *bss_info_safe;
		const char **iter;

		c_list_for_each_entry (bss_info, &priv->bss_lst_head, _bss_lst)
			bss_info->_bss_dirty = TRUE;
		c_list_for_each_entry (bss_info, &priv->bss_initializing_lst_head, _bss_lst)
			bss_info->_bss_dirty = TRUE;

		for (iter = v_strv; *iter; iter++)
			_bss_info_add (self, *iter);

		g_free (v_strv);

		c_list_for_each_entry_safe (bss_info, bss_info_safe, &priv->bss_initializing_lst_head, _bss_lst) {
			if (bss_info->_bss_dirty)
				_bss_info_remove (self, &bss_info->bss_path);
		}
		c_list_for_each_entry_safe (bss_info, bss_info_safe, &priv->bss_lst_head, _bss_lst) {
			if (bss_info->_bss_dirty)
				_bss_info_remove (self, &bss_info->bss_path);
		}
	}

	if (do_notify_current_bss)
		_notify (self, PROP_CURRENT_BSS);

	if (do_set_state)
		set_state (self, priv->supp_state);

	_notify_maybe_scanning (self);
}

static void
_properties_changed_p2p_device (NMSupplicantInterface *self,
                                GVariant *properties)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	const char **v_strv;
	const char *v_s;

	nm_assert (!properties || g_variant_is_of_type (properties, G_VARIANT_TYPE ("a{sv}")));

	if (nm_g_variant_lookup (properties, "Peers", "^a&o", &v_strv)) {
		NMSupplicantPeerInfo *peer_info;
		NMSupplicantPeerInfo *peer_info_safe;
		const char *const*iter;

		c_list_for_each_entry (peer_info, &priv->peer_lst_head, _peer_lst)
			peer_info->_peer_dirty = TRUE;
		c_list_for_each_entry (peer_info, &priv->peer_initializing_lst_head, _peer_lst)
			peer_info->_peer_dirty = TRUE;

		for (iter = v_strv; *iter; iter++)
			_peer_info_add (self, *iter);

		g_free (v_strv);

		c_list_for_each_entry_safe (peer_info, peer_info_safe, &priv->peer_initializing_lst_head, _peer_lst) {
			if (peer_info->_peer_dirty)
				_peer_info_remove (self, &peer_info->peer_path);
		}
		c_list_for_each_entry_safe (peer_info, peer_info_safe, &priv->peer_lst_head, _peer_lst) {
			if (peer_info->_peer_dirty)
				_peer_info_remove (self, &peer_info->peer_path);
		}
	}

	if (nm_g_variant_lookup (properties, "Group", "&o", &v_s))
		_p2p_group_set_path (self, v_s);
}

/*****************************************************************************/

static void
assoc_return (NMSupplicantInterface *self,
              GError *error,
              const char *message)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	AssocData *assoc_data;

	assoc_data = g_steal_pointer (&priv->assoc_data);
	if (!assoc_data)
		return;

	if (error) {
		g_dbus_error_strip_remote_error (error);
		_LOGW ("assoc["NM_HASH_OBFUSCATE_PTR_FMT"]: %s: %s",
		       NM_HASH_OBFUSCATE_PTR (assoc_data),
		       message,
		       error->message);
	} else {
		_LOGD ("assoc["NM_HASH_OBFUSCATE_PTR_FMT"]: association request successful",
		       NM_HASH_OBFUSCATE_PTR (assoc_data));
	}

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

	/* Disconnect from the current AP */
	if (   (priv->state >= NM_SUPPLICANT_INTERFACE_STATE_SCANNING)
	    && (priv->state <= NM_SUPPLICANT_INTERFACE_STATE_COMPLETED)) {
		_dbus_connection_call_simple (self,
		                              NM_WPAS_DBUS_IFACE_INTERFACE,
		                              "Disconnect",
		                              NULL,
		                              G_VARIANT_TYPE ("()"),
		                              "disconnect");
	}

	_remove_network (self);

	/* Cancel any WPS enrollment, if any */
	nm_supplicant_interface_cancel_wps (self);

	/* Cancel all pending calls related to a prior connection attempt */
	if (priv->assoc_data) {
		gs_free_error GError *error = NULL;

		nm_utils_error_set_cancelled (&error, FALSE, "NMSupplicantInterface");
		assoc_return (self, error, "abort due to disconnect");
	}
}

static void
disconnect_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	gs_unref_object NMSupplicantInterface *self = NULL;
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;
	NMSupplicantInterfaceDisconnectCb callback;
	gpointer callback_user_data;

	nm_utils_user_data_unpack (user_data, &self, &callback, &callback_user_data);

	res = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);

	if (   !res
	    && !strstr (error->message, "fi.w1.wpa_supplicant1.NotConnected")) {
		/* an already disconnected interface is not an error*/
		g_clear_error(&error);
	}

	callback (self, error, callback_user_data);
}

void
nm_supplicant_interface_disconnect_async (NMSupplicantInterface *self,
                                          GCancellable *cancellable,
                                          NMSupplicantInterfaceDisconnectCb callback,
                                          gpointer user_data)
{
	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));
	g_return_if_fail (callback);

	_dbus_connection_call (self,
	                       NM_WPAS_DBUS_IFACE_INTERFACE,
	                       "Disconnect",
	                       NULL,
	                       G_VARIANT_TYPE ("()"),
	                       G_DBUS_CALL_FLAGS_NONE,
	                       DBUS_TIMEOUT_MSEC,
	                       cancellable,
	                       disconnect_cb,
	                       nm_utils_user_data_pack (g_object_ref (self), callback, user_data));
}

static void
assoc_select_network_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;

	res = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
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

	_dbus_connection_call (self,
	                       NM_WPAS_DBUS_IFACE_INTERFACE,
	                       "SelectNetwork",
	                       g_variant_new ("(o)", priv->net_path),
	                       G_VARIANT_TYPE ("()"),
	                       G_DBUS_CALL_FLAGS_NONE,
	                       DBUS_TIMEOUT_MSEC,
	                       priv->assoc_data->cancellable,
	                       assoc_select_network_cb,
	                       self);
}

static void
assoc_add_blob_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;

	res = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (nm_utils_error_is_cancelled (error))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (error) {
		assoc_return (self, error, "failure to set network certificates");
		return;
	}

	priv->assoc_data->blobs_left--;
	_LOGT ("assoc["NM_HASH_OBFUSCATE_PTR_FMT"]: blob added (%u left)",
	       NM_HASH_OBFUSCATE_PTR (priv->assoc_data),
	       priv->assoc_data->blobs_left);
	if (priv->assoc_data->blobs_left == 0)
		assoc_call_select_network (self);
}

static void
assoc_add_network_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	AddNetworkData *add_network_data = user_data;
	AssocData *assoc_data;
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;
	GHashTable *blobs;
	GHashTableIter iter;
	const char *blob_name;
	GBytes *blob_data;
	nm_auto_ref_string NMRefString *name_owner = NULL;
	nm_auto_ref_string NMRefString *object_path = NULL;

	g_clear_object (&add_network_data->shutdown_wait_obj);

	assoc_data = add_network_data->assoc_data;
	if (assoc_data)
		assoc_data->add_network_data = NULL;
	name_owner = g_steal_pointer (&add_network_data->name_owner);
	object_path = g_steal_pointer (&add_network_data->object_path);
	nm_g_slice_free (add_network_data);

	res = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);

	if (!assoc_data) {
		if (!error) {
			const char *net_path;

			/* the assoc-request was already cancelled, but the AddNetwork request succeeded.
			 * Cleanup the created network.
			 *
			 * This cleanup action does not work when NetworkManager is about to exit
			 * and leaves the mainloop. During program shutdown, we may orphan networks. */
			g_variant_get (res, "(&o)", &net_path);
			g_dbus_connection_call (G_DBUS_CONNECTION (source),
			                        name_owner->str,
			                        object_path->str,
			                        NM_WPAS_DBUS_IFACE_INTERFACE,
			                        "RemoveNetwork",
			                        g_variant_new ("(o)", net_path),
			                        G_VARIANT_TYPE ("()"),
			                        G_DBUS_CALL_FLAGS_NONE,
			                        DBUS_TIMEOUT_MSEC,
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

	nm_assert (!priv->net_path);
	g_variant_get (res, "(o)", &priv->net_path);

	/* Send blobs first; otherwise jump to selecting the network */
	blobs = nm_supplicant_config_get_blobs (priv->assoc_data->cfg);
	priv->assoc_data->blobs_left =   blobs
	                               ? g_hash_table_size (blobs)
	                               : 0u;

	_LOGT ("assoc["NM_HASH_OBFUSCATE_PTR_FMT"]: network added (%s) (%u blobs left)",
	       NM_HASH_OBFUSCATE_PTR (priv->assoc_data),
	       priv->net_path,
	       priv->assoc_data->blobs_left);

	if (priv->assoc_data->blobs_left == 0) {
		assoc_call_select_network (self);
		return;
	}

	g_hash_table_iter_init (&iter, blobs);
	while (g_hash_table_iter_next (&iter, (gpointer) &blob_name, (gpointer) &blob_data)) {
		_dbus_connection_call (self,
		                       NM_WPAS_DBUS_IFACE_INTERFACE,
		                       "AddBlob",
		                       g_variant_new ("(s@ay)",
		                                      blob_name,
		                                      nm_utils_gbytes_to_variant_ay (blob_data)),
		                       G_VARIANT_TYPE ("()"),
		                       G_DBUS_CALL_FLAGS_NONE,
		                       DBUS_TIMEOUT_MSEC,
		                       priv->assoc_data->cancellable,
		                       assoc_add_blob_cb,
		                       self);
	}
}

static void
assoc_set_ap_scan_cb (GVariant *ret, GError *error, gpointer user_data)
{
	NMSupplicantInterface *self;
	NMSupplicantInterfacePrivate *priv;
	AddNetworkData *add_network_data;

	if (nm_utils_error_is_cancelled (error))
		return;

	self = NM_SUPPLICANT_INTERFACE (user_data);
	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (error) {
		assoc_return (self, error, "failure to set AP scan mode");
		return;
	}

	_LOGT ("assoc["NM_HASH_OBFUSCATE_PTR_FMT"]: interface ap_scan set to %d",
	       NM_HASH_OBFUSCATE_PTR (priv->assoc_data),
	       nm_supplicant_config_get_ap_scan (priv->assoc_data->cfg));

	/* the association does not keep @self alive. We want to be able to remove
	 * the network again, even if @self is already gone. Hence, track the data
	 * separately.
	 *
	 * For that we also have a shutdown_wait_obj so that on exit we still wait
	 * to handle the response. */
	add_network_data = g_slice_new (AddNetworkData);
	*add_network_data = (AddNetworkData) {
		.assoc_data        = priv->assoc_data,
		.name_owner        = nm_ref_string_ref (priv->name_owner),
		.object_path       = nm_ref_string_ref (priv->object_path),
		.shutdown_wait_obj = g_object_new (G_TYPE_OBJECT, NULL),
	};
	nm_shutdown_wait_obj_register_object (add_network_data->shutdown_wait_obj, "supplicant-add-network");
	priv->assoc_data->add_network_data = add_network_data;

	_dbus_connection_call (self,
	                       NM_WPAS_DBUS_IFACE_INTERFACE,
	                       "AddNetwork",
	                       g_variant_new ("(@a{sv})", nm_supplicant_config_to_variant (priv->assoc_data->cfg)),
	                       G_VARIANT_TYPE ("(o)"),
	                       G_DBUS_CALL_FLAGS_NONE,
	                       DBUS_TIMEOUT_MSEC,
	                       NULL,
	                       assoc_add_network_cb,
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

	assoc_data = g_slice_new (AssocData);
	*assoc_data = (AssocData) {
		.self      = self,
		.cfg       = g_object_ref (cfg),
		.callback  = callback,
		.user_data = user_data,
	};

	priv->assoc_data = assoc_data;

	_LOGD ("assoc["NM_HASH_OBFUSCATE_PTR_FMT"]: starting association...",
	       NM_HASH_OBFUSCATE_PTR (assoc_data));

	if (   _get_capability (priv, NM_SUPPL_CAP_TYPE_FAST) == NM_TERNARY_FALSE
	    && nm_supplicant_config_fast_required (cfg)) {
		/* Make sure the supplicant supports EAP-FAST before trying to send
		 * it an EAP-FAST configuration.
		 */
		assoc_data->fail_on_idle_id = g_idle_add (assoc_fail_on_idle_cb, self);
		return;
	}

	assoc_data->cancellable = g_cancellable_new();
	nm_dbus_connection_call_set (priv->dbus_connection,
	                             priv->name_owner->str,
	                             priv->object_path->str,
	                             NM_WPAS_DBUS_IFACE_INTERFACE,
	                             "ApScan",
	                             g_variant_new_uint32 (nm_supplicant_config_get_ap_scan (priv->assoc_data->cfg)),
	                             DBUS_TIMEOUT_MSEC,
	                             assoc_data->cancellable,
	                             assoc_set_ap_scan_cb,
	                             self);
}

/*****************************************************************************/

typedef struct {
	NMSupplicantInterface *self;
	GCancellable *cancellable;
	NMSupplicantInterfaceRequestScanCallback callback;
	gpointer user_data;
} ScanRequestData;

static void
scan_request_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	gs_unref_object NMSupplicantInterface *self_keep_alive = NULL;
	NMSupplicantInterface *self;
	gs_unref_variant GVariant *res = NULL;
	gs_free_error GError *error = NULL;
	ScanRequestData *data = user_data;
	gboolean cancelled = FALSE;

	res = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), result, &error);
	if (nm_utils_error_is_cancelled (error)) {
		if (!data->callback) {
			/* the self instance was not kept alive. We also must not touch it. Return. */
			nm_g_object_unref (data->cancellable);
			nm_g_slice_free (data);
			return;
		}
		cancelled = TRUE;
	}

	self = data->self;
	if (data->callback) {
		/* the self instance was kept alive. Balance the reference count. */
		self_keep_alive = self;
	}

	/* we don't propagate the error/success. That is, because either answer is not
	 * reliable. What is important to us is whether the request completed, and
	 * the current nm_supplicant_interface_get_scanning() state. */
	if (cancelled)
		_LOGD ("request-scan: request cancelled");
	else {
		if (error) {
			if (_nm_dbus_error_has_name (error, "fi.w1.wpa_supplicant1.Interface.ScanError"))
				_LOGD ("request-scan: could not get scan request result: %s", error->message);
			else {
				g_dbus_error_strip_remote_error (error);
				_LOGW ("request-scan: could not get scan request result: %s", error->message);
			}
		} else
			_LOGT ("request-scan: request scanning success");
	}

	if (data->callback)
		data->callback (self, data->cancellable, data->user_data);

	nm_g_object_unref (data->cancellable);
	nm_g_slice_free (data);
}

void
nm_supplicant_interface_request_scan (NMSupplicantInterface *self,
                                      GBytes *const*ssids,
                                      guint ssids_len,
                                      GCancellable *cancellable,
                                      NMSupplicantInterfaceRequestScanCallback callback,
                                      gpointer user_data)
{
	NMSupplicantInterfacePrivate *priv;
	GVariantBuilder builder;
	ScanRequestData *data;
	guint i;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	nm_assert (   (!cancellable && !callback)
	           || (G_IS_CANCELLABLE (cancellable) && callback));

	priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	_LOGT ("request-scan: request scanning (%u ssids)...", ssids_len);

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

	data = g_slice_new (ScanRequestData);
	*data = (ScanRequestData) {
		.self            = self,
		.callback        = callback,
		.user_data       = user_data,
		.cancellable     = nm_g_object_ref (cancellable),
	};

	if (callback) {
		/* A callback was provided. This keeps @self alive. The caller
		 * must provide a cancellable as the caller must never leave an asynchronous
		 * operation pending indefinitely. */
		nm_assert (G_IS_CANCELLABLE (cancellable));
		g_object_ref (self);
	} else {
		/* We don't keep @self alive, and we don't accept a cancellable either. */
		nm_assert (!cancellable);
		cancellable = priv->main_cancellable;
	}

	_dbus_connection_call (self,
	                       NM_WPAS_DBUS_IFACE_INTERFACE,
	                       "Scan",
	                       g_variant_new ("(a{sv})", &builder),
	                       G_VARIANT_TYPE ("()"),
	                       G_DBUS_CALL_FLAGS_NONE,
	                       DBUS_TIMEOUT_MSEC,
	                       cancellable,
	                       scan_request_cb,
	                       data);
}

/*****************************************************************************/

NMSupplicantInterfaceState
nm_supplicant_interface_get_state (NMSupplicantInterface * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NM_SUPPLICANT_INTERFACE_STATE_DOWN);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->state;
}

void
_nm_supplicant_interface_set_state_down (NMSupplicantInterface * self,
                                         gboolean force_remove_from_supplicant,
                                         const char *reason)
{
	set_state_down (self, force_remove_from_supplicant, reason);
}

NMRefString *
nm_supplicant_interface_get_name_owner (NMSupplicantInterface *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->name_owner;
}

NMRefString *
nm_supplicant_interface_get_object_path (NMSupplicantInterface *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->object_path;
}

const char *
nm_supplicant_interface_get_ifname (NMSupplicantInterface *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_INTERFACE (self), NULL);

	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->ifname;
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
	GVariantBuilder builder;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));
	g_return_if_fail (timeout > 0 && timeout <= 600);

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_add (&builder, "{sv}", "Timeout", g_variant_new_int32 (timeout));

	_dbus_connection_call_simple (self,
	                              NM_WPAS_DBUS_IFACE_INTERFACE_P2P_DEVICE,
	                              "Find",
	                              g_variant_new ("(a{sv})", &builder),
	                              G_VARIANT_TYPE ("()"),
	                              "p2p-find");
}

void
nm_supplicant_interface_p2p_stop_find (NMSupplicantInterface *self)
{
	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	_dbus_connection_call_simple (self,
	                              NM_WPAS_DBUS_IFACE_INTERFACE_P2P_DEVICE,
	                              "StopFind",
	                              NULL,
	                              G_VARIANT_TYPE ("()"),
	                              "p2p-stop-find");
}

/*****************************************************************************/

void
nm_supplicant_interface_p2p_connect (NMSupplicantInterface *self,
                                     const char *peer,
                                     const char *wps_method,
                                     const char *wps_pin)
{
	GVariantBuilder builder;

	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	g_variant_builder_add (&builder, "{sv}", "wps_method", g_variant_new_string (wps_method));
	if (wps_pin)
		g_variant_builder_add (&builder, "{sv}", "pin", g_variant_new_string (wps_pin));
	g_variant_builder_add (&builder, "{sv}", "peer", g_variant_new_object_path (peer));
	g_variant_builder_add (&builder, "{sv}", "join", g_variant_new_boolean (FALSE));
	g_variant_builder_add (&builder, "{sv}", "persistent", g_variant_new_boolean (FALSE));
	g_variant_builder_add (&builder, "{sv}", "go_intent", g_variant_new_int32 (7));

	_dbus_connection_call_simple (self,
	                              NM_WPAS_DBUS_IFACE_INTERFACE_P2P_DEVICE,
	                              "Connect",
	                              g_variant_new ("(a{sv})", &builder),
	                              G_VARIANT_TYPE ("(s)"),
	                              "p2p-connect");
}

void
nm_supplicant_interface_p2p_cancel_connect (NMSupplicantInterface * self)
{
	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	_dbus_connection_call_simple (self,
	                              NM_WPAS_DBUS_IFACE_INTERFACE_P2P_DEVICE,
	                              "Cancel",
	                              NULL,
	                              G_VARIANT_TYPE ("()"),
	                              "p2p-cancel");
}

void
nm_supplicant_interface_p2p_disconnect (NMSupplicantInterface * self)
{
	g_return_if_fail (NM_IS_SUPPLICANT_INTERFACE (self));

	_dbus_connection_call_simple (self,
	                              NM_WPAS_DBUS_IFACE_INTERFACE_P2P_DEVICE,
	                              "Disconnect",
	                              NULL,
	                              G_VARIANT_TYPE ("()"),
	                              "p2p-disconnect");
}

/*****************************************************************************/

static void
_properties_changed (NMSupplicantInterface *self,
                     const char *interface_name,
                     GVariant *properties,
                     gboolean initial)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	gboolean is_main;

	nm_assert (!properties || g_variant_is_of_type (properties, G_VARIANT_TYPE ("a{sv}")));

	if (initial)
		priv->starting_pending_count--;

	if (   (initial || priv->is_ready_main)
	    && nm_streq (interface_name, NM_WPAS_DBUS_IFACE_INTERFACE))
		is_main = TRUE;
	else if (   (initial || priv->is_ready_p2p_device)
	         && nm_streq (interface_name, NM_WPAS_DBUS_IFACE_INTERFACE_P2P_DEVICE)) {
		nm_assert (_get_capability (priv, NM_SUPPL_CAP_TYPE_P2P) == NM_TERNARY_TRUE);
		is_main = FALSE;
	} else
		return;

	g_object_freeze_notify (G_OBJECT (self));

	priv->starting_pending_count++;

	if (is_main) {
		priv->is_ready_main = TRUE;
		_properties_changed_main (self, properties);
	} else {
		priv->is_ready_p2p_device = TRUE;
		_properties_changed_p2p_device (self, properties);
	}

	priv->starting_pending_count--;
	_starting_check_ready (self);

	_notify_maybe_scanning (self);
	_notify_maybe_p2p_available (self);

	g_object_thaw_notify (G_OBJECT (self));
}

static void
_properties_changed_cb (GDBusConnection *connection,
                        const char *sender_name,
                        const char *object_path,
                        const char *signal_interface_name,
                        const char *signal_name,
                        GVariant *parameters,
                        gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	const char *interface_name;
	gs_unref_variant GVariant *changed_properties = NULL;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sa{sv}as)")))
		return;

	g_variant_get (parameters,
	               "(&s@a{sv}^a&s)",
	               &interface_name,
	               &changed_properties,
	               NULL);
	_properties_changed (self,
	                     interface_name,
	                     changed_properties,
	                     FALSE);
}

static void
_bss_properties_changed_cb (GDBusConnection *connection,
                            const char *sender_name,
                            const char *object_path,
                            const char *signal_interface_name,
                            const char *signal_name,
                            GVariant *parameters,
                            gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	nm_auto_ref_string NMRefString *bss_path = NULL;
	gs_unref_variant GVariant *changed_properties = NULL;
	NMSupplicantBssInfo *bss_info;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sa{sv}as)")))
		return;

	bss_path = nm_ref_string_new (object_path);

	bss_info = g_hash_table_lookup (priv->bss_idx, &bss_path);
	if (!bss_info)
		return;
	if (bss_info->_init_cancellable)
		return;

	g_variant_get (parameters,
	               "(&s@a{sv}^a&s)",
	               NULL,
	               &changed_properties,
	               NULL);
	_bss_info_properties_changed (self, bss_info, changed_properties, FALSE);
}

static void
_peer_properties_changed_cb (GDBusConnection *connection,
                             const char *sender_name,
                             const char *object_path,
                             const char *signal_interface_name,
                             const char *signal_name,
                             GVariant *parameters,
                             gpointer user_data)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (user_data);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	nm_auto_ref_string NMRefString *peer_path = NULL;
	gs_unref_variant GVariant *changed_properties = NULL;
	NMSupplicantPeerInfo *peer_info;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sa{sv}as)")))
		return;

	peer_path = nm_ref_string_new (object_path);

	peer_info = g_hash_table_lookup (priv->peer_idx, &peer_path);
	if (!peer_info)
		return;
	if (peer_info->_init_cancellable)
		return;

	g_variant_get (parameters,
	               "(&s@a{sv}^a&s)",
	               NULL,
	               &changed_properties,
	               NULL);
	_peer_info_properties_changed (self, peer_info, changed_properties, FALSE);
}

static void
_get_all_main_cb (GVariant *result,
                  GError *error,
                  gpointer user_data)
{
	gs_unref_variant GVariant *properties = NULL;

	if (nm_utils_error_is_cancelled (error))
		return;

	if (result)
		g_variant_get (result, "(@a{sv})", &properties);
	_properties_changed (user_data,
	                     NM_WPAS_DBUS_IFACE_INTERFACE,
	                     properties,
	                     TRUE);
}

static void
_get_all_p2p_device_cb (GVariant *result,
                        GError *error,
                        gpointer user_data)
{
	gs_unref_variant GVariant *properties = NULL;

	if (nm_utils_error_is_cancelled (error))
		return;

	if (result)
		g_variant_get (result, "(@a{sv})", &properties);
	_properties_changed (user_data,
	                     NM_WPAS_DBUS_IFACE_INTERFACE_P2P_DEVICE,
	                     properties,
	                     TRUE);
}

static void
_signal_handle (NMSupplicantInterface *self,
                const char *signal_interface_name,
                const char *signal_name,
                GVariant *parameters)
{
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);
	const char *path;

	if (nm_streq (signal_interface_name, NM_WPAS_DBUS_IFACE_INTERFACE)) {

		if (!priv->is_ready_main)
			return;

		if (nm_streq (signal_name, "BSSAdded")) {
			if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(oa{sv})")))
				return;

			g_variant_get (parameters, "(&oa{sv})", &path, NULL);
			_bss_info_add (self, path);
			return;
		}

		if (nm_streq (signal_name, "BSSRemoved")) {
			nm_auto_ref_string NMRefString *bss_path = NULL;

			if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(o)")))
				return;

			g_variant_get (parameters, "(&o)", &path);
			bss_path = nm_ref_string_new (path);
			_bss_info_remove (self, &bss_path);
			return;
		}

		if (nm_streq (signal_name, "EAP")) {
			NMSupplicantAuthState auth_state = NM_SUPPLICANT_AUTH_STATE_UNKNOWN;
			const char *status;
			const char *parameter;

			if (g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(ss)")))
				return;

			g_variant_get (parameters, "(&s&s)", &status, &parameter);

			if (nm_streq (status, "started"))
				auth_state = NM_SUPPLICANT_AUTH_STATE_STARTED;
			else if (nm_streq (status, "completion")) {
				if (nm_streq (parameter, "success"))
					auth_state = NM_SUPPLICANT_AUTH_STATE_SUCCESS;
				else if (nm_streq (parameter, "failure"))
					auth_state = NM_SUPPLICANT_AUTH_STATE_FAILURE;
			}

			/* the state eventually reaches one of started, success or failure
			 * so ignore any other intermediate (unknown) state change. */
			if (   auth_state != NM_SUPPLICANT_AUTH_STATE_UNKNOWN
			    && auth_state != priv->auth_state) {
				priv->auth_state = auth_state;
				_notify (self, PROP_AUTH_STATE);
			}
			return;
		}

		return;
	}

	if (nm_streq (signal_interface_name, NM_WPAS_DBUS_IFACE_INTERFACE_P2P_DEVICE)) {

		if (!priv->is_ready_p2p_device)
			return;

		if (nm_streq (signal_name, "DeviceFound")) {
			if (g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(o)"))) {
				g_variant_get (parameters, "(&o)", &path);
				_peer_info_add (self, path);
			}
			return;
		}

		if (nm_streq (signal_name, "DeviceLost")) {
			if (g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(o)"))) {
				nm_auto_ref_string NMRefString *peer_path = NULL;

				g_variant_get (parameters, "(&o)", &path);
				peer_path = nm_ref_string_new (path);
				_peer_info_remove (self, &peer_path);
			}
			return;
		}

		if (nm_streq (signal_name, "GroupStarted")) {
			if (g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(a{sv})"))) {
				gs_unref_variant GVariant *args = NULL;
				gs_unref_object NMSupplicantInterface *iface = NULL;
				const char *group_path;
				const char *iface_path;

				g_variant_get (parameters, "(@a{sv})", &args);
				if (!g_variant_lookup (args, "group_object", "&o", &group_path))
					return;
				if (!g_variant_lookup (args, "interface_object", "&o", &iface_path))
					return;

				if (nm_streq (iface_path, priv->object_path->str)) {
					_LOGW ("P2P: GroupStarted on existing interface");
					iface = g_object_ref (self);
				} else {
					iface = nm_supplicant_manager_create_interface_from_path (priv->supplicant_manager,
					                                                          iface_path);
					if (iface == NULL) {
						_LOGW ("P2P: Group interface already exists in GroupStarted handler, aborting further processing.");
						return;
					}
				}

				/* Signal existence of the (new) interface. */
				g_signal_emit (self, signals[GROUP_STARTED], 0, iface);
			}
			return;
		}

		if (nm_streq (signal_name, "GroupFinished")) {
			if (g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(a{sv})"))) {
				gs_unref_variant GVariant *args = NULL;
				const char *iface_path;

				g_variant_get (parameters, "(@a{sv})", &args);

				/* TODO: Group finished is called on the management interface!
				 *       This means the signal consumer will currently need to assume which
				 *       interface is finishing or it needs to match the object paths.
				 */
				if (!g_variant_lookup (args, "interface_object", "&o", &iface_path))
					return;

				_LOGD ("P2P: GroupFinished signal on interface %s for interface %s", priv->object_path->str, iface_path);

				/* Signal group finish interface (on management interface). */
				g_signal_emit (self, signals[GROUP_FINISHED], 0, iface_path);
			}
			return;
		}

		return;
	}
}

static void
_signal_cb (GDBusConnection *connection,
            const char *sender_name,
            const char *object_path,
            const char *signal_interface_name,
            const char *signal_name,
            GVariant *parameters,
            gpointer user_data)
{
	NMSupplicantInterface *self = user_data;
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	priv->starting_pending_count++;
	_signal_handle (self, signal_interface_name, signal_name, parameters);
	priv->starting_pending_count--;
	_starting_check_ready (self);

	_notify_maybe_scanning (self);
}

/*****************************************************************************/

gboolean
nm_supplicant_interface_get_p2p_available (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->p2p_capable_cached;
}

gboolean
nm_supplicant_interface_get_p2p_group_joined (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->p2p_group_joined_cached;
}

const char*
nm_supplicant_interface_get_p2p_group_path (NMSupplicantInterface *self)
{
	return nm_ref_string_get_str (NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->p2p_group_path);
}

gboolean
nm_supplicant_interface_get_p2p_group_owner (NMSupplicantInterface *self)
{
	return NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self)->p2p_group_owner_cached;
}

/*****************************************************************************/

static void
get_property (GObject *object,
              guint prop_id,
              GValue *value,
              GParamSpec *pspec)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (object);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_SCANNING:
		g_value_set_boolean (value, nm_supplicant_interface_get_scanning (self));
		break;
	case PROP_CURRENT_BSS:
		g_value_set_string (value, nm_ref_string_get_str (nm_supplicant_interface_get_current_bss (self)));
		break;
	case PROP_P2P_GROUP_JOINED:
		g_value_set_boolean (value, nm_supplicant_interface_get_p2p_group_joined (self));
		break;
	case PROP_P2P_GROUP_PATH:
		g_value_set_string (value, nm_supplicant_interface_get_p2p_group_path (self));
		break;
	case PROP_P2P_GROUP_OWNER:
		g_value_set_boolean (value, nm_supplicant_interface_get_p2p_group_owner (self));
		break;
	case PROP_P2P_AVAILABLE:
		g_value_set_boolean (value, nm_supplicant_interface_get_p2p_available (self));
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
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SUPPLICANT_MANAGER:
		/* construct-only */
		priv->supplicant_manager = g_object_ref (g_value_get_pointer (value));
		nm_assert (NM_IS_SUPPLICANT_MANAGER (priv->supplicant_manager));

		priv->dbus_connection = g_object_ref (nm_supplicant_manager_get_dbus_connection (priv->supplicant_manager));
		nm_assert (G_IS_DBUS_CONNECTION (priv->dbus_connection));

		priv->name_owner = nm_ref_string_ref (nm_supplicant_manager_get_dbus_name_owner (priv->supplicant_manager));
		nm_assert (NM_IS_REF_STRING (priv->name_owner));

		priv->global_capabilities = nm_supplicant_manager_get_global_capabilities (priv->supplicant_manager);
		break;
	case PROP_DBUS_OBJECT_PATH:
		/* construct-only */
		priv->object_path = nm_ref_string_ref (g_value_get_pointer (value));
		nm_assert (NM_IS_REF_STRING (priv->object_path));
		break;
	case PROP_IFINDEX:
		/* construct-only */
		priv->ifindex = g_value_get_int (value);
		break;
	case PROP_DRIVER:
		/* construct-only */
		priv->requested_driver = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_supplicant_interface_init (NMSupplicantInterface * self)
{
	NMSupplicantInterfacePrivate *priv;

	priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_SUPPLICANT_INTERFACE, NMSupplicantInterfacePrivate);

	self->_priv = priv;

	nm_assert (priv->global_capabilities == NM_SUPPL_CAP_MASK_NONE);
	nm_assert (priv->iface_capabilities == NM_SUPPL_CAP_MASK_NONE);

	priv->state = NM_SUPPLICANT_INTERFACE_STATE_STARTING;
	priv->supp_state = NM_SUPPLICANT_INTERFACE_STATE_INVALID;
	priv->last_scan_msec = -1;

	c_list_init (&self->supp_lst);

	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMSupplicantBssInfo, bss_path) == 0);
	priv->bss_idx = g_hash_table_new (nm_pdirect_hash, nm_pdirect_equal);

	c_list_init (&priv->bss_lst_head);
	c_list_init (&priv->bss_initializing_lst_head);

	G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NMSupplicantPeerInfo, peer_path) == 0);
	priv->peer_idx = g_hash_table_new (nm_pdirect_hash, nm_pdirect_equal);

	c_list_init (&priv->peer_lst_head);
	c_list_init (&priv->peer_initializing_lst_head);

	priv->main_cancellable = g_cancellable_new ();
}

static void
constructed (GObject *object)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (object);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	G_OBJECT_CLASS (nm_supplicant_interface_parent_class)->constructed (object);

	_LOGD ("new supplicant interface %s on %s",
	       priv->object_path->str,
	       priv->name_owner->str);

	priv->properties_changed_id = nm_dbus_connection_signal_subscribe_properties_changed (priv->dbus_connection,
	                                                                                      priv->name_owner->str,
	                                                                                      priv->object_path->str,
	                                                                                      NULL,
	                                                                                      _properties_changed_cb,
	                                                                                      self,
	                                                                                      NULL);

	priv->bss_properties_changed_id = nm_dbus_connection_signal_subscribe_properties_changed (priv->dbus_connection,
	                                                                                          priv->name_owner->str,
	                                                                                          NULL,
	                                                                                          NM_WPAS_DBUS_IFACE_BSS,
	                                                                                          _bss_properties_changed_cb,
	                                                                                          self,
	                                                                                          NULL);

	priv->signal_id = g_dbus_connection_signal_subscribe (priv->dbus_connection,
	                                                      priv->name_owner->str,
	                                                      NULL,
	                                                      NULL,
	                                                      priv->object_path->str,
	                                                      NULL,
	                                                      G_DBUS_SIGNAL_FLAGS_NONE,
	                                                      _signal_cb,
	                                                      self,
	                                                      NULL);

	/* Scan result aging parameters */
	nm_dbus_connection_call_set (priv->dbus_connection,
	                             priv->name_owner->str,
	                             priv->object_path->str,
	                             NM_WPAS_DBUS_IFACE_INTERFACE,
	                             "BSSExpireAge",
	                             g_variant_new_uint32 (250),
	                             DBUS_TIMEOUT_MSEC,
	                             NULL,
	                             NULL,
	                             NULL);
	nm_dbus_connection_call_set (priv->dbus_connection,
	                             priv->name_owner->str,
	                             priv->object_path->str,
	                             NM_WPAS_DBUS_IFACE_INTERFACE,
	                             "BSSExpireCount",
	                             g_variant_new_uint32 (2),
	                             DBUS_TIMEOUT_MSEC,
	                             NULL,
	                             NULL,
	                             NULL);

	if (_get_capability (priv, NM_SUPPL_CAP_TYPE_PMF) == NM_TERNARY_TRUE) {
		/* Initialize global PMF setting to 'optional' */
		nm_dbus_connection_call_set (priv->dbus_connection,
		                             priv->name_owner->str,
		                             priv->object_path->str,
		                             NM_WPAS_DBUS_IFACE_INTERFACE,
		                             "Pmf",
		                             g_variant_new_string ("1"),
		                             DBUS_TIMEOUT_MSEC,
		                             NULL,
		                             NULL,
		                             NULL);
	}

	if (_get_capability (priv, NM_SUPPL_CAP_TYPE_AP) == NM_TERNARY_DEFAULT) {
		/* If the global supplicant capabilities property is not present, we can
		 * fall back to checking whether the ProbeRequest method is supported.  If
		 * neither of these works we have no way of determining if AP mode is
		 * supported or not.  hostap 1.0 and earlier don't support either of these.
		 */
		priv->starting_pending_count++;
		_dbus_connection_call (self,
		                       DBUS_INTERFACE_INTROSPECTABLE,
		                       "Introspect",
		                       NULL,
		                       G_VARIANT_TYPE ("(s)"),
		                       G_DBUS_CALL_FLAGS_NONE,
		                       5000,
		                       priv->main_cancellable,
		                       iface_introspect_cb,
		                       self);
	}

	priv->starting_pending_count++;
	nm_dbus_connection_call_get_all (priv->dbus_connection,
	                                 priv->name_owner->str,
	                                 priv->object_path->str,
	                                 NM_WPAS_DBUS_IFACE_INTERFACE,
	                                 5000,
	                                 priv->main_cancellable,
	                                 _get_all_main_cb,
	                                 self);

	if (_get_capability (priv, NM_SUPPL_CAP_TYPE_P2P) == NM_TERNARY_TRUE) {
		priv->peer_properties_changed_id = nm_dbus_connection_signal_subscribe_properties_changed (priv->dbus_connection,
		                                                                                           priv->name_owner->str,
		                                                                                           NULL,
		                                                                                           NM_WPAS_DBUS_IFACE_PEER,
		                                                                                           _peer_properties_changed_cb,
		                                                                                           self,
		                                                                                           NULL);

		priv->starting_pending_count++;
		nm_dbus_connection_call_get_all (priv->dbus_connection,
		                                 priv->name_owner->str,
		                                 priv->object_path->str,
		                                 NM_WPAS_DBUS_IFACE_INTERFACE_P2P_DEVICE,
		                                 5000,
		                                 priv->main_cancellable,
		                                 _get_all_p2p_device_cb,
		                                 self);
	}
}

NMSupplicantInterface *
nm_supplicant_interface_new (NMSupplicantManager *supplicant_manager,
                             NMRefString *object_path,
                             int ifindex,
                             NMSupplicantDriver driver)
{
	nm_assert (NM_IS_SUPPLICANT_MANAGER (supplicant_manager));

	return g_object_new (NM_TYPE_SUPPLICANT_INTERFACE,
	                     NM_SUPPLICANT_INTERFACE_SUPPLICANT_MANAGER, supplicant_manager,
	                     NM_SUPPLICANT_INTERFACE_DBUS_OBJECT_PATH, object_path,
	                     NM_SUPPLICANT_INTERFACE_IFINDEX, ifindex,
	                     NM_SUPPLICANT_INTERFACE_DRIVER, (guint) driver,
	                     NULL);
}

static void
dispose (GObject *object)
{
	NMSupplicantInterface *self = NM_SUPPLICANT_INTERFACE (object);
	NMSupplicantInterfacePrivate *priv = NM_SUPPLICANT_INTERFACE_GET_PRIVATE (self);

	if (priv->state != NM_SUPPLICANT_INTERFACE_STATE_DOWN)
		set_state_down (self, TRUE, "NMSupplicantInterface is disposing");

	nm_assert (c_list_is_empty (&self->supp_lst));

	if (priv->wps_data) {
		/* we shut down, but an asynchronous Cancel request is pending.
		 * We don't want to cancel it, so mark wps-data that @self is gone.
		 * This way, _wps_handle_cancel_cb() knows it must no longer touch
		 * @self */
		priv->wps_data->self = NULL;
		priv->wps_data = NULL;
	}

	nm_assert (!priv->assoc_data);

	nm_clear_pointer (&priv->bss_idx, g_hash_table_destroy);
	nm_clear_pointer (&priv->peer_idx, g_hash_table_destroy);

	nm_clear_pointer (&priv->current_bss, nm_ref_string_unref);

	G_OBJECT_CLASS (nm_supplicant_interface_parent_class)->dispose (object);

	nm_clear_pointer (&priv->object_path, nm_ref_string_unref);
	nm_clear_pointer (&priv->name_owner, nm_ref_string_unref);
	g_clear_object (&priv->supplicant_manager);
	g_clear_object (&priv->dbus_connection);
	nm_clear_g_free (&priv->ifname);
	nm_assert (!priv->net_path);
}

static void
nm_supplicant_interface_class_init (NMSupplicantInterfaceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMSupplicantInterfacePrivate));

	object_class->constructed  = constructed;
	object_class->dispose      = dispose;
	object_class->set_property = set_property;
	object_class->get_property = get_property;

	obj_properties[PROP_SUPPLICANT_MANAGER] =
	    g_param_spec_pointer (NM_SUPPLICANT_INTERFACE_SUPPLICANT_MANAGER, "", "",
	                          G_PARAM_WRITABLE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DBUS_OBJECT_PATH] =
	    g_param_spec_pointer (NM_SUPPLICANT_INTERFACE_DBUS_OBJECT_PATH, "", "",
	                          G_PARAM_WRITABLE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_IFINDEX] =
	    g_param_spec_int (NM_SUPPLICANT_INTERFACE_IFINDEX, "", "",
	                      0, G_MAXINT, 0,
	                      G_PARAM_WRITABLE |
	                      G_PARAM_CONSTRUCT_ONLY |
	                      G_PARAM_STATIC_STRINGS);
	obj_properties[PROP_DRIVER] =
	    g_param_spec_uint (NM_SUPPLICANT_INTERFACE_DRIVER, "", "",
	                       0, G_MAXUINT, NM_SUPPLICANT_DRIVER_WIRELESS,
	                       G_PARAM_WRITABLE |
	                       G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);

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
	obj_properties[PROP_P2P_AVAILABLE] =
	    g_param_spec_boolean (NM_SUPPLICANT_INTERFACE_P2P_AVAILABLE, "", "",
	                          FALSE,
	                          G_PARAM_READABLE |
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

	signals[BSS_CHANGED] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_BSS_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_BOOLEAN);

	signals[PEER_CHANGED] =
	    g_signal_new (NM_SUPPLICANT_INTERFACE_PEER_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_LAST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_POINTER, G_TYPE_BOOLEAN);

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
