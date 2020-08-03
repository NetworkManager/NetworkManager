// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-l3cfg.h"

#include <net/if.h>

#include "platform/nm-platform.h"
#include "platform/nmp-object.h"
#include "nm-netns.h"
#include "n-acd/src/n-acd.h"

/*****************************************************************************/

#define ACD_SUPPORTED_ETH_ALEN                  ETH_ALEN
#define ACD_ENSURE_RATELIMIT_MSEC               ((guint32) 4000u)
#define ACD_WAIT_PROBING_EXTRA_TIME_MSEC        ((guint32) (1000u + ACD_ENSURE_RATELIMIT_MSEC))
#define ACD_WAIT_PROBING_EXTRA_TIME2_MSEC       ((guint32) 1000u)
#define ACD_WAIT_PROBING_RESTART_TIME_MSEC      ((guint32) 8000u)
#define ACD_MAX_TIMEOUT_MSEC                    ((guint32) 30000u)
#define ACD_WAIT_TIME_PROBING_FULL_RESTART_MSEC ((guint32) 30000u)
#define ACD_WAIT_TIME_ANNOUNCE_RESTART_MSEC     ((guint32) 20000u)

static gboolean
ACD_ADDR_SKIP (in_addr_t addr)
{
	return addr == 0u;
}

#define ACD_TRACK_FMT                  "["NM_HASH_OBFUSCATE_PTR_FMT","NM_HASH_OBFUSCATE_PTR_FMT","NM_HASH_OBFUSCATE_PTR_FMT"]"
#define ACD_TRACK_PTR2(l3cd, obj, tag) NM_HASH_OBFUSCATE_PTR (l3cd), NM_HASH_OBFUSCATE_PTR (obj), NM_HASH_OBFUSCATE_PTR (tag)
#define ACD_TRACK_PTR(acd_track)       ACD_TRACK_PTR2 ((acd_track)->l3cd, (acd_track)->obj, (acd_track)->tag)

typedef enum {
	ACD_STATE_CHANGE_MODE_INIT,
	ACD_STATE_CHANGE_MODE_POST_COMMIT,

	ACD_STATE_CHANGE_MODE_NACD_READY,
	ACD_STATE_CHANGE_MODE_NACD_USED,
	ACD_STATE_CHANGE_MODE_NACD_DOWN,

	ACD_STATE_CHANGE_MODE_EXTERNAL_ADDED,
	ACD_STATE_CHANGE_MODE_EXTERNAL_REMOVED,
	ACD_STATE_CHANGE_MODE_LINK_NOW_UP,
	ACD_STATE_CHANGE_MODE_INSTANCE_RESET,
	ACD_STATE_CHANGE_MODE_TIMEOUT,
} AcdStateChangeMode;

typedef struct {
	CList acd_track_lst;
	const NMPObject *obj;
	const NML3ConfigData *l3cd;
	gconstpointer tag;
	guint32 acd_timeout_msec;
	bool acd_dirty:1;
	bool acd_failed_notified:1;
} AcdTrackData;

typedef enum _nm_packed {
	ACD_STATE_INIT,
	ACD_STATE_PROBING,
	ACD_STATE_PROBE_DONE,
	ACD_STATE_ANNOUNCING,
} AcdState;

typedef struct {
	in_addr_t addr;

	/* This is only relevant while in state ACD_STATE_PROBING. It's the
	 * duration for how long we probe, and @probing_timestamp_msec is the
	 * timestamp when we start probing. */
	guint32 probing_timeout_msec;

	CList acd_lst;
	CList acd_track_lst_head;

	NML3Cfg *self;

	NAcdProbe *nacd_probe;

	GSource *acd_timeout_source;
	gint64 acd_timeout_expiry_msec;

	/* see probing_timeout_msec. */
	gint64 probing_timestamp_msec;

	/* the ACD state for this address. */
	AcdState acd_state;

	/* The probe result. This is only relevant if @acd_state is ACD_STATE_PROBE_DONE.
	 * In state ACD_STATE_ANNOUNCING the @probe_result must be TRUE. */
	bool probe_result:1;

	bool announcing_failed_is_retrying:1;
} AcdData;

typedef struct {
	const NML3ConfigData *l3cd;
	NML3ConfigMergeFlags merge_flags;
	union {
		struct {
			guint32 default_route_penalty_6;
			guint32 default_route_penalty_4;
		};
		guint32 default_route_penalty_x[2];
	};
	gconstpointer tag;
	guint64 pseudo_timestamp;
	int priority;
	guint32 acd_timeout_msec;
	bool dirty:1;
} L3ConfigData;

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NML3Cfg,
	PROP_NETNS,
	PROP_IFINDEX,
);

enum {
	SIGNAL_NOTIFY,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct _NML3CfgPrivate {
	GArray *property_emit_list;
	GArray *l3_config_datas;
	const NML3ConfigData *combined_l3cd;

	GHashTable *routes_temporary_not_available_hash;

	GHashTable *externally_removed_objs_hash;

	GHashTable *acd_ipv4_addresses_on_link;

	GHashTable *acd_lst_hash;
	CList acd_lst_head;

	NAcd *nacd;
	GSource *nacd_source;

	/* This is for rate-limiting the creation of nacd instance. */
	GSource *nacd_instance_ensure_retry;

	GSource *acd_ready_on_idle_source;

	guint64 pseudo_timestamp_counter;

	union {
		struct {
			guint externally_removed_objs_cnt_addresses_6;
			guint externally_removed_objs_cnt_addresses_4;
		};
		guint externally_removed_objs_cnt_addresses_x[2];
	};

	union {
		struct {
			guint externally_removed_objs_cnt_routes_6;
			guint externally_removed_objs_cnt_routes_4;
		};
		guint externally_removed_objs_cnt_routes_x[2];
	};

	guint routes_temporary_not_available_id;

	bool acd_is_pending:1;
	bool acd_is_announcing:1;

	bool nacd_acd_not_supported:1;
	bool acd_ipv4_addresses_on_link_has:1;

} NML3CfgPrivate;

struct _NML3CfgClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NML3Cfg, nm_l3cfg, G_TYPE_OBJECT)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_CORE
#define _NMLOG_PREFIX_NAME "l3cfg"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), (_NMLOG_DOMAIN), NULL, NULL, \
                "l3cfg["NM_HASH_OBFUSCATE_PTR_FMT",ifindex=%d]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                NM_HASH_OBFUSCATE_PTR (self), \
                nm_l3cfg_get_ifindex (self) \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

#define _LOGT_acd(acd_data, ...) \
	G_STMT_START { \
		char _sbuf_acd[NM_UTILS_INET_ADDRSTRLEN]; \
		\
		_LOGT ("acd[%s]: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
		       _nm_utils_inet4_ntop ((acd_data)->addr, _sbuf_acd) \
		       _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
	} G_STMT_END

/*****************************************************************************/

static void _property_emit_notify (NML3Cfg *self, NML3CfgPropertyEmitType emit_type);

static gboolean _acd_has_valid_link (const NMPObject *obj,
                                     const guint8 **out_addr_bin,
                                     gboolean *out_acd_not_supported);

static void _l3_acd_nacd_instance_reset (NML3Cfg *self,
                                         NMTernary start_timer,
                                         gboolean acd_data_notify);

static void _l3_acd_data_prune (NML3Cfg *self,
                                gboolean all);

static void _l3_acd_data_state_change (NML3Cfg *self,
                                       AcdData *acd_data,
                                       AcdStateChangeMode mode,
                                       NAcdEvent *event);

static AcdData *_l3_acd_data_find (NML3Cfg *self,
                                   in_addr_t addr);

/*****************************************************************************/

static
NM_UTILS_ENUM2STR_DEFINE (_l3_cfg_commit_type_to_string, NML3CfgCommitType,
	NM_UTILS_ENUM2STR (NM_L3_CFG_COMMIT_TYPE_ASSUME,  "assume"),
	NM_UTILS_ENUM2STR (NM_L3_CFG_COMMIT_TYPE_UPDATE,  "update"),
	NM_UTILS_ENUM2STR (NM_L3_CFG_COMMIT_TYPE_REAPPLY, "reapply"),
);

/*****************************************************************************/

static void
_l3cfg_emit_signal_notify (NML3Cfg *self,
                           NML3ConfigNotifyType notify_type,
                           const NML3ConfigNotifyPayload *pay_load)
{
	nm_assert (_NM_INT_NOT_NEGATIVE (notify_type));
	nm_assert (notify_type < _NM_L3_CONFIG_NOTIFY_TYPE_NUM);

	g_signal_emit (self,
	               signals[SIGNAL_NOTIFY],
	               0,
	               (int) notify_type,
	               pay_load);
}

/*****************************************************************************/

static void
_l3_acd_ipv4_addresses_on_link_update (NML3Cfg *self,
                                       in_addr_t addr,
                                       gboolean add /* or else remove */)
{
	AcdData *acd_data;

	acd_data = _l3_acd_data_find (self, addr);

	if (add) {
		if (self->priv.p->acd_ipv4_addresses_on_link)
			g_hash_table_add (self->priv.p->acd_ipv4_addresses_on_link, GUINT_TO_POINTER (addr));
		else
			self->priv.p->acd_ipv4_addresses_on_link_has = FALSE;
		if (acd_data)
			_l3_acd_data_state_change (self, acd_data, ACD_STATE_CHANGE_MODE_EXTERNAL_ADDED, NULL);
		return;
	}

	/* when we remove an IPv4 address from kernel, we cannot know whether the same address is still
	 * present (with a different prefix length or peer). So we cannot be sure whether we removed
	 * the only address, or whether more are still present. All we can do is forget about the
	 * cached addresses, and fetch them new the next time we need the information. */
	nm_clear_pointer (&self->priv.p->acd_ipv4_addresses_on_link, g_hash_table_unref);
	self->priv.p->acd_ipv4_addresses_on_link_has = FALSE;
	if (acd_data)
		_l3_acd_data_state_change (self, acd_data, ACD_STATE_CHANGE_MODE_EXTERNAL_REMOVED, NULL);
}

static gboolean
_l3_acd_ipv4_addresses_on_link_contains (NML3Cfg *self,
                                         in_addr_t addr)
{
	if (!self->priv.p->acd_ipv4_addresses_on_link) {
		if (self->priv.p->acd_ipv4_addresses_on_link_has)
			return FALSE;
		self->priv.p->acd_ipv4_addresses_on_link_has = TRUE;
		self->priv.p->acd_ipv4_addresses_on_link = nm_platform_ip4_address_addr_to_hash (self->priv.platform,
		                                                                                 self->priv.ifindex);
		if (!self->priv.p->acd_ipv4_addresses_on_link)
			return FALSE;
	}
	return g_hash_table_contains (self->priv.p->acd_ipv4_addresses_on_link,
	                              GUINT_TO_POINTER (addr));
}

/*****************************************************************************/

static NAcdProbe *
_nm_n_acd_data_probe_new (NML3Cfg *self,
                          in_addr_t addr,
                          guint32 timeout_msec,
                          gpointer user_data)
{
	nm_auto (n_acd_probe_config_freep) NAcdProbeConfig *probe_config = NULL;
	NAcdProbe *probe;
	int r;

	nm_assert (self);

	if (!self->priv.p->nacd)
		return NULL;

	if (addr == 0)
		return nm_assert_unreachable_val (NULL);

	r = n_acd_probe_config_new (&probe_config);
	if (r)
		return NULL;

	n_acd_probe_config_set_ip (probe_config, (struct in_addr) { addr });
	n_acd_probe_config_set_timeout (probe_config, timeout_msec);

	r = n_acd_probe (self->priv.p->nacd, &probe, probe_config);
	if (r)
		return NULL;

	n_acd_probe_set_userdata (probe, user_data);
	return probe;
}

/*****************************************************************************/

static guint *
_l3cfg_externally_removed_objs_counter (NML3Cfg *self,
                                        NMPObjectType obj_type)
{
	switch (obj_type) {
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
		return &self->priv.p->externally_removed_objs_cnt_addresses_4;
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
		return &self->priv.p->externally_removed_objs_cnt_addresses_6;
	case NMP_OBJECT_TYPE_IP4_ROUTE:
		return &self->priv.p->externally_removed_objs_cnt_routes_4;
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		return &self->priv.p->externally_removed_objs_cnt_routes_6;
	default:
		return nm_assert_unreachable_val (NULL);
	}
}

static void
_l3cfg_externally_removed_objs_drop (NML3Cfg *self,
                                     int addr_family)
{
	const gboolean IS_IPv4 = NM_IS_IPv4 (addr_family);
	GHashTableIter iter;
	const NMPObject *obj;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET, AF_INET6));

	if (addr_family == AF_UNSPEC) {
		self->priv.p->externally_removed_objs_cnt_addresses_4 = 0;
		self->priv.p->externally_removed_objs_cnt_addresses_6 = 0;
		self->priv.p->externally_removed_objs_cnt_routes_4 = 0;
		self->priv.p->externally_removed_objs_cnt_routes_6 = 0;
		if (g_hash_table_size (self->priv.p->externally_removed_objs_hash) > 0)
			_LOGD ("externally-removed: untrack all");
		nm_clear_pointer (&self->priv.p->externally_removed_objs_hash, g_hash_table_unref);
		return;
	}

	if (   self->priv.p->externally_removed_objs_cnt_addresses_x[IS_IPv4] == 0
	    && self->priv.p->externally_removed_objs_cnt_routes_x[IS_IPv4] == 0)
		return;

	_LOGD ("externally-removed: untrack IPv%c",
	       nm_utils_addr_family_to_char (addr_family));

	g_hash_table_iter_init (&iter, self->priv.p->externally_removed_objs_hash);
	while (g_hash_table_iter_next (&iter, (gpointer *) &obj, NULL)) {
		nm_assert (NM_IN_SET (NMP_OBJECT_GET_TYPE (obj), NMP_OBJECT_TYPE_IP4_ADDRESS,
		                                                 NMP_OBJECT_TYPE_IP6_ADDRESS,
		                                                 NMP_OBJECT_TYPE_IP4_ROUTE,
		                                                 NMP_OBJECT_TYPE_IP6_ROUTE));
		if (NMP_OBJECT_GET_ADDR_FAMILY (obj) != addr_family)
			g_hash_table_iter_remove (&iter);
	}
	self->priv.p->externally_removed_objs_cnt_addresses_x[IS_IPv4] = 0;
	self->priv.p->externally_removed_objs_cnt_routes_x[IS_IPv4] = 0;

	if (   self->priv.p->externally_removed_objs_cnt_addresses_x[!IS_IPv4] == 0
	    && self->priv.p->externally_removed_objs_cnt_routes_x[!IS_IPv4] == 0)
		nm_clear_pointer (&self->priv.p->externally_removed_objs_hash, g_hash_table_unref);
}

static void
_l3cfg_externally_removed_objs_drop_unused (NML3Cfg *self)
{
	GHashTableIter h_iter;
	const NMPObject *obj;
	char sbuf[sizeof (_nm_utils_to_string_buffer)];

	nm_assert (NM_IS_L3CFG (self));

	if (!self->priv.p->externally_removed_objs_hash)
		return;

	if (!self->priv.p->combined_l3cd) {
		_l3cfg_externally_removed_objs_drop (self, AF_UNSPEC);
		return;
	}

	g_hash_table_iter_init (&h_iter, self->priv.p->externally_removed_objs_hash);
	while (g_hash_table_iter_next (&h_iter, (gpointer *) &obj, NULL)) {
		if (!nm_l3_config_data_lookup_route_obj (self->priv.p->combined_l3cd,
		                                         obj)) {
			/* The object is no longer tracked in the configuration.
			 * The externally_removed_objs_hash is to prevent adding entires that were
			 * removed externally, so if we don't plan to add the entry, we no longer need to track
			 * it. */
			(*(_l3cfg_externally_removed_objs_counter (self, NMP_OBJECT_GET_TYPE (obj))))--;
			g_hash_table_iter_remove (&h_iter);
			_LOGD ("externally-removed: untrack %s",
			       nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof (sbuf)));
		}
	}
}

static void
_l3cfg_externally_removed_objs_track (NML3Cfg *self,
                                      const NMPObject *obj,
                                      gboolean is_removed)
{
	char sbuf[1000];

	nm_assert (NM_IS_L3CFG (self));

	if (!self->priv.p->combined_l3cd)
		return;

	if (!is_removed) {
		/* the object is still (or again) present. It no longer gets hidden. */
		if (self->priv.p->externally_removed_objs_hash) {
			if (g_hash_table_remove (self->priv.p->externally_removed_objs_hash,
			                         obj)) {
				(*(_l3cfg_externally_removed_objs_counter (self,
				                                           NMP_OBJECT_GET_TYPE (obj))))--;
				_LOGD ("externally-removed: untrack %s",
				       nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof (sbuf)));
			}
		}
		return;
	}

	if (!nm_l3_config_data_lookup_route_obj (self->priv.p->combined_l3cd,
	                                         obj)) {
		/* we don't care about this object, so there is nothing to hide hide */
		return;
	}

	if (G_UNLIKELY (!self->priv.p->externally_removed_objs_hash)) {
		self->priv.p->externally_removed_objs_hash = g_hash_table_new_full ((GHashFunc) nmp_object_id_hash,
		                                                                    (GEqualFunc) nmp_object_id_equal,
		                                                                    (GDestroyNotify) nmp_object_unref,
		                                                                    NULL);
	}

	if (g_hash_table_add (self->priv.p->externally_removed_objs_hash,
	                      (gpointer) nmp_object_ref (obj))) {
		(*(_l3cfg_externally_removed_objs_counter (self,
		                                           NMP_OBJECT_GET_TYPE (obj))))++;
		_LOGD ("externally-removed: track %s",
		       nmp_object_to_string (obj, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof (sbuf)));
	}
}

static void
_l3cfg_externally_removed_objs_pickup (NML3Cfg *self,
                                       int addr_family)
{
	const gboolean IS_IPv4 = NM_IS_IPv4 (addr_family);
	NMDedupMultiIter iter;
	const NMPObject *obj;

	if (!self->priv.p->combined_l3cd)
		return;

	nm_l3_config_data_iter_obj_for_each (&iter, self->priv.p->combined_l3cd, &obj, NMP_OBJECT_TYPE_IP_ADDRESS (IS_IPv4)) {
		if (!nm_platform_lookup_entry (self->priv.platform,
		                               NMP_CACHE_ID_TYPE_OBJECT_TYPE,
		                               obj))
			_l3cfg_externally_removed_objs_track (self, obj, TRUE);
	}
	nm_l3_config_data_iter_obj_for_each (&iter, self->priv.p->combined_l3cd, &obj, NMP_OBJECT_TYPE_IP_ROUTE (IS_IPv4)) {
		if (!nm_platform_lookup_entry (self->priv.platform,
		                               NMP_CACHE_ID_TYPE_OBJECT_TYPE,
		                               obj))
			_l3cfg_externally_removed_objs_track (self, obj, TRUE);
	}
}

static gboolean
_l3cfg_externally_removed_objs_filter (/* const NMDedupMultiObj * */ gconstpointer o,
                                       gpointer user_data)
{
	const NMPObject *obj = o;
	GHashTable *externally_removed_objs_hash = user_data;

	return !g_hash_table_contains (externally_removed_objs_hash, obj);
}

/*****************************************************************************/

static void
_load_link (NML3Cfg *self, gboolean initial)
{
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	const NMPObject *obj;
	const char *ifname;
	const char *ifname_old;
	gboolean nacd_changed;
	gboolean nacd_new_valid;
	gboolean nacd_old_valid;
	const guint8 *nacd_old_addr;
	const guint8 *nacd_new_addr;
	gboolean nacd_link_now_up;
	AcdData *acd_data;

	obj = nm_platform_link_get_obj (self->priv.platform, self->priv.ifindex, TRUE);

	if (   initial
	    && obj == self->priv.pllink)
		return;

	obj_old = g_steal_pointer (&self->priv.pllink);
	self->priv.pllink = nmp_object_ref (obj);

	if (   obj
	    && NM_FLAGS_HAS (NMP_OBJECT_CAST_LINK (obj)->n_ifi_flags, IFF_UP)
	    && (   !obj_old
	        || !NM_FLAGS_HAS (NMP_OBJECT_CAST_LINK (obj_old)->n_ifi_flags, IFF_UP)))
		nacd_link_now_up = TRUE;
	else
		nacd_link_now_up = FALSE;

	nacd_changed = FALSE;
	nacd_old_valid = _acd_has_valid_link (obj_old, &nacd_old_addr, NULL);
	nacd_new_valid = _acd_has_valid_link (obj, &nacd_new_addr, NULL);
	if (self->priv.p->nacd_instance_ensure_retry) {
		if (   nacd_new_valid
		    && (   !nacd_old_valid
		        || memcmp (nacd_new_addr, nacd_old_addr, ACD_SUPPORTED_ETH_ALEN) == 0))
			nacd_changed = TRUE;
	} else if (self->priv.p->nacd) {
		if (!nacd_new_valid)
			nacd_changed = TRUE;
		else if (!nacd_old_valid)
			nacd_changed = nm_assert_unreachable_val (TRUE);
		else if (memcmp (nacd_old_addr, nacd_new_addr, ACD_SUPPORTED_ETH_ALEN) != 0)
			nacd_changed = TRUE;
	} else if (nacd_new_valid)
		nacd_changed = TRUE;
	ifname_old = nmp_object_link_get_ifname (obj_old);
	ifname = nmp_object_link_get_ifname (self->priv.pllink);

	if (initial) {
		_LOGT ("link ifname changed: %s%s%s (initial)",
		        NM_PRINT_FMT_QUOTE_STRING (ifname));
	} else if (!nm_streq0 (ifname, ifname_old)) {
		_LOGT ("link ifname changed: %s%s%s (was %s%s%s)",
		        NM_PRINT_FMT_QUOTE_STRING (ifname),
		        NM_PRINT_FMT_QUOTE_STRING (ifname_old));
	}

	if (nacd_changed) {
		if (!c_list_is_empty (&self->priv.p->acd_lst_head))
			_LOGT ("acd: link change causes restart of ACD");
		_l3_acd_nacd_instance_reset (self, NM_TERNARY_FALSE, TRUE);
	} else if (nacd_link_now_up) {
		if (!c_list_is_empty (&self->priv.p->acd_lst_head)) {
			_LOGT ("acd: link up requires are re-initialize of ACD probes");
			c_list_for_each_entry (acd_data, &self->priv.p->acd_lst_head, acd_lst)
				_l3_acd_data_state_change (self, acd_data, ACD_STATE_CHANGE_MODE_LINK_NOW_UP, NULL);
		}
	}
}

/*****************************************************************************/

void
_nm_l3cfg_notify_platform_change_on_idle (NML3Cfg *self, guint32 obj_type_flags)
{
	if (NM_FLAGS_ANY (obj_type_flags, nmp_object_type_to_flags (NMP_OBJECT_TYPE_LINK)))
		_load_link (self, FALSE);
	if (NM_FLAGS_ANY (obj_type_flags, nmp_object_type_to_flags (NMP_OBJECT_TYPE_IP4_ROUTE)))
		_property_emit_notify (self, NM_L3CFG_PROPERTY_EMIT_TYPE_IP4_ROUTE);
	if (NM_FLAGS_ANY (obj_type_flags, nmp_object_type_to_flags (NMP_OBJECT_TYPE_IP6_ROUTE)))
		_property_emit_notify (self, NM_L3CFG_PROPERTY_EMIT_TYPE_IP6_ROUTE);
}

void
_nm_l3cfg_notify_platform_change (NML3Cfg *self,
                                  NMPlatformSignalChangeType change_type,
                                  const NMPObject *obj)
{
	nm_assert (NMP_OBJECT_IS_VALID (obj));

	switch (NMP_OBJECT_GET_TYPE (obj)) {
	case NMP_OBJECT_TYPE_IP4_ADDRESS:
		_l3_acd_ipv4_addresses_on_link_update (self,
		                                       NMP_OBJECT_CAST_IP4_ADDRESS (obj)->address,
		                                       change_type != NM_PLATFORM_SIGNAL_REMOVED);
		/* fall-through */
	case NMP_OBJECT_TYPE_IP6_ADDRESS:
	case NMP_OBJECT_TYPE_IP4_ROUTE:
	case NMP_OBJECT_TYPE_IP6_ROUTE:
		_l3cfg_externally_removed_objs_track (self,
		                                      obj,
		                                      change_type == NM_PLATFORM_SIGNAL_REMOVED);
	default:
		break;
	}
}

/*****************************************************************************/

typedef struct {
	GObject *target_obj;
	const GParamSpec *target_property;
	NML3CfgPropertyEmitType emit_type;
} PropertyEmitData;

static void
_property_emit_notify (NML3Cfg *self, NML3CfgPropertyEmitType emit_type)
{
	gs_free PropertyEmitData *collected_heap = NULL;
	PropertyEmitData *collected = NULL;
	PropertyEmitData *emit_data;
	guint num;
	guint i;
	guint j;

	if (!self->priv.p->property_emit_list)
		return;

	num = 0;
	emit_data = &g_array_index (self->priv.p->property_emit_list, PropertyEmitData, 0);
	for (i = 0; i < self->priv.p->property_emit_list->len; i++, emit_data++) {
		if (emit_data->emit_type == emit_type) {
			collected = emit_data;
			num++;
		}
	}

	if (num == 0)
		return;

	if (num == 1) {
		g_object_notify_by_pspec (collected->target_obj, (GParamSpec *) collected->target_property);
		return;
	}

	if (num < 300u / sizeof (*collected))
		collected = g_alloca (sizeof (PropertyEmitData) * num);
	else {
		collected_heap = g_new (PropertyEmitData, num);
		collected = collected_heap;
	}

	emit_data = &g_array_index (self->priv.p->property_emit_list, PropertyEmitData, 0);
	for (i = 0, j = 0; i < self->priv.p->property_emit_list->len; i++, emit_data++) {
		if (emit_data->emit_type == emit_type) {
			collected[j++] = *emit_data;
			g_object_ref (collected->target_obj);
		}
	}

	nm_assert (j == num);

	for (i = 0; i < num; i++) {
		g_object_notify_by_pspec (collected[i].target_obj, (GParamSpec *) collected[i].target_property);
		if (i > 0)
			g_object_unref (collected[i].target_obj);
	}
}

void
nm_l3cfg_property_emit_register (NML3Cfg *self,
                                 GObject *target_obj,
                                 const GParamSpec *target_property,
                                 NML3CfgPropertyEmitType emit_type)
{
	PropertyEmitData *emit_data;
	guint i;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (G_IS_OBJECT (target_obj));
	nm_assert (target_property);
	nm_assert (NM_IN_SET (emit_type, NM_L3CFG_PROPERTY_EMIT_TYPE_IP4_ROUTE,
	                                 NM_L3CFG_PROPERTY_EMIT_TYPE_IP6_ROUTE));
	nm_assert (target_property == nm_g_object_class_find_property_from_gtype (G_OBJECT_TYPE (target_obj),
	                                                                          target_property->name));

	if (!self->priv.p->property_emit_list)
		self->priv.p->property_emit_list = g_array_new (FALSE, FALSE, sizeof (PropertyEmitData));
	else {
		emit_data = &g_array_index (self->priv.p->property_emit_list, PropertyEmitData, 0);
		for (i = 0; i < self->priv.p->property_emit_list->len; i++, emit_data++) {
			if (   emit_data->target_obj != target_obj
			    || emit_data->target_property != target_property)
				continue;
			nm_assert (emit_data->emit_type == emit_type);
			emit_data->emit_type = emit_type;
			return;
		}
	}

	emit_data = nm_g_array_append_new (self->priv.p->property_emit_list, PropertyEmitData);
	*emit_data = (PropertyEmitData) {
		.target_obj      = target_obj,
		.target_property = target_property,
		.emit_type       = emit_type,
	};
}

void
nm_l3cfg_property_emit_unregister (NML3Cfg *self,
                                   GObject *target_obj,
                                   const GParamSpec *target_property)
{
	PropertyEmitData *emit_data;
	guint i;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (G_IS_OBJECT (target_obj));
	nm_assert (   !target_property
	           || target_property == nm_g_object_class_find_property_from_gtype (G_OBJECT_TYPE (target_obj),
	                                                                             target_property->name));

	if (!self->priv.p->property_emit_list)
		return;

	for (i = self->priv.p->property_emit_list->len; i > 0; i--) {
		emit_data = &g_array_index (self->priv.p->property_emit_list, PropertyEmitData, i);

		if (emit_data->target_obj != target_obj)
			continue;
		if (   target_property
		    && emit_data->target_property != target_property)
			continue;

		g_array_remove_index_fast (self->priv.p->property_emit_list, i);

		if (target_property) {
			/* if a target-property is given, we don't have another entry in
			 * the list. */
			return;
		}
	}
}

/*****************************************************************************/

gboolean
nm_l3cfg_get_acd_is_pending (NML3Cfg *self)
{
	g_return_val_if_fail (NM_IS_L3CFG (self), FALSE);

	return self->priv.p->acd_is_pending;
}

static gboolean
_acd_track_data_is_not_dirty (const AcdTrackData *acd_track)
{
	return    acd_track
	       && !acd_track->acd_dirty;
}

static void
_acd_track_data_free (AcdTrackData *acd_track)
{
	c_list_unlink_stale (&acd_track->acd_track_lst);
	nm_l3_config_data_unref (acd_track->l3cd);
	nmp_object_unref (acd_track->obj);
	nm_g_slice_free (acd_track);
}

static void
_acd_data_free (AcdData *acd_data)
{
	nm_assert (c_list_is_empty (&acd_data->acd_track_lst_head));

	n_acd_probe_free (acd_data->nacd_probe);
	nm_clear_g_source_inst (&acd_data->acd_timeout_source);
	c_list_unlink_stale (&acd_data->acd_lst);
	nm_g_slice_free (acd_data);
}

static gboolean
_acd_data_probe_result_is_good (const AcdData *acd_data)
{
	nm_assert (acd_data);

	if (acd_data->acd_state < ACD_STATE_PROBE_DONE) {
		/* we are currently probing. Wait. */
		return FALSE;
	}

	/* Probing is already completed. Use the probe result. */
	return acd_data->probe_result;
}

static guint
_acd_data_collect_tracks_data (const AcdData *acd_data,
                               NMTernary dirty_selector,
                               NMTernary acd_failed_notified_selector,
                               guint32 *out_best_acd_timeout_msec)
{
	guint32 best_acd_timeout_msec = G_MAXUINT32;
	AcdTrackData *acd_track;
	guint n = 0;

	c_list_for_each_entry (acd_track, &acd_data->acd_track_lst_head, acd_track_lst) {
		if (dirty_selector != NM_TERNARY_DEFAULT) {
			if ((!!dirty_selector) != (!!acd_track->acd_dirty))
				continue;
		}
		if (acd_failed_notified_selector != NM_TERNARY_DEFAULT) {
			if ((!!acd_failed_notified_selector) != (!!acd_track->acd_failed_notified))
				continue;
		}
		n++;
		if (best_acd_timeout_msec > acd_track->acd_timeout_msec)
			best_acd_timeout_msec = acd_track->acd_timeout_msec;
	}

	NM_SET_OUT (out_best_acd_timeout_msec, n > 0 ? best_acd_timeout_msec : 0u);
	return n;
}

static AcdTrackData *
_acd_data_find_track (const AcdData *acd_data,
                      const NML3ConfigData *l3cd,
                      const NMPObject *obj,
                      gconstpointer tag)
{
	AcdTrackData *acd_track;

	c_list_for_each_entry (acd_track, &acd_data->acd_track_lst_head, acd_track_lst) {
		if (   acd_track->obj == obj
		    && acd_track->l3cd == l3cd
		    && acd_track->tag == tag)
			return acd_track;
	}

	return NULL;
}

/*****************************************************************************/

static void
_l3_acd_platform_commit_acd_update (NML3Cfg *self)
{
	/* The idea with NML3Cfg is that multiple users (NMDevice/NMVpnConnection) share one layer 3 configuration
	 * and push their (portion of) IP configuration to it. That implies, that any user may issue nm_l3cfg_platform_commit()
	 * at any time, in order to say that a new configuration is ready.
	 *
	 * This makes the mechanism also suitable for internally triggering a commit when ACD completes. */
	_LOGT ("acd: acd update now");
	self->priv.changed_configs = TRUE;
	nm_l3cfg_platform_commit (self,
	                          NM_L3_CFG_COMMIT_TYPE_UPDATE,
	                          AF_INET,
	                          NULL);
}

static gboolean
_acd_has_valid_link (const NMPObject *obj,
                     const guint8 **out_addr_bin,
                     gboolean *out_acd_not_supported)
{
	const NMPlatformLink *link;
	const guint8 *addr_bin;
	gsize addr_len;

	if (!obj) {
		NM_SET_OUT (out_acd_not_supported, FALSE);
		return FALSE;
	}

	link = NMP_OBJECT_CAST_LINK (obj);

	addr_bin = nmp_link_address_get (&link->l_address, &addr_len);
	if (   !addr_bin
	    || addr_len != ACD_SUPPORTED_ETH_ALEN) {
		NM_SET_OUT (out_acd_not_supported, TRUE);
		return FALSE;
	}

	NM_SET_OUT (out_acd_not_supported, FALSE);
	NM_SET_OUT (out_addr_bin, addr_bin);
	return TRUE;
}

static gboolean
_l3_acd_nacd_event (int fd,
                    GIOCondition condition,
                    gpointer user_data)
{
	NML3Cfg *self = user_data;
	int r;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (self->priv.p->nacd);

	r = n_acd_dispatch (self->priv.p->nacd);
	if (!NM_IN_SET (r, 0, N_ACD_E_PREEMPTED)) {
		_LOGT ("acd: dispatch failed with error %d", r);
		goto handle_failure;
	}

	while (TRUE) {
		AcdData *acd_data;
		NAcdEvent *event;

		r = n_acd_pop_event (self->priv.p->nacd, &event);
		if (r) {
			_LOGT ("acd: pop-event failed with error %d", r);
			goto handle_failure;
		}
		if (!event)
			return G_SOURCE_CONTINUE;

#define _acd_event_payload used
		G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NAcdEvent, _acd_event_payload) == G_STRUCT_OFFSET (NAcdEvent, defended));
		G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NAcdEvent, _acd_event_payload) == G_STRUCT_OFFSET (NAcdEvent, conflict));
		G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET (NAcdEvent, _acd_event_payload) == G_STRUCT_OFFSET (NAcdEvent, used));
		nm_assert (&event->_acd_event_payload == &event->defended);
		nm_assert (&event->_acd_event_payload == &event->conflict);
		nm_assert (&event->_acd_event_payload == &event->used);

		switch (event->event) {
		case N_ACD_EVENT_READY:
			n_acd_probe_get_userdata (event->_acd_event_payload.probe, (void **) &acd_data);
			_l3_acd_data_state_change (self, acd_data, ACD_STATE_CHANGE_MODE_NACD_READY, event);
			break;
		case N_ACD_EVENT_USED:
			n_acd_probe_get_userdata (event->_acd_event_payload.probe, (void **) &acd_data);
			_l3_acd_data_state_change (self, acd_data, ACD_STATE_CHANGE_MODE_NACD_USED, event);
			break;
		case N_ACD_EVENT_DEFENDED:
		case N_ACD_EVENT_CONFLICT: {
			gs_free char *sender_str = NULL;
			const char *addr_str = NULL;
			char sbuf_addr[NM_UTILS_INET_ADDRSTRLEN];

			/* since we announce with N_ACD_DEFEND_ALWAYS, we don't actually expect any
			 * conflict reported and don't handle it. It would be complicated to de-configure
			 * the address. */
			nm_assert (event->event == N_ACD_EVENT_DEFENDED);

			n_acd_probe_get_userdata (event->_acd_event_payload.probe, (void **) &acd_data);
			_LOGT_acd (acd_data,
			           "address %s %s from %s",
			           (addr_str = nm_utils_inet4_ntop (acd_data->addr, sbuf_addr)),
			             event->event == N_ACD_EVENT_DEFENDED
			           ? "defended"
			           : "conflict detected",
			           (sender_str = nm_utils_bin2hexstr_full (event->_acd_event_payload.sender,
			                                                   event->_acd_event_payload.n_sender,
			                                                   ':',
			                                                   FALSE,
			                                                   NULL)));
			if (event->event == N_ACD_EVENT_CONFLICT) {
				_LOGW ("IPv4 address collision detection sees conflict on interface %i%s%s%s for address %s from host %s",
				       self->priv.ifindex,
				       NM_PRINT_FMT_QUOTED (self->priv.pllink, " (", NMP_OBJECT_CAST_LINK (self->priv.pllink)->name, ")", ""),
				       addr_str ?: nm_utils_inet4_ntop (acd_data->addr, sbuf_addr),
				          sender_str
				       ?: (sender_str = nm_utils_bin2hexstr_full (event->_acd_event_payload.sender,
				                                                  event->_acd_event_payload.n_sender,
				                                                  ':',
				                                                  FALSE,
				                                                  NULL)));
			}
			break;
		}
		case N_ACD_EVENT_DOWN:
			_LOGT ("acd: message possibly dropped due to device down.");
			c_list_for_each_entry (acd_data, &self->priv.p->acd_lst_head, acd_lst)
				_l3_acd_data_state_change (self, acd_data, ACD_STATE_CHANGE_MODE_NACD_DOWN, NULL);
			break;
		default:
			_LOGT ("acd: unexpected event %u. Ignore", event->event);
			break;
		}
	}

	nm_assert_not_reached ();

handle_failure:
	/* Something is seriously wrong with our nacd instance. We handle that by resetting the
	 * ACD instance. */
	_l3_acd_nacd_instance_reset (self, NM_TERNARY_TRUE, TRUE);
	return G_SOURCE_CONTINUE;
}

static gboolean
_l3_acd_nacd_instance_ensure_retry_cb (gpointer user_data)
{
	NML3Cfg *self = user_data;

	nm_clear_g_source_inst (&self->priv.p->nacd_instance_ensure_retry);

	_l3_acd_platform_commit_acd_update (self);

	return G_SOURCE_REMOVE;
}

static void
_l3_acd_nacd_instance_reset (NML3Cfg *self,
                             NMTernary start_timer,
                             gboolean acd_data_notify)
{
	nm_assert (NM_IS_L3CFG (self));

	if (self->priv.p->nacd) {
		_LOGT ("acd: clear nacd instance");
		self->priv.p->nacd = n_acd_unref (self->priv.p->nacd);
	}
	nm_clear_g_source_inst (&self->priv.p->nacd_source);
	nm_clear_g_source_inst (&self->priv.p->nacd_instance_ensure_retry);

	if (c_list_is_empty (&self->priv.p->acd_lst_head))
		start_timer = NM_TERNARY_DEFAULT;

	switch (start_timer) {
	case NM_TERNARY_FALSE:
		self->priv.p->nacd_instance_ensure_retry = nm_g_idle_source_new (G_PRIORITY_DEFAULT,
		                                                                 _l3_acd_nacd_instance_ensure_retry_cb,
		                                                                 self,
		                                                                 NULL);
		g_source_attach (self->priv.p->nacd_instance_ensure_retry, NULL);
		break;
	case NM_TERNARY_TRUE:
		self->priv.p->nacd_instance_ensure_retry = nm_g_timeout_source_new_seconds (ACD_ENSURE_RATELIMIT_MSEC / 1000u,
		                                                                            G_PRIORITY_DEFAULT,
		                                                                            _l3_acd_nacd_instance_ensure_retry_cb,
		                                                                            self,
		                                                                            NULL);
		g_source_attach (self->priv.p->nacd_instance_ensure_retry, NULL);
		break;
	case NM_TERNARY_DEFAULT:
		break;
	}

	if (acd_data_notify) {
		AcdData *acd_data;

		c_list_for_each_entry (acd_data, &self->priv.p->acd_lst_head, acd_lst)
			_l3_acd_data_state_change (self, acd_data, ACD_STATE_CHANGE_MODE_INSTANCE_RESET, NULL);
	}
}

static NAcd *
_l3_acd_nacd_instance_ensure (NML3Cfg *self,
                              gboolean *out_acd_not_supported)
{
	nm_auto (n_acd_config_freep) NAcdConfig *config = NULL;
	nm_auto (n_acd_unrefp) NAcd *nacd = NULL;
	const guint8 *addr_bin;
	gboolean acd_not_supported;
	gboolean valid;
	int fd;
	int r;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (self->priv.ifindex > 0);

again:
	if (G_LIKELY (self->priv.p->nacd)) {
		NM_SET_OUT (out_acd_not_supported, FALSE);
		return self->priv.p->nacd;
	}

	if (self->priv.p->nacd_instance_ensure_retry) {
		/* we just tried to create an instance and failed. We are rate-limited,
		 * don't yet try again. */
		NM_SET_OUT (out_acd_not_supported, self->priv.p->nacd_acd_not_supported);
		return NULL;
	}

	valid = _acd_has_valid_link (self->priv.pllink, &addr_bin, &acd_not_supported);
	if (!valid)
		goto failed_create_acd;

	nm_assert (!acd_not_supported);

	r = n_acd_config_new (&config);
	if (r)
		goto failed_create_acd;

	n_acd_config_set_ifindex (config, self->priv.ifindex);
	n_acd_config_set_transport (config, N_ACD_TRANSPORT_ETHERNET);
	n_acd_config_set_mac (config, addr_bin, ACD_SUPPORTED_ETH_ALEN);

	r = n_acd_new (&nacd, config);
	if (r)
		goto failed_create_acd;

	self->priv.p->nacd = g_steal_pointer (&nacd);

	n_acd_get_fd (self->priv.p->nacd, &fd);

	self->priv.p->nacd_source = nm_g_unix_fd_source_new (fd,
	                                                     G_IO_IN,
	                                                     G_PRIORITY_DEFAULT,
	                                                     _l3_acd_nacd_event,
	                                                     self,
	                                                     NULL);
	nm_g_source_attach (self->priv.p->nacd_source, NULL);

	NM_SET_OUT (out_acd_not_supported, FALSE);
	return self->priv.p->nacd;

failed_create_acd:
	/* is-internal-error means that we failed to create the NAcd instance. Most likely due
	 * to being unable to create a file descriptor. Anyway, something is seriously wrong here.
	 *
	 * Otherwise, the MAC address might just not be suitable (ETH_ALEN) or we might have
	 * not NMPlatformLink. In that case, it means the interface is currently not ready to
	 * do acd. */
	self->priv.p->nacd_acd_not_supported = acd_not_supported;
	_l3_acd_nacd_instance_reset (self, NM_TERNARY_TRUE, FALSE);
	goto again;
}

static NAcdProbe *
_l3_acd_nacd_instance_create_probe (NML3Cfg *self,
                                    in_addr_t addr,
                                    guint32 timeout_msec,
                                    gpointer user_data,
                                    gboolean *out_acd_not_supported,
                                    const char **out_failure_reason)
{
	gboolean acd_not_supported;
	NAcdProbe *probe;

	if (!_l3_acd_nacd_instance_ensure (self, &acd_not_supported)) {
		NM_SET_OUT (out_acd_not_supported, acd_not_supported);
		if (acd_not_supported)
			NM_SET_OUT (out_failure_reason, "interface not suitable for ACD");
		else
			NM_SET_OUT (out_failure_reason, "failure to create nacd instance");
		return NULL;
	}

	nm_assert (!acd_not_supported);
	NM_SET_OUT (out_acd_not_supported, FALSE);

	probe = _nm_n_acd_data_probe_new (self, addr, timeout_msec, user_data);
	if (!probe) {
		NM_SET_OUT (out_failure_reason, "failure to create nacd probe");
		return NULL;
	}

	NM_SET_OUT (out_failure_reason, NULL);
	return probe;
}

static void
_l3_acd_data_free_trackers (NML3Cfg *self,
                            AcdData *acd_data,
                            gboolean all /* or only dirty */)
{
	AcdTrackData *acd_track;
	AcdTrackData *acd_track_safe;

	c_list_for_each_entry_safe (acd_track, acd_track_safe, &acd_data->acd_track_lst_head, acd_track_lst) {

		/* If not "all" is requested, we only delete the dirty ones
		 * (and mark the survivors as dirty right away). */
		if (   !all
		    && !acd_track->acd_dirty) {
			acd_track->acd_dirty = TRUE;
			continue;
		}

		_LOGT_acd (acd_data,
		           "untrack "ACD_TRACK_FMT"",
		           ACD_TRACK_PTR (acd_track));

		_acd_track_data_free (acd_track);
	}

	if (!c_list_is_empty (&acd_data->acd_track_lst_head))
		return;

	if (!g_hash_table_remove (self->priv.p->acd_lst_hash, acd_data))
		nm_assert_not_reached ();
	_acd_data_free (acd_data);
}

static void
_l3_acd_data_prune (NML3Cfg *self,
                    gboolean all /* or only dirty */)
{
	AcdData *acd_data_safe;
	AcdData *acd_data;

	c_list_for_each_entry_safe (acd_data, acd_data_safe, &self->priv.p->acd_lst_head, acd_lst)
		_l3_acd_data_free_trackers (self, acd_data, all);
}

static AcdData *
_l3_acd_data_find (NML3Cfg *self,
                   in_addr_t addr)
{
	return nm_g_hash_table_lookup (self->priv.p->acd_lst_hash, &addr);
}

static void
_l3_acd_data_add (NML3Cfg *self,
                  const NML3ConfigData *l3cd,
                  const NMPObject *obj,
                  gconstpointer tag,
                  guint32 acd_timeout_msec)
{
	in_addr_t addr = NMP_OBJECT_CAST_IP4_ADDRESS (obj)->address;
	AcdTrackData *acd_track;
	AcdData *acd_data;
	const char *track_mode;

	if (ACD_ADDR_SKIP (addr))
		return;

	acd_data = _l3_acd_data_find (self, addr);

	if (acd_timeout_msec > ACD_MAX_TIMEOUT_MSEC) {
		/* we limit the maximum timeout. Otherwise we have to handle integer overflow
		 * when adding timeouts. */
		acd_timeout_msec = ACD_MAX_TIMEOUT_MSEC;
	}

	if (!acd_data) {

		if (G_UNLIKELY (!self->priv.p->acd_lst_hash)) {
			G_STATIC_ASSERT_EXPR (G_STRUCT_OFFSET(AcdData, addr) == 0);
			self->priv.p->acd_lst_hash = g_hash_table_new (nm_puint32_hash,
			                                               nm_puint32_equals);
		}

		acd_data = g_slice_new (AcdData);
		*acd_data = (AcdData) {
			.self                   = self,
			.addr                   = addr,
			.acd_track_lst_head     = C_LIST_INIT (acd_data->acd_track_lst_head),
			.acd_state              = ACD_STATE_INIT,
			.probing_timestamp_msec = 0,
			.probe_result           = FALSE,
		};
		c_list_link_tail (&self->priv.p->acd_lst_head, &acd_data->acd_lst);
		if (!g_hash_table_add (self->priv.p->acd_lst_hash, acd_data))
			nm_assert_not_reached ();
		acd_track = NULL;
	} else {
		acd_track = _acd_data_find_track (acd_data,
		                                  l3cd,
		                                  obj,
		                                  tag);
	}

	if (!acd_track) {
		acd_track = g_slice_new (AcdTrackData);
		*acd_track = (AcdTrackData) {
			.l3cd             = nm_l3_config_data_ref (l3cd),
			.obj              = nmp_object_ref (obj),
			.tag              = tag,
			.acd_dirty        = FALSE,
			.acd_timeout_msec = acd_timeout_msec,
		};
		c_list_link_tail (&acd_data->acd_track_lst_head, &acd_track->acd_track_lst);
		track_mode = "new";
	} else {
		nm_assert (acd_track->acd_dirty);
		acd_track->acd_dirty = FALSE;
		if (acd_track->acd_timeout_msec != acd_timeout_msec) {
			acd_track->acd_timeout_msec = acd_timeout_msec;
			track_mode = "update";
		} else
			track_mode = NULL;
	}

	if (track_mode) {
		_LOGT_acd (acd_data,
		           "track "ACD_TRACK_FMT" with timeout %u msec (%s)",
		           ACD_TRACK_PTR (acd_track),
		           acd_timeout_msec,
		           track_mode);
	}
}

static void
_l3_acd_data_add_all (NML3Cfg *self,
                      const L3ConfigData *const*infos,
                      guint infos_len)
{
	AcdData *acd_data;
	guint i_info;

	/* First we add/track all the relevant addresses for ACD. */
	for (i_info = 0; i_info < infos_len; i_info++) {
		const L3ConfigData *info = infos[i_info];
		NMDedupMultiIter iter;
		const NMPObject *obj;

		nm_l3_config_data_iter_obj_for_each (&iter, info->l3cd, &obj, NMP_OBJECT_TYPE_IP4_ADDRESS)
			_l3_acd_data_add (self, info->l3cd, obj, info->tag, info->acd_timeout_msec);
	}

	/* Then we do a pre-flight check, whether some of the acd_data entries can already
	 * move forward to automatically pass ACD. That is the case if acd_timeout_msec
	 * is zero (to disable ACD) or if the address is already configured on the
	 * interface. */
	c_list_for_each_entry (acd_data, &self->priv.p->acd_lst_head, acd_lst)
		_l3_acd_data_state_change (self, acd_data, ACD_STATE_CHANGE_MODE_INIT, NULL);
}

static gboolean
_l3_acd_ready_on_idle_cb (gpointer user_data)
{
	NML3Cfg *self = user_data;

	nm_clear_g_source_inst (&self->priv.p->acd_ready_on_idle_source);

	_LOGT ("acd: handle ACD changes on idle");

	_l3_acd_platform_commit_acd_update (self);

	return G_SOURCE_REMOVE;
}

static gboolean
_l3_acd_data_timeout_cb (gpointer user_data)
{
	AcdData *acd_data = user_data;
	NML3Cfg *self = acd_data->self;

	nm_assert (NM_IS_L3CFG (self));

	nm_clear_g_source_inst (&acd_data->acd_timeout_source);
	_l3_acd_data_state_change (self, acd_data, ACD_STATE_CHANGE_MODE_TIMEOUT, NULL);
	return G_SOURCE_REMOVE;
}

static void
_l3_acd_data_timeout_schedule (AcdData *acd_data,
                               gint64 now_msec,
                               gint64 expiry_msec,
                               gboolean msec_granularity)
{
	nm_assert (expiry_msec > 0);
	nm_assert (now_msec > 0);

	if (   acd_data->acd_timeout_source
	    && acd_data->acd_timeout_expiry_msec == expiry_msec)
		return;

	nm_clear_g_source_inst (&acd_data->acd_timeout_source);

	acd_data->acd_timeout_expiry_msec = expiry_msec;

	if (msec_granularity) {
		acd_data->acd_timeout_source = nm_g_timeout_source_new (NM_MAX (0, expiry_msec - now_msec),
		                                                        G_PRIORITY_DEFAULT,
		                                                        _l3_acd_data_timeout_cb,
		                                                        acd_data,
		                                                        NULL);
	} else {
		acd_data->acd_timeout_source = nm_g_timeout_source_new_seconds ((NM_MAX (0, expiry_msec - now_msec) + 999) / 1000,
		                                                                G_PRIORITY_DEFAULT,
		                                                                _l3_acd_data_timeout_cb,
		                                                                acd_data,
		                                                                NULL);
	}

	g_source_attach (acd_data->acd_timeout_source, NULL);
}

static void
_l3_acd_data_timeout_schedule_probing_restart (AcdData *acd_data,
                                               gint64 now_msec)
{
	gint64 expiry_msec;
	gint64 timeout_msec;

	nm_assert (acd_data);
	nm_assert (now_msec > 0);
	nm_assert (acd_data->acd_state == ACD_STATE_PROBING);
	nm_assert (!acd_data->nacd_probe);
	nm_assert (acd_data->probing_timeout_msec > 0);
	nm_assert (acd_data->probing_timestamp_msec > 0);

	expiry_msec = acd_data->probing_timestamp_msec + ACD_WAIT_PROBING_EXTRA_TIME_MSEC;

	timeout_msec = NM_MAX (0, expiry_msec - now_msec);

	if (timeout_msec > 1000) {
		/* we poll at least once per second to re-check the state. */
		timeout_msec = 1000;
	}

	_l3_acd_data_timeout_schedule (acd_data, now_msec, now_msec + timeout_msec, TRUE);
}

static void
_l3_acd_data_timeout_schedule_probing_full_restart (AcdData *acd_data,
                                                    gint64 now_msec)
{
	nm_assert (acd_data);
	nm_assert (now_msec > 0);
	nm_assert (acd_data->acd_state == ACD_STATE_PROBE_DONE);
	nm_assert (!acd_data->probe_result);

	_l3_acd_data_timeout_schedule (acd_data, now_msec, now_msec + ACD_WAIT_TIME_PROBING_FULL_RESTART_MSEC, FALSE);
}

static void
_l3_acd_data_timeout_schedule_announce_restart (AcdData *acd_data,
                                                gint64 now_msec)
{
	nm_assert (acd_data);
	nm_assert (now_msec > 0);
	nm_assert (acd_data->acd_state == ACD_STATE_PROBE_DONE);
	nm_assert (acd_data->probe_result);

	_l3_acd_data_timeout_schedule (acd_data, now_msec, now_msec + ACD_WAIT_TIME_ANNOUNCE_RESTART_MSEC, FALSE);
}

static void
_l3_acd_data_notify_acd_failed (NML3Cfg *self,
                                AcdData *acd_data,
                                gboolean force_all)
{
	gs_free NML3ConfigNotifyPayloadAcdFailedSource *sources_free = NULL;
	NML3ConfigNotifyPayloadAcdFailedSource *sources = NULL;
	NML3ConfigNotifyPayload payload;
	AcdTrackData *acd_track;
	guint i, n;
	NMTernary acd_failed_notified_selector;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (acd_data);
	nm_assert (_acd_data_collect_tracks_data (acd_data, FALSE, NM_TERNARY_DEFAULT, NULL) == 0);

	acd_failed_notified_selector =   force_all
	                               ? NM_TERNARY_DEFAULT
	                               : FALSE;

	n = _acd_data_collect_tracks_data (acd_data, NM_TERNARY_DEFAULT, acd_failed_notified_selector, NULL);

	if (n == 0)
		return;

	if (!force_all) {
		_LOGT_acd (acd_data,
		           "state: acd probe failed earlier. Emit notification for new trackers");
	}

	if (n * sizeof (sources[0]) > 300) {
		sources_free = g_new (NML3ConfigNotifyPayloadAcdFailedSource, n);
		sources = sources_free;
	} else
		sources = g_newa (NML3ConfigNotifyPayloadAcdFailedSource, n);

	i = 0;
	c_list_for_each_entry (acd_track, &acd_data->acd_track_lst_head, acd_track_lst) {
		if (   !force_all
		    && acd_track->acd_failed_notified) {
			/* already notified before. Skip. */
			continue;
		}
		nm_assert (i < n);
		acd_track->acd_failed_notified = TRUE;
		sources[i++] = (NML3ConfigNotifyPayloadAcdFailedSource) {
			.obj  = nmp_object_ref (acd_track->obj),
			.l3cd = nm_l3_config_data_ref (acd_track->l3cd),
			.tag  = acd_track->tag,
		};
	}
	nm_assert (i == n);

	payload = (NML3ConfigNotifyPayload) {
		.acd_failed = {
			.addr        = acd_data->addr,
			.sources_len = n,
			.sources     = sources,
		},
	};

	_l3cfg_emit_signal_notify (self, NM_L3_CONFIG_NOTIFY_TYPE_ACD_FAILED, &payload);

	for (i = 0; i < n; i++) {
		nmp_object_unref (sources[i].obj);
		nm_l3_config_data_unref (sources[i].l3cd);
	}
}

static void
_l3_acd_data_state_change (NML3Cfg *self,
                           AcdData *acd_data,
                           AcdStateChangeMode state_change_mode,
                           NAcdEvent *event)
{
	guint32 acd_timeout_msec;
	gint64 now_msec = 0;
	const char *log_reason;
	gboolean was_probing;

	/* Keeping track of ACD inevitably requires keeping (and mutating) state. Then a multitude of
	 * things can happen, and depending on the state, we need to do something.
	 *
	 * Here, all the state for one address that we probe/announce is tracked in AcdData/acd_data.
	 *
	 * The acd_data has a list of AcdTrackData/acd_track_lst_head, which are configuration items
	 * that are interested in configuring this address. The "owners" of the ACD check for a certain
	 * address.
	 *
	 * We try to do all the state changes in this _l3_acd_data_state_change() function, where --
	 * depending on the @state_change_mode -- we progress the state.
	 *
	 * It is complicated, but I think this is not really avoidable if you want to handle all
	 * the special things (state-changes) that can happen.
	 */

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (acd_data);
	nm_assert (!c_list_is_empty (&acd_data->acd_track_lst_head));

	was_probing = acd_data->acd_state < ACD_STATE_PROBE_DONE;

	switch (state_change_mode) {

	case ACD_STATE_CHANGE_MODE_INIT: {
		AcdTrackData *acd_track;
		gboolean any_no_timeout;

		/* we are called from _l3_acd_data_add_all(), and we do a fast check whether
		 * newly tracked entries already passed ACD so that we can use the address
		 * right away. */

		if (_l3_acd_ipv4_addresses_on_link_contains (self, acd_data->addr)) {
			/* the address is already configured on the link. It is an automatic pass. */
			if (_acd_data_collect_tracks_data (acd_data, FALSE, NM_TERNARY_DEFAULT, NULL) <= 0) {
				/* The entry has no non-dirty trackers, that means, it's no longer referenced
				 * and will be removed during the next _l3_acd_data_prune(). We can ignore
				 * this entry. */
				return;
			}
			log_reason = "address initially already configured";
			goto handle_probing_acd_good;
		}

		/* we are called at the end of _l3_acd_data_add_all(). We updated the list of a
		 * all tracked IP addresses before we actually collect the addresses that are
		 * ready. We don't do regular handling of ACD states at this point, however,
		 * we check whether ACD for new elements is disabled entirely, so we can signal
		 * the address are ready right away (without going through another hop). */

		if (acd_data->acd_state != ACD_STATE_INIT) {
			/* this element is not new and we don't perform the quick-check. */
			return;
		}

		any_no_timeout = FALSE;
		c_list_for_each_entry (acd_track, &acd_data->acd_track_lst_head, acd_track_lst) {
			/* There should be no dirty trackers, because the element is in init-state. */
			nm_assert (!acd_track->acd_dirty);
			if (acd_track->acd_timeout_msec <= 0) {
				/* ACD for this element is disabled. We can process is right away. */
				any_no_timeout = TRUE;
				break;
			}
		}
		if (!any_no_timeout) {
			/* there are elements that request the address, but they all specify
			 * an ACD timeout. We cannot progress the state. */
			return;
		}

		/* ACD is disabled, we can artificially moving the state further to
		 * ACD_STATE_PROBE_DONE and configure the address right away. This avoids
		 * that we go through another hop.
		 */
		_LOGT_acd (acd_data,
		           "state: probe-done good (ACD disabled by configuration from the start)");
		acd_data->acd_state = ACD_STATE_PROBE_DONE;
		acd_data->probe_result = TRUE;
		return;
	}

	case ACD_STATE_CHANGE_MODE_POST_COMMIT:
		goto handle_post_commit;

	case ACD_STATE_CHANGE_MODE_TIMEOUT: {

		if (   acd_data->acd_state == ACD_STATE_PROBING
		    && !acd_data->nacd_probe) {
			const char *failure_reason;
			gboolean acd_not_supported;

			nm_utils_get_monotonic_timestamp_msec_cached (&now_msec);

			if (acd_data->probing_timestamp_msec + ACD_WAIT_PROBING_EXTRA_TIME_MSEC + ACD_WAIT_PROBING_EXTRA_TIME2_MSEC >= now_msec) {
				_LOGT_acd (acd_data,
				           "state: probe-good (waiting for creating probe timed out. Assume good)");
				acd_data->acd_state = ACD_STATE_PROBE_DONE;
				acd_data->probe_result = TRUE;
				goto handle_probe_done;
			}

			/* try create a new probe. The timeout is always as originally requested. */
			acd_data->nacd_probe = _l3_acd_nacd_instance_create_probe (self,
			                                                           acd_data->addr,
			                                                           acd_data->probing_timeout_msec,
			                                                           acd_data,
			                                                           &acd_not_supported,
			                                                           &failure_reason);
			if (acd_not_supported) {
				nm_assert (!acd_data->nacd_probe);
				_LOGT_acd (acd_data,
				           "state: probe-good (interface does not support ACD anymore after timeout)");
				acd_data->acd_state = ACD_STATE_PROBE_DONE;
				acd_data->probe_result = TRUE;
				goto handle_probe_done;
			}

			if (!acd_data->nacd_probe) {
				_LOGT_acd (acd_data,
				           "state: probing not possible at this time (%s). Wait longer",
				           failure_reason);
				_l3_acd_data_timeout_schedule_probing_restart (acd_data, now_msec);
				return;
			}

			/* probing started (with the original timeout. Note that acd_data->probing_time*_msec
			 * no longer corresponds to the actual timeout of the nacd_probe. This is not a problem
			 * because at this point we only trust the internal timer from nacd_probe to get
			 * it right. Instead, we keep acd_data->probing_time*_msec unchanged, to remember when
			 * we originally wanted to start. */
			_LOGT_acd (acd_data,
			           "state: probing started (after retry, timeout %u msec)",
			           acd_data->probing_timeout_msec);
			return;
		}

		if (   acd_data->acd_state == ACD_STATE_PROBE_DONE
		    && !acd_data->probe_result) {
			/* Probing is done, but previously we detected a conflict. After a restart, we retry to
			 * probe. */
			nm_assert (!acd_data->nacd_probe);
			nm_assert (!acd_data->announcing_failed_is_retrying);

			_LOGT_acd (acd_data,
			           "state: restart a new probe after previous conflict");
			acd_data->acd_state = ACD_STATE_INIT;
			goto handle_post_commit;
		}

		if (   acd_data->acd_state == ACD_STATE_PROBE_DONE
		    && acd_data->probe_result
		    && !acd_data->nacd_probe
		    && acd_data->announcing_failed_is_retrying) {
			/* Probing is done, but previously we failed to start announcing. Retry now. */
			nm_assert (!was_probing);
			_LOGT_acd (acd_data,
			           "state: retry announcing address");
			acd_data->announcing_failed_is_retrying = FALSE;
			goto handle_probe_done;
		}

		return;
	}

	case ACD_STATE_CHANGE_MODE_NACD_READY:
		if (acd_data->acd_state == ACD_STATE_PROBING) {
			log_reason = "acd indicates ready";
			goto handle_probing_acd_good;
		}
		if (acd_data->acd_state == ACD_STATE_ANNOUNCING) {
			_LOGT_acd (acd_data,
			           "state: ready to start announcing");
			if (n_acd_probe_announce (acd_data->nacd_probe, N_ACD_DEFEND_ALWAYS) != 0)
				nm_assert_not_reached ();
			return;
		}

		/* nacd really shouldn't call us in this state. There is a bug somewhere. */
		nm_assert_not_reached ();
		return;

	case ACD_STATE_CHANGE_MODE_NACD_USED: {
		gs_free char *str_to_free = NULL;

		nm_assert (acd_data->acd_state == ACD_STATE_PROBING);
		_LOGT_acd (acd_data,
		           "state: probe-done bad (address already in use by %s)",
		           nm_utils_bin2hexstr_a (event->_acd_event_payload.sender,
		                                  event->_acd_event_payload.n_sender,
		                                  ':',
		                                  FALSE,
		                                  &str_to_free));
		acd_data->nacd_probe = n_acd_probe_free (acd_data->nacd_probe);
		acd_data->acd_state = ACD_STATE_PROBE_DONE;
		acd_data->probe_result = FALSE;
		goto handle_probe_done;
	}

	case ACD_STATE_CHANGE_MODE_EXTERNAL_ADDED:
		/* the address is configured on the link. This means, ACD passed */
		log_reason = "address configured on link";
		goto handle_probing_acd_good;

	case ACD_STATE_CHANGE_MODE_EXTERNAL_REMOVED:
		/* The address got removed. Either we ourself removed it or it was removed externally.
		 * In either case, it's not clear what we should do about that, regardless in which
		 * ACD state we are, so ignore it. */
		_LOGT_acd (acd_data,
		           "state: address was externally removed. Ignore");
		return;

	case ACD_STATE_CHANGE_MODE_NACD_DOWN:
		if (acd_data->acd_state < ACD_STATE_PROBE_DONE) {

			/* we are probing, but the probe has a problem that the link went down. Maybe
			 * we need to restart. */

			nm_assert (acd_data->acd_state == ACD_STATE_PROBING);

			if (!acd_data->nacd_probe) {
				/* we are in probing state, but currently not really probing. A timer is
				 * running, and we will handle this situation that way. */
				return;
			}

			/* We abort the probing, but we also schedule a timer to restart it. Let
			 * the regular re-start handling handle this. */
			_LOGT_acd (acd_data,
			           "state: interface-down. Probing aborted but we keep waiting to retry");
			acd_data->nacd_probe = n_acd_probe_free (acd_data->nacd_probe);
			_l3_acd_data_timeout_schedule_probing_restart (acd_data, now_msec);
			return;
		}

		/* We already completed a probe and acted accordingly (by either configuring the address
		 * already or by rejecting it). We cannot (easily) re-evaluate what to do now. Should
		 * we later restart probing? But what about the decisions we already made??
		 * Ignore the situation. */
		return;

	case ACD_STATE_CHANGE_MODE_LINK_NOW_UP:

		/* The interface just came up. */

		if (acd_data->acd_state <= ACD_STATE_PROBING) {
			nm_auto (n_acd_probe_freep) NAcdProbe *probe = NULL;
			const char *failure_reason;
			gboolean acd_not_supported;

			/* the interface was probing. We will restart the probe. */
			nm_assert (acd_data->acd_state == ACD_STATE_PROBING);

			nm_utils_get_monotonic_timestamp_msec_cached (&now_msec);

			if (!acd_data->nacd_probe) {
				/* We currently are waiting to restart probing. We don't handle the link-up
				 * event here, we only trigger a timeout right away. */
				_LOGT_acd (acd_data,
				           "state: ignore link up event while we are waiting to start probing");
				_l3_acd_data_timeout_schedule (acd_data, now_msec, now_msec, TRUE);
				return;
			}

			if (acd_data->probing_timestamp_msec + ACD_WAIT_PROBING_RESTART_TIME_MSEC >= now_msec) {
				/* This probe was already started quite a while ago. We ignore the link-up event
				 * and let it complete regularly. This is to avoid restarting to probing indefinitely. */
				_LOGT_acd (acd_data,
				           "state: ignore link up event for a probe started long ago");
				return;
			}

			probe = _l3_acd_nacd_instance_create_probe (self,
			                                            acd_data->addr,
			                                            acd_data->probing_timeout_msec,
			                                            acd_data,
			                                            &acd_not_supported,
			                                            &failure_reason);
			if (!probe) {
				_LOGT_acd (acd_data,
				           "state: link up event would cause to retry probing, but creating a probe failed (%s). Ignore and keep previous probe",
				           failure_reason);
				return;
			}

			NM_SWAP (&probe, &acd_data->nacd_probe);

			/* We just restarted probing. Note that we don't touch the original acd_data->probing_time*_msec
			 * times, otherwise a repeated link up/down cycle could extend the probing indefinitely.
			 *
			 * This is despite the new probe just started counting now. So, at this point, the
			 * timestamp/timeout of acd_data no longer corresponds to the internal timestamp of
			 * acd_data->nacd_probe. But since we don't run our own timer against the internal timer of
			 * acd_data->nacd_probe, that is not a problem.
			 */
			_LOGT_acd (acd_data,
			           "state: probing restarted (after link up, new timeout %u msec)",
			           acd_data->probing_timeout_msec);
			return;
		}

		/* we are already done with the ACD state. Bringing up an interface has
		 * no further consequence w.r.t. the ACD state. */
		return;

	case ACD_STATE_CHANGE_MODE_INSTANCE_RESET:
		if (acd_data->acd_state <= ACD_STATE_PROBING) {

			nm_assert (acd_data->acd_state == ACD_STATE_PROBING);

			_LOGT_acd (acd_data,
			           "state: n-acd instance reset. Trigger a restart of the probing (was %sprobing)",
			             acd_data->nacd_probe
			           ? ""
			           : "not");
			/* Just destroy the current probe (if any) and retrigger a restart right away. */
			acd_data->nacd_probe = n_acd_probe_free (acd_data->nacd_probe);
			_l3_acd_data_timeout_schedule (acd_data, now_msec, now_msec, TRUE);
			return;
		}

		if (acd_data->probe_result) {
			_LOGT_acd (acd_data,
			           "state: n-acd instance reset. Restart announcing");
		} else {
			_LOGT_acd (acd_data,
			           "state: n-acd instance reset. Reprobe the address that conflicted before");
		}
		acd_data->nacd_probe = n_acd_probe_free (acd_data->nacd_probe);
		acd_data->acd_state = ACD_STATE_PROBE_DONE;
		_l3_acd_data_timeout_schedule (acd_data, now_msec, now_msec, TRUE);
		break;
	}

	nm_assert_not_reached ();
	return;


handle_post_commit:
	/* we just did a commit of the IP configuration and now visit all ACD states
	 * and kick off the necessary actions... */
	if (_l3_acd_ipv4_addresses_on_link_contains (self, acd_data->addr)) {
		log_reason = "address already configured";
		goto handle_probing_acd_good;
	}
	if (_acd_data_collect_tracks_data (acd_data, TRUE, NM_TERNARY_DEFAULT, &acd_timeout_msec) <= 0)
		nm_assert_not_reached ();
	if (acd_timeout_msec <= 0) {
		log_reason = "ACD disabled by configuration";
		goto handle_probing_acd_good;
	}

	switch (acd_data->acd_state) {
	case ACD_STATE_INIT: {
		const char *failure_reason;
		gboolean acd_not_supported;
		NAcdProbe *probe;

		nm_assert (!acd_data->nacd_probe);

		probe = _l3_acd_nacd_instance_create_probe (self,
		                                            acd_data->addr,
		                                            acd_timeout_msec,
		                                            acd_data,
		                                            &acd_not_supported,
		                                            &failure_reason);
		if (acd_not_supported) {
			nm_assert (!probe);
			_LOGT_acd (acd_data,
			           "state: probe-good (interface does not support ACD)");
			acd_data->acd_state = ACD_STATE_PROBE_DONE;
			acd_data->probe_result = TRUE;
			goto handle_probe_done;
		}

		if (!probe) {
			_LOGT_acd (acd_data,
			           "state: probing currently not possible (timeout %u msec; %s)",
			           acd_timeout_msec,
			           failure_reason);
			acd_data->acd_state = ACD_STATE_PROBING;
			acd_data->probing_timeout_msec = acd_timeout_msec;
			acd_data->probing_timestamp_msec = nm_utils_get_monotonic_timestamp_msec_cached (&now_msec);
			_l3_acd_data_timeout_schedule_probing_restart (acd_data, now_msec);
			return;
		}

		_LOGT_acd (acd_data,
		           "state: start probing (timeout %u msec)",
		           acd_timeout_msec);
		acd_data->acd_state = ACD_STATE_PROBING;
		acd_data->nacd_probe = probe;
		acd_data->probing_timeout_msec = acd_timeout_msec;
		acd_data->probing_timestamp_msec = nm_utils_get_monotonic_timestamp_msec_cached (&now_msec);
		return;
	}

	case ACD_STATE_PROBING: {
		nm_auto (n_acd_probe_freep) NAcdProbe *probe = NULL;
		const char *failure_reason;
		gboolean acd_not_supported;
		gint64 old_expiry_msec;
		gint64 new_expiry_msec;

		nm_utils_get_monotonic_timestamp_msec_cached (&now_msec);

		new_expiry_msec = now_msec + acd_timeout_msec;
		old_expiry_msec = acd_data->probing_timestamp_msec + acd_data->probing_timeout_msec;

		if (!acd_data->nacd_probe) {

			/* we are currently waiting for restarting a probe. At this point, at most we have
			 * to adjust the timeout/timestamp and let the regular timeouts handle this. */

			if (new_expiry_msec >= old_expiry_msec) {
				/* the running timeout expires before the new timeout. We don't update the timestamp/timerout,
				 * because we don't want to prolong the overall probing time. */
				return;
			}
			/* update the timers after out timeout got reduced. Also, reschedule the timeout
			 * so that it expires immediately. */
			acd_data->probing_timestamp_msec = now_msec;
			acd_data->probing_timeout_msec = acd_timeout_msec;
			_l3_acd_data_timeout_schedule (acd_data, now_msec, now_msec, TRUE);
			return;
		}

		if (new_expiry_msec >= old_expiry_msec) {
			/* we already have ACD running with a timeout that expires before the requested one. There
			 * is nothing to do at this time. */
			return;
		}

		/* the timeout got reduced. We try to restart the probe. */
		probe = _l3_acd_nacd_instance_create_probe (self,
		                                            acd_data->addr,
		                                            acd_timeout_msec,
		                                            acd_data,
		                                            &acd_not_supported,
		                                            &failure_reason);
		NM_SWAP (&probe, &acd_data->nacd_probe);

		if (acd_not_supported) {
			nm_assert (!acd_data->nacd_probe);
			_LOGT_acd (acd_data,
			           "state: probe-good (interface does not support ACD anymore)");
			acd_data->acd_state = ACD_STATE_PROBE_DONE;
			acd_data->probe_result = TRUE;
			goto handle_probe_done;
		}

		if (!acd_data->nacd_probe) {
			_LOGT_acd (acd_data,
			           "state: probing currently still not possible (timeout %u msec; %s)",
			           acd_timeout_msec,
			           failure_reason);
			acd_data->acd_state = ACD_STATE_PROBING;
			acd_data->probing_timeout_msec = acd_timeout_msec;
			acd_data->probing_timestamp_msec = now_msec;
			_l3_acd_data_timeout_schedule_probing_restart (acd_data, now_msec);
			return;
		}

		/* We update the timestamps (after also restarting the probe).
		 *
		 * Note that we only reduced the overall expiry. */
		acd_data->probing_timestamp_msec = now_msec;
		acd_data->probing_timeout_msec = acd_timeout_msec;
		_LOGT_acd (acd_data,
		           "state: restart probing (timeout %u msec)",
		           acd_timeout_msec);
		return;
	}

	case ACD_STATE_PROBE_DONE:
	case ACD_STATE_ANNOUNCING:
		goto handle_probe_done;
	}
	nm_assert_not_reached ();
	return;


handle_probing_acd_good:
	switch (acd_data->acd_state) {
	case ACD_STATE_INIT:
		_LOGT_acd (acd_data,
		           "state: probe-done good (%s, inializingbcwin)",
		           log_reason);
		acd_data->acd_state = ACD_STATE_PROBE_DONE;
		acd_data->probe_result = TRUE;
		goto handle_probe_done;
	case ACD_STATE_PROBING:
		_LOGT_acd (acd_data,
		           "state: probe-done good (%s, probing done)",
		            log_reason);
		if (state_change_mode != ACD_STATE_CHANGE_MODE_NACD_READY)
			acd_data->nacd_probe = n_acd_probe_free (acd_data->nacd_probe);
		acd_data->acd_state = ACD_STATE_PROBE_DONE;
		acd_data->probe_result = TRUE;
		goto handle_probe_done;
	case ACD_STATE_PROBE_DONE:
		if (!acd_data->probe_result) {
			nm_assert (!acd_data->nacd_probe);
			_LOGT_acd (acd_data,
			           "state: probe-done good (%s, after probe failed)",
			            log_reason);
			acd_data->probe_result = TRUE;
		}
		goto handle_probe_done;
	case ACD_STATE_ANNOUNCING:
		nm_assert (acd_data->probe_result);
		goto handle_probe_done;
	}
	nm_assert_not_reached ();
	return;


handle_probe_done:
	nm_assert (NM_IN_SET (acd_data->acd_state, ACD_STATE_PROBE_DONE,
	                                           ACD_STATE_ANNOUNCING));

	if (state_change_mode == ACD_STATE_CHANGE_MODE_INIT)
		return;

	if (acd_data->acd_state >= ACD_STATE_ANNOUNCING) {
		nm_assert (acd_data->nacd_probe);
		nm_assert (acd_data->probe_result);
		return;
	}

	if (!acd_data->probe_result) {
		nm_assert (acd_data->acd_state == ACD_STATE_PROBE_DONE);
		nm_assert (!acd_data->nacd_probe);
		/* we just completed probing with negative result.
		 * Emit a signal, but also reschedule a timer to restart. */
		if (was_probing) {
			_LOGT_acd (acd_data,
			           "state: acd probe failed; signal failure");
			acd_data->probing_timestamp_msec = nm_utils_get_monotonic_timestamp_msec_cached (&now_msec);
			_l3_acd_data_timeout_schedule_probing_full_restart (acd_data, now_msec);
		}
		_l3_acd_data_notify_acd_failed (self, acd_data, was_probing);
		return;
	}

	if (   was_probing
	    && acd_data->probe_result) {
		/* probing just completed. Schedule handling the change. */
		_LOGT_acd (acd_data,
		           "state: acd probe succeed");
		if (!self->priv.p->acd_ready_on_idle_source) {
			self->priv.p->acd_ready_on_idle_source = nm_g_idle_source_new (G_PRIORITY_DEFAULT,
			                                                               _l3_acd_ready_on_idle_cb,
			                                                               self,
			                                                               NULL);
			g_source_attach (self->priv.p->acd_ready_on_idle_source, NULL);
		}
	}

	if (!acd_data->nacd_probe) {
		const char *failure_reason;
		NAcdProbe *probe;

		if (acd_data->announcing_failed_is_retrying) {
			/* we already failed to create a probe. We are ratelimited to retry, but
			 * we have a timer pending... */
			return;
		}

		probe = _l3_acd_nacd_instance_create_probe (self,
		                                            acd_data->addr,
		                                            0,
		                                            acd_data,
		                                            NULL,
		                                            &failure_reason);
		if (!probe) {
			/* we failed to create a probe for announcing the address. We log a (rate limited)
			 * warning and start a timer to retry. */
			_LOGT_acd (acd_data,
			           "state: start announcing failed to create probe (%s)",
			           failure_reason);
			acd_data->announcing_failed_is_retrying = TRUE;
			acd_data->probing_timestamp_msec = nm_utils_get_monotonic_timestamp_msec_cached (&now_msec);
			_l3_acd_data_timeout_schedule_announce_restart (acd_data, now_msec);
			return;
		}

		_LOGT_acd (acd_data, "state: start announcing (with new probe)");
		acd_data->nacd_probe = probe;
		acd_data->acd_state = ACD_STATE_ANNOUNCING;
		return;
	}

	if (acd_data->acd_state == ACD_STATE_PROBE_DONE) {
		_LOGT_acd (acd_data, "state: start announcing (with existing probe)");
		acd_data->acd_state = ACD_STATE_ANNOUNCING;
		if (n_acd_probe_announce (acd_data->nacd_probe, N_ACD_DEFEND_ALWAYS) != 0)
			nm_assert_not_reached ();
		return;
	}
}

static void
_l3_acd_data_process_changes (NML3Cfg *self)
{
	gboolean acd_is_announcing = FALSE;
	gboolean acd_is_pending = FALSE;
	AcdData *acd_data;

	_l3_acd_data_prune (self, FALSE);

	c_list_for_each_entry (acd_data, &self->priv.p->acd_lst_head, acd_lst) {
		_l3_acd_data_state_change (self, acd_data, ACD_STATE_CHANGE_MODE_POST_COMMIT, NULL);
		if (acd_data->acd_state < ACD_STATE_PROBE_DONE)
			acd_is_pending = TRUE;
		else if (   acd_data->acd_state >= ACD_STATE_ANNOUNCING
		         || (   acd_data->acd_state >= ACD_STATE_PROBE_DONE
		             && acd_data->probe_result))
			acd_is_announcing = TRUE;
	}

	self->priv.p->acd_is_pending = acd_is_pending;
	self->priv.p->acd_is_announcing = acd_is_announcing;

	if (   !acd_is_pending
	    && !acd_is_announcing)
		_l3_acd_nacd_instance_reset (self, NM_TERNARY_DEFAULT, FALSE);
}

/*****************************************************************************/

static GArray *
_l3_config_datas_ensure (GArray **p_arr)
{
	if (!*p_arr)
		*p_arr = g_array_new (FALSE, FALSE, sizeof (L3ConfigData));
	return *p_arr;
}

#define _l3_config_datas_at(l3_config_datas, idx) \
	(&g_array_index ((l3_config_datas), L3ConfigData, (idx)))

static gssize
_l3_config_datas_find_next (GArray *l3_config_datas,
                            guint start_idx,
                            gconstpointer needle_tag,
                            const NML3ConfigData *needle_l3cd)
{
	guint i;

	nm_assert (l3_config_datas);
	nm_assert (start_idx <= l3_config_datas->len);

	for (i = start_idx; i < l3_config_datas->len; i++) {
		const L3ConfigData *l3_config_data = _l3_config_datas_at (l3_config_datas, i);

		if (   NM_IN_SET (needle_tag, NULL, l3_config_data->tag)
		    && NM_IN_SET (needle_l3cd, NULL, l3_config_data->l3cd))
			return i;
	}
	return -1;
}

static int
_l3_config_datas_get_sorted_cmp (gconstpointer p_a,
                                 gconstpointer p_b,
                                 gpointer user_data)
{
	const L3ConfigData *a = *((L3ConfigData **) p_a);
	const L3ConfigData *b = *((L3ConfigData **) p_b);

	nm_assert (a);
	nm_assert (b);
	nm_assert (nm_l3_config_data_get_ifindex (a->l3cd) == nm_l3_config_data_get_ifindex (b->l3cd));

	/* we sort the entries with higher priority (more important, lower numerical value)
	 * first. */
	NM_CMP_FIELD (a, b, priority);

	/* if the priority is not unique, we sort them in the order they were added,
	 * with the oldest first (lower numerical value). */
	NM_CMP_FIELD (a, b, pseudo_timestamp);

	return nm_assert_unreachable_val (0);
}

#define _l3_config_datas_get_sorted_a(l3_config_datas, \
                                      out_infos, \
                                      out_infos_len, \
                                      out_infos_free) \
	G_STMT_START { \
		GArray *const _l3_config_datas = (l3_config_datas); \
		const L3ConfigData *const**const _out_infos = (out_infos); \
		guint *const _out_infos_len = (out_infos_len); \
		const L3ConfigData ***const _out_infos_free = (out_infos_free); \
		gs_free const L3ConfigData **_infos_free = NULL; \
		const L3ConfigData **_infos; \
		guint _l3_config_datas_len; \
		guint _i; \
		\
		_l3_config_datas_len = nm_g_array_len (_l3_config_datas); \
		\
		if (_l3_config_datas_len == 0) \
			_infos = NULL; \
		else if (_l3_config_datas_len < 300 / sizeof (_infos[0])) \
			_infos = g_alloca (_l3_config_datas_len * sizeof (_infos[0])); \
		else { \
			_infos_free = g_new (const L3ConfigData *, _l3_config_datas_len); \
			_infos = _infos_free; \
		} \
		for (_i = 0; _i < _l3_config_datas_len; _i++) \
			_infos[_i] = _l3_config_datas_at (_l3_config_datas, _i); \
		\
		if (_l3_config_datas_len > 1) { \
			g_qsort_with_data (_infos, \
			                   _l3_config_datas_len, \
			                   sizeof (_infos[0]), \
			                   _l3_config_datas_get_sorted_cmp, \
			                   NULL); \
		} \
		\
		*_out_infos = _infos; \
		*_out_infos_len = _l3_config_datas_len; \
		*_out_infos_free = g_steal_pointer (&_infos_free); \
	} G_STMT_END

static void
_l3_config_datas_remove_index_fast (GArray *arr,
                                    guint idx)
{
	L3ConfigData *l3_config_data;

	nm_assert (arr);
	nm_assert (idx < arr->len);

	l3_config_data = _l3_config_datas_at (arr, idx);

	nm_l3_config_data_unref (l3_config_data->l3cd);

	g_array_remove_index_fast (arr, idx);
}

void
nm_l3cfg_mark_config_dirty (NML3Cfg *self,
                            gconstpointer tag,
                            gboolean dirty)
{
	GArray *l3_config_datas;
	gssize idx;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (tag);

	l3_config_datas = self->priv.p->l3_config_datas;
	if (!l3_config_datas)
		return;

	idx = 0;
	while (TRUE) {
		idx = _l3_config_datas_find_next (l3_config_datas,
		                                  idx,
		                                  tag,
		                                  NULL);
		if (idx < 0)
			return;

		_l3_config_datas_at (l3_config_datas, idx)->dirty = dirty;
		idx++;
	}
}

void
nm_l3cfg_add_config (NML3Cfg *self,
                     gconstpointer tag,
                     gboolean replace_same_tag,
                     const NML3ConfigData *l3cd,
                     int priority,
                     guint32 default_route_penalty_4,
                     guint32 default_route_penalty_6,
                     guint32 acd_timeout_msec,
                     NML3ConfigMergeFlags merge_flags)
{
	GArray *l3_config_datas;
	L3ConfigData *l3_config_data;
	gssize idx;
	gboolean changed = FALSE;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (tag);
	nm_assert (l3cd);
	nm_assert (nm_l3_config_data_get_ifindex (l3cd) == self->priv.ifindex);

	l3_config_datas = _l3_config_datas_ensure (&self->priv.p->l3_config_datas);

	idx = _l3_config_datas_find_next (l3_config_datas,
	                                  0,
	                                  tag,
	                                  replace_same_tag ? NULL : l3cd);

	if (replace_same_tag) {
		gssize idx2;

		idx2 = idx;
		idx = -1;
		while (TRUE) {
			l3_config_data = _l3_config_datas_at (l3_config_datas, idx2);

			if (l3_config_data->l3cd == l3cd) {
				nm_assert (idx == -1);
				idx = idx2;
				continue;
			}

			changed = TRUE;
			_l3_config_datas_remove_index_fast (l3_config_datas, idx2);

			idx2 = _l3_config_datas_find_next (l3_config_datas, idx2, tag, NULL);
			if (idx2 < 0)
				break;
		}
	}

	if (idx < 0) {
		l3_config_data = nm_g_array_append_new (l3_config_datas, L3ConfigData);
		*l3_config_data = (L3ConfigData) {
			.tag                     = tag,
			.l3cd                    = nm_l3_config_data_ref_and_seal (l3cd),
			.merge_flags             = merge_flags,
			.default_route_penalty_4 = default_route_penalty_4,
			.default_route_penalty_6 = default_route_penalty_6,
			.acd_timeout_msec        = acd_timeout_msec,
			.priority                = priority,
			.pseudo_timestamp        = ++self->priv.p->pseudo_timestamp_counter,
			.dirty                   = FALSE,
		};
		changed = TRUE;
	} else {
		l3_config_data = _l3_config_datas_at (l3_config_datas, idx);
		l3_config_data->dirty = FALSE;
		nm_assert (l3_config_data->tag == tag);
		nm_assert (l3_config_data->l3cd == l3cd);
		if (l3_config_data->priority != priority) {
			l3_config_data->priority = priority;
			changed = TRUE;
		}
		if (l3_config_data->merge_flags != merge_flags) {
			l3_config_data->merge_flags = merge_flags;
			changed = TRUE;
		}
		if (l3_config_data->default_route_penalty_4 != default_route_penalty_4) {
			l3_config_data->default_route_penalty_4 = default_route_penalty_4;
			changed = TRUE;
		}
		if (l3_config_data->default_route_penalty_6 != default_route_penalty_6) {
			l3_config_data->default_route_penalty_6 = default_route_penalty_6;
			changed = TRUE;
		}
		if (l3_config_data->acd_timeout_msec != acd_timeout_msec) {
			l3_config_data->acd_timeout_msec = acd_timeout_msec;
			changed = TRUE;
		}
	}

	if (changed)
		self->priv.changed_configs = TRUE;
}

static void
_l3cfg_remove_config (NML3Cfg *self,
                      gconstpointer tag,
                      gboolean only_dirty,
                      const NML3ConfigData *l3cd)
{
	GArray *l3_config_datas;
	gssize idx;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (tag);

	l3_config_datas = self->priv.p->l3_config_datas;
	if (!l3_config_datas)
		return;

	idx = 0;
	while (TRUE) {
		idx = _l3_config_datas_find_next (l3_config_datas,
		                                  idx,
		                                  tag,
		                                  l3cd);
		if (idx < 0)
			return;

		if (   only_dirty
		    && !_l3_config_datas_at (l3_config_datas, idx)->dirty) {
			idx++;
			continue;
		}

		self->priv.changed_configs = TRUE;
		_l3_config_datas_remove_index_fast (l3_config_datas, idx);
		if (!l3cd)
			return;
	}
}

void
nm_l3cfg_remove_config (NML3Cfg *self,
                        gconstpointer tag,
                        const NML3ConfigData *ifcfg)
{
	nm_assert (ifcfg);

	_l3cfg_remove_config (self, tag, FALSE, ifcfg);
}

void
nm_l3cfg_remove_config_all (NML3Cfg *self,
                            gconstpointer tag,
                            gboolean only_dirty)
{
	_l3cfg_remove_config (self, tag, only_dirty, NULL);
}

/*****************************************************************************/

typedef struct {
	NML3Cfg *self;
	gconstpointer tag;
} L3ConfigMergeHookAddObjData;

static gboolean
_l3_hook_add_addr_cb (const NML3ConfigData *l3cd,
                      const NMPObject *obj,
                      gpointer user_data)
{
	const L3ConfigMergeHookAddObjData *hook_data = user_data;
	NML3Cfg *self = hook_data->self;
	AcdData *acd_data;
	in_addr_t addr;

	if (NMP_OBJECT_GET_TYPE (obj) != NMP_OBJECT_TYPE_IP4_ADDRESS)
		return TRUE;

	addr = NMP_OBJECT_CAST_IP4_ADDRESS (obj)->address;

	if (ACD_ADDR_SKIP (addr))
		return TRUE;

	acd_data = _l3_acd_data_find (self, addr);
	nm_assert (acd_data);
	nm_assert (_acd_track_data_is_not_dirty (_acd_data_find_track (acd_data, l3cd, obj, hook_data->tag)));
	return _acd_data_probe_result_is_good (acd_data);
}

static void
_l3cfg_update_combined_config (NML3Cfg *self,
                               const NML3ConfigData **out_old /* transfer reference */,
                               gboolean *out_changed_configs,
                               gboolean *out_changed_combined_l3cd)
{
	nm_auto_unref_l3cd const NML3ConfigData *l3cd_old = NULL;
	nm_auto_unref_l3cd_init NML3ConfigData *l3cd = NULL;
	gs_free const L3ConfigData **l3_config_datas_free = NULL;
	const L3ConfigData *const*l3_config_datas;
	guint l3_config_datas_len;
	guint i;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (!out_old || !*out_old);

	NM_SET_OUT (out_changed_configs, self->priv.changed_configs);
	NM_SET_OUT (out_changed_combined_l3cd, FALSE);

	if (!self->priv.changed_configs)
		return;

	self->priv.changed_configs = FALSE;

	_l3_config_datas_get_sorted_a (self->priv.p->l3_config_datas,
	                               &l3_config_datas,
	                               &l3_config_datas_len,
	                               &l3_config_datas_free);

	_l3_acd_data_add_all (self,
	                      l3_config_datas,
	                      l3_config_datas_len);

	if (l3_config_datas_len > 0) {
		L3ConfigMergeHookAddObjData hook_data = {
			.self = self,
		};

		l3cd = nm_l3_config_data_new (nm_platform_get_multi_idx (self->priv.platform),
		                              self->priv.ifindex);

		for (i = 0; i < l3_config_datas_len; i++) {
			hook_data.tag = l3_config_datas[i]->tag;
			nm_l3_config_data_merge (l3cd,
			                         l3_config_datas[i]->l3cd,
			                         l3_config_datas[i]->merge_flags,
			                         l3_config_datas[i]->default_route_penalty_x,
			                         _l3_hook_add_addr_cb,
			                         &hook_data);
		}

		nm_assert (l3cd);
		nm_assert (nm_l3_config_data_get_ifindex (l3cd) == self->priv.ifindex);

		nm_l3_config_data_seal (l3cd);
	}


	if (nm_l3_config_data_equal (l3cd, self->priv.p->combined_l3cd))
		return;

	_LOGT ("desired IP configuration changed");

	l3cd_old = g_steal_pointer (&self->priv.p->combined_l3cd);
	self->priv.p->combined_l3cd = nm_l3_config_data_seal (g_steal_pointer (&l3cd));
	NM_SET_OUT (out_old, nm_l3_config_data_ref (self->priv.p->combined_l3cd));
	NM_SET_OUT (out_changed_combined_l3cd, TRUE);
}

/*****************************************************************************/

typedef struct {
	const NMPObject *obj;
	gint64 timestamp_msec;
	bool dirty;
} RoutesTemporaryNotAvailableData;

static void
_routes_temporary_not_available_data_free (gpointer user_data)
{
	RoutesTemporaryNotAvailableData *data = user_data;

	nmp_object_unref (data->obj);
	nm_g_slice_free (data);
}

#define ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC ((gint64) 20000)

static gboolean
_routes_temporary_not_available_timeout (gpointer user_data)
{
	RoutesTemporaryNotAvailableData *data;
	NML3Cfg *self = NM_L3CFG (user_data);
	GHashTableIter iter;
	gint64 expiry_threshold_msec;
	gboolean any_expired = FALSE;
	gint64 now_msec;
	gint64 oldest_msec;

	self->priv.p->routes_temporary_not_available_id = 0;

	if (!self->priv.p->routes_temporary_not_available_hash)
		return G_SOURCE_REMOVE;

	/* we check the timeouts again. That is, because we allow to remove
	 * entries from routes_temporary_not_available_hash, without rescheduling
	 * out timeouts. */

	now_msec = nm_utils_get_monotonic_timestamp_msec ();

	expiry_threshold_msec = now_msec - ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC;
	oldest_msec = G_MAXINT64;

	g_hash_table_iter_init (&iter, self->priv.p->routes_temporary_not_available_hash);
	while (g_hash_table_iter_next (&iter, (gpointer *) &data, NULL)) {
		if (data->timestamp_msec >= expiry_threshold_msec) {
			any_expired = TRUE;
			break;
		}
		if (data->timestamp_msec < oldest_msec)
			oldest_msec = data->timestamp_msec;
	}

	if (any_expired) {
		/* a route expired. We emit a signal, but we don't schedule it again. That will
		 * only happen if the user calls nm_l3cfg_platform_commit() again. */
		_l3cfg_emit_signal_notify (self, NM_L3_CONFIG_NOTIFY_TYPE_ROUTES_TEMPORARY_NOT_AVAILABLE_EXPIRED, NULL);
		return G_SOURCE_REMOVE;
	}

	if (oldest_msec != G_MAXINT64) {
		/* we have a timeout still. Reschedule. */
		self->priv.p->routes_temporary_not_available_id = g_timeout_add (oldest_msec + ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC - now_msec,
		                                                                 _routes_temporary_not_available_timeout,
		                                                                 self);
	}
	return G_SOURCE_REMOVE;
}

static gboolean
_routes_temporary_not_available_update (NML3Cfg *self,
                                        int addr_family,
                                        GPtrArray *routes_temporary_not_available_arr)
{

	RoutesTemporaryNotAvailableData *data;
	GHashTableIter iter;
	gint64 oldest_msec;
	gint64 now_msec;
	gboolean prune_all = FALSE;
	gboolean success = TRUE;
	guint i;

	now_msec = nm_utils_get_monotonic_timestamp_msec ();

	if (nm_g_ptr_array_len (routes_temporary_not_available_arr) <= 0) {
		prune_all = TRUE;
		goto out_prune;
	}

	if (self->priv.p->routes_temporary_not_available_hash) {
		g_hash_table_iter_init (&iter, self->priv.p->routes_temporary_not_available_hash);
		while (g_hash_table_iter_next (&iter, (gpointer *) &data, NULL)) {
			if (NMP_OBJECT_GET_ADDR_FAMILY (data->obj) == addr_family)
				data->dirty = TRUE;
		}
	} else {
		self->priv.p->routes_temporary_not_available_hash = g_hash_table_new_full (nmp_object_indirect_id_hash,
		                                                                           nmp_object_indirect_id_equal,
		                                                                           _routes_temporary_not_available_data_free,
		                                                                           NULL);
	}

	for (i = 0; i < routes_temporary_not_available_arr->len; i++) {
		const NMPObject *o = routes_temporary_not_available_arr->pdata[i];
		char sbuf[1024];

		nm_assert (NMP_OBJECT_GET_TYPE (o) == NMP_OBJECT_TYPE_IP_ROUTE (NM_IS_IPv4 (addr_family)));

		data = g_hash_table_lookup (self->priv.p->routes_temporary_not_available_hash, &o);

		if (data) {
			if (!data->dirty)
				continue;

			nm_assert (   data->timestamp_msec > 0
			           && data->timestamp_msec <= now_msec);

			if (now_msec > data->timestamp_msec + ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC) {

				/* timeout. Could not add this address. */
				_LOGW ("failure to add IPv%c route: %s",
				       nm_utils_addr_family_to_char (addr_family),
				       nmp_object_to_string (o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof (sbuf)));
				success = FALSE;
				continue;
			}

			data->dirty = FALSE;
			continue;
		}

		_LOGT ("(temporarily) unable to add IPv%c route: %s",
		       nm_utils_addr_family_to_char (addr_family),
		       nmp_object_to_string (o, NMP_OBJECT_TO_STRING_PUBLIC, sbuf, sizeof (sbuf)));

		data = g_slice_new (RoutesTemporaryNotAvailableData);
		*data = (RoutesTemporaryNotAvailableData) {
			.obj            = nmp_object_ref (o),
			.timestamp_msec = now_msec,
			.dirty          = FALSE,
		};
		g_hash_table_add (self->priv.p->routes_temporary_not_available_hash, data);
	}

out_prune:
	oldest_msec = G_MAXINT64;

	if (self->priv.p->routes_temporary_not_available_hash) {
		g_hash_table_iter_init (&iter, self->priv.p->routes_temporary_not_available_hash);
		while (g_hash_table_iter_next (&iter, (gpointer *) &data, NULL)) {
			nm_assert (   NMP_OBJECT_GET_ADDR_FAMILY (data->obj) == addr_family
			           || !data->dirty);
			if (   !prune_all
			    && !data->dirty) {
				if (data->timestamp_msec < oldest_msec)
					oldest_msec = data->timestamp_msec;
				continue;
			}
			g_hash_table_iter_remove (&iter);
		}
		if (oldest_msec != G_MAXINT64)
			nm_clear_pointer (&self->priv.p->routes_temporary_not_available_hash, g_hash_table_unref);
	}

	nm_clear_g_source (&self->priv.p->routes_temporary_not_available_id);
	if (oldest_msec != G_MAXINT64) {
		nm_assert (oldest_msec + ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC < now_msec);
		self->priv.p->routes_temporary_not_available_id = g_timeout_add (oldest_msec + ROUTES_TEMPORARY_NOT_AVAILABLE_MAX_AGE_MSEC - now_msec,
		                                                                 _routes_temporary_not_available_timeout,
		                                                                 self);
	}

	return success;
}

/*****************************************************************************/

static gboolean
_platform_commit (NML3Cfg *self,
                  int addr_family,
                  NML3CfgCommitType commit_type,
                  gboolean *out_final_failure_for_temporary_not_available)
{
	const gboolean IS_IPv4 = NM_IS_IPv4 (addr_family);
	nm_auto_unref_l3cd const NML3ConfigData *l3cd_old = NULL;
	gs_unref_ptrarray GPtrArray *addresses = NULL;
	gs_unref_ptrarray GPtrArray *routes = NULL;
	gs_unref_ptrarray GPtrArray *addresses_prune = NULL;
	gs_unref_ptrarray GPtrArray *routes_prune = NULL;
	gs_unref_ptrarray GPtrArray *routes_temporary_not_available_arr = NULL;
	NMIPRouteTableSyncMode route_table_sync = NM_IP_ROUTE_TABLE_SYNC_MODE_NONE;
	gboolean final_failure_for_temporary_not_available = FALSE;
	gboolean changed_combined_l3cd;
	gboolean changed_configs;
	char sbuf_commit_type[50];
	gboolean success = TRUE;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (NM_IN_SET (commit_type, NM_L3_CFG_COMMIT_TYPE_REAPPLY,
	                                   NM_L3_CFG_COMMIT_TYPE_UPDATE,
	                                   NM_L3_CFG_COMMIT_TYPE_ASSUME));
	nm_assert_addr_family (addr_family);

	_LOGT ("committing IPv%c configuration (%s)",
	       nm_utils_addr_family_to_char (addr_family),
	       _l3_cfg_commit_type_to_string (commit_type, sbuf_commit_type, sizeof (sbuf_commit_type)));

	_l3cfg_update_combined_config (self, &l3cd_old, &changed_configs, &changed_combined_l3cd);

	if (changed_combined_l3cd) {
		/* our combined configuration changed. We may track entries in externally_removed_objs_hash,
		 * which are not longer to be considered by our configuration. We need to forget about them. */
		_l3cfg_externally_removed_objs_drop_unused (self);
	}

	if (commit_type == NM_L3_CFG_COMMIT_TYPE_ASSUME) {
		/* we need to artificially pre-populate the externally remove hash. */
		_l3cfg_externally_removed_objs_pickup (self, addr_family);
	}

	if (self->priv.p->combined_l3cd) {
		NMDedupMultiFcnSelectPredicate predicate;

		if (   commit_type != NM_L3_CFG_COMMIT_TYPE_REAPPLY
		    && self->priv.p->externally_removed_objs_cnt_addresses_x[IS_IPv4] > 0)
			predicate = _l3cfg_externally_removed_objs_filter;
		else
			predicate = NULL;
		addresses = nm_dedup_multi_objs_to_ptr_array_head (nm_l3_config_data_lookup_objs (self->priv.p->combined_l3cd,
		                                                                                  NMP_OBJECT_TYPE_IP_ADDRESS (IS_IPv4)),
		                                                   predicate,
		                                                   self->priv.p->externally_removed_objs_hash);

		if (   commit_type != NM_L3_CFG_COMMIT_TYPE_REAPPLY
		    && self->priv.p->externally_removed_objs_cnt_routes_x[IS_IPv4] > 0)
			predicate = _l3cfg_externally_removed_objs_filter;
		else
			predicate = NULL;
		routes = nm_dedup_multi_objs_to_ptr_array_head (nm_l3_config_data_lookup_objs (self->priv.p->combined_l3cd,
		                                                                               NMP_OBJECT_TYPE_IP_ROUTE (IS_IPv4)),
		                                                predicate,
		                                                self->priv.p->externally_removed_objs_hash);

		route_table_sync = nm_l3_config_data_get_route_table_sync (self->priv.p->combined_l3cd, addr_family);
	}

	if (route_table_sync == NM_IP_ROUTE_TABLE_SYNC_MODE_NONE)
		route_table_sync = NM_IP_ROUTE_TABLE_SYNC_MODE_ALL;

	if (commit_type == NM_L3_CFG_COMMIT_TYPE_REAPPLY) {
		addresses_prune = nm_platform_ip_address_get_prune_list (self->priv.platform,
		                                                         addr_family,
		                                                         self->priv.ifindex,
		                                                         TRUE);
		routes_prune = nm_platform_ip_route_get_prune_list (self->priv.platform,
		                                                    addr_family,
		                                                    self->priv.ifindex,
		                                                    route_table_sync);
	} else if (commit_type == NM_L3_CFG_COMMIT_TYPE_UPDATE) {
		/* during update, we do a cross with the previous configuration.
		 *
		 * Of course, if an entry is both to be pruned and to be added, then
		 * the latter wins. So, this works just nicely. */
		if (l3cd_old) {
			const NMDedupMultiHeadEntry *head_entry;

			head_entry = nm_l3_config_data_lookup_objs (l3cd_old,
			                                            NMP_OBJECT_TYPE_IP_ADDRESS (IS_IPv4));
			addresses_prune = nm_dedup_multi_objs_to_ptr_array_head (head_entry,
			                                                         NULL,
			                                                         NULL);

			head_entry = nm_l3_config_data_lookup_objs (l3cd_old,
			                                            NMP_OBJECT_TYPE_IP_ROUTE (IS_IPv4));
			addresses_prune = nm_dedup_multi_objs_to_ptr_array_head (head_entry,
			                                                         NULL,
			                                                         NULL);
		}
	}

	nm_platform_ip_address_sync (self->priv.platform,
	                             addr_family,
	                             self->priv.ifindex,
	                             addresses,
	                             addresses_prune);

	if (!nm_platform_ip_route_sync (self->priv.platform,
	                                addr_family,
	                                self->priv.ifindex,
	                                routes,
	                                routes_prune,
	                                &routes_temporary_not_available_arr))
		success = FALSE;

	final_failure_for_temporary_not_available = FALSE;
	if (!_routes_temporary_not_available_update (self,
	                                             addr_family,
	                                             routes_temporary_not_available_arr))
		final_failure_for_temporary_not_available = TRUE;

	if (final_failure_for_temporary_not_available)
		NM_SET_OUT (out_final_failure_for_temporary_not_available, TRUE);
	return success;
}

gboolean
nm_l3cfg_platform_commit (NML3Cfg *self,
                          NML3CfgCommitType commit_type,
                          int addr_family,
                          gboolean *out_final_failure_for_temporary_not_available)
{
	gboolean success = TRUE;
	gboolean acd_was_pending;

	g_return_val_if_fail (NM_IS_L3CFG (self), FALSE);
	nm_assert (NM_IN_SET (commit_type, NM_L3_CFG_COMMIT_TYPE_REAPPLY,
	                                   NM_L3_CFG_COMMIT_TYPE_UPDATE,
	                                   NM_L3_CFG_COMMIT_TYPE_ASSUME));

	NM_SET_OUT (out_final_failure_for_temporary_not_available, FALSE);

	acd_was_pending = self->priv.p->acd_is_pending;

	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET))
		nm_clear_g_source_inst (&self->priv.p->acd_ready_on_idle_source);

	if (commit_type == NM_L3_CFG_COMMIT_TYPE_REAPPLY)
		_l3cfg_externally_removed_objs_drop (self, addr_family);

	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET)) {
		if (!_platform_commit (self, AF_INET, commit_type, out_final_failure_for_temporary_not_available))
			success = FALSE;
	}
	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET6)) {
		if (!_platform_commit (self, AF_INET6, commit_type, out_final_failure_for_temporary_not_available))
			success = FALSE;
	}

	if (NM_IN_SET (addr_family, AF_UNSPEC, AF_INET))
		_l3_acd_data_process_changes (self);

	if (   acd_was_pending
	    && !self->priv.p->acd_is_pending)
		_l3cfg_emit_signal_notify (self, NM_L3_CONFIG_NOTIFY_TYPE_ACD_COMPLETED, NULL);

	return success;
}

/*****************************************************************************/

static void
set_property (GObject *object,
              guint prop_id,
              const GValue *value,
              GParamSpec *pspec)
{
	NML3Cfg *self = NM_L3CFG (object);

	switch (prop_id) {
	case PROP_NETNS:
		/* construct-only */
		self->priv.netns = g_object_ref (g_value_get_pointer (value));
		nm_assert (NM_IS_NETNS (self->priv.netns));
		break;
	case PROP_IFINDEX:
		/* construct-only */
		self->priv.ifindex = g_value_get_int (value);
		nm_assert (self->priv.ifindex > 0);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_l3cfg_init (NML3Cfg *self)
{
	self->priv.p = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_L3CFG, NML3CfgPrivate);

	c_list_init (&self->priv.p->acd_lst_head);
}

static void
constructed (GObject *object)
{
	NML3Cfg *self = NM_L3CFG (object);

	nm_assert (NM_IS_NETNS (self->priv.netns));
	nm_assert (self->priv.ifindex > 0);

	self->priv.platform = g_object_ref (nm_netns_get_platform (self->priv.netns));
	nm_assert (NM_IS_PLATFORM (self->priv.platform));

	_LOGT ("created (netns="NM_HASH_OBFUSCATE_PTR_FMT")",
	       NM_HASH_OBFUSCATE_PTR (self->priv.netns));

	G_OBJECT_CLASS (nm_l3cfg_parent_class)->constructed (object);

	_load_link (self, TRUE);
}

NML3Cfg *
nm_l3cfg_new (NMNetns *netns, int ifindex)
{
	nm_assert (NM_IS_NETNS (netns));
	nm_assert (ifindex > 0);

	return g_object_new (NM_TYPE_L3CFG,
	                     NM_L3CFG_NETNS, netns,
	                     NM_L3CFG_IFINDEX, ifindex,
	                     NULL);
}

static void
finalize (GObject *object)
{
	NML3Cfg *self = NM_L3CFG (object);

	nm_clear_g_source_inst (&self->priv.p->acd_ready_on_idle_source);

	nm_assert (nm_g_array_len (self->priv.p->property_emit_list) == 0u);

	_l3_acd_data_prune (self, TRUE);

	nm_assert (c_list_is_empty (&self->priv.p->acd_lst_head));
	nm_assert (nm_g_hash_table_size (self->priv.p->acd_lst_hash) == 0);

	nm_clear_pointer (&self->priv.p->acd_lst_hash, g_hash_table_unref);
	nm_clear_pointer (&self->priv.p->nacd, n_acd_unref);
	nm_clear_g_source_inst (&self->priv.p->nacd_source);
	nm_clear_g_source_inst (&self->priv.p->nacd_instance_ensure_retry);

	nm_clear_g_source (&self->priv.p->routes_temporary_not_available_id);
	nm_clear_pointer (&self->priv.p->routes_temporary_not_available_hash, g_hash_table_unref);

	nm_clear_pointer (&self->priv.p->externally_removed_objs_hash, g_hash_table_unref);

	g_clear_object (&self->priv.netns);
	g_clear_object (&self->priv.platform);

	nm_clear_pointer (&self->priv.p->combined_l3cd, nm_l3_config_data_unref);

	nm_clear_pointer (&self->priv.pllink, nmp_object_unref);

	nm_clear_pointer (&self->priv.p->acd_ipv4_addresses_on_link, g_hash_table_unref);

	_LOGT ("finalized");

	G_OBJECT_CLASS (nm_l3cfg_parent_class)->finalize (object);
}

static void
nm_l3cfg_class_init (NML3CfgClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (klass, sizeof (NML3CfgPrivate));

	object_class->set_property = set_property;
	object_class->constructed  = constructed;
	object_class->finalize     = finalize;

	obj_properties[PROP_NETNS] =
	    g_param_spec_pointer (NM_L3CFG_NETNS, "", "",
	                          G_PARAM_WRITABLE |
	                          G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_IFINDEX] =
	     g_param_spec_int (NM_L3CFG_IFINDEX, "", "",
	                       0,
	                       G_MAXINT,
	                       0,
	                       G_PARAM_WRITABLE |
	                       G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[SIGNAL_NOTIFY] =
	    g_signal_new (NM_L3CFG_SIGNAL_NOTIFY,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE,
	                  2,
	                  G_TYPE_INT /* NML3ConfigNotifyType */,
	                  G_TYPE_POINTER /* (const NML3ConfigNotifyPayload *) */ );
}
