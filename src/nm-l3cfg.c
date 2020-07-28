// SPDX-License-Identifier: LGPL-2.1+

#include "nm-default.h"

#include "nm-l3cfg.h"

#include "platform/nm-platform.h"
#include "platform/nmp-object.h"
#include "nm-netns.h"

/*****************************************************************************/

typedef struct {
	NML3ConfigDatMergeInfo merge_info;
	gconstpointer tag;
	guint64 pseudo_timestamp;
	int priority;
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

static GQuark signal_notify_quarks[_NM_L3_CONFIG_NOTIFY_TYPE_NUM];

typedef struct _NML3CfgPrivate {
	GArray *property_emit_list;
	GArray *l3_config_datas;
	const NML3ConfigData *combined_l3cfg;

	GHashTable *routes_temporary_not_available_hash;

	guint64 pseudo_timestamp_counter;

	guint routes_temporary_not_available_id;
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

/*****************************************************************************/

static void _property_emit_notify (NML3Cfg *self, NML3CfgPropertyEmitType emit_type);

/*****************************************************************************/

static void
_l3cfg_emit_signal_notify (NML3Cfg *self,
                           NML3ConfigNotifyType notify_type,
                           gpointer pay_load)
{
	nm_assert (_NM_INT_NOT_NEGATIVE (notify_type));
	nm_assert (notify_type < G_N_ELEMENTS (signal_notify_quarks));

	g_signal_emit (self,
	               signals[SIGNAL_NOTIFY],
	               signal_notify_quarks[notify_type],
	               (int) notify_type,
	               pay_load);
}

/*****************************************************************************/

static void
_load_link (NML3Cfg *self, gboolean initial)
{
	nm_auto_nmpobj const NMPObject *obj_old = NULL;
	const NMPObject *obj;
	const char *ifname;
	const char *ifname_old;

	obj = nm_platform_link_get_obj (self->priv.platform, self->priv.ifindex, TRUE);

	if (   initial
	    && obj == self->priv.pllink)
		return;

	obj_old = g_steal_pointer (&self->priv.pllink);
	self->priv.pllink = nmp_object_ref (obj);

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
                            const NML3ConfigData *needle_l3cfg)
{
	guint i;

	nm_assert (l3_config_datas);
	nm_assert (start_idx <= l3_config_datas->len);

	for (i = start_idx; i < l3_config_datas->len; i++) {
		const L3ConfigData *l3_config_data = _l3_config_datas_at (l3_config_datas, i);

		if (   NM_IN_SET (needle_tag, NULL, l3_config_data->tag)
		    && NM_IN_SET (needle_l3cfg, NULL, l3_config_data->merge_info.l3cfg))
			return i;
	}
	return -1;
}

static void
_l3_config_datas_remove_index_fast (GArray *arr,
                                    guint idx)
{
	L3ConfigData *l3_config_data;

	nm_assert (arr);
	nm_assert (idx < arr->len);

	l3_config_data = _l3_config_datas_at (arr, idx);

	nm_l3_config_data_unref (l3_config_data->merge_info.l3cfg);

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
                     const NML3ConfigData *l3cfg,
                     int priority,
                     guint32 default_route_penalty_4,
                     guint32 default_route_penalty_6,
                     NML3ConfigMergeFlags merge_flags)
{
	GArray *l3_config_datas;
	L3ConfigData *l3_config_data;
	gssize idx;
	gboolean changed = FALSE;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (tag);
	nm_assert (l3cfg);
	nm_assert (nm_l3_config_data_get_ifindex (l3cfg) == self->priv.ifindex);

	l3_config_datas = _l3_config_datas_ensure (&self->priv.p->l3_config_datas);

	idx = _l3_config_datas_find_next (l3_config_datas,
	                                  0,
	                                  tag,
	                                  replace_same_tag ? NULL : l3cfg);

	if (replace_same_tag) {
		gssize idx2;

		idx2 = idx;
		idx = -1;
		while (TRUE) {
			l3_config_data = _l3_config_datas_at (l3_config_datas, idx2);

			if (l3_config_data->merge_info.l3cfg == l3cfg) {
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
			.tag                                = tag,
			.merge_info.l3cfg                   = nm_l3_config_data_ref_and_seal (l3cfg),
			.merge_info.merge_flags             = merge_flags,
			.merge_info.default_route_penalty_4 = default_route_penalty_4,
			.merge_info.default_route_penalty_6 = default_route_penalty_6,
			.priority                           = priority,
			.pseudo_timestamp                   = ++self->priv.p->pseudo_timestamp_counter,
			.dirty                              = FALSE,
		};
		changed = TRUE;
	} else {
		l3_config_data = _l3_config_datas_at (l3_config_datas, idx);
		l3_config_data->dirty = FALSE;
		nm_assert (l3_config_data->tag == tag);
		nm_assert (l3_config_data->merge_info.l3cfg == l3cfg);
		if (l3_config_data->priority != priority) {
			l3_config_data->priority = priority;
			changed = TRUE;
		}
		if (l3_config_data->merge_info.merge_flags != merge_flags) {
			l3_config_data->merge_info.merge_flags = merge_flags;
			changed = TRUE;
		}
		if (l3_config_data->merge_info.default_route_penalty_4 != default_route_penalty_4) {
			l3_config_data->merge_info.default_route_penalty_4 = default_route_penalty_4;
			changed = TRUE;
		}
		if (l3_config_data->merge_info.default_route_penalty_6 != default_route_penalty_6) {
			l3_config_data->merge_info.default_route_penalty_6 = default_route_penalty_6;
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
                      const NML3ConfigData *l3cfg)
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
		                                  l3cfg);
		if (idx < 0)
			return;

		if (   only_dirty
		    && !_l3_config_datas_at (l3_config_datas, idx)->dirty) {
			idx++;
			continue;
		}

		self->priv.changed_configs = TRUE;
		_l3_config_datas_remove_index_fast (l3_config_datas, idx);
		if (!l3cfg)
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

static int
_l3_config_combine_sort_fcn (gconstpointer p_a,
                             gconstpointer p_b,
                             gpointer user_data)
{
	const L3ConfigData *a = *((L3ConfigData **) p_a);
	const L3ConfigData *b = *((L3ConfigData **) p_b);

	nm_assert (a);
	nm_assert (b);
	nm_assert (nm_l3_config_data_get_ifindex (a->merge_info.l3cfg) == nm_l3_config_data_get_ifindex (b->merge_info.l3cfg));

	/* we sort the entries with higher priority (more important, lower numerical value)
	 * first. */
	NM_CMP_FIELD (a, b, priority);

	/* if the priority is not unique, we sort them in the order they were added,
	 * with the oldest first (lower numerical value). */
	NM_CMP_FIELD (a, b, pseudo_timestamp);

	return nm_assert_unreachable_val (0);
}

static const NML3ConfigData *
_l3cfg_combine_config (GArray *l3_config_datas,
                       NMDedupMultiIndex *multi_idx,
                       int ifindex)
{
	gs_free L3ConfigData **infos_heap = NULL;
	NML3ConfigData *l3cfg;
	L3ConfigData **infos;
	guint i;

	if (   !l3_config_datas
	    || l3_config_datas->len == 0)
		return NULL;

	if (l3_config_datas->len == 1)
		return nm_l3_config_data_ref (_l3_config_datas_at (l3_config_datas, 0)->merge_info.l3cfg);

	if (l3_config_datas->len < 300 / sizeof (infos[0]))
		infos = g_alloca (l3_config_datas->len * sizeof (infos[0]));
	else {
		infos_heap = g_new (L3ConfigData *, l3_config_datas->len);
		infos = infos_heap;
	}

	for (i = 0; i < l3_config_datas->len; i++)
		infos[i] = _l3_config_datas_at (l3_config_datas, i);

	g_qsort_with_data (infos,
	                   l3_config_datas->len,
	                   sizeof (infos[0]),
	                   _l3_config_combine_sort_fcn,
	                   NULL);

	nm_assert (&infos[0]->merge_info == (NML3ConfigDatMergeInfo *) infos[0]);

	l3cfg = nm_l3_config_data_new_combined (multi_idx,
	                                        ifindex,
	                                        (const NML3ConfigDatMergeInfo *const*) infos,
	                                        l3_config_datas->len);

	nm_assert (l3cfg);
	nm_assert (nm_l3_config_data_get_ifindex (l3cfg) == ifindex);

	return nm_l3_config_data_seal (l3cfg);
}

static gboolean
_l3cfg_update_combined_config (NML3Cfg *self,
                               const NML3ConfigData **out_old /* transfer reference */)
{
	nm_auto_unref_l3cfg const NML3ConfigData *l3cfg_old = NULL;
	nm_auto_unref_l3cfg const NML3ConfigData *l3cfg = NULL;

	nm_assert (NM_IS_L3CFG (self));
	nm_assert (!out_old || !*out_old);

	if (!self->priv.changed_configs)
		return FALSE;

	self->priv.changed_configs = FALSE;

	l3cfg = _l3cfg_combine_config (self->priv.p->l3_config_datas,
	                               nm_platform_get_multi_idx (self->priv.platform),
	                               self->priv.ifindex);

	if (nm_l3_config_data_equal (l3cfg, self->priv.p->combined_l3cfg))
		return FALSE;

	_LOGT ("desired IP configuration changed");

	l3cfg_old = g_steal_pointer (&self->priv.p->combined_l3cfg);
	self->priv.p->combined_l3cfg = nm_l3_config_data_seal (g_steal_pointer (&l3cfg));
	NM_SET_OUT (out_old, nm_l3_config_data_ref (self->priv.p->combined_l3cfg));
	return TRUE;
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

gboolean
nm_l3cfg_platform_commit (NML3Cfg *self,
                          int addr_family,
                          gboolean *out_final_failure_for_temporary_not_available)
{
	gs_unref_ptrarray GPtrArray *addresses = NULL;
	gs_unref_ptrarray GPtrArray *routes = NULL;
	gs_unref_ptrarray GPtrArray *routes_prune = NULL;
	gs_unref_ptrarray GPtrArray *routes_temporary_not_available_arr = NULL;
	NMIPRouteTableSyncMode route_table_sync = NM_IP_ROUTE_TABLE_SYNC_MODE_NONE;
	gboolean final_failure_for_temporary_not_available = FALSE;
	gboolean success = TRUE;
	int IS_IPv4;

	g_return_val_if_fail (NM_IS_L3CFG (self), FALSE);

	if (addr_family == AF_UNSPEC) {
		gboolean final_failure_for_temporary_not_available_6 = FALSE;

		if (!nm_l3cfg_platform_commit (self, AF_INET, &final_failure_for_temporary_not_available))
			success = FALSE;
		if (!nm_l3cfg_platform_commit (self, AF_INET6, &final_failure_for_temporary_not_available_6))
			success = FALSE;
		NM_SET_OUT (out_final_failure_for_temporary_not_available,
		            (   final_failure_for_temporary_not_available
		             || final_failure_for_temporary_not_available_6));
		return success;
	}

	_l3cfg_update_combined_config (self, NULL);

	IS_IPv4 = NM_IS_IPv4 (addr_family);

	_LOGT ("committing IPv%c configuration...", nm_utils_addr_family_to_char (addr_family));

	if (self->priv.p->combined_l3cfg) {
		addresses = nm_dedup_multi_objs_to_ptr_array_head (nm_l3_config_data_lookup_objs (self->priv.p->combined_l3cfg,
		                                                                                  NMP_OBJECT_TYPE_IP_ADDRESS (IS_IPv4)),
		                                                   NULL, NULL);

		routes = nm_dedup_multi_objs_to_ptr_array_head (nm_l3_config_data_lookup_objs (self->priv.p->combined_l3cfg,
		                                                                               NMP_OBJECT_TYPE_IP_ROUTE (IS_IPv4)),
		                                                NULL, NULL);

		route_table_sync = nm_l3_config_data_get_route_table_sync (self->priv.p->combined_l3cfg, addr_family);
	}

	if (route_table_sync == NM_IP_ROUTE_TABLE_SYNC_MODE_NONE)
		route_table_sync = NM_IP_ROUTE_TABLE_SYNC_MODE_ALL;

	routes_prune = nm_platform_ip_route_get_prune_list (self->priv.platform,
	                                                    addr_family,
	                                                    self->priv.ifindex,
	                                                    route_table_sync);

	nm_platform_ip4_address_sync (self->priv.platform,
	                              self->priv.ifindex,
	                              addresses);

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

	NM_SET_OUT (out_final_failure_for_temporary_not_available, final_failure_for_temporary_not_available);
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
	NML3CfgPrivate *p;

	p = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_L3CFG, NML3CfgPrivate);

	self->priv.p = p;
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

	nm_assert (nm_g_array_len (self->priv.p->property_emit_list) == 0u);

	nm_clear_g_source (&self->priv.p->routes_temporary_not_available_id);
	nm_clear_pointer (&self->priv.p->routes_temporary_not_available_hash, g_hash_table_unref);

	g_clear_object (&self->priv.netns);
	g_clear_object (&self->priv.platform);

	nm_clear_pointer (&self->priv.p->combined_l3cfg, nm_l3_config_data_unref);

	nm_clear_pointer (&self->priv.pllink, nmp_object_unref);

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
	                    G_SIGNAL_DETAILED
	                  | G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE,
	                  2,
	                  G_TYPE_INT /* NML3ConfigNotifyType */,
	                  G_TYPE_POINTER /* pay-load */ );

	signal_notify_quarks[NM_L3_CONFIG_NOTIFY_TYPE_ROUTES_TEMPORARY_NOT_AVAILABLE_EXPIRED] = g_quark_from_static_string (NM_L3_CONFIG_NOTIFY_TYPE_ROUTES_TEMPORARY_NOT_AVAILABLE_EXPIRED_DETAIL);
}
