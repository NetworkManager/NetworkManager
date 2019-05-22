/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2019 Red Hat, Inc.
 */

#define NM_VALUE_TYPE_DEFINE_FUNCTIONS

#include "nm-default.h"

#include "nm-team-utils.h"

#include "nm-errors.h"
#include "nm-utils-private.h"
#include "nm-json.h"
#include "nm-glib-aux/nm-json-aux.h"
#include "nm-core-internal.h"
#include "nm-setting-team.h"
#include "nm-setting-team-port.h"

/*****************************************************************************/

/* we rely on "config" being the first. At various places we iterate over attribute types,
 * starting after "config".*/
G_STATIC_ASSERT (_NM_TEAM_ATTRIBUTE_0     == 0);
G_STATIC_ASSERT (NM_TEAM_ATTRIBUTE_CONFIG == 1);

typedef struct {
	const char *const*js_keys;
	const char *dbus_name;
	NMValueTypUnion default_val;
	NMTeamAttribute team_attr;
	NMValueType value_type;
	guint8 field_offset;
	guint8 js_keys_len;
	bool for_master:1;
	bool for_port:1;
} TeamAttrData;

#define TEAM_ATTR_IDX(_is_port, _team_attr) \
	((  (!(_is_port) || (_team_attr) < _NM_TEAM_ATTRIBUTE_START) \
	  ? (int) (_team_attr) \
	  : (((int) (_NM_TEAM_ATTRIBUTE_MASTER_NUM - _NM_TEAM_ATTRIBUTE_START)) + ((int) (_team_attr)))) - 1)

#define TEAM_ATTR_IDX_CONFIG (TEAM_ATTR_IDX (FALSE, NM_TEAM_ATTRIBUTE_CONFIG))

static const TeamAttrData team_attr_datas[] = {

#define _JS_KEYS(...) \
		.js_keys = NM_MAKE_STRV (__VA_ARGS__), \
		.js_keys_len = NM_NARG (__VA_ARGS__)

#define _INIT(_is_port, _team_attr, field, _value_type, _dbus_name, ...) \
	[TEAM_ATTR_IDX (_is_port, _team_attr)] = { \
		.for_master    = (_team_attr) < _NM_TEAM_ATTRIBUTE_START || !(_is_port), \
		.for_port      = (_team_attr) < _NM_TEAM_ATTRIBUTE_START ||  (_is_port), \
		.team_attr     = (_team_attr), \
		.field_offset  = G_STRUCT_OFFSET (NMTeamSetting, _data_priv.field), \
		.value_type    = (_value_type), \
		.dbus_name     = ""_dbus_name"", \
		__VA_ARGS__ \
	}

	_INIT (0, NM_TEAM_ATTRIBUTE_CONFIG,                             _js_str,                            NM_VALUE_TYPE_UNSPEC, NM_SETTING_TEAM_CONFIG,                                                                                                                                               ),

	_INIT (0, NM_TEAM_ATTRIBUTE_LINK_WATCHERS,                      link_watchers,                      NM_VALUE_TYPE_UNSPEC, NM_SETTING_TEAM_LINK_WATCHERS,               _JS_KEYS ("link_watch"),                                                                                                 ),

	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_COUNT,          master.notify_peers_count,          NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_NOTIFY_PEERS_COUNT,          _JS_KEYS ("notify_peers", "count"),                                                                                      ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_INTERVAL,       master.notify_peers_interval,       NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_NOTIFY_PEERS_INTERVAL,       _JS_KEYS ("notify_peers", "interval"),                                                                                   ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_COUNT,          master.mcast_rejoin_count,          NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_MCAST_REJOIN_COUNT,          _JS_KEYS ("mcast_rejoin", "count"),                                                                                      ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_INTERVAL,       master.mcast_rejoin_interval,       NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_MCAST_REJOIN_INTERVAL,       _JS_KEYS ("mcast_rejoin", "interval"),                                                                                   ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER,                      master.runner,                      NM_VALUE_TYPE_STRING, NM_SETTING_TEAM_RUNNER,                      _JS_KEYS ("runner", "name"),                              .default_val.v_string = NM_SETTING_TEAM_RUNNER_DEFAULT,        ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_HWADDR_POLICY,        master.runner_hwaddr_policy,        NM_VALUE_TYPE_STRING, NM_SETTING_TEAM_RUNNER_HWADDR_POLICY,        _JS_KEYS ("runner", "hwaddr_policy"),                                                                                    ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH,              master.runner_tx_hash,              NM_VALUE_TYPE_UNSPEC, NM_SETTING_TEAM_RUNNER_TX_HASH,              _JS_KEYS ("runner", "tx_hash"),                                                                                          ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER,          master.runner_tx_balancer,          NM_VALUE_TYPE_STRING, NM_SETTING_TEAM_RUNNER_TX_BALANCER,          _JS_KEYS ("runner", "tx_balancer", "name"),                                                                              ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL, master.runner_tx_balancer_interval, NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL, _JS_KEYS ("runner", "tx_balancer", "balancing_interval"), .default_val.v_int32 = -1                                      ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_ACTIVE,               master.runner_active,               NM_VALUE_TYPE_BOOL,   NM_SETTING_TEAM_RUNNER_ACTIVE,               _JS_KEYS ("runner", "active"),                                                                                           ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_FAST_RATE,            master.runner_fast_rate,            NM_VALUE_TYPE_BOOL,   NM_SETTING_TEAM_RUNNER_FAST_RATE,            _JS_KEYS ("runner", "fast_rate"),                                                                                        ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO,             master.runner_sys_prio,             NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_RUNNER_SYS_PRIO,             _JS_KEYS ("runner", "sys_prio"),                          .default_val.v_int32 = -1,                                     ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_MIN_PORTS,            master.runner_min_ports,            NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_RUNNER_MIN_PORTS,            _JS_KEYS ("runner", "min_ports"),                         .default_val.v_int32 = -1,                                     ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_AGG_SELECT_POLICY,    master.runner_agg_select_policy,    NM_VALUE_TYPE_STRING, NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY,    _JS_KEYS ("runner", "agg_select_policy"),                                                                                ),

	_INIT (1, NM_TEAM_ATTRIBUTE_PORT_QUEUE_ID,                      port.queue_id,                      NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_PORT_QUEUE_ID,               _JS_KEYS ("queue_id"),                                    .default_val.v_int32 = NM_SETTING_TEAM_PORT_QUEUE_ID_DEFAULT,  ),
	_INIT (1, NM_TEAM_ATTRIBUTE_PORT_PRIO,                          port.prio,                          NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_PORT_PRIO,                   _JS_KEYS ("prio"),                                                                                                       ),
	_INIT (1, NM_TEAM_ATTRIBUTE_PORT_STICKY,                        port.sticky,                        NM_VALUE_TYPE_BOOL,   NM_SETTING_TEAM_PORT_STICKY,                 _JS_KEYS ("sticky"),                                                                                                     ),
	_INIT (1, NM_TEAM_ATTRIBUTE_PORT_LACP_PRIO,                     port.lacp_prio,                     NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_PORT_LACP_PRIO,              _JS_KEYS ("lacp_prio"),                                   .default_val.v_int32 = NM_SETTING_TEAM_PORT_LACP_PRIO_DEFAULT, ),
	_INIT (1, NM_TEAM_ATTRIBUTE_PORT_LACP_KEY,                      port.lacp_key,                      NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_PORT_LACP_KEY,               _JS_KEYS ("lacp_key"),                                                                                                   ),

#undef _INIT

};

/*****************************************************************************/

typedef enum {
	LINK_WATCHER_ATTRIBUTE_NAME,
	LINK_WATCHER_ATTRIBUTE_TARGET_HOST,
	LINK_WATCHER_ATTRIBUTE_SOURCE_HOST,
	LINK_WATCHER_ATTRIBUTE_DELAY_UP,
	LINK_WATCHER_ATTRIBUTE_DELAY_DOWN,
	LINK_WATCHER_ATTRIBUTE_INIT_WAIT,
	LINK_WATCHER_ATTRIBUTE_INTERVAL,
	LINK_WATCHER_ATTRIBUTE_MISSED_MAX,
	LINK_WATCHER_ATTRIBUTE_VLANID,
	LINK_WATCHER_ATTRIBUTE_VALIDATE_ACTIVE,
	LINK_WATCHER_ATTRIBUTE_VALIDATE_INACTIVE,
	LINK_WATCHER_ATTRIBUTE_SEND_ALWAYS,
} LinkWatcherAttribute;

typedef struct {
	const char *js_key;
	NMValueTypUnion default_val;
	LinkWatcherAttribute link_watcher_attr;
	NMValueType value_type;
} LinkWatcherAttrData;

static const LinkWatcherAttrData link_watcher_attr_datas[] = {
#define _INIT(_link_watcher_attr, _js_key, _value_type, ...) \
	[_link_watcher_attr] = { \
		.link_watcher_attr = (_link_watcher_attr), \
		.value_type = (_value_type), \
		.js_key = (""_js_key""), \
		__VA_ARGS__ \
	}
	_INIT (LINK_WATCHER_ATTRIBUTE_NAME,              "name",              NM_VALUE_TYPE_STRING,                          ),
	_INIT (LINK_WATCHER_ATTRIBUTE_TARGET_HOST,       "target_host",       NM_VALUE_TYPE_STRING,                          ),
	_INIT (LINK_WATCHER_ATTRIBUTE_SOURCE_HOST,       "source_host",       NM_VALUE_TYPE_STRING,                          ),
	_INIT (LINK_WATCHER_ATTRIBUTE_DELAY_UP,          "delay_up",          NM_VALUE_TYPE_INT,                             ),
	_INIT (LINK_WATCHER_ATTRIBUTE_DELAY_DOWN,        "delay_down",        NM_VALUE_TYPE_INT,                             ),
	_INIT (LINK_WATCHER_ATTRIBUTE_INIT_WAIT,         "init_wait",         NM_VALUE_TYPE_INT,                             ),
	_INIT (LINK_WATCHER_ATTRIBUTE_INTERVAL,          "interval",          NM_VALUE_TYPE_INT,                             ),
	_INIT (LINK_WATCHER_ATTRIBUTE_MISSED_MAX,        "missed_max",        NM_VALUE_TYPE_INT,    .default_val.v_int =  3, ),
	_INIT (LINK_WATCHER_ATTRIBUTE_VLANID,            "vlanid",            NM_VALUE_TYPE_INT,    .default_val.v_int = -1, ),
	_INIT (LINK_WATCHER_ATTRIBUTE_VALIDATE_ACTIVE,   "validate_active",   NM_VALUE_TYPE_BOOL,                            ),
	_INIT (LINK_WATCHER_ATTRIBUTE_VALIDATE_INACTIVE, "validate_inactive", NM_VALUE_TYPE_BOOL,                            ),
	_INIT (LINK_WATCHER_ATTRIBUTE_SEND_ALWAYS,       "send_always",       NM_VALUE_TYPE_BOOL,                            ),
#undef _INIT
};

/*****************************************************************************/

static const TeamAttrData *_team_attr_data_get (gboolean is_port,
                                                NMTeamAttribute team_attr);
static gpointer _team_setting_get_field (const NMTeamSetting *self,
                                         const TeamAttrData *attr_data);
static gboolean _team_setting_verify (const NMTeamSetting *self,
                                      GError **error);
static void _link_watcher_to_json (const NMTeamLinkWatcher *link_watcher,
                                   GString *gstr);

/*****************************************************************************/

static void
_team_attr_data_ASSERT (const TeamAttrData *attr_data)
{
#if NM_MORE_ASSERTS > 5
	nm_assert (attr_data);
	if (attr_data->for_port)
		nm_assert (attr_data == _team_attr_data_get (TRUE, attr_data->team_attr));
	if (attr_data->for_master)
		nm_assert (attr_data == _team_attr_data_get (FALSE, attr_data->team_attr));
	nm_assert ((attr_data - team_attr_datas) == TEAM_ATTR_IDX (attr_data->for_port, attr_data->team_attr));
	nm_assert (attr_data->value_type > 0);
	nm_assert (attr_data->field_offset < sizeof (NMTeamSetting));
	nm_assert (attr_data->js_keys_len == NM_PTRARRAY_LEN (attr_data->js_keys));
	nm_assert (attr_data->dbus_name);
	{
		static int checked = 0;

		if (checked == 0) {
			checked = 1;

			for (attr_data = &team_attr_datas[TEAM_ATTR_IDX_CONFIG + 1]; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++)
				_team_attr_data_ASSERT (attr_data);
		}
	}
#endif
}

static gboolean
_team_attr_data_is_relevant (const TeamAttrData *attr_data,
                             gboolean is_port)
{
	return   is_port
	       ? attr_data->for_port
	       : attr_data->for_master;
}

static const TeamAttrData *
_team_attr_data_get (gboolean is_port,
                     NMTeamAttribute team_attr)
{
	const int idx = TEAM_ATTR_IDX (is_port, team_attr);

	nm_assert (   idx >= 0
	           && idx < G_N_ELEMENTS (team_attr_datas));
	nm_assert (team_attr_datas[idx].team_attr == team_attr);
	nm_assert (_team_attr_data_is_relevant (&team_attr_datas[idx], is_port));

	return &team_attr_datas[idx];
}

static const TeamAttrData *
_team_attr_data_find_for_dbus_name (gboolean is_port,
                                    const char *dbus_name)
{
	const TeamAttrData *attr_data;

	for (attr_data = team_attr_datas; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {
		if (   _team_attr_data_is_relevant (attr_data, is_port)
		    && nm_streq (dbus_name, attr_data->dbus_name))
			return attr_data;
	}
	return NULL;
}

static const NMValueTypUnion *
_team_attr_data_get_default (const TeamAttrData *attr_data,
                             gboolean is_port,
                             const char *v_master_runner,
                             NMValueTypUnion *value_tmp)
{
	GPtrArray *v_ptrarray;

	/* unfortunately, the default certain values depends on other values :(
	 *
	 * For examle, master attributes depend on the "runner" setting.
	 * and port settings default to the ethtool link-watcher. */

	if (is_port) {

		switch (attr_data->team_attr) {
		case NM_TEAM_ATTRIBUTE_LINK_WATCHERS: {
			static GPtrArray *volatile gl_arr = NULL;

again_port_link_watchers:
			v_ptrarray = g_atomic_pointer_get (&gl_arr);
			if (G_UNLIKELY (!v_ptrarray)) {
				v_ptrarray = g_ptr_array_new_full (1, (GDestroyNotify) nm_team_link_watcher_unref);
				g_ptr_array_add (v_ptrarray, nm_team_link_watcher_new_ethtool (0, 0, NULL));
				if (!g_atomic_pointer_compare_and_exchange (&gl_arr, NULL, v_ptrarray)) {
					g_ptr_array_unref (v_ptrarray);
					goto again_port_link_watchers;
				}
			}
			return NM_VALUE_TYP_UNION_SET (value_tmp, v_ptrarray, v_ptrarray);
		}
		default:
			break;
		}

	} else {

		if (NM_IN_STRSET (v_master_runner, NULL,
		                                   NM_SETTING_TEAM_RUNNER_DEFAULT)) {
			/* a runner %NULL is the same as NM_SETTING_TEAM_RUNNER_DEFAULT ("roundrobin").
			 * In this case, the settings in attr_data are accurate. */
			return &attr_data->default_val;
		}

		switch (attr_data->team_attr) {
		case NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_COUNT:
			if (nm_streq (v_master_runner, NM_SETTING_TEAM_RUNNER_ACTIVEBACKUP))
				return NM_VALUE_TYP_UNION_SET (value_tmp, v_int32, NM_SETTING_TEAM_NOTIFY_PEERS_COUNT_ACTIVEBACKUP_DEFAULT);
			break;
		case NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_COUNT:
			if (nm_streq (v_master_runner, NM_SETTING_TEAM_RUNNER_ACTIVEBACKUP))
				return NM_VALUE_TYP_UNION_SET (value_tmp, v_int32, NM_SETTING_TEAM_NOTIFY_MCAST_COUNT_ACTIVEBACKUP_DEFAULT);
			break;
		case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_HWADDR_POLICY:
			if (nm_streq (v_master_runner, NM_SETTING_TEAM_RUNNER_ACTIVEBACKUP))
				return NM_VALUE_TYP_UNION_SET (value_tmp, v_string, "same_all");
			break;
		case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH:
			if (NM_IN_STRSET (v_master_runner, NM_SETTING_TEAM_RUNNER_LOADBALANCE,
			                                   NM_SETTING_TEAM_RUNNER_LACP)) {
				static GPtrArray *volatile gl_arr = NULL;

again_master_runner_tx_hash:
				v_ptrarray = g_atomic_pointer_get (&gl_arr);
				if (G_UNLIKELY (!v_ptrarray)) {
					v_ptrarray = g_ptr_array_sized_new (3);
					g_ptr_array_add (v_ptrarray, "eth");
					g_ptr_array_add (v_ptrarray, "ipv4");
					g_ptr_array_add (v_ptrarray, "ipv6");
					if (!g_atomic_pointer_compare_and_exchange (&gl_arr, NULL, v_ptrarray)) {
						g_ptr_array_unref (v_ptrarray);
						goto again_master_runner_tx_hash;
					}
				}
				return NM_VALUE_TYP_UNION_SET (value_tmp, v_ptrarray, v_ptrarray);
			}
			break;
		case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL:
			if (NM_IN_STRSET (v_master_runner, NM_SETTING_TEAM_RUNNER_LOADBALANCE,
			                                   NM_SETTING_TEAM_RUNNER_LACP))
				return NM_VALUE_TYP_UNION_SET (value_tmp, v_int32, NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL_DEFAULT);
			break;
		case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_ACTIVE:
			if (nm_streq (v_master_runner, NM_SETTING_TEAM_RUNNER_LACP))
				return NM_VALUE_TYP_UNION_SET (value_tmp, v_bool, TRUE);
			break;
		case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO:
			if (nm_streq (v_master_runner, NM_SETTING_TEAM_RUNNER_LACP))
				return NM_VALUE_TYP_UNION_SET (value_tmp, v_int32, NM_SETTING_TEAM_RUNNER_SYS_PRIO_DEFAULT);
			break;
		case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_MIN_PORTS:
			if (nm_streq (v_master_runner, NM_SETTING_TEAM_RUNNER_LACP))
				return NM_VALUE_TYP_UNION_SET (value_tmp, v_int32, 0);
			break;
		case NM_TEAM_ATTRIBUTE_MASTER_RUNNER_AGG_SELECT_POLICY:
			if (nm_streq (v_master_runner, NM_SETTING_TEAM_RUNNER_LACP))
				return NM_VALUE_TYP_UNION_SET (value_tmp, v_string, NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY_DEFAULT);
			break;
		default:
			break;
		}
	}

	return &attr_data->default_val;
}
static int
_team_attr_data_cmp (const TeamAttrData *attr_data,
                     gboolean is_port,
                     gconstpointer val_a,
                     gconstpointer val_b)
{
	const GPtrArray *v_ptrarray_a;
	const GPtrArray *v_ptrarray_b;
	guint len;

	_team_attr_data_ASSERT (attr_data);
	nm_assert (val_a);
	nm_assert (val_b);

	if (attr_data->value_type != NM_VALUE_TYPE_UNSPEC)
		NM_CMP_RETURN (nm_value_type_cmp (attr_data->value_type, val_a, val_b));
	else if (attr_data->team_attr == NM_TEAM_ATTRIBUTE_LINK_WATCHERS) {
		v_ptrarray_a = *((const GPtrArray *const*) val_a);
		v_ptrarray_b = *((const GPtrArray *const*) val_b);
		len = v_ptrarray_a ? v_ptrarray_a->len : 0u;
		NM_CMP_DIRECT (len, (v_ptrarray_b ? v_ptrarray_b->len : 0u));
		if (len > 0) {
			NM_CMP_RETURN (nm_team_link_watchers_cmp ((const NMTeamLinkWatcher *const*) v_ptrarray_a->pdata,
		                                              (const NMTeamLinkWatcher *const*) v_ptrarray_b->pdata,
		                                              len,
		                                              FALSE));
		}
	} else if (   !is_port
	           && attr_data->team_attr == NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH) {
		v_ptrarray_a = *((const GPtrArray *const*) val_a);
		v_ptrarray_b = *((const GPtrArray *const*) val_b);
		NM_CMP_RETURN (_nm_utils_strv_cmp_n (v_ptrarray_a ? (const char *const*) v_ptrarray_a->pdata : NULL,
		                                     v_ptrarray_a ? v_ptrarray_a->len : 0u,
		                                     v_ptrarray_b ? (const char *const*) v_ptrarray_b->pdata : NULL,
		                                     v_ptrarray_b ? v_ptrarray_b->len : 0u));
	} else
		nm_assert_not_reached ();
	return 0;
}

static gboolean
_team_attr_data_equal (const TeamAttrData *attr_data,
                       gboolean is_port,
                       gconstpointer val_a,
                       gconstpointer val_b)
{
	return _team_attr_data_cmp (attr_data, is_port, val_a, val_b) == 0;
}

static void
_team_attr_data_copy (const TeamAttrData *attr_data,
                      gboolean is_port,
                      gpointer dst,
                      gconstpointer src)
{
	GPtrArray *v_ptrarray_dst;
	const GPtrArray *v_ptrarray_src;
	GPtrArray *dst_array;
	guint i, len;

	if (attr_data->value_type != NM_VALUE_TYPE_UNSPEC)
		nm_value_type_copy (attr_data->value_type, dst, src);
	else if (attr_data->team_attr == NM_TEAM_ATTRIBUTE_LINK_WATCHERS) {
		v_ptrarray_src = *((const GPtrArray *const *) src);
		v_ptrarray_dst = *((GPtrArray **) dst);
		len = (v_ptrarray_src ? v_ptrarray_src->len : 0u);

		if (len == 0) {
			if (v_ptrarray_dst)
				g_ptr_array_set_size (v_ptrarray_dst, 0);
		} else {
			dst_array = g_ptr_array_new_full (len, (GDestroyNotify) nm_team_link_watcher_unref);
			for (i = 0; i < len; i++) {
				if (v_ptrarray_src->pdata[i]) {
					nm_team_link_watcher_ref (v_ptrarray_src->pdata[i]);
					g_ptr_array_add (dst_array,v_ptrarray_src->pdata[i]);
				}
			}
			if (v_ptrarray_dst)
				g_ptr_array_unref (v_ptrarray_dst);
			*((GPtrArray **) dst) = dst_array;
		}
	} else if (   !is_port
	           && attr_data->team_attr == NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH) {
		v_ptrarray_src = *((const GPtrArray *const *) src);
		v_ptrarray_dst = *((GPtrArray **) dst);
		len = (v_ptrarray_src ? v_ptrarray_src->len : 0u);

		if (   v_ptrarray_src
		    && v_ptrarray_src->len > 0) {
			dst_array = g_ptr_array_new_full (v_ptrarray_src->len, g_free);
			for (i = 0; i < v_ptrarray_src->len; i++)
				g_ptr_array_add (dst_array, g_strdup (v_ptrarray_src->pdata[i]));
		} else
			dst_array = NULL;
		if (v_ptrarray_dst)
			g_ptr_array_unref (v_ptrarray_dst);
		*((GPtrArray **) dst) = dst_array;
	} else
		nm_assert_not_reached ();
}

static gboolean
_team_attr_data_is_default (const TeamAttrData *attr_data,
                            gboolean is_port,
                            const char *v_master_runner,
                            gconstpointer p_field)
{
	const NMValueTypUnion *default_value;
	NMValueTypUnion value_tmp;

	_team_attr_data_ASSERT (attr_data);
	nm_assert (p_field);

	default_value = _team_attr_data_get_default (attr_data,
	                                             is_port,
	                                             v_master_runner,
	                                             &value_tmp);
	if (_team_attr_data_equal (attr_data,
	                           is_port,
	                           default_value,
	                           p_field))
		return TRUE;

	if (    attr_data->value_type == NM_VALUE_TYPE_STRING
	    &&  default_value->v_string) {
		const char *str0 = NULL;

		/* this is a string value, whose default is not NULL. In such a case,
		 * NULL is also treated like the default. */
		if (_team_attr_data_equal (attr_data,
		                           is_port,
		                           &str0,
		                           p_field))
			return TRUE;
	}

	return FALSE;
}

static void
_team_attr_data_to_json (const TeamAttrData *attr_data,
                         gboolean is_port,
                         GString *gstr,
                         gconstpointer p_field)
{
	guint i;

	_team_attr_data_ASSERT (attr_data);
	nm_assert (p_field);

	nm_json_aux_gstr_append_obj_name (gstr,
	                                  attr_data->js_keys[attr_data->js_keys_len - 1],
	                                  '\0');

	if (attr_data->value_type != NM_VALUE_TYPE_UNSPEC) {
		nm_value_type_to_json (attr_data->value_type, gstr, p_field);
		return;
	}

	if (attr_data->team_attr == NM_TEAM_ATTRIBUTE_LINK_WATCHERS) {
		const GPtrArray *v_ptrarray = *((const GPtrArray *const*) p_field);

		if (!v_ptrarray)
			g_string_append (gstr, "null");
		else if (v_ptrarray->len == 0)
			g_string_append (gstr, "[ ]");
		else if (v_ptrarray->len == 1)
			_link_watcher_to_json (v_ptrarray->pdata[0], gstr);
		else {
			g_string_append (gstr, "[ ");
			for (i = 0; i < v_ptrarray->len; i++) {
				if (i > 0)
					nm_json_aux_gstr_append_delimiter (gstr);
				_link_watcher_to_json (v_ptrarray->pdata[i], gstr);
			}
			g_string_append (gstr, " ]");
		}
		return;
	}

	if (   !is_port
	    && attr_data->team_attr == NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH) {
		const GPtrArray *v_ptrarray = *((const GPtrArray *const*) p_field);

		if (!v_ptrarray)
			g_string_append (gstr, "null");
		else {
			g_string_append (gstr, "[ ");
			for (i = 0; i < v_ptrarray->len; i++) {
				if (i > 0)
					nm_json_aux_gstr_append_delimiter (gstr);
				nm_json_aux_gstr_append_string (gstr, v_ptrarray->pdata[i]);
			}
			g_string_append (gstr, i > 0 ? " ]" : "]");
		}
		return;
	}

	nm_assert_not_reached ();
}

/*****************************************************************************/

static void
_team_setting_ASSERT (const NMTeamSetting *self)
{
	nm_assert (self);
	nm_assert (!self->d._js_str_need_synthetize || !self->d._js_str);
#if NM_MORE_ASSERTS > 2
	if (!self->d.strict_validated) {
		nm_assert (!self->d._js_str_need_synthetize);
		nm_assert (self->d._js_str);
	}
	nm_assert (self->d.link_watchers);
	nm_assert (   self->d.is_port
	           || !self->d.master.runner_tx_hash
	           || self->d.master.runner_tx_hash->len > 0);
#endif
}

static gpointer
_team_setting_get_field (const NMTeamSetting *self,
                         const TeamAttrData *attr_data)
{
	_team_setting_ASSERT (self);
	_team_attr_data_ASSERT (attr_data);
	nm_assert (_team_attr_data_is_relevant (attr_data, self->d.is_port));

#if NM_MORE_ASSERTS > 5
	if (   attr_data->for_master
	    && attr_data->team_attr == NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO )
		nm_assert ((gpointer) (((char *) self) + attr_data->field_offset) == &self->d.master.runner_sys_prio);
#endif

	return (((char *) self) + attr_data->field_offset);
}

static guint32
_team_setting_attribute_changed (NMTeamSetting *self,
                                 NMTeamAttribute team_attr,
                                 gboolean changed)
{
	guint32 changed_flags;

	nm_assert (_team_attr_data_get (self->d.is_port, team_attr));

	if (!changed) {
		/* a regular attribute was set, but the value did not change.
		 *
		 * If we previously were in non-strict mode, then
		 *
		 * - switch to strict-mode. Clearly the user set a regular attribute
		 *   and hence now we want to validate the setting.
		 *
		 * - clear the JSON string. We need to regenerate it.
		 */
		if (self->_data_priv.strict_validated)
			return 0;
		changed_flags = nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_CONFIG);
	} else {
		changed_flags =   nm_team_attribute_to_flags (team_attr)
		                | nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_CONFIG);
	}

	nm_clear_g_free ((char **) &self->_data_priv._js_str);
	self->_data_priv.strict_validated = TRUE;
	self->_data_priv._js_str_need_synthetize = TRUE;

	return changed_flags;
}

static void
_team_setting_field_to_json (const NMTeamSetting *self,
                             GString *gstr,
                             gboolean prepend_delimiter,
                             NMTeamAttribute team_attr)
{
	const TeamAttrData *attr_data = _team_attr_data_get (self->d.is_port, team_attr);

	if (prepend_delimiter)
		nm_json_aux_gstr_append_delimiter (gstr);
	_team_attr_data_to_json (attr_data,
	                         self->d.is_port,
	                         gstr,
	                         _team_setting_get_field (self, attr_data));
}

static gboolean
_team_setting_fields_to_json_maybe (const NMTeamSetting *self,
                                    GString *gstr,
                                    gboolean prepend_delimiter,
                                    const bool is_default_lst[static _NM_TEAM_ATTRIBUTE_NUM],
                                    const NMTeamAttribute *team_attrs_lst,
                                    gsize team_attrs_lst_len)
{
	gsize i;
	gboolean any_added = FALSE;

	for (i = 0; i < team_attrs_lst_len; i++) {
		NMTeamAttribute team_attr = team_attrs_lst[i];

		if (is_default_lst[team_attr])
			continue;

		_team_setting_field_to_json (self, gstr, prepend_delimiter, team_attr);
		any_added = TRUE;
		prepend_delimiter = TRUE;
	}
	return any_added;
}

static guint32
_team_setting_set (NMTeamSetting *self,
                   gboolean modify,
                   const bool *has_lst,
                   const NMValueTypUnion *val_lst)
{
	guint32 changed_flags = 0;
	const TeamAttrData *attr_data;
	const char *v_master_runner;

	nm_assert ((!has_lst) == (!val_lst));

	if (!self->d.is_port) {
		if (   has_lst
		    && has_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER])
			v_master_runner = val_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER].v_string;
		else {
			nm_assert (nm_streq0 (_team_attr_data_get (FALSE, NM_TEAM_ATTRIBUTE_MASTER_RUNNER)->default_val.v_string,
			                      NM_SETTING_TEAM_RUNNER_DEFAULT));
			v_master_runner = NM_SETTING_TEAM_RUNNER_DEFAULT;
		}
	} else
		v_master_runner = NULL;

	for (attr_data = &team_attr_datas[TEAM_ATTR_IDX_CONFIG + 1]; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {
		NMValueTypUnion value_tmp;
		const NMValueTypUnion *p_val;
		gconstpointer p_field;

		if (!_team_attr_data_is_relevant (attr_data, self->d.is_port))
			continue;

		if (   has_lst
		    && has_lst[attr_data->team_attr])
			p_val = &val_lst[attr_data->team_attr];
		else {
			p_val = _team_attr_data_get_default (attr_data,
			                                     self->d.is_port,
			                                     v_master_runner,
			                                     &value_tmp);
		}

		p_field = _team_setting_get_field (self, attr_data);

		if (!_team_attr_data_equal (attr_data,
		                            self->d.is_port,
		                            p_val,
		                            p_field)) {
			if (modify) {
				_team_attr_data_copy (attr_data,
				                      self->d.is_port,
				                      (gpointer) p_field,
				                      p_val);
			}
			changed_flags |= nm_team_attribute_to_flags (attr_data->team_attr);
		}
	}

	return changed_flags;
}

static guint32
_team_setting_check_default (const NMTeamSetting *self)
{
	return _team_setting_set ((NMTeamSetting *) self, FALSE, NULL, NULL);
}

static guint32
_team_setting_set_default (NMTeamSetting *self)
{
	return _team_setting_set (self, TRUE, NULL, NULL);
}

/*****************************************************************************/

gconstpointer
_nm_team_setting_value_get (const NMTeamSetting *self,
                            NMTeamAttribute team_attr,
                            NMValueType value_type)
{
	const TeamAttrData *attr_data = _team_attr_data_get (self->d.is_port, team_attr);

	nm_assert (value_type == attr_data->value_type);

	return _team_setting_get_field (self, attr_data);
}

static guint32
_team_setting_value_set (NMTeamSetting *self,
                         NMTeamAttribute team_attr,
                         NMValueType value_type,
                         gconstpointer val)
{
	const TeamAttrData *attr_data;
	gpointer p_field;

	nm_assert (self);

	attr_data = _team_attr_data_get (self->d.is_port, team_attr);

	nm_assert (val);
	nm_assert (value_type == attr_data->value_type);

	p_field = _team_setting_get_field (self, attr_data);

	if (nm_value_type_equal (attr_data->value_type, p_field, val))
		return 0u;
	nm_value_type_copy (attr_data->value_type, p_field, val);
	return nm_team_attribute_to_flags (team_attr);
}

guint32
_nm_team_setting_value_set (NMTeamSetting *self,
                            NMTeamAttribute team_attr,
                            NMValueType value_type,
                            gconstpointer val)
{
	return _team_setting_attribute_changed (self,
	                                        team_attr,
	                                        (_team_setting_value_set (self,
	                                                                  team_attr,
	                                                                  value_type,
	                                                                  val) != 0u));
}

guint32
nm_team_setting_value_link_watchers_add (NMTeamSetting *self,
                                         const NMTeamLinkWatcher *link_watcher)
{
	guint i;

	for (i = 0; i < self->d.link_watchers->len; i++) {
		if (nm_team_link_watcher_equal (self->d.link_watchers->pdata[i], link_watcher))
			return _team_setting_attribute_changed (self, NM_TEAM_ATTRIBUTE_LINK_WATCHERS, FALSE);
	}
	g_ptr_array_add ((GPtrArray *) self->d.link_watchers,
	                 _nm_team_link_watcher_ref ((NMTeamLinkWatcher *) link_watcher));
	return _team_setting_attribute_changed (self, NM_TEAM_ATTRIBUTE_LINK_WATCHERS, TRUE);
}

guint32
nm_team_setting_value_link_watchers_remove_by_value (NMTeamSetting *self,
                                                     const NMTeamLinkWatcher *link_watcher)
{
	guint i;

	for (i = 0; i < self->d.link_watchers->len; i++) {
		if (nm_team_link_watcher_equal (self->d.link_watchers->pdata[i],
		                                link_watcher))
			return nm_team_setting_value_link_watchers_remove (self, i);
	}
	return _team_setting_attribute_changed (self, NM_TEAM_ATTRIBUTE_LINK_WATCHERS, FALSE);
}

guint32
nm_team_setting_value_link_watchers_remove (NMTeamSetting *self,
                                            guint idx)
{
	g_ptr_array_remove_index ((GPtrArray *) self->d.link_watchers, idx);
	return _team_setting_attribute_changed (self, NM_TEAM_ATTRIBUTE_LINK_WATCHERS, TRUE);
}

static guint32
_team_setting_value_link_watchers_set_list (NMTeamSetting *self,
                                            const NMTeamLinkWatcher *const*arr,
                                            guint len)
{
	if (   self->d.link_watchers->len == len
	    && nm_team_link_watchers_cmp ((const NMTeamLinkWatcher *const*) self->d.link_watchers->pdata,
	                                  arr,
	                                  len,
	                                  FALSE) == 0)
		return 0;

	if (len == 0)
		g_ptr_array_set_size ((GPtrArray *) self->d.link_watchers, 0);
	else {
		_nm_unused gs_unref_ptrarray GPtrArray *old_val_destroy = NULL;
		guint i;

		old_val_destroy = (GPtrArray *) g_steal_pointer (&self->_data_priv.link_watchers);

		self->_data_priv.link_watchers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);

		for (i = 0; i < len; i++) {
			if (arr[i]) {
				g_ptr_array_add ((GPtrArray *) self->d.link_watchers,
				                 _nm_team_link_watcher_ref ((NMTeamLinkWatcher *) arr[i]));
			}
		}
	}

	return nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_LINK_WATCHERS);
}

guint32
nm_team_setting_value_link_watchers_set_list (NMTeamSetting *self,
                                              const NMTeamLinkWatcher *const*arr,
                                              guint len)
{
	return _team_setting_attribute_changed (self,
	                                        NM_TEAM_ATTRIBUTE_LINK_WATCHERS,
	                                        (_team_setting_value_link_watchers_set_list (self,
	                                                                                     arr,
	                                                                                     len) != 0u));
}

/*****************************************************************************/

guint32
nm_team_setting_value_master_runner_tx_hash_add (NMTeamSetting *self,
                                                 const char *txhash)
{
	guint i;

	if (!self->d.master.runner_tx_hash)
		self->_data_priv.master.runner_tx_hash = g_ptr_array_new_with_free_func (g_free);
	else {
		for (i = 0; i < self->d.master.runner_tx_hash->len; i++) {
			if (nm_streq (txhash, self->d.master.runner_tx_hash->pdata[i]))
				return _team_setting_attribute_changed (self, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH, FALSE);
		}
	}
	g_ptr_array_add ((GPtrArray *) self->d.master.runner_tx_hash, g_strdup (txhash));
	return _team_setting_attribute_changed (self, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH, TRUE);
}

guint32
nm_team_setting_value_master_runner_tx_hash_remove (NMTeamSetting *self,
                                                    guint idx)
{
	g_ptr_array_remove_index ((GPtrArray *) self->d.master.runner_tx_hash, idx);
	return _team_setting_attribute_changed (self, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH, TRUE);
}

static guint32
_team_setting_value_master_runner_tx_hash_set_list (NMTeamSetting *self,
                                                    const char *const*arr,
                                                    guint len)
{
	_nm_unused gs_unref_ptrarray GPtrArray *old_val_destroy = NULL;
	guint i;

	if (_nm_utils_strv_cmp_n (self->d.master.runner_tx_hash ? (const char *const*) self->d.master.runner_tx_hash->pdata : NULL,
	                          self->d.master.runner_tx_hash ? self->d.master.runner_tx_hash->len : 0u,
	                          arr,
	                          len) == 0)
		return 0u;

	old_val_destroy = (GPtrArray *) g_steal_pointer (&self->_data_priv.master.runner_tx_hash);

	for (i = 0; i < len; i++) {
		if (!arr[i])
			continue;
		if (!self->d.master.runner_tx_hash)
			self->_data_priv.master.runner_tx_hash = g_ptr_array_new_with_free_func (g_free);
		g_ptr_array_add ((GPtrArray *) self->d.master.runner_tx_hash, g_strdup (arr[i]));
	}

	return nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH);
}

guint32
nm_team_setting_value_master_runner_tx_hash_set_list (NMTeamSetting *self,
                                                      const char *const*arr,
                                                      guint len)
{
	return _team_setting_attribute_changed (self,
	                                        NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH,
	                                        (_team_setting_value_master_runner_tx_hash_set_list (self,
	                                                                                             arr,
	                                                                                             len) != 0u));
}

/*****************************************************************************/

#define _LINK_WATCHER_ATTR_GET(args, link_watcher_attribute, _value_type) \
	({ \
		const NMValueTypUnioMaybe *const _args = (args); \
		\
		nm_assert (link_watcher_attr_datas[(link_watcher_attribute)].value_type == (_value_type)); \
		\
		  _args[(link_watcher_attribute)].has \
		? &_args[(link_watcher_attribute)].val \
		: &link_watcher_attr_datas[(link_watcher_attribute)].default_val; \
	})
#define _LINK_WATCHER_ATTR_GET_BOOL(args, link_watcher_attribute)   (_LINK_WATCHER_ATTR_GET (args, link_watcher_attribute, NM_VALUE_TYPE_BOOL   )->v_bool)
#define _LINK_WATCHER_ATTR_GET_INT(args, link_watcher_attribute)    (_LINK_WATCHER_ATTR_GET (args, link_watcher_attribute, NM_VALUE_TYPE_INT    )->v_int)
#define _LINK_WATCHER_ATTR_GET_STRING(args, link_watcher_attribute) (_LINK_WATCHER_ATTR_GET (args, link_watcher_attribute, NM_VALUE_TYPE_STRING )->v_string)

#define _LINK_WATCHER_ATTR_SET(args, link_watcher_attribute, _value_type, c_type, val) \
	({ \
		nm_assert (link_watcher_attr_datas[(link_watcher_attribute)].value_type == (_value_type)); \
		\
		NM_VALUE_TYP_UNIO_MAYBE_SET (&(args)[(link_watcher_attribute)], c_type, (val)); \
	})
#define _LINK_WATCHER_ATTR_SET_BOOL(args, link_watcher_attribute, val)   _LINK_WATCHER_ATTR_SET((args), (link_watcher_attribute), NM_VALUE_TYPE_BOOL,   v_bool,   (val))
#define _LINK_WATCHER_ATTR_SET_INT(args, link_watcher_attribute, val)    _LINK_WATCHER_ATTR_SET((args), (link_watcher_attribute), NM_VALUE_TYPE_INT,    v_int,    (val))
#define _LINK_WATCHER_ATTR_SET_STRING(args, link_watcher_attribute, val) _LINK_WATCHER_ATTR_SET((args), (link_watcher_attribute), NM_VALUE_TYPE_STRING, v_string, (val))

static void
_link_watcher_to_json (const NMTeamLinkWatcher *link_watcher,
                       GString *gstr)
{
	NMValueTypUnioMaybe args[G_N_ELEMENTS (link_watcher_attr_datas)] = { };
	NMTeamLinkWatcherArpPingFlags v_arp_ping_flags;
	const char *v_name;
	int i;

	if (!link_watcher) {
		g_string_append (gstr, "null");
		return;
	}

	v_name = nm_team_link_watcher_get_name (link_watcher);

	g_string_append (gstr, "{ ");

	nm_json_aux_gstr_append_obj_name (gstr, "name", '\0');
	nm_json_aux_gstr_append_string (gstr, v_name);

	if (nm_streq (v_name, NM_TEAM_LINK_WATCHER_ETHTOOL)) {
		_LINK_WATCHER_ATTR_SET_INT (args, LINK_WATCHER_ATTRIBUTE_DELAY_UP,   nm_team_link_watcher_get_delay_up (link_watcher));
		_LINK_WATCHER_ATTR_SET_INT (args, LINK_WATCHER_ATTRIBUTE_DELAY_DOWN, nm_team_link_watcher_get_delay_down (link_watcher));
	} else if (NM_IN_STRSET (v_name, NM_TEAM_LINK_WATCHER_NSNA_PING,
	                                 NM_TEAM_LINK_WATCHER_ARP_PING)) {
		_LINK_WATCHER_ATTR_SET_INT    (args, LINK_WATCHER_ATTRIBUTE_INIT_WAIT,   nm_team_link_watcher_get_init_wait (link_watcher));
		_LINK_WATCHER_ATTR_SET_INT    (args, LINK_WATCHER_ATTRIBUTE_INTERVAL,    nm_team_link_watcher_get_interval (link_watcher));
		_LINK_WATCHER_ATTR_SET_INT    (args, LINK_WATCHER_ATTRIBUTE_MISSED_MAX,  nm_team_link_watcher_get_missed_max (link_watcher));
		_LINK_WATCHER_ATTR_SET_STRING (args, LINK_WATCHER_ATTRIBUTE_TARGET_HOST, nm_team_link_watcher_get_target_host (link_watcher));
		if (nm_streq (v_name, NM_TEAM_LINK_WATCHER_ARP_PING)) {
			v_arp_ping_flags = nm_team_link_watcher_get_flags (link_watcher);
			_LINK_WATCHER_ATTR_SET_INT    (args, LINK_WATCHER_ATTRIBUTE_VLANID,            nm_team_link_watcher_get_vlanid (link_watcher));
			_LINK_WATCHER_ATTR_SET_STRING (args, LINK_WATCHER_ATTRIBUTE_SOURCE_HOST,       nm_team_link_watcher_get_source_host (link_watcher));
			_LINK_WATCHER_ATTR_SET_BOOL   (args, LINK_WATCHER_ATTRIBUTE_VALIDATE_ACTIVE,   NM_FLAGS_HAS (v_arp_ping_flags, NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE));
			_LINK_WATCHER_ATTR_SET_BOOL   (args, LINK_WATCHER_ATTRIBUTE_VALIDATE_INACTIVE, NM_FLAGS_HAS (v_arp_ping_flags, NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE));
			_LINK_WATCHER_ATTR_SET_BOOL   (args, LINK_WATCHER_ATTRIBUTE_SEND_ALWAYS,       NM_FLAGS_HAS (v_arp_ping_flags, NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS));
		}
	}

	for (i = 0; i < (int) G_N_ELEMENTS (link_watcher_attr_datas); i++) {
		const NMValueTypUnioMaybe *p_val = &args[i];
		const LinkWatcherAttrData *attr_data = &link_watcher_attr_datas[i];

		if (!p_val->has)
			continue;
		if (nm_value_type_equal (attr_data->value_type, &attr_data->default_val, &p_val->val))
			continue;
		nm_json_aux_gstr_append_delimiter (gstr);
		nm_json_aux_gstr_append_obj_name (gstr, attr_data->js_key, '\0');
		nm_value_type_to_json (attr_data->value_type, gstr, &p_val->val);
	}

	g_string_append (gstr, "}");
}

#if WITH_JSON_VALIDATION
static NMTeamLinkWatcher *
_link_watcher_from_json (const json_t *root_js_obj,
                         gboolean *out_unrecognized_content)
{
	NMValueTypUnioMaybe args[G_N_ELEMENTS (link_watcher_attr_datas)] = { };
	const char *j_key;
	json_t *j_val;
	const char *v_name;
	NMTeamLinkWatcher *result = NULL;

	if (!json_is_object (root_js_obj))
		goto fail;

	json_object_foreach ((json_t *) root_js_obj, j_key, j_val) {
		const LinkWatcherAttrData *attr_data = NULL;
		NMValueTypUnioMaybe *parse_result;

		if (j_key) {
			int i;

			for (i = 0; i < (int) G_N_ELEMENTS (link_watcher_attr_datas); i++) {
				if (nm_streq (link_watcher_attr_datas[i].js_key, j_key)) {
					attr_data = &link_watcher_attr_datas[i];
					break;
				}
			}
		}
		if (!attr_data) {
			*out_unrecognized_content = TRUE;
			continue;
		}

		parse_result = &args[attr_data->link_watcher_attr];

		if (parse_result->has)
			*out_unrecognized_content = TRUE;

		if (!nm_value_type_from_json (attr_data->value_type, j_val, &parse_result->val))
			*out_unrecognized_content = TRUE;
		else
			parse_result->has = TRUE;
	}

#define _PARSE_RESULT_HAS_UNEXPECTED_ATTRIBUTES(_parse_results, ...) \
	({ \
		int _i; \
		\
		for (_i = 0; _i < (int) G_N_ELEMENTS ((_parse_results)); _i++) { \
			if (   (_parse_results)[_i].has \
			    && !NM_IN_SET ((LinkWatcherAttribute) _i, LINK_WATCHER_ATTRIBUTE_NAME, \
			                                              __VA_ARGS__)) \
				break; \
		} \
		\
		(_i == (int) G_N_ELEMENTS ((_parse_results))); \
	})

	v_name = _LINK_WATCHER_ATTR_GET_STRING (args, LINK_WATCHER_ATTRIBUTE_NAME);

	if (nm_streq0 (v_name, NM_TEAM_LINK_WATCHER_ETHTOOL)) {
		if (_PARSE_RESULT_HAS_UNEXPECTED_ATTRIBUTES (args,
		                                             LINK_WATCHER_ATTRIBUTE_DELAY_UP,
		                                             LINK_WATCHER_ATTRIBUTE_DELAY_DOWN))
			*out_unrecognized_content = TRUE;
		result = nm_team_link_watcher_new_ethtool (_LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_DELAY_UP),
		                                           _LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_DELAY_DOWN),
		                                           NULL);
	} else if (nm_streq0 (v_name, NM_TEAM_LINK_WATCHER_NSNA_PING)) {
		if (_PARSE_RESULT_HAS_UNEXPECTED_ATTRIBUTES (args,
		                                             LINK_WATCHER_ATTRIBUTE_INIT_WAIT,
		                                             LINK_WATCHER_ATTRIBUTE_INTERVAL,
		                                             LINK_WATCHER_ATTRIBUTE_MISSED_MAX,
		                                             LINK_WATCHER_ATTRIBUTE_TARGET_HOST))
			*out_unrecognized_content = TRUE;
		result = nm_team_link_watcher_new_nsna_ping (_LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_INIT_WAIT),
		                                             _LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_INTERVAL),
		                                             _LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_MISSED_MAX),
		                                             _LINK_WATCHER_ATTR_GET_STRING (args, LINK_WATCHER_ATTRIBUTE_TARGET_HOST),
		                                             NULL);
	} else if (nm_streq0 (v_name, NM_TEAM_LINK_WATCHER_ARP_PING)) {
		NMTeamLinkWatcherArpPingFlags v_flags = NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE;

		if (_PARSE_RESULT_HAS_UNEXPECTED_ATTRIBUTES (args,
		                                             LINK_WATCHER_ATTRIBUTE_INIT_WAIT,
		                                             LINK_WATCHER_ATTRIBUTE_INTERVAL,
		                                             LINK_WATCHER_ATTRIBUTE_MISSED_MAX,
		                                             LINK_WATCHER_ATTRIBUTE_VLANID,
		                                             LINK_WATCHER_ATTRIBUTE_TARGET_HOST,
		                                             LINK_WATCHER_ATTRIBUTE_SOURCE_HOST,
		                                             LINK_WATCHER_ATTRIBUTE_VALIDATE_ACTIVE,
		                                             LINK_WATCHER_ATTRIBUTE_VALIDATE_INACTIVE,
		                                             LINK_WATCHER_ATTRIBUTE_SEND_ALWAYS))
			*out_unrecognized_content = TRUE;

		if (_LINK_WATCHER_ATTR_GET_BOOL (args, LINK_WATCHER_ATTRIBUTE_VALIDATE_ACTIVE))
			v_flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE;
		if (_LINK_WATCHER_ATTR_GET_BOOL (args, LINK_WATCHER_ATTRIBUTE_VALIDATE_INACTIVE))
			v_flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE;
		if (_LINK_WATCHER_ATTR_GET_BOOL (args, LINK_WATCHER_ATTRIBUTE_SEND_ALWAYS))
			v_flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS;

		result = nm_team_link_watcher_new_arp_ping2 (_LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_INIT_WAIT),
		                                             _LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_INTERVAL),
		                                             _LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_MISSED_MAX),
		                                             _LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_VLANID),
		                                             _LINK_WATCHER_ATTR_GET_STRING (args, LINK_WATCHER_ATTRIBUTE_TARGET_HOST),
		                                             _LINK_WATCHER_ATTR_GET_STRING (args, LINK_WATCHER_ATTRIBUTE_SOURCE_HOST),
		                                             v_flags,
		                                             NULL);
	}

	if (result)
		return result;
fail:
	*out_unrecognized_content = TRUE;
	return NULL;
}
#endif

/*****************************************************************************/

static GVariant *
_link_watcher_to_variant (const NMTeamLinkWatcher *watcher)
{
	GVariantBuilder builder;
	const char *name;
	int int_val;
	NMTeamLinkWatcherArpPingFlags flags;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

	name = nm_team_link_watcher_get_name (watcher);
	g_variant_builder_add (&builder, "{sv}",
	                       "name",
	                       g_variant_new_string (name));

	if (nm_streq (name, NM_TEAM_LINK_WATCHER_ETHTOOL)) {
		int_val = nm_team_link_watcher_get_delay_up (watcher);
		if (int_val) {
			g_variant_builder_add (&builder, "{sv}",
			                       "delay-up",
			                       g_variant_new_int32 (int_val));
		}
		int_val = nm_team_link_watcher_get_delay_down (watcher);
		if (int_val) {
			g_variant_builder_add (&builder, "{sv}",
			                       "delay-down",
			                       g_variant_new_int32 (int_val));
		}
		return g_variant_builder_end (&builder);
	}

	/* Common properties for arp_ping and nsna_ping link watchers */
	int_val = nm_team_link_watcher_get_init_wait (watcher);
	if (int_val) {
		g_variant_builder_add (&builder, "{sv}",
		                       "init-wait",
		                       g_variant_new_int32 (int_val));
	}
	int_val = nm_team_link_watcher_get_interval (watcher);
	if (int_val) {
		g_variant_builder_add (&builder, "{sv}",
		                       "interval",
		                       g_variant_new_int32 (int_val));
	}
	int_val = nm_team_link_watcher_get_missed_max (watcher);
	if (int_val != 3) {
		g_variant_builder_add (&builder, "{sv}",
		                       "missed-max",
		                       g_variant_new_int32 (int_val));
	}
	g_variant_builder_add (&builder, "{sv}",
	                       "target-host",
	                       g_variant_new_string (nm_team_link_watcher_get_target_host (watcher)));

	if (nm_streq (name, NM_TEAM_LINK_WATCHER_NSNA_PING))
		return g_variant_builder_end (&builder);

	/* arp_ping watcher only */
	int_val = nm_team_link_watcher_get_vlanid (watcher);
	if (int_val != -1) {
		g_variant_builder_add (&builder, "{sv}",
		                       "vlanid",
		                       g_variant_new_int32 (int_val));
	}
	g_variant_builder_add (&builder, "{sv}",
	                       "source-host",
	                       g_variant_new_string (nm_team_link_watcher_get_source_host (watcher)));
	flags = nm_team_link_watcher_get_flags (watcher);
	if (flags & NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE) {
		g_variant_builder_add (&builder, "{sv}",
		                       "validate-active",
		                       g_variant_new_boolean (TRUE));
	}
	if (flags & NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE) {
		g_variant_builder_add (&builder, "{sv}",
		                       "validate-inactive",
		                       g_variant_new_boolean (TRUE));
	}
	if (flags & NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS) {
		g_variant_builder_add (&builder, "{sv}",
		                       "send-always",
		                       g_variant_new_boolean (TRUE));
	}
	return g_variant_builder_end (&builder);
}

static NMTeamLinkWatcher *
_link_watcher_from_variant (GVariant *watcher_var)
{
	NMTeamLinkWatcher *watcher;
	const char *name;
	int val1;
	int val2;
	int val3 = 0;
	int val4 = -1;
	const char *target_host = NULL;
	const char *source_host = NULL;
	gboolean bval;
	NMTeamLinkWatcherArpPingFlags flags = NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE;
	gs_free_error GError *error = NULL;

	nm_assert (g_variant_is_of_type (watcher_var, G_VARIANT_TYPE ("a{sv}")));

	if (!g_variant_lookup (watcher_var, "name", "&s", &name))
		return NULL;

	if (!NM_IN_STRSET (name,
	                   NM_TEAM_LINK_WATCHER_ETHTOOL,
	                   NM_TEAM_LINK_WATCHER_ARP_PING,
	                   NM_TEAM_LINK_WATCHER_NSNA_PING)) {
		return NULL;
	}

	if (nm_streq (name, NM_TEAM_LINK_WATCHER_ETHTOOL)) {
		if (!g_variant_lookup (watcher_var, "delay-up", "i", &val1))
			val1 = 0;
		if (!g_variant_lookup (watcher_var, "delay-down", "i", &val2))
			val2 = 0;
		watcher = nm_team_link_watcher_new_ethtool (val1, val2, &error);
	} else {
		if (!g_variant_lookup (watcher_var, "target-host", "&s", &target_host))
			return NULL;
		if (!g_variant_lookup (watcher_var, "init-wait", "i", &val1))
			val1 = 0;
		if (!g_variant_lookup (watcher_var, "interval", "i", &val2))
			val2 = 0;
		if (!g_variant_lookup (watcher_var, "missed-max", "i", &val3))
			val3 = 3;
		if (nm_streq (name, NM_TEAM_LINK_WATCHER_ARP_PING)) {
			if (!g_variant_lookup (watcher_var, "vlanid", "i", &val4))
				val4 = -1;
			if (!g_variant_lookup (watcher_var, "source-host", "&s", &source_host))
				return NULL;
			if (!g_variant_lookup (watcher_var, "validate-active", "b", &bval))
				bval = FALSE;
			if (bval)
				flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE;
			if (!g_variant_lookup (watcher_var, "validate-inactive", "b", &bval))
				bval = FALSE;
			if (bval)
				flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE;
			if (!g_variant_lookup (watcher_var, "send-always", "b", &bval))
				bval = FALSE;
			if (bval)
				flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS;
			watcher = nm_team_link_watcher_new_arp_ping2 (val1, val2, val3, val4,
			                                              target_host, source_host,
			                                              flags, &error);
		} else {
			watcher = nm_team_link_watcher_new_nsna_ping (val1, val2, val3,
			                                              target_host, &error);
		}
	}

	return watcher;
}

/*****************************************************************************/

/**
 * _nm_utils_team_link_watchers_to_variant:
 * @link_watchers: (element-type NMTeamLinkWatcher): array of #NMTeamLinkWatcher
 *
 * Utility function to convert a #GPtrArray of #NMTeamLinkWatcher objects
 * representing link watcher configuration for team devices into a #GVariant
 * of type 'aa{sv}' representing an array of link watchers.
 *
 * Returns: (transfer full): a new floating #GVariant representing link watchers.
 **/
GVariant *
_nm_utils_team_link_watchers_to_variant (GPtrArray *link_watchers)
{
	GVariantBuilder builder;
	guint i;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("aa{sv}"));
	if (link_watchers) {
		for (i = 0; i < link_watchers->len; i++) {
			g_variant_builder_add (&builder,
			                       "@a{sv}",
			                       _link_watcher_to_variant (link_watchers->pdata[i]));
		}
	}
	return g_variant_builder_end (&builder);
}

/**
 * _nm_utils_team_link_watchers_from_variant:
 * @value: a #GVariant of type 'aa{sv}'
 *
 * Utility function to convert a #GVariant representing a list of team link
 * watchers int a #GPtrArray of #NMTeamLinkWatcher objects.
 *
 * Returns: (transfer full) (element-type NMTeamLinkWatcher): a newly allocated
 *   #GPtrArray of #NMTeamLinkWatcher objects.
 **/
GPtrArray *
_nm_utils_team_link_watchers_from_variant (GVariant *value)
{
	GPtrArray *link_watchers;
	GVariantIter iter;
	GVariant *watcher_var;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), NULL);

	link_watchers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);

	g_variant_iter_init (&iter, value);
	while (g_variant_iter_next (&iter, "@a{sv}", &watcher_var)) {
		_nm_unused gs_unref_variant GVariant *watcher_var_free = watcher_var;
		NMTeamLinkWatcher *watcher;

		watcher = _link_watcher_from_variant (watcher_var);
		if (watcher)
			g_ptr_array_add (link_watchers, watcher);
	}

	return link_watchers;
}

/*****************************************************************************/

const char *
nm_team_setting_config_get (const NMTeamSetting *self)
{
	char *js_str;

	nm_assert (self);

	if (G_LIKELY (!self->d._js_str_need_synthetize))
		return self->d._js_str;

	nm_assert (!self->d._js_str);
	nm_assert (self->d.strict_validated);

	if (_team_setting_check_default (self) == 0) {
		/* the default is set. We signal this as a NULL JSON string.
		 * Nothing to do. */
		js_str = NULL;
	} else {
		const TeamAttrData *attr_data;
		GString *gstr;
		bool is_default_lst[_NM_TEAM_ATTRIBUTE_NUM] = { FALSE, };
		gboolean list_is_empty = TRUE;
		const char *v_master_runner;

		gstr = g_string_new (NULL);

		g_string_append (gstr, "{ ");

		v_master_runner =   self->d.is_port
		                  ? NULL
		                  : self->d.master.runner;

		for (attr_data = &team_attr_datas[TEAM_ATTR_IDX_CONFIG + 1]; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {
			if (_team_attr_data_is_relevant (attr_data, self->d.is_port)) {
				is_default_lst[attr_data->team_attr] = _team_attr_data_is_default (attr_data,
				                                                                   self->d.is_port,
				                                                                   v_master_runner,
				                                                                   _team_setting_get_field (self, attr_data));
			}
		}

		if (self->d.is_port) {
			static const NMTeamAttribute attr_lst_port[] = {
				NM_TEAM_ATTRIBUTE_PORT_QUEUE_ID,
				NM_TEAM_ATTRIBUTE_PORT_PRIO,
				NM_TEAM_ATTRIBUTE_PORT_STICKY,
				NM_TEAM_ATTRIBUTE_PORT_LACP_PRIO,
				NM_TEAM_ATTRIBUTE_PORT_LACP_KEY,
			};

			if (_team_setting_fields_to_json_maybe (self, gstr, !list_is_empty, is_default_lst, attr_lst_port, G_N_ELEMENTS (attr_lst_port)))
				list_is_empty = FALSE;
		} else {

			if (   !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER]
			    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_HWADDR_POLICY]
			    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH]
			    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER]
			    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL]
			    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_ACTIVE]
			    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_FAST_RATE]
			    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO]
			    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_MIN_PORTS]
			    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_AGG_SELECT_POLICY]) {
				static const NMTeamAttribute attr_lst_runner_pt1[] = {
					NM_TEAM_ATTRIBUTE_MASTER_RUNNER,
					NM_TEAM_ATTRIBUTE_MASTER_RUNNER_HWADDR_POLICY,
					NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH,
				};
				static const NMTeamAttribute attr_lst_runner_pt2[] = {
					NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER,
					NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL,
				};
				static const NMTeamAttribute attr_lst_runner_pt3[] = {
					NM_TEAM_ATTRIBUTE_MASTER_RUNNER_ACTIVE,
					NM_TEAM_ATTRIBUTE_MASTER_RUNNER_FAST_RATE,
					NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO,
					NM_TEAM_ATTRIBUTE_MASTER_RUNNER_MIN_PORTS,
					NM_TEAM_ATTRIBUTE_MASTER_RUNNER_AGG_SELECT_POLICY,
				};
				gboolean list_is_empty2 = TRUE;

				if (!list_is_empty)
					nm_json_aux_gstr_append_delimiter (gstr);
				nm_json_aux_gstr_append_obj_name (gstr, "runner", '{');

				if (_team_setting_fields_to_json_maybe (self, gstr, !list_is_empty2, is_default_lst, attr_lst_runner_pt1, G_N_ELEMENTS (attr_lst_runner_pt1)))
					list_is_empty2 = FALSE;

				if (   !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER]
				    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL]) {
					if (!list_is_empty2)
						nm_json_aux_gstr_append_delimiter (gstr);
					nm_json_aux_gstr_append_obj_name (gstr, "tx_balancer", '{');
					if (!_team_setting_fields_to_json_maybe (self, gstr, FALSE, is_default_lst, attr_lst_runner_pt2, G_N_ELEMENTS (attr_lst_runner_pt2)))
						nm_assert_not_reached ();
					g_string_append (gstr, " }");
					list_is_empty2 = FALSE;
				}

				if (_team_setting_fields_to_json_maybe (self, gstr, !list_is_empty2, is_default_lst, attr_lst_runner_pt3, G_N_ELEMENTS (attr_lst_runner_pt3)))
					list_is_empty2 = FALSE;

				nm_assert (!list_is_empty2);
				g_string_append (gstr, " }");
				list_is_empty = FALSE;
			}

			if (   !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_COUNT]
			    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_INTERVAL]) {
				static const NMTeamAttribute attr_lst_notify_peers[] = {
					NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_COUNT,
					NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_INTERVAL,
				};

				if (!list_is_empty)
					nm_json_aux_gstr_append_delimiter (gstr);
				nm_json_aux_gstr_append_obj_name (gstr, "notify_peers", '{');
				if (!_team_setting_fields_to_json_maybe (self, gstr, FALSE, is_default_lst, attr_lst_notify_peers, G_N_ELEMENTS (attr_lst_notify_peers)))
					nm_assert_not_reached ();
				g_string_append (gstr, " }");
				list_is_empty = FALSE;
			}

			if (   !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_COUNT]
			    || !is_default_lst[NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_INTERVAL]) {
				static const NMTeamAttribute attr_lst_notify_peers[] = {
					NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_COUNT,
					NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_INTERVAL,
				};

				if (!list_is_empty)
					nm_json_aux_gstr_append_delimiter (gstr);
				nm_json_aux_gstr_append_obj_name (gstr, "mcast_rejoin", '{');
				if (!_team_setting_fields_to_json_maybe (self, gstr, FALSE, is_default_lst, attr_lst_notify_peers, G_N_ELEMENTS (attr_lst_notify_peers)))
					nm_assert_not_reached ();
				g_string_append (gstr, " }");
				list_is_empty = FALSE;
			}
		}

		if (!is_default_lst[NM_TEAM_ATTRIBUTE_LINK_WATCHERS]) {
			_team_setting_field_to_json (self, gstr, !list_is_empty, NM_TEAM_ATTRIBUTE_LINK_WATCHERS);
			list_is_empty = FALSE;
		}
		if (!list_is_empty)
			g_string_append (gstr, " }");

		js_str = g_string_free (gstr, list_is_empty);;
	}

	/* mutate the constant object. In C++ speak, these fields are "mutable".
	 * That is because we construct the JSON string lazily/on-demand. */
	*((char **) &self->_data_priv._js_str) = js_str;
	*((bool *) &self->_data_priv._js_str_need_synthetize) = FALSE;

	return self->d._js_str;
}

/*****************************************************************************/

#if WITH_JSON_VALIDATION
static gboolean
_attr_data_match_keys (const TeamAttrData *attr_data,
                       const char *const*keys,
                       guint8 n_keys)
{
	guint8 i;

	_team_attr_data_ASSERT (attr_data);
	nm_assert (keys);
	nm_assert (n_keys > 0);
	nm_assert (({
		gboolean all_non_null = TRUE;

		for (i = 0; i < n_keys; i++)
			all_non_null = all_non_null && keys[i] && keys[i][0] != '\0';
		all_non_null;
	}));

	if (attr_data->js_keys_len < n_keys)
		return FALSE;
	for (i = 0; i < n_keys; i++) {
		if (!nm_streq (keys[i], attr_data->js_keys[i]))
			return FALSE;
	}
	return TRUE;
}

static const TeamAttrData *
_attr_data_find_by_json_key (gboolean is_port,
                             const char *const*keys,
                             guint8 n_keys)
{
	const TeamAttrData *attr_data;

	for (attr_data = &team_attr_datas[TEAM_ATTR_IDX_CONFIG + 1]; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {
		if (    _team_attr_data_is_relevant (attr_data, is_port)
		    && _attr_data_match_keys (attr_data, keys, n_keys))
			return attr_data;
	}

	return NULL;
}

static void
_js_parse_locate_keys (NMTeamSetting *self,
                       json_t *root_js_obj,
                       json_t *found_keys[static _NM_TEAM_ATTRIBUTE_NUM],
                       gboolean *out_unrecognized_content)
{
	const char *keys[3];
	const char *cur_key1;
	const char *cur_key2;
	const char *cur_key3;
	json_t *cur_val1;
	json_t *cur_val2;
	json_t *cur_val3;

#define _handle(_self, _cur_key, _cur_val, _keys, _level, _found_keys, _out_unrecognized_content) \
	({ \
		const TeamAttrData *_attr_data; \
		gboolean _handled = FALSE; \
		\
		(_keys)[(_level) - 1] = (_cur_key); \
		_attr_data = _attr_data_find_by_json_key ((_self)->d.is_port, (_keys), (_level)); \
		if (   _attr_data \
			&& _attr_data->js_keys_len == (_level)) { \
			if ((_found_keys)[_attr_data->team_attr]) \
				*(_out_unrecognized_content) = TRUE; \
			(_found_keys)[_attr_data->team_attr] = (_cur_val); \
			_handled = TRUE; \
		} else if (   !_attr_data \
		           || !json_is_object ((_cur_val))) { \
			*(_out_unrecognized_content) = TRUE; \
			_handled = TRUE; \
		} \
		_handled; \
	})

	json_object_foreach (root_js_obj, cur_key1, cur_val1) {
		if (!_handle (self, cur_key1, cur_val1, keys, 1, found_keys, out_unrecognized_content)) {
			json_object_foreach (cur_val1, cur_key2, cur_val2) {
				if (!_handle (self, cur_key2, cur_val2, keys, 2, found_keys, out_unrecognized_content)) {
					json_object_foreach (cur_val2, cur_key3, cur_val3) {
						if (!_handle (self, cur_key3, cur_val3, keys, 3, found_keys, out_unrecognized_content))
							*out_unrecognized_content = TRUE;
					}
				}
			}
		}
	}

#undef _handle
}

static void
_js_parse_unpack (gboolean is_port,
                  json_t *found_keys[static _NM_TEAM_ATTRIBUTE_NUM],
                  bool out_has_lst[static _NM_TEAM_ATTRIBUTE_NUM],
                  NMValueTypUnion out_val_lst[static _NM_TEAM_ATTRIBUTE_NUM],
                  gboolean *out_unrecognized_content,
                  GPtrArray **out_ptr_array_link_watchers_free,
                  GPtrArray **out_ptr_array_master_runner_tx_hash_free)
{
	const TeamAttrData *attr_data;

	for (attr_data = &team_attr_datas[TEAM_ATTR_IDX_CONFIG + 1]; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {
		NMValueTypUnion *p_out_val;
		gboolean valid = FALSE;
		json_t *arg_js_obj;

		if (!_team_attr_data_is_relevant (attr_data, is_port))
			continue;

		nm_assert (!out_has_lst[attr_data->team_attr]);

		arg_js_obj = found_keys[attr_data->team_attr];
		if (!arg_js_obj)
			continue;

		p_out_val = &out_val_lst[attr_data->team_attr];

		if (attr_data->value_type != NM_VALUE_TYPE_UNSPEC)
			valid = nm_value_type_from_json (attr_data->value_type, arg_js_obj, p_out_val);
		else if (attr_data->team_attr == NM_TEAM_ATTRIBUTE_LINK_WATCHERS) {
			GPtrArray *link_watchers = NULL;
			NMTeamLinkWatcher *link_watcher;

			nm_assert (out_ptr_array_link_watchers_free && !*out_ptr_array_link_watchers_free);
			if (json_is_array (arg_js_obj)) {
				gsize i, len;

				len = json_array_size (arg_js_obj);
				link_watchers = g_ptr_array_new_full (len, (GDestroyNotify) nm_team_link_watcher_unref);
				for (i = 0; i < len; i++) {
					link_watcher = _link_watcher_from_json (json_array_get (arg_js_obj, i),
					                                        out_unrecognized_content);
					if (link_watcher)
						g_ptr_array_add (link_watchers, link_watcher);
				}
			} else {
				link_watcher = _link_watcher_from_json (arg_js_obj,
				                                        out_unrecognized_content);
				if (link_watcher) {
					link_watchers = g_ptr_array_new_full (1, (GDestroyNotify) nm_team_link_watcher_unref);
					g_ptr_array_add (link_watchers, link_watcher);
				}
			}
			if (link_watchers) {
				valid = TRUE;
				p_out_val->v_ptrarray = link_watchers;
				*out_ptr_array_link_watchers_free = link_watchers;
			}
		} else if (   !is_port
		           && attr_data->team_attr == NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH) {
			GPtrArray *strv = NULL;

			nm_assert (out_ptr_array_master_runner_tx_hash_free && !*out_ptr_array_master_runner_tx_hash_free);
			if (json_is_array (arg_js_obj)) {
				gsize i, len;

				len = json_array_size (arg_js_obj);
				if (len > 0) {
					strv = g_ptr_array_sized_new (len);
					for (i = 0; i < len; i++) {
						const char *v_string;

						if (   nm_jansson_json_as_string (json_array_get (arg_js_obj, i),
						                                  &v_string) <= 0
						    || !v_string
						    || v_string[0] == '\0') {
							/* we remember that there was some invalid content, but parts of the
							 * list could still be parsed. */
							*out_unrecognized_content = TRUE;
							continue;
						}
						g_ptr_array_add (strv, (char *) v_string);
					}
				}
				valid = TRUE;
				*out_ptr_array_master_runner_tx_hash_free = strv;
			}
			p_out_val->v_ptrarray = strv;
		} else
			nm_assert_not_reached ();

		out_has_lst[attr_data->team_attr] = valid;
		if (!valid)
			*out_unrecognized_content = TRUE;
	}
}
#endif

guint32
nm_team_setting_config_set (NMTeamSetting *self, const char *js_str)
{
	guint32 changed_flags = 0;
	gboolean do_set_default = TRUE;
	gboolean new_strict_validated = FALSE;
	gboolean new_js_str_invalid = FALSE;

	_team_setting_ASSERT (self);

	if (   !js_str
	    || js_str[0] == '\0') {
		changed_flags = _team_setting_set_default (self);
		if (   changed_flags != 0
		    || !nm_streq0 (js_str, self->d._js_str))
			changed_flags |= nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_CONFIG);
		nm_clear_g_free ((char **) &self->_data_priv._js_str);
		self->_data_priv._js_str = g_strdup (js_str);
		self->_data_priv._js_str_need_synthetize = FALSE;
		self->_data_priv.strict_validated = TRUE;
		self->_data_priv.js_str_invalid = FALSE;
		return changed_flags;
	}

	if (   self->d._js_str
	    && nm_streq (js_str, self->d._js_str))
		return 0;

	changed_flags |= nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_CONFIG);

#if WITH_JSON_VALIDATION
	if (js_str[0] != '\0') {
		nm_auto_decref_json json_t *root_js_obj = NULL;

		if (nm_jansson_load ())
			root_js_obj = json_loads (js_str, 0, NULL);

		if (   !root_js_obj
		    || !json_is_object (root_js_obj))
			new_js_str_invalid = TRUE;
		else {
			gboolean unrecognized_content = FALSE;
			bool has_lst[_NM_TEAM_ATTRIBUTE_NUM] = { FALSE, };
			NMValueTypUnion val_lst[_NM_TEAM_ATTRIBUTE_NUM];
			json_t *found_keys[_NM_TEAM_ATTRIBUTE_NUM] = { NULL, };
			gs_unref_ptrarray GPtrArray *ptr_array_master_runner_tx_hash_free = NULL;
			gs_unref_ptrarray GPtrArray *ptr_array_link_watchers_free = NULL;

			_js_parse_locate_keys (self,
			                       root_js_obj,
			                       found_keys,
			                       &unrecognized_content);

			_js_parse_unpack (self->d.is_port,
			                  found_keys,
			                  has_lst,
			                  val_lst,
			                  &unrecognized_content,
			                  &ptr_array_link_watchers_free,
			                  &ptr_array_master_runner_tx_hash_free);

			do_set_default = FALSE;

			changed_flags |= _team_setting_set (self,
			                                    TRUE,
			                                    has_lst,
			                                    val_lst);

			if (   !unrecognized_content
			    && _team_setting_verify (self, NULL)) {
				/* if we could parse everything without unexpected/unknown data,
				 * we switch into strictly validating mode. */
				new_strict_validated = TRUE;
			}
		}
	}

#endif

	if (do_set_default)
		changed_flags |= _team_setting_set_default (self);

	self->_data_priv.strict_validated = new_strict_validated;
	self->_data_priv._js_str_need_synthetize = FALSE;
	self->_data_priv.js_str_invalid = new_js_str_invalid;
	g_free ((char *) self->_data_priv._js_str);
	self->_data_priv._js_str = g_strdup (js_str);

	return changed_flags;
}

/*****************************************************************************/

static void
_team_setting_prefix_error (const NMTeamSetting *self,
                            GError **error,
                            const char *prop_name_master,
                            const char *prop_name_port)
{
	_team_setting_ASSERT (self);
	nm_assert (  self->d.is_port
	           ? (!!prop_name_port)
	           : (!!prop_name_master));
	g_prefix_error (error,
	                "%s.%s: ",
	                  self->d.is_port
	                ? NM_SETTING_TEAM_PORT_SETTING_NAME
	                : NM_SETTING_TEAM_SETTING_NAME,
	                  self->d.is_port
	                ? prop_name_master
	                : prop_name_port);
}

static gboolean
_team_setting_verify (const NMTeamSetting *self,
                      GError **error)
{
	guint i;
	const char *js_str;

	if (!self->d.is_port) {
		if (!self->d.master.runner) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
			             _("missing runner"));
			_team_setting_prefix_error (self, error, NM_SETTING_TEAM_RUNNER, NULL);
			return FALSE;
		}
		if (   self->d.master.runner
		    && g_ascii_strcasecmp (self->d.master.runner, NM_SETTING_TEAM_RUNNER_BROADCAST) != 0
		    && g_ascii_strcasecmp (self->d.master.runner, NM_SETTING_TEAM_RUNNER_ROUNDROBIN) != 0
		    && g_ascii_strcasecmp (self->d.master.runner, NM_SETTING_TEAM_RUNNER_RANDOM) != 0
		    && g_ascii_strcasecmp (self->d.master.runner, NM_SETTING_TEAM_RUNNER_ACTIVEBACKUP) != 0
		    && g_ascii_strcasecmp (self->d.master.runner, NM_SETTING_TEAM_RUNNER_LOADBALANCE) != 0
		    && g_ascii_strcasecmp (self->d.master.runner, NM_SETTING_TEAM_RUNNER_LACP) != 0) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
			             _("invalid runner \"%s\""), self->d.master.runner);
			_team_setting_prefix_error (self, error, NM_SETTING_TEAM_RUNNER, NULL);
			return FALSE;
		}

		if (self->d.master.runner_tx_hash) {
			for (i = 0; i < self->d.master.runner_tx_hash->len; i++) {
				const char *val = self->d.master.runner_tx_hash->pdata[i];

				if (!val[0]) {
					g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
					             _("invalid runner.tx-hash"));
					_team_setting_prefix_error (self, error, NM_SETTING_TEAM_RUNNER_TX_HASH, NULL);
					return FALSE;
				}
			}
		}
	}

	for (i = 0; i < self->d.link_watchers->len; i++) {
		NMTeamLinkWatcher *link_watcher = self->d.link_watchers->pdata[i];
		const char *name = nm_team_link_watcher_get_name (link_watcher);

		if (!NM_IN_STRSET (name,
		                   NM_TEAM_LINK_WATCHER_ETHTOOL,
		                   NM_TEAM_LINK_WATCHER_ARP_PING,
		                   NM_TEAM_LINK_WATCHER_NSNA_PING)) {
			if (!name) {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_SETTING,
				             _("missing link watcher name"));
			} else {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
				             _("unknown link watcher \"%s\""), name);
			}
			_team_setting_prefix_error (self, error, NM_SETTING_TEAM_LINK_WATCHERS, NM_SETTING_TEAM_PORT_LINK_WATCHERS);
			return FALSE;
		}

		if (   NM_IN_STRSET (name,
		                     NM_TEAM_LINK_WATCHER_ARP_PING,
		                     NM_TEAM_LINK_WATCHER_NSNA_PING)
		    && !nm_team_link_watcher_get_target_host (link_watcher)) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_SETTING,
			             _("missing target host"));
			_team_setting_prefix_error (self, error, NM_SETTING_TEAM_LINK_WATCHERS, NM_SETTING_TEAM_PORT_LINK_WATCHERS);
			return FALSE;
		}
		if (   nm_streq (name, NM_TEAM_LINK_WATCHER_ARP_PING)
		    && !nm_team_link_watcher_get_source_host (link_watcher)) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_MISSING_SETTING,
			             _("missing source address"));
			_team_setting_prefix_error (self, error, NM_SETTING_TEAM_LINK_WATCHERS, NM_SETTING_TEAM_PORT_LINK_WATCHERS);
			return FALSE;
		}
	}

	/* we always materialize the JSON string. That is because we want to validate the
	 * string length of the resulting JSON. */
	js_str = nm_team_setting_config_get (self);

	if (js_str) {
		if (strlen (js_str) > 1*1024*1024) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("team config exceeds size limit"));
			_team_setting_prefix_error (self, error, NM_SETTING_TEAM_CONFIG, NM_SETTING_TEAM_PORT_CONFIG);
			return FALSE;
		}
		if (!g_utf8_validate (js_str, -1, NULL)) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("team config is not valid UTF-8"));
			_team_setting_prefix_error (self, error, NM_SETTING_TEAM_CONFIG, NM_SETTING_TEAM_PORT_CONFIG);
			return FALSE;
		}
		if (self->d.js_str_invalid) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("invalid json"));
			_team_setting_prefix_error (self, error, NM_SETTING_TEAM_CONFIG, NM_SETTING_TEAM_PORT_CONFIG);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
nm_team_setting_verify (const NMTeamSetting *self,
                        GError **error)
{
	return _team_setting_verify (self, error);
}

/*****************************************************************************/

int
nm_team_setting_cmp (const NMTeamSetting *self_a,
                     const NMTeamSetting *self_b,
                     gboolean ignore_js_str)
{
	const TeamAttrData *attr_data;

	NM_CMP_SELF (self_a, self_b);

	NM_CMP_FIELD_UNSAFE (self_a, self_b, d.is_port);

	for (attr_data = &team_attr_datas[TEAM_ATTR_IDX_CONFIG + 1]; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {
		if (_team_attr_data_is_relevant (attr_data, self_a->d.is_port)) {
			NM_CMP_RETURN (_team_attr_data_cmp (attr_data,
			                                    self_a->d.is_port,
			                                    _team_setting_get_field (self_a, attr_data),
			                                    _team_setting_get_field (self_b, attr_data)));
		}
	}

	if (!ignore_js_str) {
		NM_CMP_DIRECT_STRCMP0 (nm_team_setting_config_get (self_a),
		                       nm_team_setting_config_get (self_b));
	}

	return 0;
}

guint32
nm_team_setting_reset (NMTeamSetting *self,
                       const NMTeamSetting *src)
{
	const TeamAttrData *attr_data;
	guint32 changed;

	_team_setting_ASSERT (self);
	_team_setting_ASSERT (src);
	nm_assert (self->d.is_port == src->d.is_port);

	if (self == src)
		return 0;

	changed = 0;

	for (attr_data = &team_attr_datas[TEAM_ATTR_IDX_CONFIG + 1]; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {
		if (!_team_attr_data_is_relevant (attr_data, self->d.is_port))
			continue;
		if (_team_attr_data_equal (attr_data,
		                           self->d.is_port,
		                           _team_setting_get_field (self, attr_data),
		                           _team_setting_get_field (src, attr_data)))
			continue;
		_team_attr_data_copy (attr_data,
		                      self->d.is_port,
		                      _team_setting_get_field (self, attr_data),
		                      _team_setting_get_field (src, attr_data));
		changed |= nm_team_attribute_to_flags (attr_data->team_attr);
	}

	if (!nm_streq0 (self->d._js_str, src->d._js_str)) {
		g_free ((char *) self->_data_priv._js_str);
		self->_data_priv._js_str = g_strdup (src->d._js_str);
		changed |= nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_CONFIG);
	} else if (changed != 0)
		changed |= nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_CONFIG);

	self->_data_priv._js_str_need_synthetize = src->d._js_str_need_synthetize;
	self->_data_priv.strict_validated = src->d.strict_validated;
	self->_data_priv.js_str_invalid = src->d.js_str_invalid;

	return changed;
}

static void
_variants_list_unref_auto (GVariant *(*p_variants)[])
{
	int i;

	for (i = 0; i < _NM_TEAM_ATTRIBUTE_NUM; i++)
		nm_g_variant_unref ((*p_variants)[i]);
}

gboolean
nm_team_setting_reset_from_dbus (NMTeamSetting *self,
                                 GVariant *setting_dict,
                                 GHashTable *keys,
                                 guint32 *out_changed,
                                 guint /* NMSettingParseFlags */ parse_flags,
                                 GError **error)
{
	nm_auto (_variants_list_unref_auto) GVariant *variants[_NM_TEAM_ATTRIBUTE_NUM] = { NULL, };
	gs_unref_ptrarray GPtrArray *v_link_watchers = NULL;
	const TeamAttrData *attr_data;
	GVariantIter iter;
	const char *v_key;
	GVariant *v_val;

	*out_changed = 0;

	g_variant_iter_init (&iter, setting_dict);
	while (g_variant_iter_next (&iter, "{&sv}", &v_key, &v_val)) {
		_nm_unused gs_unref_variant GVariant *v_val_free = v_val;
		const GVariantType *variant_type = NULL;

		attr_data = _team_attr_data_find_for_dbus_name (self->d.is_port, v_key);
		if (!attr_data) {
			/* _nm_setting_new_from_dbus() already checks for unknown keys. Don't
			 * do that here. */
			continue;
		}

		if (keys)
			g_hash_table_remove (keys, v_key);

		if (attr_data->value_type != NM_VALUE_TYPE_UNSPEC)
			variant_type = nm_value_type_get_variant_type (attr_data->value_type);
		else if (attr_data->team_attr == NM_TEAM_ATTRIBUTE_CONFIG)
			variant_type = G_VARIANT_TYPE_STRING;
		else if (attr_data->team_attr == NM_TEAM_ATTRIBUTE_LINK_WATCHERS)
			variant_type = G_VARIANT_TYPE ("aa{sv}");
		else if (   !self->d.is_port
		         && attr_data->team_attr == NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH)
			variant_type = G_VARIANT_TYPE_STRING_ARRAY;
		else
			nm_assert_not_reached ();

		if (!g_variant_is_of_type (v_val, variant_type)) {
			if (NM_FLAGS_HAS (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT)) {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("invalid D-Bus type \"%s\""),
				             g_variant_get_type_string (v_val));
				_team_setting_prefix_error (self,
				                            error,
				                            attr_data->dbus_name,
				                            attr_data->dbus_name);
				return FALSE;
			}
			continue;
		}

		/* _nm_setting_new_from_dbus() already checks for duplicate keys. Don't
		 * do that here. */
		nm_g_variant_unref (variants[attr_data->team_attr]);
		variants[attr_data->team_attr] = g_steal_pointer (&v_val_free);
	}

	*out_changed |= nm_team_setting_config_set (self,
	                                              variants[NM_TEAM_ATTRIBUTE_CONFIG]
	                                            ? g_variant_get_string (variants[NM_TEAM_ATTRIBUTE_CONFIG], NULL)
	                                            : NULL);

	if (   variants[NM_TEAM_ATTRIBUTE_CONFIG]
	    && WITH_JSON_VALIDATION) {
		/* for team settings, the JSON must be able to express all possible options. That means,
		 * if the GVariant contains both the JSON "config" and other options, then the other options
		 * are silently ignored. */
	} else {
		guint32 extra_changed = 0u;

		if (variants[NM_TEAM_ATTRIBUTE_LINK_WATCHERS]) {
			/* FIXME: handle errors for NM_SETTING_PARSE_FLAGS_STRICT.
			 *
			 * But then also move the check before starting to modify the setting so we fail
			 * early.  */
			v_link_watchers = _nm_utils_team_link_watchers_from_variant (variants[NM_TEAM_ATTRIBUTE_LINK_WATCHERS]);
		}

		for (attr_data = &team_attr_datas[TEAM_ATTR_IDX_CONFIG + 1]; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {
			NMValueTypUnion val;
			guint32 changed = 0u;

			if (!_team_attr_data_is_relevant (attr_data, self->d.is_port))
				continue;
			if (!variants[attr_data->team_attr])
				continue;

			if (attr_data->value_type != NM_VALUE_TYPE_UNSPEC) {
				nm_value_type_get_from_variant (attr_data->value_type, &val, variants[attr_data->team_attr], FALSE);
				changed = _team_setting_value_set (self,
				                                   attr_data->team_attr,
				                                   attr_data->value_type,
				                                   &val);
			} else if (attr_data->team_attr == NM_TEAM_ATTRIBUTE_LINK_WATCHERS) {
				changed = _team_setting_value_link_watchers_set_list (self,
				                                                      v_link_watchers ? (const NMTeamLinkWatcher *const *) v_link_watchers->pdata : NULL,
				                                                      v_link_watchers ? v_link_watchers->len : 0u);
			} else if (   !self->d.is_port
			           && attr_data->team_attr == NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH) {
				gs_free const char **strv = NULL;
				gsize len;

				strv = g_variant_get_strv (variants[attr_data->team_attr], &len);
				changed = _team_setting_value_master_runner_tx_hash_set_list (self,
				                                                              strv,
				                                                              NM_MIN (len, (gsize) G_MAXUINT));
			} else
				nm_assert_not_reached ();

			extra_changed |= changed;
		}

		if (   !variants[NM_TEAM_ATTRIBUTE_CONFIG]
		    && extra_changed) {
			/* clear the JSON string so it can be regenerated. But only if we didn't set
			 * it above. */
			self->_data_priv.strict_validated = TRUE;
			self->_data_priv._js_str_need_synthetize = TRUE;
		}

		*out_changed |= extra_changed;
	}

	return TRUE;
}

/*****************************************************************************/

gboolean
nm_team_setting_maybe_changed (NMSetting *source,
                               const GParamSpec *const*obj_properties,
                               guint32 changed_flags)
{
	NMTeamAttribute team_attr;
	int count_flags;
	guint32 ch;

	if (changed_flags == 0u)
		return FALSE;

	count_flags = 0;
	for (ch = changed_flags; ch != 0u; ch >>= 1) {
		if (NM_FLAGS_HAS (ch, 0x1u))
			count_flags++;
	}

	if (count_flags > 1)
		g_object_freeze_notify (G_OBJECT (source));

	ch = changed_flags;
	for (team_attr = 0; team_attr < _NM_TEAM_ATTRIBUTE_NUM; team_attr++) {
		if (!NM_FLAGS_ANY (ch, nm_team_attribute_to_flags (team_attr)))
			continue;
		g_object_notify_by_pspec (G_OBJECT (source),
		                          (GParamSpec *) obj_properties[team_attr]);
		ch &= ~nm_team_attribute_to_flags (team_attr);
		if (ch == 0)
			break;
	}

	if (count_flags > 1)
		g_object_thaw_notify (G_OBJECT (source));

	return TRUE;
}

/*****************************************************************************/

NMTeamSetting *
nm_team_setting_new (gboolean is_port,
                     const char *js_str)
{
	NMTeamSetting *self;
	gsize l;

	G_STATIC_ASSERT_EXPR (sizeof (*self) == sizeof (self->_data_priv));
	G_STATIC_ASSERT_EXPR (sizeof (*self) == NM_CONST_MAX (nm_offsetofend (NMTeamSetting, d.master), nm_offsetofend (NMTeamSetting, d.port)));

	l =   is_port
	    ? nm_offsetofend (NMTeamSetting, d.port)
	    : nm_offsetofend (NMTeamSetting, d.master);

	self = g_malloc0 (l);

	self->_data_priv.is_port                 = is_port;
	self->_data_priv.strict_validated        = TRUE;
	self->_data_priv._js_str_need_synthetize = FALSE;
	self->_data_priv.link_watchers           = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);

	_team_setting_ASSERT (self);

	nm_team_setting_config_set (self, js_str);

	_team_setting_ASSERT (self);

	return self;
}

void
nm_team_setting_free (NMTeamSetting *self)
{
	if (!self)
		return;

	_team_setting_ASSERT (self);

	if (!self->d.is_port) {
		nm_clear_pointer (((GPtrArray **) &self->_data_priv.master.runner_tx_hash), g_ptr_array_unref);
		g_free ((char *) self->_data_priv.master.runner);
		g_free ((char *) self->_data_priv.master.runner_hwaddr_policy);
		g_free ((char *) self->_data_priv.master.runner_tx_balancer);
		g_free ((char *) self->_data_priv.master.runner_agg_select_policy);
	}
	g_ptr_array_unref ((GPtrArray *) self->_data_priv.link_watchers);
	g_free ((char *) self->_data_priv._js_str);
	g_free (self);
}
