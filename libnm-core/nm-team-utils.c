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

typedef enum {
	SET_FIELD_MODE_UNSET              = 0,
	SET_FIELD_MODE_SET                = 1,

	/* Sets the field as set, unless the field is at the default.
	 * This is the case for API that is called from NMSettingTeam/NMSettingTeamPort.
	 * This means, using libnm API to reset the value of a NMSetting to the default,
	 * will mark the field as unset.
	 * This is different from initializing the field when parsing JSON/GVariant. In
	 * that case an explicitly set field (even set to the default value) will be remembered
	 * to be set. */
	SET_FIELD_MODE_SET_UNLESS_DEFAULT = 2,
} SetFieldModeEnum;

typedef enum {
	RESET_JSON_NO  = FALSE,
	RESET_JSON_YES = TRUE,
} ResetJsonEnum;

/* we rely on "config" being the first. At various places we iterate over attribute types,
 * starting after "config".*/
G_STATIC_ASSERT (_NM_TEAM_ATTRIBUTE_0     == 0);
G_STATIC_ASSERT (NM_TEAM_ATTRIBUTE_CONFIG == 1);

static const char *const _valid_names_runner[] = {
	NM_SETTING_TEAM_RUNNER_BROADCAST,
	NM_SETTING_TEAM_RUNNER_ROUNDROBIN,
	NM_SETTING_TEAM_RUNNER_RANDOM,
	NM_SETTING_TEAM_RUNNER_ACTIVEBACKUP,
	NM_SETTING_TEAM_RUNNER_LOADBALANCE,
	NM_SETTING_TEAM_RUNNER_LACP,
	NULL,
};

static const char *const _valid_names_runner_hwaddr_policy[] = {
	NM_SETTING_TEAM_RUNNER_HWADDR_POLICY_SAME_ALL,
	NM_SETTING_TEAM_RUNNER_HWADDR_POLICY_BY_ACTIVE,
	NM_SETTING_TEAM_RUNNER_HWADDR_POLICY_ONLY_ACTIVE,
	NULL,
};

static const char *const _valid_names_runner_tx_balancer[] = {
	"basic",
	NULL,
};

static const char *const _valid_names_runner_tx_hash[] = {
	"eth",
	"vlan",
	"ipv4",
	"ipv6",
	"ip",
	"l3",
	"l4",
	"tcp",
	"udp",
	"sctp",
	NULL,
};

static const char *const _valid_names_runner_agg_select_policy[] = {
	"lacp_prio",
	"lacp_prio_stable",
	"bandwidth",
	"count",
	"port_config",
	NULL,
};

typedef struct {
	NMTeamAttribute team_attr;
	const char *const*valid_runners;
} RunnerCompatElem;

static const RunnerCompatElem _runner_compat_lst[] = {
	{ NM_TEAM_ATTRIBUTE_MASTER_RUNNER_HWADDR_POLICY,        NM_MAKE_STRV (NM_SETTING_TEAM_RUNNER_ACTIVEBACKUP), },
	{ NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH,              NM_MAKE_STRV (NM_SETTING_TEAM_RUNNER_LOADBALANCE,
	                                                                      NM_SETTING_TEAM_RUNNER_LACP), },
	{ NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER,          NM_MAKE_STRV (NM_SETTING_TEAM_RUNNER_LOADBALANCE,
	                                                                      NM_SETTING_TEAM_RUNNER_LACP), },
	{ NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL, NM_MAKE_STRV (NM_SETTING_TEAM_RUNNER_LOADBALANCE,
	                                                                      NM_SETTING_TEAM_RUNNER_LACP), },
	{ NM_TEAM_ATTRIBUTE_MASTER_RUNNER_ACTIVE,               NM_MAKE_STRV (NM_SETTING_TEAM_RUNNER_LACP), },
	{ NM_TEAM_ATTRIBUTE_MASTER_RUNNER_FAST_RATE,            NM_MAKE_STRV (NM_SETTING_TEAM_RUNNER_LACP), },
	{ NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO,             NM_MAKE_STRV (NM_SETTING_TEAM_RUNNER_LACP), },
	{ NM_TEAM_ATTRIBUTE_MASTER_RUNNER_MIN_PORTS,            NM_MAKE_STRV (NM_SETTING_TEAM_RUNNER_LACP), },
	{ NM_TEAM_ATTRIBUTE_MASTER_RUNNER_AGG_SELECT_POLICY,    NM_MAKE_STRV (NM_SETTING_TEAM_RUNNER_LACP), },
};

typedef struct {
	const char *const*js_keys;
	const char *property_name;
	NMValueTypUnion default_val;
	union {
		struct {
			gint32 min;
			gint32 max;
		} r_int32;
		struct {
			const char *const*valid_names;
		} r_string;
	} range;
	NMTeamAttribute team_attr;
	NMValueType value_type;
	guint8 field_offset;
	guint8 js_keys_len;
	bool for_master:1;
	bool for_port:1;
	bool has_range:1;
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

#define _VAL_BOOL(_default) \
		.default_val.v_bool = (_default)

#define _VAL_INT32(_default) \
		.default_val.v_int32 = (_default)

#define _VAL_INT32_RANGE(_default, _min,_max) \
		_VAL_INT32 (_default), \
		.has_range = TRUE, \
		.range.r_int32 = { .min = _min, .max = _max, }

#define _VAL_STRING() \
		.default_val.v_string = NULL

#define _VAL_STRING_RANGE(_valid_names) \
		_VAL_STRING (), \
		.has_range = TRUE, \
		.range.r_string = { .valid_names = (_valid_names), }

#define _VAL_UNSPEC() \
		.default_val.v_string = (NULL)

#define _INIT(_is_port, _team_attr, field, _value_type, _property_name, ...) \
	[TEAM_ATTR_IDX (_is_port, _team_attr)] = { \
		.for_master    = (_team_attr) < _NM_TEAM_ATTRIBUTE_START || !(_is_port), \
		.for_port      = (_team_attr) < _NM_TEAM_ATTRIBUTE_START ||  (_is_port), \
		.team_attr     = (_team_attr), \
		.field_offset  = G_STRUCT_OFFSET (NMTeamSetting, _data_priv.field), \
		.value_type    = (_value_type), \
		.property_name = ""_property_name"", \
		__VA_ARGS__ \
	}

	_INIT (0, NM_TEAM_ATTRIBUTE_CONFIG,                             _js_str,                            NM_VALUE_TYPE_UNSPEC, NM_SETTING_TEAM_CONFIG,                                                                                                                                           ),

	_INIT (0, NM_TEAM_ATTRIBUTE_LINK_WATCHERS,                      link_watchers,                      NM_VALUE_TYPE_UNSPEC, NM_SETTING_TEAM_LINK_WATCHERS,               _JS_KEYS ("link_watch"),                                  _VAL_UNSPEC (),                                            ),

	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_COUNT,          master.notify_peers_count,          NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_NOTIFY_PEERS_COUNT,          _JS_KEYS ("notify_peers", "count"),                       _VAL_INT32_RANGE (-1, 0, G_MAXINT32),                      ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_INTERVAL,       master.notify_peers_interval,       NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_NOTIFY_PEERS_INTERVAL,       _JS_KEYS ("notify_peers", "interval"),                    _VAL_INT32_RANGE (-1, 0, G_MAXINT32),                      ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_COUNT,          master.mcast_rejoin_count,          NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_MCAST_REJOIN_COUNT,          _JS_KEYS ("mcast_rejoin", "count"),                       _VAL_INT32_RANGE (-1, 0, G_MAXINT32),                      ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_INTERVAL,       master.mcast_rejoin_interval,       NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_MCAST_REJOIN_INTERVAL,       _JS_KEYS ("mcast_rejoin", "interval"),                    _VAL_INT32_RANGE (-1, 0, G_MAXINT32),                      ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER,                      master.runner,                      NM_VALUE_TYPE_STRING, NM_SETTING_TEAM_RUNNER,                      _JS_KEYS ("runner", "name"),                              _VAL_STRING_RANGE (_valid_names_runner),                   ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_HWADDR_POLICY,        master.runner_hwaddr_policy,        NM_VALUE_TYPE_STRING, NM_SETTING_TEAM_RUNNER_HWADDR_POLICY,        _JS_KEYS ("runner", "hwaddr_policy"),                     _VAL_STRING_RANGE (_valid_names_runner_hwaddr_policy),     ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH,              master.runner_tx_hash,              NM_VALUE_TYPE_UNSPEC, NM_SETTING_TEAM_RUNNER_TX_HASH,              _JS_KEYS ("runner", "tx_hash"),                           _VAL_UNSPEC (),                                            ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER,          master.runner_tx_balancer,          NM_VALUE_TYPE_STRING, NM_SETTING_TEAM_RUNNER_TX_BALANCER,          _JS_KEYS ("runner", "tx_balancer", "name"),               _VAL_STRING_RANGE (_valid_names_runner_tx_balancer),       ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL, master.runner_tx_balancer_interval, NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL, _JS_KEYS ("runner", "tx_balancer", "balancing_interval"), _VAL_INT32_RANGE (-1, 0, G_MAXINT32),                      ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_ACTIVE,               master.runner_active,               NM_VALUE_TYPE_BOOL,   NM_SETTING_TEAM_RUNNER_ACTIVE,               _JS_KEYS ("runner", "active"),                            _VAL_BOOL (TRUE),                                          ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_FAST_RATE,            master.runner_fast_rate,            NM_VALUE_TYPE_BOOL,   NM_SETTING_TEAM_RUNNER_FAST_RATE,            _JS_KEYS ("runner", "fast_rate"),                         _VAL_BOOL (FALSE),                                         ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO,             master.runner_sys_prio,             NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_RUNNER_SYS_PRIO,             _JS_KEYS ("runner", "sys_prio"),                          _VAL_INT32_RANGE (-1, 0, USHRT_MAX + 1),                   ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_MIN_PORTS,            master.runner_min_ports,            NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_RUNNER_MIN_PORTS,            _JS_KEYS ("runner", "min_ports"),                         _VAL_INT32_RANGE (-1, 1, UCHAR_MAX + 1),                   ),
	_INIT (0, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_AGG_SELECT_POLICY,    master.runner_agg_select_policy,    NM_VALUE_TYPE_STRING, NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY,    _JS_KEYS ("runner", "agg_select_policy"),                 _VAL_STRING_RANGE (_valid_names_runner_agg_select_policy), ),

	_INIT (1, NM_TEAM_ATTRIBUTE_PORT_QUEUE_ID,                      port.queue_id,                      NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_PORT_QUEUE_ID,               _JS_KEYS ("queue_id"),                                    _VAL_INT32_RANGE (-1, 0, G_MAXINT32),                      ),
	_INIT (1, NM_TEAM_ATTRIBUTE_PORT_PRIO,                          port.prio,                          NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_PORT_PRIO,                   _JS_KEYS ("prio"),                                        _VAL_INT32 (0),                                            ),
	_INIT (1, NM_TEAM_ATTRIBUTE_PORT_STICKY,                        port.sticky,                        NM_VALUE_TYPE_BOOL,   NM_SETTING_TEAM_PORT_STICKY,                 _JS_KEYS ("sticky"),                                      _VAL_BOOL (FALSE),                                         ),
	_INIT (1, NM_TEAM_ATTRIBUTE_PORT_LACP_PRIO,                     port.lacp_prio,                     NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_PORT_LACP_PRIO,              _JS_KEYS ("lacp_prio"),                                   _VAL_INT32_RANGE (-1, 0, USHRT_MAX + 1),                   ),
	_INIT (1, NM_TEAM_ATTRIBUTE_PORT_LACP_KEY,                      port.lacp_key,                      NM_VALUE_TYPE_INT32,  NM_SETTING_TEAM_PORT_LACP_KEY,               _JS_KEYS ("lacp_key"),                                    _VAL_INT32_RANGE (-1, 0, USHRT_MAX + 1),                   ),

#undef _INIT
};

/*****************************************************************************/

typedef enum {
	LINK_WATCHER_ATTRIBUTE_NAME,
	LINK_WATCHER_ATTRIBUTE_DELAY_UP,
	LINK_WATCHER_ATTRIBUTE_DELAY_DOWN,
	LINK_WATCHER_ATTRIBUTE_INTERVAL,
	LINK_WATCHER_ATTRIBUTE_INIT_WAIT,
	LINK_WATCHER_ATTRIBUTE_MISSED_MAX,
	LINK_WATCHER_ATTRIBUTE_SOURCE_HOST,
	LINK_WATCHER_ATTRIBUTE_TARGET_HOST,
	LINK_WATCHER_ATTRIBUTE_VALIDATE_ACTIVE,
	LINK_WATCHER_ATTRIBUTE_VALIDATE_INACTIVE,
	LINK_WATCHER_ATTRIBUTE_VLANID,
	LINK_WATCHER_ATTRIBUTE_SEND_ALWAYS,
} LinkWatcherAttribute;

#define _EXPECTED_LINK_WATCHER_ATTRIBUTES_ETHTOOL    LINK_WATCHER_ATTRIBUTE_NAME, \
                                                     LINK_WATCHER_ATTRIBUTE_DELAY_UP, \
                                                     LINK_WATCHER_ATTRIBUTE_DELAY_DOWN
#define _EXPECTED_LINK_WATCHER_ATTRIBUTES_NSNA_PING  LINK_WATCHER_ATTRIBUTE_NAME, \
                                                     LINK_WATCHER_ATTRIBUTE_INTERVAL, \
                                                     LINK_WATCHER_ATTRIBUTE_INIT_WAIT, \
                                                     LINK_WATCHER_ATTRIBUTE_MISSED_MAX, \
                                                     LINK_WATCHER_ATTRIBUTE_TARGET_HOST
#define _EXPECTED_LINK_WATCHER_ATTRIBUTES_ARP_PING   LINK_WATCHER_ATTRIBUTE_NAME, \
                                                     LINK_WATCHER_ATTRIBUTE_INTERVAL, \
                                                     LINK_WATCHER_ATTRIBUTE_INIT_WAIT, \
                                                     LINK_WATCHER_ATTRIBUTE_MISSED_MAX, \
                                                     LINK_WATCHER_ATTRIBUTE_SOURCE_HOST, \
                                                     LINK_WATCHER_ATTRIBUTE_TARGET_HOST, \
                                                     LINK_WATCHER_ATTRIBUTE_VALIDATE_ACTIVE, \
                                                     LINK_WATCHER_ATTRIBUTE_VALIDATE_INACTIVE, \
                                                     LINK_WATCHER_ATTRIBUTE_VLANID, \
                                                     LINK_WATCHER_ATTRIBUTE_SEND_ALWAYS

typedef struct {
	const char *js_key;
	const char *dbus_name;
	NMValueTypUnion default_val;
	LinkWatcherAttribute link_watcher_attr;
	NMValueType value_type;
} LinkWatcherAttrData;

static const LinkWatcherAttrData link_watcher_attr_datas[] = {
#define _INIT(_link_watcher_attr, _js_key, _dbus_name, _value_type, ...) \
	[_link_watcher_attr] = { \
		.link_watcher_attr = (_link_watcher_attr), \
		.value_type = (_value_type), \
		.js_key = (""_js_key""), \
		.dbus_name = (""_dbus_name""), \
		__VA_ARGS__ \
	}
	_INIT (LINK_WATCHER_ATTRIBUTE_NAME,              "name",              "name",              NM_VALUE_TYPE_STRING,                          ),
	_INIT (LINK_WATCHER_ATTRIBUTE_DELAY_UP,          "delay_up",          "delay-up",          NM_VALUE_TYPE_INT,                             ),
	_INIT (LINK_WATCHER_ATTRIBUTE_DELAY_DOWN,        "delay_down",        "delay-down",        NM_VALUE_TYPE_INT,                             ),
	_INIT (LINK_WATCHER_ATTRIBUTE_INTERVAL,          "interval",          "interval",          NM_VALUE_TYPE_INT,                             ),
	_INIT (LINK_WATCHER_ATTRIBUTE_INIT_WAIT,         "init_wait",         "init-wait",         NM_VALUE_TYPE_INT,                             ),
	_INIT (LINK_WATCHER_ATTRIBUTE_MISSED_MAX,        "missed_max",        "missed-max",        NM_VALUE_TYPE_INT,    .default_val.v_int =  3, ),
	_INIT (LINK_WATCHER_ATTRIBUTE_SOURCE_HOST,       "source_host",       "source-host",       NM_VALUE_TYPE_STRING,                          ),
	_INIT (LINK_WATCHER_ATTRIBUTE_TARGET_HOST,       "target_host",       "target-host",       NM_VALUE_TYPE_STRING,                          ),
	_INIT (LINK_WATCHER_ATTRIBUTE_VALIDATE_ACTIVE,   "validate_active",   "validate-active",   NM_VALUE_TYPE_BOOL,                            ),
	_INIT (LINK_WATCHER_ATTRIBUTE_VALIDATE_INACTIVE, "validate_inactive", "validate-inactive", NM_VALUE_TYPE_BOOL,                            ),
	_INIT (LINK_WATCHER_ATTRIBUTE_VLANID,            "vlanid",            "vlanid",            NM_VALUE_TYPE_INT,    .default_val.v_int = -1, ),
	_INIT (LINK_WATCHER_ATTRIBUTE_SEND_ALWAYS,       "send_always",       "send-always",       NM_VALUE_TYPE_BOOL,                            ),
#undef _INIT
};

/*****************************************************************************/

static const TeamAttrData *_team_attr_data_get (gboolean is_port,
                                                NMTeamAttribute team_attr);
static gpointer _team_setting_get_field (const NMTeamSetting *self,
                                         const TeamAttrData *attr_data);
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
	nm_assert (attr_data->property_name);
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
_team_attr_data_find_for_property_name (gboolean is_port,
                                        const char *property_name)
{
	const TeamAttrData *attr_data;

	for (attr_data = team_attr_datas; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {
		if (   _team_attr_data_is_relevant (attr_data, is_port)
		    && nm_streq (property_name, attr_data->property_name))
			return attr_data;
	}
	return NULL;
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

static gboolean
_team_setting_has_field (const NMTeamSetting *self,
                         const TeamAttrData *attr_data)
{
	_team_setting_ASSERT (self);
	return NM_FLAGS_ALL (self->d.has_fields_mask, nm_team_attribute_to_flags (attr_data->team_attr));
}

static gboolean
_team_setting_has_fields_any_v (const NMTeamSetting *self,
                                const NMTeamAttribute *team_attrs,
                                gsize n_team_attrs)
{
	gsize i;

	for (i = 0; i < n_team_attrs; i++) {
		const TeamAttrData *attr_data = _team_attr_data_get (self->d.is_port, team_attrs[i]);

		if (_team_setting_has_field (self, attr_data))
			return TRUE;
	}
	return FALSE;
}

#define _team_setting_has_fields_any(self, ...) \
   _team_setting_has_fields_any_v ((self), ((const NMTeamAttribute []) { __VA_ARGS__ }), NM_NARG (__VA_ARGS__))

static void
_team_setting_has_field_set (NMTeamSetting *self,
                             const TeamAttrData *attr_data,
                             SetFieldModeEnum set_field_mode)
{
	guint32 mask = nm_team_attribute_to_flags (attr_data->team_attr);

	_team_setting_ASSERT (self);

	switch (set_field_mode) {
	case SET_FIELD_MODE_UNSET:
		goto do_unset;
	case SET_FIELD_MODE_SET:
		goto do_set;
	case SET_FIELD_MODE_SET_UNLESS_DEFAULT:
		if (_team_attr_data_equal (attr_data,
		                           self->d.is_port,
		                           _team_setting_get_field (self, attr_data),
		                           &attr_data->default_val))
			goto do_unset;
		goto do_set;
	}
	nm_assert_not_reached ();

do_unset:
	self->_data_priv.has_fields_mask &= ~mask;
	return;
do_set:
	self->_data_priv.has_fields_mask |= mask;
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
                                 const TeamAttrData *attr_data,
                                 gboolean changed,
                                 SetFieldModeEnum set_field_mode,
                                 ResetJsonEnum reset_json)
{
	guint32 changed_flags;

	_team_setting_has_field_set (self, attr_data, set_field_mode);

	if (!reset_json) {
		return   changed
		       ? nm_team_attribute_to_flags (attr_data->team_attr)
		       : 0u;
	}

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
		changed_flags =   nm_team_attribute_to_flags (attr_data->team_attr)
		                | nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_CONFIG);
	}

	nm_clear_g_free ((char **) &self->_data_priv._js_str);
	self->_data_priv.strict_validated = TRUE;
	self->_data_priv._js_str_need_synthetize = TRUE;

	return changed_flags;
}

static guint32
_team_setting_attribute_changed_attr (NMTeamSetting *self,
                                      NMTeamAttribute team_attr,
                                      gboolean changed,
                                      SetFieldModeEnum set_field_mode,
                                      ResetJsonEnum reset_json)
{
	return _team_setting_attribute_changed (self,
	                                        _team_attr_data_get (self->d.is_port, team_attr),
	                                        changed,
	                                        set_field_mode,
	                                        reset_json);
}

static gboolean
_team_setting_field_to_json (const NMTeamSetting *self,
                             GString *gstr,
                             gboolean prepend_delimiter,
                             const TeamAttrData *attr_data)
{
	if (!_team_setting_has_field (self, attr_data))
		return FALSE;

	if (prepend_delimiter)
		nm_json_aux_gstr_append_delimiter (gstr);
	_team_attr_data_to_json (attr_data,
	                         self->d.is_port,
	                         gstr,
	                         _team_setting_get_field (self, attr_data));
	return TRUE;
}

static gboolean
_team_setting_fields_to_json_maybe (const NMTeamSetting *self,
                                    GString *gstr,
                                    gboolean prepend_delimiter,
                                    const NMTeamAttribute *team_attrs_lst,
                                    gsize team_attrs_lst_len)
{
	gsize i;
	gboolean any_added = FALSE;

	for (i = 0; i < team_attrs_lst_len; i++) {
		if (_team_setting_field_to_json (self,
		                                 gstr,
		                                 prepend_delimiter,
		                                 _team_attr_data_get (self->d.is_port, team_attrs_lst[i]))) {
			any_added = TRUE;
			prepend_delimiter = TRUE;
		}
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

	nm_assert ((!has_lst) == (!val_lst));

	for (attr_data = &team_attr_datas[TEAM_ATTR_IDX_CONFIG + 1]; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {
		const NMValueTypUnion *p_val;
		gconstpointer p_field;
		gboolean has_field;

		if (!_team_attr_data_is_relevant (attr_data, self->d.is_port))
			continue;

		has_field = (has_lst && has_lst[attr_data->team_attr]);

		p_val = has_field
		        ? &val_lst[attr_data->team_attr]
		        : &attr_data->default_val;

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

		if (modify) {
			_team_setting_has_field_set (self,
			                             attr_data,
			                               has_field
			                             ? SET_FIELD_MODE_SET
			                             : SET_FIELD_MODE_UNSET);
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

	nm_assert (   _team_setting_has_field (self, attr_data)
	           || _team_attr_data_equal (attr_data,
	                                     self->d.is_port,
	                                     _team_setting_get_field (self, attr_data),
	                                     &attr_data->default_val));
	return _team_setting_get_field (self, attr_data);
}

static guint32
_team_setting_value_set (NMTeamSetting *self,
                         const TeamAttrData *attr_data,
                         gconstpointer val,
                         SetFieldModeEnum set_field_mode,
                         ResetJsonEnum reset_json)
{
	gpointer p_field;
	gboolean changed;

	nm_assert (self);
	_team_attr_data_ASSERT (attr_data);
	nm_assert (val);

	p_field = _team_setting_get_field (self, attr_data);

	changed = !_team_attr_data_equal (attr_data, self->d.is_port, p_field, val);
	if (changed)
		nm_value_type_copy (attr_data->value_type, p_field, val);
	return _team_setting_attribute_changed (self, attr_data, changed, set_field_mode, reset_json);
}

guint32
nm_team_setting_value_reset (NMTeamSetting *self,
                             NMTeamAttribute team_attr,
                             gboolean to_default /* or else unset */)
{
	const TeamAttrData *attr_data;

	nm_assert (self);

	attr_data = _team_attr_data_get (self->d.is_port, team_attr);

	return _team_setting_value_set (self,
	                                attr_data,
	                                &attr_data->default_val,
	                                  to_default
	                                ? SET_FIELD_MODE_SET
	                                : SET_FIELD_MODE_UNSET,
	                                RESET_JSON_YES);
}

guint32
_nm_team_setting_value_set (NMTeamSetting *self,
                            NMTeamAttribute team_attr,
                            NMValueType value_type,
                            gconstpointer val)
{
	const TeamAttrData *attr_data;

	nm_assert (self);

	attr_data = _team_attr_data_get (self->d.is_port, team_attr);

	nm_assert (value_type == attr_data->value_type);

	return _team_setting_value_set (self,
	                                attr_data,
	                                val,
	                                SET_FIELD_MODE_SET_UNLESS_DEFAULT,
	                                RESET_JSON_YES);
}

guint32
nm_team_setting_value_link_watchers_add (NMTeamSetting *self,
                                         const NMTeamLinkWatcher *link_watcher)
{
	guint i;
	gboolean changed;

	for (i = 0; i < self->d.link_watchers->len; i++) {
		if (nm_team_link_watcher_equal (self->d.link_watchers->pdata[i], link_watcher)) {
			changed = FALSE;
			goto out;
		}
	}
	changed = TRUE;
	g_ptr_array_add ((GPtrArray *) self->d.link_watchers,
	                 _nm_team_link_watcher_ref ((NMTeamLinkWatcher *) link_watcher));
out:
	return _team_setting_attribute_changed_attr (self, NM_TEAM_ATTRIBUTE_LINK_WATCHERS, changed, SET_FIELD_MODE_SET_UNLESS_DEFAULT, RESET_JSON_YES);
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
	return _team_setting_attribute_changed_attr (self, NM_TEAM_ATTRIBUTE_LINK_WATCHERS, FALSE, SET_FIELD_MODE_SET_UNLESS_DEFAULT, RESET_JSON_YES);
}

guint32
nm_team_setting_value_link_watchers_remove (NMTeamSetting *self,
                                            guint idx)
{
	g_ptr_array_remove_index ((GPtrArray *) self->d.link_watchers, idx);
	return _team_setting_attribute_changed_attr (self, NM_TEAM_ATTRIBUTE_LINK_WATCHERS, TRUE, SET_FIELD_MODE_SET_UNLESS_DEFAULT, RESET_JSON_YES);
}

static guint32
_team_setting_value_link_watchers_set_list (NMTeamSetting *self,
                                            const NMTeamLinkWatcher *const*arr,
                                            guint len,
                                            SetFieldModeEnum set_field_mode,
                                            ResetJsonEnum reset_json)
{
	gboolean changed;

	if (   self->d.link_watchers->len == len
	    && nm_team_link_watchers_cmp ((const NMTeamLinkWatcher *const*) self->d.link_watchers->pdata,
	                                  arr,
	                                  len,
	                                  FALSE) == 0) {
		changed = FALSE;
		goto out;
	}

	changed = TRUE;
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

out:
	return _team_setting_attribute_changed_attr (self, NM_TEAM_ATTRIBUTE_LINK_WATCHERS, changed, set_field_mode, reset_json);
}

guint32
nm_team_setting_value_link_watchers_set_list (NMTeamSetting *self,
                                              const NMTeamLinkWatcher *const*arr,
                                              guint len)
{
	return _team_setting_value_link_watchers_set_list (self,
	                                                   arr,
	                                                   len,
	                                                   SET_FIELD_MODE_SET_UNLESS_DEFAULT,
	                                                   RESET_JSON_YES);
}

/*****************************************************************************/

guint32
nm_team_setting_value_master_runner_tx_hash_add (NMTeamSetting *self,
                                                 const char *txhash)
{
	gboolean changed;
	guint i;

	if (!self->d.master.runner_tx_hash)
		self->_data_priv.master.runner_tx_hash = g_ptr_array_new_with_free_func (g_free);
	else {
		for (i = 0; i < self->d.master.runner_tx_hash->len; i++) {
			if (nm_streq (txhash, self->d.master.runner_tx_hash->pdata[i])) {
				changed = FALSE;
				goto out;
			}
		}
	}
	changed = TRUE;
	g_ptr_array_add ((GPtrArray *) self->d.master.runner_tx_hash, g_strdup (txhash));
out:
	return _team_setting_attribute_changed_attr (self, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH, changed, SET_FIELD_MODE_SET_UNLESS_DEFAULT, RESET_JSON_YES);
}

guint32
nm_team_setting_value_master_runner_tx_hash_remove (NMTeamSetting *self,
                                                    guint idx)
{
	g_ptr_array_remove_index ((GPtrArray *) self->d.master.runner_tx_hash, idx);
	return _team_setting_attribute_changed_attr (self, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH, TRUE, SET_FIELD_MODE_SET_UNLESS_DEFAULT, RESET_JSON_YES);
}

static guint32
_team_setting_value_master_runner_tx_hash_set_list (NMTeamSetting *self,
                                                    const char *const*arr,
                                                    guint len,
                                                    SetFieldModeEnum set_field_mode,
                                                    ResetJsonEnum reset_json)
{
	_nm_unused gs_unref_ptrarray GPtrArray *old_val_destroy = NULL;
	gboolean changed;
	guint i;

	if (_nm_utils_strv_cmp_n (self->d.master.runner_tx_hash ? (const char *const*) self->d.master.runner_tx_hash->pdata : NULL,
	                          self->d.master.runner_tx_hash ? self->d.master.runner_tx_hash->len : 0u,
	                          arr,
	                          len) == 0) {
		changed = FALSE;
		goto out;
	}

	changed = TRUE;

	old_val_destroy = (GPtrArray *) g_steal_pointer (&self->_data_priv.master.runner_tx_hash);

	for (i = 0; i < len; i++) {
		if (!arr[i])
			continue;
		if (!self->d.master.runner_tx_hash)
			self->_data_priv.master.runner_tx_hash = g_ptr_array_new_with_free_func (g_free);
		g_ptr_array_add ((GPtrArray *) self->d.master.runner_tx_hash, g_strdup (arr[i]));
	}

out:
	return _team_setting_attribute_changed_attr (self, NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH, changed, set_field_mode, reset_json);
}

guint32
nm_team_setting_value_master_runner_tx_hash_set_list (NMTeamSetting *self,
                                                      const char *const*arr,
                                                      guint len)
{
	return _team_setting_value_master_runner_tx_hash_set_list (self,
	                                                           arr,
	                                                           len,
	                                                           SET_FIELD_MODE_SET_UNLESS_DEFAULT,
	                                                           RESET_JSON_YES);
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
_link_watcher_unpack (const NMTeamLinkWatcher *link_watcher,
                      NMValueTypUnioMaybe args[static G_N_ELEMENTS (link_watcher_attr_datas)])
{
	const char *v_name = nm_team_link_watcher_get_name (link_watcher);
	NMTeamLinkWatcherArpPingFlags v_arp_ping_flags;

	memset (args, 0, sizeof (args[0]) * G_N_ELEMENTS (link_watcher_attr_datas));

	_LINK_WATCHER_ATTR_SET_STRING (args, LINK_WATCHER_ATTRIBUTE_NAME, v_name);

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
}

static void
_link_watcher_to_json (const NMTeamLinkWatcher *link_watcher,
                       GString *gstr)
{
	NMValueTypUnioMaybe args[G_N_ELEMENTS (link_watcher_attr_datas)];
	int i;
	gboolean is_first = TRUE;

	if (!link_watcher) {
		g_string_append (gstr, "null");
		return;
	}

	_link_watcher_unpack (link_watcher, args);

	g_string_append (gstr, "{ ");

	for (i = 0; i < (int) G_N_ELEMENTS (link_watcher_attr_datas); i++) {
		const NMValueTypUnioMaybe *p_val = &args[i];
		const LinkWatcherAttrData *attr_data = &link_watcher_attr_datas[i];

		if (!p_val->has)
			continue;
		if (nm_value_type_equal (attr_data->value_type, &attr_data->default_val, &p_val->val))
			continue;

		if (is_first)
			is_first = FALSE;
		else
			nm_json_aux_gstr_append_delimiter (gstr);
		nm_json_aux_gstr_append_obj_name (gstr, attr_data->js_key, '\0');
		nm_value_type_to_json (attr_data->value_type, gstr, &p_val->val);
	}

	g_string_append (gstr, " }");
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
			    && !NM_IN_SET ((LinkWatcherAttribute) _i, __VA_ARGS__)) \
				break; \
		} \
		\
		(_i == (int) G_N_ELEMENTS ((_parse_results))); \
	})

	v_name = _LINK_WATCHER_ATTR_GET_STRING (args, LINK_WATCHER_ATTRIBUTE_NAME);

	if (nm_streq0 (v_name, NM_TEAM_LINK_WATCHER_ETHTOOL)) {
		if (_PARSE_RESULT_HAS_UNEXPECTED_ATTRIBUTES (args, _EXPECTED_LINK_WATCHER_ATTRIBUTES_ETHTOOL))
			*out_unrecognized_content = TRUE;
		result = nm_team_link_watcher_new_ethtool (_LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_DELAY_UP),
		                                           _LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_DELAY_DOWN),
		                                           NULL);
	} else if (nm_streq0 (v_name, NM_TEAM_LINK_WATCHER_NSNA_PING)) {
		if (_PARSE_RESULT_HAS_UNEXPECTED_ATTRIBUTES (args, _EXPECTED_LINK_WATCHER_ATTRIBUTES_NSNA_PING))
			*out_unrecognized_content = TRUE;
		result = nm_team_link_watcher_new_nsna_ping (_LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_INIT_WAIT),
		                                             _LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_INTERVAL),
		                                             _LINK_WATCHER_ATTR_GET_INT (args, LINK_WATCHER_ATTRIBUTE_MISSED_MAX),
		                                             _LINK_WATCHER_ATTR_GET_STRING (args, LINK_WATCHER_ATTRIBUTE_TARGET_HOST),
		                                             NULL);
	} else if (nm_streq0 (v_name, NM_TEAM_LINK_WATCHER_ARP_PING)) {
		NMTeamLinkWatcherArpPingFlags v_flags = NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE;

		if (_PARSE_RESULT_HAS_UNEXPECTED_ATTRIBUTES (args, _EXPECTED_LINK_WATCHER_ATTRIBUTES_ARP_PING))
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
_link_watcher_to_variant (const NMTeamLinkWatcher *link_watcher)
{
	NMValueTypUnioMaybe args[G_N_ELEMENTS (link_watcher_attr_datas)];
	GVariantBuilder builder;
	int i;

	if (!link_watcher)
		return NULL;

	_link_watcher_unpack (link_watcher, args);

	if (!args[LINK_WATCHER_ATTRIBUTE_NAME].has)
		return NULL;

	g_variant_builder_init (&builder, G_VARIANT_TYPE ("a{sv}"));

	for (i = 0; i < (int) G_N_ELEMENTS (link_watcher_attr_datas); i++) {
		const NMValueTypUnioMaybe *p_val = &args[i];
		const LinkWatcherAttrData *attr_data = &link_watcher_attr_datas[i];
		GVariant *v;

		if (!p_val->has)
			continue;
		if (nm_value_type_equal (attr_data->value_type, &attr_data->default_val, &p_val->val))
			continue;

		if (attr_data->value_type == NM_VALUE_TYPE_INT)
			v = g_variant_new_int32 (p_val->val.v_int);
		else {
			v = nm_value_type_to_variant (attr_data->value_type,
			                              &p_val->val);
		}
		if (!v)
			continue;

		nm_assert (g_variant_is_floating (v));
		g_variant_builder_add (&builder,
		                       "{sv}",
		                       attr_data->dbus_name,
		                       v);
	}

	return g_variant_builder_end (&builder);
}

#define _LINK_WATCHER_ATTR_VARGET(variants, link_watcher_attribute, _value_type, c_type, _cmd) \
	({ \
		GVariant *const*_variants = (variants); \
		GVariant *_cc; \
		\
		nm_assert (link_watcher_attr_datas[(link_watcher_attribute)].value_type == (_value_type)); \
		\
		  (_cc = _variants[(link_watcher_attribute)]) \
		? (_cmd) \
		: link_watcher_attr_datas[(link_watcher_attribute)].default_val.c_type; \
	})
#define _LINK_WATCHER_ATTR_VARGET_BOOL(variants, link_watcher_attribute)   (_LINK_WATCHER_ATTR_VARGET (variants, link_watcher_attribute, NM_VALUE_TYPE_BOOL,   v_bool,   g_variant_get_boolean (_cc)      ))
#define _LINK_WATCHER_ATTR_VARGET_INT(variants, link_watcher_attribute)    (_LINK_WATCHER_ATTR_VARGET (variants, link_watcher_attribute, NM_VALUE_TYPE_INT,    v_int,    g_variant_get_int32 (_cc)        ))
#define _LINK_WATCHER_ATTR_VARGET_STRING(variants, link_watcher_attribute) (_LINK_WATCHER_ATTR_VARGET (variants, link_watcher_attribute, NM_VALUE_TYPE_STRING, v_string, g_variant_get_string (_cc, NULL) ))

static void
_variants_list_link_watcher_unref_auto (GVariant *(*p_variants)[])
{
	int i;

	for (i = 0; i < (int) G_N_ELEMENTS (link_watcher_attr_datas); i++)
		nm_g_variant_unref ((*p_variants)[i]);
}

static NMTeamLinkWatcher *
_link_watcher_from_variant (GVariant *watcher_var,
                            gboolean strict_parsing,
                            GError **error)
{
	nm_auto (_variants_list_link_watcher_unref_auto) GVariant *variants[G_N_ELEMENTS (link_watcher_attr_datas)] = { NULL, };
	const char *v_key;
	GVariant *v_val;
	const char *v_name;
	GVariantIter iter;

	g_return_val_if_fail (g_variant_is_of_type (watcher_var, G_VARIANT_TYPE ("a{sv}")), NULL);

	g_variant_iter_init (&iter, watcher_var);
	while (g_variant_iter_next (&iter, "{&sv}", &v_key, &v_val)) {
		_nm_unused gs_unref_variant GVariant *v_val_free = v_val;
		const LinkWatcherAttrData *attr_data = NULL;
		const GVariantType *variant_type;
		int i;

		for (i = 0; i < (int) G_N_ELEMENTS (link_watcher_attr_datas); i++) {
			if (nm_streq (link_watcher_attr_datas[i].dbus_name, v_key)) {
				attr_data = &link_watcher_attr_datas[i];
				break;
			}
		}
		if (!attr_data) {
			if (strict_parsing) {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("invalid D-Bus property \"%s\""),
				             v_key);
				return NULL;
			}
			continue;
		}

		if (attr_data->value_type == NM_VALUE_TYPE_INT)
			variant_type = G_VARIANT_TYPE_INT32;
		else
			variant_type = nm_value_type_get_variant_type (attr_data->value_type);

		if (!g_variant_is_of_type (v_val, variant_type)) {
			if (strict_parsing) {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("invalid D-Bus property \"%s\""),
				             v_key);
				return NULL;
			}
			continue;
		}

		if (variants[attr_data->link_watcher_attr]) {
			if (strict_parsing) {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("duplicate D-Bus property \"%s\""),
				             v_key);
				return NULL;
			}
			g_variant_unref (variants[attr_data->link_watcher_attr]);
		}
		variants[attr_data->link_watcher_attr] = g_steal_pointer (&v_val_free);
	}

#define _VARIANTS_HAVE_UNEXPECTED_ATTRIBUTES(_type, _variants, _error, ...) \
	({ \
		int _i; \
		gboolean _has_error = FALSE; \
		\
		for (_i = 0; _i < (int) G_N_ELEMENTS ((_variants)); _i++) { \
			if (   (_variants)[_i] \
			    && !NM_IN_SET ((LinkWatcherAttribute) _i, __VA_ARGS__)) { \
				_has_error = TRUE; \
				g_set_error (_error, \
				             NM_CONNECTION_ERROR, \
				             NM_CONNECTION_ERROR_INVALID_PROPERTY, \
				             _("invalid D-Bus property \"%s\" for \"%s\""), \
				             link_watcher_attr_datas[_i].dbus_name, \
				             _type); \
				break; \
			} \
		} \
		\
		_has_error; \
	})

	v_name = _LINK_WATCHER_ATTR_VARGET_STRING (variants, LINK_WATCHER_ATTRIBUTE_NAME);

	if (nm_streq0 (v_name, NM_TEAM_LINK_WATCHER_ETHTOOL)) {
		if (   strict_parsing
		    && _VARIANTS_HAVE_UNEXPECTED_ATTRIBUTES (v_name, variants, error, _EXPECTED_LINK_WATCHER_ATTRIBUTES_ETHTOOL))
			return NULL;
		return nm_team_link_watcher_new_ethtool (_LINK_WATCHER_ATTR_VARGET_INT (variants, LINK_WATCHER_ATTRIBUTE_DELAY_UP),
		                                         _LINK_WATCHER_ATTR_VARGET_INT (variants, LINK_WATCHER_ATTRIBUTE_DELAY_DOWN),
		                                         strict_parsing ? error : NULL);
	}

	if (nm_streq0 (v_name, NM_TEAM_LINK_WATCHER_NSNA_PING)) {
		if (   strict_parsing
		    && _VARIANTS_HAVE_UNEXPECTED_ATTRIBUTES (v_name, variants, error, _EXPECTED_LINK_WATCHER_ATTRIBUTES_NSNA_PING))
			return NULL;
		return nm_team_link_watcher_new_nsna_ping (_LINK_WATCHER_ATTR_VARGET_INT (variants, LINK_WATCHER_ATTRIBUTE_INIT_WAIT),
		                                           _LINK_WATCHER_ATTR_VARGET_INT (variants, LINK_WATCHER_ATTRIBUTE_INTERVAL),
		                                           _LINK_WATCHER_ATTR_VARGET_INT (variants, LINK_WATCHER_ATTRIBUTE_MISSED_MAX),
		                                           _LINK_WATCHER_ATTR_VARGET_STRING (variants, LINK_WATCHER_ATTRIBUTE_TARGET_HOST),
		                                           strict_parsing ? error : NULL);
	}

	if (nm_streq0 (v_name, NM_TEAM_LINK_WATCHER_ARP_PING)) {
		NMTeamLinkWatcherArpPingFlags v_flags = NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_NONE;

		if (   strict_parsing
		    && _VARIANTS_HAVE_UNEXPECTED_ATTRIBUTES (v_name, variants, error, _EXPECTED_LINK_WATCHER_ATTRIBUTES_ARP_PING))
			return NULL;

		if (_LINK_WATCHER_ATTR_VARGET_BOOL (variants, LINK_WATCHER_ATTRIBUTE_VALIDATE_ACTIVE))
			v_flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_ACTIVE;
		if (_LINK_WATCHER_ATTR_VARGET_BOOL (variants, LINK_WATCHER_ATTRIBUTE_VALIDATE_INACTIVE))
			v_flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_VALIDATE_INACTIVE;
		if (_LINK_WATCHER_ATTR_VARGET_BOOL (variants, LINK_WATCHER_ATTRIBUTE_SEND_ALWAYS))
			v_flags |= NM_TEAM_LINK_WATCHER_ARP_PING_FLAG_SEND_ALWAYS;

		return nm_team_link_watcher_new_arp_ping2 (_LINK_WATCHER_ATTR_VARGET_INT (variants, LINK_WATCHER_ATTRIBUTE_INIT_WAIT),
		                                           _LINK_WATCHER_ATTR_VARGET_INT (variants, LINK_WATCHER_ATTRIBUTE_INTERVAL),
		                                           _LINK_WATCHER_ATTR_VARGET_INT (variants, LINK_WATCHER_ATTRIBUTE_MISSED_MAX),
		                                           _LINK_WATCHER_ATTR_VARGET_INT (variants, LINK_WATCHER_ATTRIBUTE_VLANID),
		                                           _LINK_WATCHER_ATTR_VARGET_STRING (variants, LINK_WATCHER_ATTRIBUTE_TARGET_HOST),
		                                           _LINK_WATCHER_ATTR_VARGET_STRING (variants, LINK_WATCHER_ATTRIBUTE_SOURCE_HOST),
		                                           v_flags,
		                                           strict_parsing ? error : NULL);
	}

	if (strict_parsing) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("unknown link-watcher name \"%s\""),
		             v_name);
	}
	return NULL;
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
_nm_utils_team_link_watchers_to_variant (const GPtrArray *link_watchers)
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
 * @strict_parsing: whether to parse strictly or ignore everything invalid.
 * @error: error reason.
 *
 * Utility function to convert a #GVariant representing a list of team link
 * watchers int a #GPtrArray of #NMTeamLinkWatcher objects.
 *
 * Returns: (transfer full) (element-type NMTeamLinkWatcher): a newly allocated
 *   #GPtrArray of #NMTeamLinkWatcher objects.
 *
 * Note that if you provide an @error, then the function can only fail (and return %NULL)
 * or succeed (and not return %NULL). If you don't provide an @error, then the function
 * never returns %NULL.
 **/
GPtrArray *
_nm_utils_team_link_watchers_from_variant (GVariant *value,
                                           gboolean strict_parsing,
                                           GError **error)
{
	gs_unref_ptrarray GPtrArray *link_watchers = NULL;
	GVariantIter iter;
	GVariant *watcher_var;

	g_return_val_if_fail (g_variant_is_of_type (value, G_VARIANT_TYPE ("aa{sv}")), NULL);

	link_watchers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);

	g_variant_iter_init (&iter, value);
	while (g_variant_iter_next (&iter, "@a{sv}", &watcher_var)) {
		_nm_unused gs_unref_variant GVariant *watcher_var_free = watcher_var;
		NMTeamLinkWatcher *watcher;

		watcher = _link_watcher_from_variant (watcher_var, strict_parsing, error);
		if (error && *error)
			return NULL;
		if (watcher)
			g_ptr_array_add (link_watchers, watcher);
	}

	return g_steal_pointer (&link_watchers);
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
		gboolean list_is_empty = TRUE;
		GString *gstr;

		gstr = g_string_new (NULL);

		g_string_append (gstr, "{ ");

		if (self->d.is_port) {
			static const NMTeamAttribute attr_lst_port[] = {
				NM_TEAM_ATTRIBUTE_PORT_QUEUE_ID,
				NM_TEAM_ATTRIBUTE_PORT_PRIO,
				NM_TEAM_ATTRIBUTE_PORT_STICKY,
				NM_TEAM_ATTRIBUTE_PORT_LACP_PRIO,
				NM_TEAM_ATTRIBUTE_PORT_LACP_KEY,
			};

			if (_team_setting_fields_to_json_maybe (self, gstr, !list_is_empty, attr_lst_port, G_N_ELEMENTS (attr_lst_port)))
				list_is_empty = FALSE;
		} else {
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
			static const NMTeamAttribute attr_lst_notify_peers[] = {
				NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_COUNT,
				NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_INTERVAL,
			};
			static const NMTeamAttribute attr_lst_mcast_rejoin[] = {
				NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_COUNT,
				NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_INTERVAL,
			};

			if (   _team_setting_has_fields_any_v (self, attr_lst_runner_pt1, G_N_ELEMENTS (attr_lst_runner_pt1))
			    || _team_setting_has_fields_any_v (self, attr_lst_runner_pt2, G_N_ELEMENTS (attr_lst_runner_pt2))
			    || _team_setting_has_fields_any_v (self, attr_lst_runner_pt3, G_N_ELEMENTS (attr_lst_runner_pt3))) {
				gboolean list_is_empty2 = TRUE;

				nm_assert (list_is_empty);

				nm_json_aux_gstr_append_obj_name (gstr, "runner", '{');

				if (_team_setting_fields_to_json_maybe (self, gstr, !list_is_empty2, attr_lst_runner_pt1, G_N_ELEMENTS (attr_lst_runner_pt1)))
					list_is_empty2 = FALSE;

				if (_team_setting_has_fields_any_v (self, attr_lst_runner_pt2, G_N_ELEMENTS (attr_lst_runner_pt2))) {
					if (!list_is_empty2)
						nm_json_aux_gstr_append_delimiter (gstr);
					nm_json_aux_gstr_append_obj_name (gstr, "tx_balancer", '{');
					if (!_team_setting_fields_to_json_maybe (self, gstr, FALSE, attr_lst_runner_pt2, G_N_ELEMENTS (attr_lst_runner_pt2)))
						nm_assert_not_reached ();
					g_string_append (gstr, " }");
					list_is_empty2 = FALSE;
				}

				if (_team_setting_fields_to_json_maybe (self, gstr, !list_is_empty2, attr_lst_runner_pt3, G_N_ELEMENTS (attr_lst_runner_pt3)))
					list_is_empty2 = FALSE;

				nm_assert (!list_is_empty2);
				g_string_append (gstr, " }");
				list_is_empty = FALSE;
			}

			if (_team_setting_has_fields_any_v (self, attr_lst_notify_peers, G_N_ELEMENTS (attr_lst_notify_peers))) {
				if (!list_is_empty)
					nm_json_aux_gstr_append_delimiter (gstr);
				nm_json_aux_gstr_append_obj_name (gstr, "notify_peers", '{');
				if (!_team_setting_fields_to_json_maybe (self, gstr, FALSE, attr_lst_notify_peers, G_N_ELEMENTS (attr_lst_notify_peers)))
					nm_assert_not_reached ();
				g_string_append (gstr, " }");
				list_is_empty = FALSE;
			}

			if (_team_setting_has_fields_any_v (self, attr_lst_mcast_rejoin, G_N_ELEMENTS (attr_lst_mcast_rejoin))) {
				if (!list_is_empty)
					nm_json_aux_gstr_append_delimiter (gstr);
				nm_json_aux_gstr_append_obj_name (gstr, "mcast_rejoin", '{');
				if (!_team_setting_fields_to_json_maybe (self, gstr, FALSE, attr_lst_mcast_rejoin, G_N_ELEMENTS (attr_lst_mcast_rejoin)))
					nm_assert_not_reached ();
				g_string_append (gstr, " }");
				list_is_empty = FALSE;
			}
		}

		if (_team_setting_field_to_json (self,
		                                 gstr,
		                                 !list_is_empty,
		                                 _team_attr_data_get (self->d.is_port, NM_TEAM_ATTRIBUTE_LINK_WATCHERS)))
			list_is_empty = FALSE;

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
	    && nm_streq (js_str, self->d._js_str)) {
	    if (!self->d.strict_validated) {
			/* setting the same JSON string twice in a row has no effect. */
			return 0;
		}
	} else
		changed_flags |= nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_CONFIG);

#if WITH_JSON_VALIDATION
	{
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
		}
	}

#endif

	if (do_set_default)
		changed_flags |= _team_setting_set_default (self);

	self->_data_priv.strict_validated = FALSE;
	self->_data_priv._js_str_need_synthetize = FALSE;
	self->_data_priv.js_str_invalid = new_js_str_invalid;
	g_free ((char *) self->_data_priv._js_str);
	self->_data_priv._js_str = g_strdup (js_str);

	return changed_flags;
}

/*****************************************************************************/

static void
_team_setting_prefix_error_plain (gboolean is_port,
                                  const char *property_name,
                                  GError **error)
{
	g_prefix_error (error,
	                "%s.%s: ",
	                  is_port
	                ? NM_SETTING_TEAM_PORT_SETTING_NAME
	                : NM_SETTING_TEAM_SETTING_NAME,
	                property_name);
}

static void
_team_setting_prefix_error (const NMTeamSetting *self,
                            const char *prop_name_master,
                            const char *prop_name_port,
                            GError **error)
{
	_team_setting_ASSERT (self);
	nm_assert (  self->d.is_port
	           ? (!!prop_name_port)
	           : (!!prop_name_master));
	_team_setting_prefix_error_plain (self->d.is_port,
	                                    self->d.is_port
	                                  ? prop_name_port
	                                  : prop_name_master,
	                                  error);
}

static gboolean
_team_setting_verify_properties (const NMTeamSetting *self,
                                 GError **error)
{
	const TeamAttrData *attr_data;
	guint i;

	for (attr_data = &team_attr_datas[TEAM_ATTR_IDX_CONFIG + 1]; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {

		if (!_team_attr_data_is_relevant (attr_data, self->d.is_port))
			continue;
		if (!_team_setting_has_field (self, attr_data))
			continue;

		if (attr_data->has_range) {
			gconstpointer p_field;

			p_field = _team_setting_get_field (self, attr_data);
			if (attr_data->value_type == NM_VALUE_TYPE_INT32) {
				gint32 v = *((const gint32 *) p_field);

				if (   v < attr_data->range.r_int32.min
				    || v > attr_data->range.r_int32.max) {
					g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
					             _("value out or range"));
					_team_setting_prefix_error_plain (self->d.is_port, attr_data->property_name, error);
					return FALSE;
				}
			} else if (attr_data->value_type == NM_VALUE_TYPE_STRING) {
				const char *v = *((const char *const*) p_field);

				if (nm_utils_strv_find_first ((char **) attr_data->range.r_string.valid_names,
				                              -1,
				                              v) < 0) {
					g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
					             _("invalid value"));
					_team_setting_prefix_error_plain (self->d.is_port, attr_data->property_name, error);
					return FALSE;
				}
			} else
				nm_assert_not_reached ();
		}

		if (   !self->d.is_port
		    && attr_data->team_attr == NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH) {
			if (self->d.master.runner_tx_hash) {
				for (i = 0; i < self->d.master.runner_tx_hash->len; i++) {
					const char *val = self->d.master.runner_tx_hash->pdata[i];

					if (  !val
					    || (nm_utils_strv_find_first ((char **) _valid_names_runner_tx_hash,
					                                  -1,
					                                  val) < 0)) {
						g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
						             _("invalid runner-tx-hash"));
						_team_setting_prefix_error_plain (self->d.is_port, NM_SETTING_TEAM_RUNNER_TX_HASH, error);
						return FALSE;
					}
				}
			}
		}
	}

	if (!self->d.is_port) {

		for (i = 0; i < G_N_ELEMENTS (_runner_compat_lst); i++) {
			const RunnerCompatElem *e = &_runner_compat_lst[i];

			nm_assert (NM_PTRARRAY_LEN (e->valid_runners) > 0);

			attr_data = _team_attr_data_get (FALSE, e->team_attr);

			if (!_team_setting_has_field (self, attr_data))
				continue;
			if (   self->d.master.runner
			    && (nm_utils_strv_find_first ((char **) e->valid_runners,
			                                  -1,
			                                  self->d.master.runner) >= 0))
				continue;
			if (e->valid_runners[1] == NULL) {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
				             _("%s is only allowed for runner %s"),
				             attr_data->property_name,
				             e->valid_runners[0]);
			} else {
				gs_free char *s = NULL;

				s = g_strjoinv (",", (char **) e->valid_runners);
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
				             _("%s is only allowed for runners %s"),
				             attr_data->property_name,
				             s);
			}
			_team_setting_prefix_error_plain (self->d.is_port, NM_SETTING_TEAM_RUNNER, error);
			return FALSE;
		}
	} else {
		gboolean has_lacp_attrs;
		gboolean has_activebackup_attrs;

		has_lacp_attrs = _team_setting_has_fields_any (self, NM_TEAM_ATTRIBUTE_PORT_LACP_PRIO,
		                                                     NM_TEAM_ATTRIBUTE_PORT_LACP_KEY);
		has_activebackup_attrs = _team_setting_has_fields_any (self, NM_TEAM_ATTRIBUTE_PORT_PRIO,
		                                                             NM_TEAM_ATTRIBUTE_PORT_STICKY);
		if (has_lacp_attrs && has_activebackup_attrs) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
			             _("cannot set parameters for lacp and activebackup runners together"));
			_team_setting_prefix_error (self, NM_SETTING_TEAM_LINK_WATCHERS, NM_SETTING_TEAM_PORT_LINK_WATCHERS, error);
			return FALSE;
		}
	}

	for (i = 0; i < self->d.link_watchers->len; i++) {
		if (!self->d.link_watchers->pdata[i]) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
			             _("missing link watcher"));
			_team_setting_prefix_error (self, NM_SETTING_TEAM_LINK_WATCHERS, NM_SETTING_TEAM_PORT_LINK_WATCHERS, error);
			return FALSE;
		}
	}

	return TRUE;
}

static gboolean
_team_setting_verify_config (const NMTeamSetting *self,
                             GError **error)
{
	const char *js_str;

	/* we always materialize the JSON string. That is because we want to validate the
	 * string length of the resulting JSON. */
	js_str = nm_team_setting_config_get (self);

	if (js_str) {
		if (strlen (js_str) > 1*1024*1024) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("team config exceeds size limit"));
			_team_setting_prefix_error (self, NM_SETTING_TEAM_CONFIG, NM_SETTING_TEAM_PORT_CONFIG, error);
			return FALSE;
		}
		if (!g_utf8_validate (js_str, -1, NULL)) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("team config is not valid UTF-8"));
			_team_setting_prefix_error (self, NM_SETTING_TEAM_CONFIG, NM_SETTING_TEAM_PORT_CONFIG, error);
			return FALSE;
		}
		if (self->d.js_str_invalid) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("invalid json"));
			_team_setting_prefix_error (self, NM_SETTING_TEAM_CONFIG, NM_SETTING_TEAM_PORT_CONFIG, error);
			return FALSE;
		}
	}

	return TRUE;
}

gboolean
nm_team_setting_verify (const NMTeamSetting *self,
                        GError **error)
{
	if (self->d.strict_validated) {
		if (!_team_setting_verify_properties (self, error))
			return FALSE;
	}
	return _team_setting_verify_config (self, error);
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
		if (!_team_attr_data_is_relevant (attr_data, self_a->d.is_port))
			continue;

		NM_CMP_RETURN (_team_attr_data_cmp (attr_data,
		                                    self_a->d.is_port,
		                                    _team_setting_get_field (self_a, attr_data),
		                                    _team_setting_get_field (self_b, attr_data)));
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
	guint32 changed_flags;

	_team_setting_ASSERT (self);
	_team_setting_ASSERT (src);
	nm_assert (self->d.is_port == src->d.is_port);

	if (self == src)
		return 0;

	changed_flags = 0;

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
		changed_flags |= nm_team_attribute_to_flags (attr_data->team_attr);
	}

	self->_data_priv.has_fields_mask = src->d.has_fields_mask;

	if (!nm_streq0 (self->d._js_str, src->d._js_str)) {
		g_free ((char *) self->_data_priv._js_str);
		self->_data_priv._js_str = g_strdup (src->d._js_str);
		changed_flags |= nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_CONFIG);
	} else if (changed_flags != 0)
		changed_flags |= nm_team_attribute_to_flags (NM_TEAM_ATTRIBUTE_CONFIG);

	self->_data_priv._js_str_need_synthetize = src->d._js_str_need_synthetize;
	self->_data_priv.strict_validated = src->d.strict_validated;
	self->_data_priv.js_str_invalid = src->d.js_str_invalid;

	return changed_flags;
}

static void
_variants_list_team_unref_auto (GVariant *(*p_variants)[])
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
	nm_auto (_variants_list_team_unref_auto) GVariant *variants[_NM_TEAM_ATTRIBUTE_NUM] = { NULL, };
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

		attr_data = _team_attr_data_find_for_property_name (self->d.is_port, v_key);
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
				_team_setting_prefix_error_plain (self->d.is_port,
				                                  attr_data->property_name,
				                                  error);
				return FALSE;
			}
			continue;
		}

		/* _nm_setting_new_from_dbus() already checks for duplicate keys. Don't
		 * do that here. */
		nm_g_variant_unref (variants[attr_data->team_attr]);
		variants[attr_data->team_attr] = g_steal_pointer (&v_val_free);
	}

	if (variants[NM_TEAM_ATTRIBUTE_LINK_WATCHERS]) {

		if (   variants[NM_TEAM_ATTRIBUTE_CONFIG]
		    && WITH_JSON_VALIDATION
		    && !NM_FLAGS_HAS (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT)) {
			/* we don't require the content of the "link-watchers" and we also
			 * don't perform strict validation. No need to parse it. */
		} else {
			gs_free_error GError *local = NULL;

			/* We might need the parsed v_link_watchers array below (because there is no JSON
			 * "config" present or because we don't build WITH_JSON_VALIDATION).
			 *
			 * Or we might run with NM_SETTING_PARSE_FLAGS_STRICT. In that mode, we may not necessarily
			 * require that the entire setting as a whole validates (if a JSON config is present and
			 * we are not "strict_validated") , but we require that we can at least parse the link watchers
			 * on their own. */
			v_link_watchers = _nm_utils_team_link_watchers_from_variant (variants[NM_TEAM_ATTRIBUTE_LINK_WATCHERS],
			                                                             NM_FLAGS_HAS (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT),
			                                                             &local);
			if (   local
			    && NM_FLAGS_HAS (parse_flags, NM_SETTING_PARSE_FLAGS_STRICT)) {
				g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("invalid link-watchers: %s"),
				             local->message);
				_team_setting_prefix_error (self,
				                            NM_SETTING_TEAM_LINK_WATCHERS,
				                            NM_SETTING_TEAM_PORT_LINK_WATCHERS,
				                            error);
				return FALSE;
			}
		}
	}

	*out_changed |= nm_team_setting_config_set (self,
	                                              variants[NM_TEAM_ATTRIBUTE_CONFIG]
	                                            ? g_variant_get_string (variants[NM_TEAM_ATTRIBUTE_CONFIG], NULL)
	                                            : NULL);

	if (   WITH_JSON_VALIDATION
	    && variants[NM_TEAM_ATTRIBUTE_CONFIG]) {
		/* for team settings, the JSON must be able to express all possible options. That means,
		 * if the GVariant contains both the JSON "config" and other options, then the other options
		 * are silently ignored. */
	} else {
		guint32 extra_changed = 0u;

		for (attr_data = &team_attr_datas[TEAM_ATTR_IDX_CONFIG + 1]; attr_data < &team_attr_datas[G_N_ELEMENTS (team_attr_datas)]; attr_data++) {
			NMValueTypUnion val;
			guint32 changed_flags = 0u;

			if (!_team_attr_data_is_relevant (attr_data, self->d.is_port))
				continue;
			if (!variants[attr_data->team_attr])
				continue;

			if (attr_data->value_type != NM_VALUE_TYPE_UNSPEC) {
				nm_value_type_get_from_variant (attr_data->value_type, &val, variants[attr_data->team_attr], FALSE);
				changed_flags = _team_setting_value_set (self,
				                                         attr_data,
				                                         &val,
				                                         SET_FIELD_MODE_SET,
				                                         RESET_JSON_NO);
			} else if (attr_data->team_attr == NM_TEAM_ATTRIBUTE_LINK_WATCHERS) {
				changed_flags = _team_setting_value_link_watchers_set_list (self,
				                                                            v_link_watchers ? (const NMTeamLinkWatcher *const *) v_link_watchers->pdata : NULL,
				                                                            v_link_watchers ? v_link_watchers->len : 0u,
				                                                            SET_FIELD_MODE_SET,
				                                                            RESET_JSON_NO);
			} else if (   !self->d.is_port
			           && attr_data->team_attr == NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH) {
				gs_free const char **strv = NULL;
				gsize len;

				strv = g_variant_get_strv (variants[attr_data->team_attr], &len);
				changed_flags = _team_setting_value_master_runner_tx_hash_set_list (self,
				                                                                    strv,
				                                                                    NM_MIN (len, (gsize) G_MAXUINT),
				                                                                    SET_FIELD_MODE_SET,
				                                                                    RESET_JSON_NO);
			} else
				nm_assert_not_reached ();

			extra_changed |= changed_flags;
		}

		if (!variants[NM_TEAM_ATTRIBUTE_CONFIG]) {
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
_nm_setting_get_team_setting (struct _NMSetting *setting)
{
	if (NM_IS_SETTING_TEAM (setting))
		return _nm_setting_team_get_team_setting (NM_SETTING_TEAM (setting));
	return _nm_setting_team_port_get_team_setting (NM_SETTING_TEAM_PORT (setting));
}

GVariant *
_nm_team_settings_property_to_dbus (const NMSettInfoSetting *sett_info,
                                    guint property_idx,
                                    NMConnection *connection,
                                    NMSetting *setting,
                                    NMConnectionSerializationFlags flags,
                                    const NMConnectionSerializationOptions *options)
{
	NMTeamSetting *self = _nm_setting_get_team_setting (setting);
	const TeamAttrData *attr_data = _team_attr_data_get (self->d.is_port, sett_info->property_infos[property_idx].param_spec->param_id);

	if (attr_data->team_attr == NM_TEAM_ATTRIBUTE_CONFIG) {
		const char *config;

		if (   self->d.strict_validated
		    && !_nm_utils_is_manager_process) {
			/* if we are in strict validating mode on the client side, the JSON is generated
			 * artificially. In this case, don't send the config via D-Bus to the server.
			 *
			 * This also will cause NetworkManager to strictly validate the settings.
			 * If a JSON "config" is present, strict validation won't be performed. */
			return NULL;
		}

		config = nm_team_setting_config_get (self);
		return config ? g_variant_new_string (config) : NULL;
	}

	if (!_team_setting_has_field (self, attr_data))
		return NULL;

	if (attr_data->value_type != NM_VALUE_TYPE_UNSPEC) {
		return nm_value_type_to_variant (attr_data->value_type,
	                                     _team_setting_get_field (self, attr_data));
	}
	if (attr_data->team_attr == NM_TEAM_ATTRIBUTE_LINK_WATCHERS)
		return _nm_utils_team_link_watchers_to_variant (self->d.link_watchers);
	if (   !self->d.is_port
	    && attr_data->team_attr == NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH) {
		return g_variant_new_strv (self->d.master.runner_tx_hash ? (const char *const*) self->d.master.runner_tx_hash->pdata : NULL,
		                           self->d.master.runner_tx_hash ? self->d.master.runner_tx_hash->len : 0u);
	}

	nm_assert_not_reached ();
	return NULL;
}

void
_nm_team_settings_property_from_dbus_link_watchers (GVariant *dbus_value,
                                                    GValue *prop_value)
{
	g_value_take_boxed (prop_value,
	                    _nm_utils_team_link_watchers_from_variant (dbus_value, FALSE, NULL));
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
