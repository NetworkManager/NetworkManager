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

#ifndef __NM_TEAM_UITLS_H__
#define __NM_TEAM_UITLS_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_CORE_PRIVATE)
#error Cannot use this header.
#endif

#include "nm-glib-aux/nm-value-type.h"

struct _NMSetting;

struct NMTeamLinkWatcher;

typedef enum {

	_NM_TEAM_ATTRIBUTE_0            = 0,
	NM_TEAM_ATTRIBUTE_CONFIG        = 1,
	NM_TEAM_ATTRIBUTE_LINK_WATCHERS = 2,

	_NM_TEAM_ATTRIBUTE_START        = 3,

	NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_COUNT = _NM_TEAM_ATTRIBUTE_START,
	NM_TEAM_ATTRIBUTE_MASTER_NOTIFY_PEERS_INTERVAL,
	NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_COUNT,
	NM_TEAM_ATTRIBUTE_MASTER_MCAST_REJOIN_INTERVAL,
	NM_TEAM_ATTRIBUTE_MASTER_RUNNER,
	NM_TEAM_ATTRIBUTE_MASTER_RUNNER_HWADDR_POLICY,
	NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_HASH,
	NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER,
	NM_TEAM_ATTRIBUTE_MASTER_RUNNER_TX_BALANCER_INTERVAL,
	NM_TEAM_ATTRIBUTE_MASTER_RUNNER_ACTIVE,
	NM_TEAM_ATTRIBUTE_MASTER_RUNNER_FAST_RATE,
	NM_TEAM_ATTRIBUTE_MASTER_RUNNER_SYS_PRIO,
	NM_TEAM_ATTRIBUTE_MASTER_RUNNER_MIN_PORTS,
	NM_TEAM_ATTRIBUTE_MASTER_RUNNER_AGG_SELECT_POLICY,
	_NM_TEAM_ATTRIBUTE_MASTER_NUM,

	NM_TEAM_ATTRIBUTE_PORT_QUEUE_ID = _NM_TEAM_ATTRIBUTE_START,
	NM_TEAM_ATTRIBUTE_PORT_PRIO,
	NM_TEAM_ATTRIBUTE_PORT_STICKY,
	NM_TEAM_ATTRIBUTE_PORT_LACP_PRIO,
	NM_TEAM_ATTRIBUTE_PORT_LACP_KEY,
	_NM_TEAM_ATTRIBUTE_PORT_NUM,

	_NM_TEAM_ATTRIBUTE_NUM = MAX (_NM_TEAM_ATTRIBUTE_MASTER_NUM, _NM_TEAM_ATTRIBUTE_PORT_NUM),

} NMTeamAttribute;

static inline guint32
nm_team_attribute_to_flags (NMTeamAttribute team_attr)
{
	nm_assert (_NM_INT_NOT_NEGATIVE (team_attr));
	nm_assert (team_attr < _NM_TEAM_ATTRIBUTE_NUM);
	G_STATIC_ASSERT_EXPR (_NM_TEAM_ATTRIBUTE_NUM < 32);

	return ((guint32) 1) << team_attr;
}

struct _NMTeamSettingData {

	const char *_js_str;

	const GPtrArray *link_watchers;

	/* this means that @_js_str is unset and needs to be created by
	 * converting the properties to JSON. This flag indicates that
	 * we need to re-generate the JSON string on-demand (lazily). */
	bool _js_str_need_synthetize;

	bool strict_validated:1;

	/* indicates tha the JSON is invalid. Usually, we do a very relaxed validation of
	 * the JSON config, in case !@strict_validated and accept all unknown fields. This
	 * flag indicates that the JSON value is not even parsable as JSON. nm_connection_verify()
	 * would reject such a setting. */
	bool js_str_invalid:1;

	bool is_port:1;

	guint32 has_fields_mask;

	union {
		struct {
			const GPtrArray *runner_tx_hash;
			const char *runner;
			const char *runner_hwaddr_policy;
			const char *runner_tx_balancer;
			const char *runner_agg_select_policy;
			gint32 notify_peers_count;
			gint32 notify_peers_interval;
			gint32 mcast_rejoin_count;
			gint32 mcast_rejoin_interval;
			gint32 runner_sys_prio;
			gint32 runner_min_ports;
			gint32 runner_tx_balancer_interval;
			bool runner_active;
			bool runner_fast_rate;
		} master;
		struct {
			gint32 queue_id;
			gint32 prio;
			gint32 lacp_prio;
			gint32 lacp_key;
			bool sticky;
		} port;
	};
};

/*****************************************************************************/

typedef struct {
	union {
		const struct _NMTeamSettingData d;

		struct _NMTeamSettingData _data_priv;
	};
} NMTeamSetting;

NMTeamSetting *nm_team_setting_new (gboolean is_port,
                                    const char *js_str);

void nm_team_setting_free (NMTeamSetting *self);

NM_AUTO_DEFINE_FCN0 (NMTeamSetting *, _nm_auto_free_team_setting, nm_team_setting_free)
#define nm_auto_free_team_setting nm_auto (_nm_auto_free_team_setting)

/*****************************************************************************/

const char *nm_team_setting_config_get (const NMTeamSetting *self);

guint32 nm_team_setting_config_set (NMTeamSetting *self, const char *js_str);

/*****************************************************************************/

gconstpointer _nm_team_setting_value_get (const NMTeamSetting *self,
                                          NMTeamAttribute team_attr,
                                          NMValueType value_type);

static inline gboolean
nm_team_setting_value_get_bool (const NMTeamSetting *self,
                                NMTeamAttribute team_attr)
{
	const bool *p;

	p = _nm_team_setting_value_get (self, team_attr, NM_VALUE_TYPE_BOOL);
	return p ? *p : 0;
}

static inline gint32
nm_team_setting_value_get_int32 (const NMTeamSetting *self,
                                 NMTeamAttribute team_attr)
{
	const gint32 *p;

	p = _nm_team_setting_value_get (self, team_attr, NM_VALUE_TYPE_INT32);
	return p ? *p : 0;
}

static inline const char *
nm_team_setting_value_get_string (const NMTeamSetting *self,
                                  NMTeamAttribute team_attr)
{
	const char *const*p;

	p = _nm_team_setting_value_get (self, team_attr, NM_VALUE_TYPE_STRING);
	return p ? *p : NULL;
}

/*****************************************************************************/

guint32 nm_team_setting_value_reset (NMTeamSetting *self,
                                     NMTeamAttribute team_attr,
                                     gboolean to_default /* or else unset */);

guint32 _nm_team_setting_value_set (NMTeamSetting *self,
                                    NMTeamAttribute team_attr,
                                    NMValueType value_type,
                                    gconstpointer val);

static inline guint32
nm_team_setting_value_set_bool (NMTeamSetting *self,
                                NMTeamAttribute team_attr,
                                gboolean val)
{
	const bool bool_val = val;

	return _nm_team_setting_value_set (self, team_attr, NM_VALUE_TYPE_BOOL, &bool_val);
}

static inline guint32
nm_team_setting_value_set_int32 (NMTeamSetting *self,
                                 NMTeamAttribute team_attr,
                                 gint32 val)
{
	return _nm_team_setting_value_set (self, team_attr, NM_VALUE_TYPE_INT32, &val);
}

static inline guint32
nm_team_setting_value_set_string (NMTeamSetting *self,
                                  NMTeamAttribute team_attr,
                                  const char *arg)
{
	return _nm_team_setting_value_set (self, team_attr, NM_VALUE_TYPE_STRING, &arg);
}

/*****************************************************************************/

guint32 nm_team_setting_value_link_watchers_add (NMTeamSetting *self,
                                                 const struct NMTeamLinkWatcher *link_watcher);

guint32 nm_team_setting_value_link_watchers_remove (NMTeamSetting *self,
                                                    guint idx);

guint32 nm_team_setting_value_link_watchers_remove_by_value (NMTeamSetting *self,
                                                             const struct NMTeamLinkWatcher *link_watcher);

guint32 nm_team_setting_value_link_watchers_set_list (NMTeamSetting *self,
                                                      const struct NMTeamLinkWatcher *const*arr,
                                                      guint len);

/*****************************************************************************/

guint32 nm_team_setting_value_master_runner_tx_hash_add (NMTeamSetting *self,
                                                         const char *txhash);

guint32 nm_team_setting_value_master_runner_tx_hash_remove (NMTeamSetting *self,
                                                            guint idx);

guint32 nm_team_setting_value_master_runner_tx_hash_set_list (NMTeamSetting *self,
                                                              const char *const*arr,
                                                              guint len);

/*****************************************************************************/

gboolean nm_team_setting_verify (const NMTeamSetting *self,
                                 GError **error);

/*****************************************************************************/

int nm_team_setting_cmp (const NMTeamSetting *self_a,
                         const NMTeamSetting *self_b,
                         gboolean ignore_js_str);

guint32 nm_team_setting_reset (NMTeamSetting *self,
                               const NMTeamSetting *src);

gboolean nm_team_setting_reset_from_dbus (NMTeamSetting *self,
                                          GVariant *setting_dict,
                                          GHashTable *keys,
                                          guint32 *out_changed,
                                          guint /* NMSettingParseFlags */ parse_flags,
                                          GError **error);

/*****************************************************************************/

GPtrArray *_nm_utils_team_link_watchers_from_variant (GVariant *value,
                                                      gboolean strict_parsing,
                                                      GError **error);
GVariant  *_nm_utils_team_link_watchers_to_variant (const GPtrArray *link_watchers);

/*****************************************************************************/

gboolean nm_team_setting_maybe_changed (struct _NMSetting *source,
                                        const GParamSpec *const*obj_properties,
                                        guint32 changed);

struct _NMSettingTeam;
struct _NMSettingTeamPort;
NMTeamSetting *_nm_setting_team_get_team_setting (struct _NMSettingTeam *setting);
NMTeamSetting *_nm_setting_team_port_get_team_setting (struct _NMSettingTeamPort *setting);
NMTeamSetting *_nm_setting_get_team_setting (struct _NMSetting *setting);

/*****************************************************************************/

#include "nm-connection.h"
#include "nm-core-internal.h"

GVariant *_nm_team_settings_property_to_dbus (const NMSettInfoSetting *sett_info,
                                              guint property_idx,
                                              NMConnection *connection,
                                              NMSetting *setting,
                                              NMConnectionSerializationFlags flags,
                                              const NMConnectionSerializationOptions *options);

void _nm_team_settings_property_from_dbus_link_watchers (GVariant *dbus_value,
                                                         GValue *prop_value);

#endif /* __NM_TEAM_UITLS_H__ */
