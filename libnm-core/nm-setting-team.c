/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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
 * Copyright 2013 Jiri Pirko <jiri@resnulli.us>
 */

#include "nm-default.h"

#include <string.h>
#include <stdlib.h>

#include "nm-setting-team.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-connection-private.h"

/**
 * SECTION:nm-setting-team
 * @short_description: Describes connection properties for teams
 *
 * The #NMSettingTeam object is a #NMSetting subclass that describes properties
 * necessary for team connections.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingTeam, nm_setting_team, NM_TYPE_SETTING,
                         _nm_register_setting (TEAM, NM_SETTING_PRIORITY_HW_BASE))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_TEAM)

#define NM_SETTING_TEAM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_TEAM, NMSettingTeamPrivate))

typedef struct {
	char *config;
	gint notify_peers_count;
	gint notify_peers_interval;
	gint mcast_rejoin_count;
	gint mcast_rejoin_interval;
	char *runner;
	char *runner_hwaddr_policy;
	GPtrArray *runner_tx_hash;
	char *runner_tx_balancer;
	gint runner_tx_balancer_interval;
	gboolean runner_active;
	gboolean runner_fast_rate;
	gint runner_sys_prio;
	gint runner_min_ports;
	char *runner_agg_select_policy;
} NMSettingTeamPrivate;

/* Keep aligned with _prop_to_keys[] */
enum {
	PROP_0,
	PROP_CONFIG,
	PROP_NOTIFY_PEERS_COUNT,
	PROP_NOTIFY_PEERS_INTERVAL,
	PROP_MCAST_REJOIN_COUNT,
	PROP_MCAST_REJOIN_INTERVAL,
	PROP_RUNNER,
	PROP_RUNNER_HWADDR_POLICY,
	PROP_RUNNER_TX_HASH,
	PROP_RUNNER_TX_BALANCER,
	PROP_RUNNER_TX_BALANCER_INTERVAL,
	PROP_RUNNER_ACTIVE,
	PROP_RUNNER_FAST_RATE,
	PROP_RUNNER_SYS_PRIO,
	PROP_RUNNER_MIN_PORTS,
	PROP_RUNNER_AGG_SELECT_POLICY,
	LAST_PROP
};

/* Keep aligned with team properties enum */
static const _NMUtilsTeamPropertyKeys _prop_to_keys[LAST_PROP] = {
	[PROP_0] =                           { NULL, NULL, NULL, 0 },
	[PROP_CONFIG] =                      { NULL, NULL, NULL, 0 },
	[PROP_NOTIFY_PEERS_COUNT] =          { "notify_peers", "count", NULL, 0 },
	[PROP_NOTIFY_PEERS_INTERVAL] =       { "notify_peers", "interval", NULL, 0 },
	[PROP_MCAST_REJOIN_COUNT] =          { "mcast_rejoin", "count", NULL, 0 },
	[PROP_MCAST_REJOIN_INTERVAL] =       { "mcast_rejoin", "interval", NULL, 0 },
	[PROP_RUNNER] =                      { "runner", "name", NULL,
	                                       {.default_str = NM_SETTING_TEAM_RUNNER_DEFAULT} },
	[PROP_RUNNER_HWADDR_POLICY] =        { "runner", "hwaddr_policy", NULL, 0 },
	[PROP_RUNNER_TX_HASH] =              { "runner", "tx_hash", NULL, 0 },
	[PROP_RUNNER_TX_BALANCER] =          { "runner", "tx_balancer", "name", 0 },
	[PROP_RUNNER_TX_BALANCER_INTERVAL] = { "runner", "tx_balancer", "interval",
	                                       NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL_DEFAULT },
	[PROP_RUNNER_ACTIVE] =               { "runner", "active", NULL, 0 },
	[PROP_RUNNER_FAST_RATE] =            { "runner", "fast_rate", NULL, 0 },
	[PROP_RUNNER_SYS_PRIO] =             { "runner", "sys_prio", NULL,
	                                       NM_SETTING_TEAM_RUNNER_SYS_PRIO_DEFAULT },
	[PROP_RUNNER_MIN_PORTS] =            { "runner", "min_ports", NULL, 0 },
	[PROP_RUNNER_AGG_SELECT_POLICY] =    { "runner", "agg_select_policy", NULL,
	                                       {.default_str = NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY_DEFAULT} },
};

/**
 * nm_setting_team_new:
 *
 * Creates a new #NMSettingTeam object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingTeam object
 **/
NMSetting *
nm_setting_team_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_TEAM, NULL);
}

/**
 * nm_setting_team_get_config:
 * @setting: the #NMSettingTeam
 *
 * Returns: the #NMSettingTeam:config property of the setting
 **/
const char *
nm_setting_team_get_config (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->config;
}

/**
 * nm_setting_team_get_notify_peers_count:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:notify-peers-count property of the setting
 *
 * Since: 1.10.2
 **/
gint
nm_setting_team_get_notify_peers_count (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->notify_peers_count;
}

/**
 * nm_setting_team_get_notify_peers_interval:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:notify-peers-interval property of the setting
 *
 * Since: 1.10.2
 **/
gint
nm_setting_team_get_notify_peers_interval (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->notify_peers_interval;
}

/**
 * nm_setting_team_get_mcast_rejoin_count:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:mcast-rejoin-count property of the setting
 *
 * Since: 1.10.2
 **/
gint
nm_setting_team_get_mcast_rejoin_count (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->mcast_rejoin_count;
}

/**
 * nm_setting_team_get_mcast_rejoin_interval:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:mcast-rejoin-interval property of the setting
 *
 * Since: 1.10.2
 **/
gint
nm_setting_team_get_mcast_rejoin_interval (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->mcast_rejoin_interval;
}

/**
 * nm_setting_team_get_runner:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner property of the setting
 *
 * Since: 1.10.2
 **/
const char *
nm_setting_team_get_runner (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->runner;
}

/**
 * nm_setting_team_get_runner_hwaddr_policy:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-hwaddr-policy property of the setting
 *
 * Since: 1.10.2
 **/
const char *
nm_setting_team_get_runner_hwaddr_policy (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->runner_hwaddr_policy;
}

/**
 * nm_setting_team_get_runner_tx_balancer:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-tx-balancer property of the setting
 *
 * Since: 1.10.2
 **/
const char *
nm_setting_team_get_runner_tx_balancer (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->runner_tx_balancer;
}

/**
 * nm_setting_team_get_runner_tx_balancer_interval:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-tx-balancer_interval property of the setting
 *
 * Since: 1.10.2
 **/
gint
nm_setting_team_get_runner_tx_balancer_interval (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->runner_tx_balancer_interval;
}

/**
 * nm_setting_team_get_runner_active:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner_active property of the setting
 *
 * Since: 1.10.2
 **/
gboolean
nm_setting_team_get_runner_active (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), FALSE);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->runner_active;
}

/**
 * nm_setting_team_get_runner_fast_rate:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-fast-rate property of the setting
 *
 * Since: 1.10.2
 **/
gboolean
nm_setting_team_get_runner_fast_rate (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), FALSE);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->runner_fast_rate;
}

/**
 * nm_setting_team_get_runner_sys_prio:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-sys-prio property of the setting
 *
 * Since: 1.10.2
 **/
gint
nm_setting_team_get_runner_sys_prio (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->runner_sys_prio;
}

/**
 * nm_setting_team_get_runner_min_ports:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-min-ports property of the setting
 *
 * Since: 1.10.2
 **/
gint
nm_setting_team_get_runner_min_ports (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->runner_min_ports;
}

/**
 * nm_setting_team_get_runner_agg_select_policy:
 * @setting: the #NMSettingTeam
 *
 * Returns: the ##NMSettingTeam:runner-agg-select-policy property of the setting
 *
 * Since: 1.10.2
 **/
const char *
nm_setting_team_get_runner_agg_select_policy (NMSettingTeam *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);

	return NM_SETTING_TEAM_GET_PRIVATE (setting)->runner_agg_select_policy;
}

/**
 * nm_setting_team_remove_runner_tx_hash_by_value:
 * @setting: the #NMSetetingTeam
 * @txhash: the txhash element to remove
 *
 * Removes the txhash element #txhash
 *
 * Returns: %TRUE if the txhash element was found and removed; %FALSE if it was not.
 *
 * Since: 1.10.2
 **/
gboolean
nm_setting_team_remove_runner_tx_hash_by_value (NMSettingTeam *setting,
                                               const char *txhash)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), FALSE);
	g_return_val_if_fail (txhash != NULL, FALSE);
	g_return_val_if_fail (txhash[0] != '\0', FALSE);

	for (i = 0; i < priv->runner_tx_hash->len; i++) {
		if (nm_streq (txhash, priv->runner_tx_hash->pdata[i])) {
			g_ptr_array_remove_index (priv->runner_tx_hash, i);
			g_object_notify (G_OBJECT (setting), NM_SETTING_TEAM_RUNNER_TX_HASH);
			return TRUE;
		}
	}
	return FALSE;
}

/**
 * nm_setting_team_get_num_runner_tx_hash:
 * @setting: the #NMSettingTeam
 *
 * Returns: the number of elements in txhash
 *
 * Since: 1.10.2
 **/
guint
nm_setting_team_get_num_runner_tx_hash (NMSettingTeam *setting)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);

	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), 0);

	return priv->runner_tx_hash ? priv->runner_tx_hash->len : 0;
}

/**
 * nm_setting_team_get_runner_tx_hash
 * @setting: the #NMSettingTeam
 * @idx: index number of the txhash element to return
 *
 * Returns: the txhash element at index @idx
 *
 * Since: 1.10.2
 **/
const char *
nm_setting_team_get_runner_tx_hash (NMSettingTeam *setting, int idx)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);

	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), NULL);
	g_return_val_if_fail (idx >= 0 && idx < priv->runner_tx_hash->len, NULL);

	return priv->runner_tx_hash->pdata[idx];
}

/**
 * nm_setting_team_remove_runner_tx_hash:
 * @setting: the #NMSettingTeam
 * @idx: index number of the element to remove from txhash
 *
 * Removes the txhash element at index @idx.
 *
 * Since: 1.10.2
 **/
void
nm_setting_team_remove_runner_tx_hash (NMSettingTeam *setting, int idx)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_TEAM (setting));
	g_return_if_fail (idx >= 0 && idx < priv->runner_tx_hash->len);

	g_ptr_array_remove_index (priv->runner_tx_hash, idx);
	g_object_notify (G_OBJECT (setting), NM_SETTING_TEAM_RUNNER_TX_HASH);
}

/**
 * nm_setting_team_add_runner_tx_hash:
 * @setting: the #NMSettingTeam
 * @txhash: the element to add to txhash
 *
 * Adds a new txhash element to the setting.
 *
 * Returns: %TRUE if the txhash element was added; %FALSE if the element
 * was already knnown.
 *
 * Since: 1.10.2
 **/
gboolean
nm_setting_team_add_runner_tx_hash (NMSettingTeam *setting, const char *txhash)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_TEAM (setting), FALSE);
	g_return_val_if_fail (txhash != NULL, FALSE);
	g_return_val_if_fail (txhash[0] != '\0', FALSE);

	if (!priv->runner_tx_hash)
		priv->runner_tx_hash = g_ptr_array_new_with_free_func (g_free);
	for (i = 0; i < priv->runner_tx_hash->len; i++) {
		if (nm_streq (txhash, priv->runner_tx_hash->pdata[i]))
			return FALSE;
	}

	g_ptr_array_add (priv->runner_tx_hash, g_strdup (txhash));
	g_object_notify (G_OBJECT (setting), NM_SETTING_TEAM_RUNNER_TX_HASH);
	return TRUE;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);

	if (!_nm_connection_verify_required_interface_name (connection, error))
		return FALSE;

	if (priv->config) {
		if (strlen (priv->config) > 1*1024*1024) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("team config exceeds size limit"));
			g_prefix_error (error,
			                "%s.%s: ",
			                NM_SETTING_TEAM_SETTING_NAME,
			                NM_SETTING_TEAM_CONFIG);
			return FALSE;
		}

		if (!nm_utils_is_json_object (priv->config, error)) {
			g_prefix_error (error,
			                "%s.%s: ",
			                NM_SETTING_TEAM_SETTING_NAME,
			                NM_SETTING_TEAM_CONFIG);
			/* We treat an empty string as no config for compatibility. */
			return *priv->config ? FALSE : NM_SETTING_VERIFY_NORMALIZABLE;
		}
	}

	if (   priv->runner
	    && g_ascii_strcasecmp (priv->runner, NM_SETTING_TEAM_RUNNER_BROADCAST)
	    && g_ascii_strcasecmp (priv->runner, NM_SETTING_TEAM_RUNNER_ROUNDROBIN)
	    && g_ascii_strcasecmp (priv->runner, NM_SETTING_TEAM_RUNNER_ACTIVEBACKUP)
	    && g_ascii_strcasecmp (priv->runner, NM_SETTING_TEAM_RUNNER_LOADBALANCE)
	    && g_ascii_strcasecmp (priv->runner, NM_SETTING_TEAM_RUNNER_LACP)) {
		g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_SETTING,
		                     _("invalid runner \"%s\""), priv->runner);

		g_prefix_error (error, "%s.%s: ", nm_setting_get_name (setting), NM_SETTING_TEAM_RUNNER);
		return FALSE;
	}

	/* NOTE: normalizable/normalizable-errors must appear at the end with decreasing severity.
	 * Take care to properly order statements with priv->config above. */

	return TRUE;
}

static gboolean
compare_property (NMSetting *setting,
                  NMSetting *other,
                  const GParamSpec *prop_spec,
                  NMSettingCompareFlags flags)
{
	NMSettingClass *parent_class;

	/* If we are trying to match a connection in order to assume it (and thus
	 * @flags contains INFERRABLE), use the "relaxed" matching for team
	 * configuration. Otherwise, for all other purposes (including connection
	 * comparison before an update), resort to the default string comparison.
	 */
	if (   NM_FLAGS_HAS (flags, NM_SETTING_COMPARE_FLAG_INFERRABLE)
	    && nm_streq0 (prop_spec->name, NM_SETTING_TEAM_CONFIG)) {
		return _nm_utils_team_config_equal (NM_SETTING_TEAM_GET_PRIVATE (setting)->config,
		                                    NM_SETTING_TEAM_GET_PRIVATE (other)->config,
		                                    FALSE);
	}

	/* Otherwise chain up to parent to handle generic compare */
	parent_class = NM_SETTING_CLASS (nm_setting_team_parent_class);
	return parent_class->compare_property (setting, other, prop_spec, flags);
}

static void
nm_setting_team_init (NMSettingTeam *setting)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);

	priv->runner = g_strdup (NM_SETTING_TEAM_RUNNER_ROUNDROBIN);
	priv->runner_sys_prio = NM_SETTING_TEAM_RUNNER_SYS_PRIO_DEFAULT;
	priv->runner_tx_balancer_interval = NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL_DEFAULT;
}

static void
finalize (GObject *object)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (object);

	g_free (priv->config);
	g_free (priv->runner);
	g_free (priv->runner_hwaddr_policy);
	g_free (priv->runner_tx_balancer);
	g_free (priv->runner_agg_select_policy);
	if (priv->runner_tx_hash)
		g_ptr_array_unref (priv->runner_tx_hash);

	G_OBJECT_CLASS (nm_setting_team_parent_class)->finalize (object);
}


#define JSON_TO_VAL(typ, id)   _nm_utils_json_extract_##typ (priv->config, _prop_to_keys[id], FALSE)

static void
_align_team_properties (NMSettingTeam *setting)
{
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);
	char **strv;
	int i;

	priv->notify_peers_count =          JSON_TO_VAL (int, PROP_NOTIFY_PEERS_COUNT);
	priv->notify_peers_interval =       JSON_TO_VAL (int, PROP_NOTIFY_PEERS_INTERVAL);
	priv->mcast_rejoin_count =          JSON_TO_VAL (int, PROP_MCAST_REJOIN_COUNT);
	priv->mcast_rejoin_interval =       JSON_TO_VAL (int, PROP_MCAST_REJOIN_INTERVAL);
	priv->runner_tx_balancer_interval = JSON_TO_VAL (int, PROP_RUNNER_TX_BALANCER_INTERVAL);
	priv->runner_sys_prio =             JSON_TO_VAL (int, PROP_RUNNER_SYS_PRIO);
	priv->runner_min_ports =            JSON_TO_VAL (int, PROP_RUNNER_MIN_PORTS);

	priv->runner_active =    JSON_TO_VAL (boolean, PROP_RUNNER_ACTIVE);
	priv->runner_fast_rate = JSON_TO_VAL (boolean, PROP_RUNNER_FAST_RATE);

	g_free (priv->runner);
	g_free (priv->runner_hwaddr_policy);
	g_free (priv->runner_tx_balancer);
	g_free (priv->runner_agg_select_policy);
	priv->runner =                   JSON_TO_VAL (string, PROP_RUNNER);
	priv->runner_hwaddr_policy =     JSON_TO_VAL (string, PROP_RUNNER_HWADDR_POLICY);
	priv->runner_tx_balancer =       JSON_TO_VAL (string, PROP_RUNNER_TX_BALANCER);
	priv->runner_agg_select_policy = JSON_TO_VAL (string, PROP_RUNNER_AGG_SELECT_POLICY);

	if (priv->runner_tx_hash) {
		g_ptr_array_unref (priv->runner_tx_hash);
		priv->runner_tx_hash = NULL;
	}
	strv = JSON_TO_VAL (strv, PROP_RUNNER_TX_HASH);
	if (strv) {
		for (i = 0; strv[i]; i++)
			nm_setting_team_add_runner_tx_hash (setting, strv[i]);
		g_strfreev (strv);
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingTeam *setting = NM_SETTING_TEAM (object);
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (object);
	const GValue *align_value = NULL;
	gboolean align_config = FALSE;
	char **strv;

	switch (prop_id) {
	case PROP_CONFIG:
		g_free (priv->config);
		priv->config = g_value_dup_string (value);
		_align_team_properties (setting);
		break;
	case PROP_NOTIFY_PEERS_COUNT:
		if (priv->notify_peers_count == g_value_get_int (value))
			break;
		priv->notify_peers_count = g_value_get_int (value);
		if (priv->notify_peers_count)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_NOTIFY_PEERS_INTERVAL:
		if (priv->notify_peers_interval == g_value_get_int (value))
			break;
		priv->notify_peers_interval = g_value_get_int (value);
		if (priv->notify_peers_interval)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_MCAST_REJOIN_COUNT:
		if (priv->mcast_rejoin_count == g_value_get_int (value))
			break;
		priv->mcast_rejoin_count = g_value_get_int (value);
		if (priv->mcast_rejoin_count)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_MCAST_REJOIN_INTERVAL:
		if (priv->mcast_rejoin_interval == g_value_get_int (value))
			break;
		priv->mcast_rejoin_interval = g_value_get_int (value);
		if (priv->mcast_rejoin_interval)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_RUNNER:
		g_free (priv->runner);
		priv->runner = g_value_dup_string (value);
		if (   priv->runner
		    && !nm_streq (priv->runner,
		                  NM_SETTING_TEAM_RUNNER_DEFAULT))
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_RUNNER_HWADDR_POLICY:
		g_free (priv->runner_hwaddr_policy);
		priv->runner_hwaddr_policy = g_value_dup_string (value);
		if (   priv->runner_hwaddr_policy
		    && !nm_streq (priv->runner_hwaddr_policy,
		                  NM_SETTING_TEAM_RUNNER_HWADDR_POLICY_SAME_ALL)) {
			align_value = value;
		}
		align_config = TRUE;
		break;
	case PROP_RUNNER_TX_HASH:
		if (priv->runner_tx_hash)
			g_ptr_array_unref (priv->runner_tx_hash);
		strv = g_value_get_boxed (value);
		if (strv && strv[0]) {
			priv->runner_tx_hash = _nm_utils_strv_to_ptrarray (strv);
			align_value = value;
		} else
			priv->runner_tx_hash = NULL;
		align_config = TRUE;
		break;
	case PROP_RUNNER_TX_BALANCER:
		g_free (priv->runner_tx_balancer);
		priv->runner_tx_balancer = g_value_dup_string (value);
		if (priv->runner_tx_balancer)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_RUNNER_TX_BALANCER_INTERVAL:
		if (priv->runner_tx_balancer_interval == g_value_get_int (value))
			break;
		priv->runner_tx_balancer_interval = g_value_get_int (value);
		if (priv->runner_tx_balancer_interval !=
		    NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL_DEFAULT)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_RUNNER_ACTIVE:
		if (priv->runner_active == g_value_get_boolean (value))
			break;
		priv->runner_active = g_value_get_boolean (value);
		if (priv->runner_active)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_RUNNER_FAST_RATE:
		if (priv->runner_fast_rate == g_value_get_boolean (value))
			break;
		priv->runner_fast_rate = g_value_get_boolean (value);
		if (priv->runner_fast_rate)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_RUNNER_SYS_PRIO:
		if (priv->runner_sys_prio == g_value_get_int (value))
			break;
		priv->runner_sys_prio = g_value_get_int (value);
		if (priv->runner_sys_prio != NM_SETTING_TEAM_RUNNER_SYS_PRIO_DEFAULT)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_RUNNER_MIN_PORTS:
		if (priv->runner_min_ports == g_value_get_int (value))
			break;
		priv->runner_min_ports = g_value_get_int (value);
		if (priv->runner_min_ports)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_RUNNER_AGG_SELECT_POLICY:
		g_free (priv->runner_agg_select_policy);
		priv->runner_agg_select_policy = g_value_dup_string (value);
		if (   priv->runner_agg_select_policy
		    && !nm_streq (priv->runner_agg_select_policy,
		                  NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY_LACP_PRIO))
			align_value = value;
		align_config = TRUE;
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}

	if (align_config)
		_nm_utils_json_append_gvalue (&priv->config, _prop_to_keys[prop_id], align_value);
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingTeam *setting = NM_SETTING_TEAM (object);
	NMSettingTeamPrivate *priv = NM_SETTING_TEAM_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_CONFIG:
		g_value_set_string (value, nm_setting_team_get_config (setting));
		break;
	case PROP_NOTIFY_PEERS_COUNT:
		g_value_set_int (value, priv->notify_peers_count);
		break;
	case PROP_NOTIFY_PEERS_INTERVAL:
		g_value_set_int (value, priv->notify_peers_interval);
		break;
	case PROP_MCAST_REJOIN_COUNT:
		g_value_set_int (value, priv->mcast_rejoin_count);
		break;
	case PROP_MCAST_REJOIN_INTERVAL:
		g_value_set_int (value, priv->mcast_rejoin_interval);
		break;
	case PROP_RUNNER:
		g_value_set_string (value, nm_setting_team_get_runner (setting));
		break;
	case PROP_RUNNER_HWADDR_POLICY:
		g_value_set_string (value, nm_setting_team_get_runner_hwaddr_policy (setting));
		break;
	case PROP_RUNNER_TX_HASH:
		g_value_take_boxed (value, priv->runner_tx_hash ?
		                    _nm_utils_ptrarray_to_strv (priv->runner_tx_hash): NULL);
		break;
	case PROP_RUNNER_TX_BALANCER:
		g_value_set_string (value, nm_setting_team_get_runner_tx_balancer (setting));
		break;
	case PROP_RUNNER_TX_BALANCER_INTERVAL:
		g_value_set_int (value, priv->runner_tx_balancer_interval);
		break;
	case PROP_RUNNER_ACTIVE:
		g_value_set_boolean (value, nm_setting_team_get_runner_active (setting));
		break;
	case PROP_RUNNER_FAST_RATE:
		g_value_set_boolean (value, nm_setting_team_get_runner_fast_rate (setting));
		break;
	case PROP_RUNNER_SYS_PRIO:
		g_value_set_int (value, priv->runner_sys_prio);
		break;
	case PROP_RUNNER_MIN_PORTS:
		g_value_set_int (value, priv->runner_min_ports);
		break;
	case PROP_RUNNER_AGG_SELECT_POLICY:
		g_value_set_string (value, nm_setting_team_get_runner_agg_select_policy (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_team_class_init (NMSettingTeamClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingTeamPrivate));

	/* virtual methods */
	object_class->set_property     = set_property;
	object_class->get_property     = get_property;
	object_class->finalize         = finalize;
	parent_class->compare_property = compare_property;
	parent_class->verify           = verify;

	/* Properties */
	/**
	 * NMSettingTeam:config:
	 *
	 * The JSON configuration for the team network interface.  The property
	 * should contain raw JSON configuration data suitable for teamd, because
	 * the value is passed directly to teamd. If not specified, the default
	 * configuration is used.  See man teamd.conf for the format details.
	 **/
	/* ---ifcfg-rh---
	 * property: config
	 * variable: TEAM_CONFIG
	 * description: Team configuration in JSON. See man teamd.conf for details.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_CONFIG,
		 g_param_spec_string (NM_SETTING_TEAM_CONFIG, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:notify-peers-count:
	 *
	 * Corresponds to the teamd notify_peers.count.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_NOTIFY_PEERS_COUNT,
		 g_param_spec_int (NM_SETTING_TEAM_NOTIFY_PEERS_COUNT, "", "",
		                   G_MININT32, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:notify-peers-interval:
	 *
	 * Corresponds to the teamd notify_peers.interval.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_NOTIFY_PEERS_INTERVAL,
		 g_param_spec_int (NM_SETTING_TEAM_NOTIFY_PEERS_INTERVAL, "", "",
		                   G_MININT32, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:mcast-rejoin-count:
	 *
	 * Corresponds to the teamd mcast_rejoin.count.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_MCAST_REJOIN_COUNT,
		 g_param_spec_int (NM_SETTING_TEAM_MCAST_REJOIN_COUNT, "", "",
		                   G_MININT32, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:mcast-rejoin-interval:
	 *
	 * Corresponds to the teamd mcast_rejoin.interval.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_MCAST_REJOIN_INTERVAL,
		 g_param_spec_int (NM_SETTING_TEAM_MCAST_REJOIN_INTERVAL, "", "",
		                   G_MININT32, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:runner:
	 *
	 * Corresponds to the teamd runner.name.
	 * Permitted values are: "roundrobin", "broadcast", "activebackup",
	 * "loadbalance", "lacp".
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_RUNNER,
		 g_param_spec_string (NM_SETTING_TEAM_RUNNER, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:runner-hwaddr-policy:
	 *
	 * Corresponds to the teamd runner.hwaddr_policy.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_RUNNER_HWADDR_POLICY,
		 g_param_spec_string (NM_SETTING_TEAM_RUNNER_HWADDR_POLICY, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:runner-tx-hash:
	 *
	 * Corresponds to the teamd runner.tx_hash.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_RUNNER_TX_HASH,
		 g_param_spec_boxed (NM_SETTING_TEAM_RUNNER_TX_HASH, "", "",
		                     G_TYPE_STRV,
	                             G_PARAM_READWRITE |
		                     NM_SETTING_PARAM_INFERRABLE |
	                             G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:runner-tx-balancer:
	 *
	 * Corresponds to the teamd runner.tx_balancer.name.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_RUNNER_TX_BALANCER,
		 g_param_spec_string (NM_SETTING_TEAM_RUNNER_TX_BALANCER, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:runner-tx-balancer-interval:
	 *
	 * Corresponds to the teamd runner.tx_balancer.interval.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_RUNNER_TX_BALANCER_INTERVAL,
		 g_param_spec_int (NM_SETTING_TEAM_RUNNER_TX_BALANCER_INTERVAL, "", "",
		                   G_MININT32, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:runner-active:
	 *
	 * Corresponds to the teamd runner.active.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_RUNNER_ACTIVE,
		 g_param_spec_boolean (NM_SETTING_TEAM_RUNNER_ACTIVE, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:runner-fast-rate:
	 *
	 * Corresponds to the teamd runner.fast_rate.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_RUNNER_FAST_RATE,
		 g_param_spec_boolean (NM_SETTING_TEAM_RUNNER_FAST_RATE, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:runner-sys-prio:
	 *
	 * Corresponds to the teamd runner.sys_prio.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_RUNNER_SYS_PRIO,
		 g_param_spec_int (NM_SETTING_TEAM_RUNNER_SYS_PRIO, "", "",
		                   G_MININT32, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:runner-min-ports:
	 *
	 * Corresponds to the teamd runner.min_ports.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_RUNNER_MIN_PORTS,
		 g_param_spec_int (NM_SETTING_TEAM_RUNNER_MIN_PORTS, "", "",
		                   G_MININT32, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeam:runner-agg-select-policy:
	 *
	 * Corresponds to the teamd runner.agg_select_policy.
	 *
	 * Since: 1.10.2
	 **/
	g_object_class_install_property
		(object_class, PROP_RUNNER_AGG_SELECT_POLICY,
		 g_param_spec_string (NM_SETTING_TEAM_RUNNER_AGG_SELECT_POLICY, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/* ---dbus---
	 * property: interface-name
	 * format: string
	 * description: Deprecated in favor of connection.interface-name, but can
	 *   be used for backward-compatibility with older daemons, to set the
	 *   team's interface name.
	 * ---end---
	 */
	_nm_setting_class_add_dbus_only_property (parent_class, "interface-name",
	                                          G_VARIANT_TYPE_STRING,
	                                          _nm_setting_get_deprecated_virtual_interface_name,
	                                          NULL);
}
