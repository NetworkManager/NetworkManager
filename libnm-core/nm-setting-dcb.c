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
 * Copyright 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-setting-dcb.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"
#include "nm-core-enum-types.h"

/**
 * SECTION:nm-setting-dcb
 * @short_description: Connection properties for Data Center Bridging
 *
 * The #NMSettingDcb object is a #NMSetting subclass that describes properties
 * for enabling and using Data Center Bridging (DCB) on Ethernet networks.
 * DCB is a set of protocols (including 802.1Qbb, 802.1Qaz, 802.1Qau, and
 * 802.1AB) to eliminate packet loss in Ethernet networks and support the use
 * of storage technologies like Fibre Channel over Ethernet (FCoE) and iSCSI.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingDcb, nm_setting_dcb, NM_TYPE_SETTING,
                         _nm_register_setting (DCB, NM_SETTING_PRIORITY_HW_AUX))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_DCB)

#define NM_SETTING_DCB_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_DCB, NMSettingDcbPrivate))

typedef struct {
	NMSettingDcbFlags app_fcoe_flags;
	gint              app_fcoe_priority;
	char *            app_fcoe_mode;

	NMSettingDcbFlags app_iscsi_flags;
	gint              app_iscsi_priority;

	NMSettingDcbFlags app_fip_flags;
	gint              app_fip_priority;

	/* Priority Flow Control */
	NMSettingDcbFlags pfc_flags;
	guint             pfc[8];

	/* Priority Groups */
	NMSettingDcbFlags priority_group_flags;
	guint             priority_group_id[8];
	guint             priority_group_bandwidth[8];
	guint             priority_bandwidth[8];
	guint             priority_strict[8];
	guint             priority_traffic_class[8];
} NMSettingDcbPrivate;

enum {
	PROP_0,
	PROP_APP_FCOE_FLAGS,
	PROP_APP_FCOE_PRIORITY,
	PROP_APP_FCOE_MODE,

	PROP_APP_ISCSI_FLAGS,
	PROP_APP_ISCSI_PRIORITY,

	PROP_APP_FIP_FLAGS,
	PROP_APP_FIP_PRIORITY,

	PROP_PFC_FLAGS,
	PROP_PFC,

	PROP_PRIORITY_GROUP_FLAGS,
	PROP_PRIORITY_GROUP_ID,
	PROP_PRIORITY_GROUP_BANDWIDTH,
	PROP_PRIORITY_BANDWIDTH,
	PROP_PRIORITY_STRICT,
	PROP_PRIORITY_TRAFFIC_CLASS,

	LAST_PROP
};

/**
 * nm_setting_dcb_new:
 *
 * Creates a new #NMSettingDcb object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingDcb object
 **/
NMSetting *
nm_setting_dcb_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_DCB, NULL);
}

/**
 * nm_setting_dcb_get_app_fcoe_flags:
 * @setting: the #NMSettingDcb
 *
 * Returns: the #NMSettingDcb:app-fcoe-flags property of the setting
 **/
NMSettingDcbFlags
nm_setting_dcb_get_app_fcoe_flags (NMSettingDcb *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->app_fcoe_flags;
}

/**
 * nm_setting_dcb_get_app_fcoe_priority:
 * @setting: the #NMSettingDcb
 *
 * Returns: the #NMSettingDcb:app-fcoe-priority property of the setting
 **/
gint
nm_setting_dcb_get_app_fcoe_priority (NMSettingDcb *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->app_fcoe_priority;
}

/**
 * nm_setting_dcb_get_app_fcoe_mode:
 * @setting: the #NMSettingDcb
 *
 * Returns: the #NMSettingDcb:app-fcoe-mode property of the setting
 **/
const char *
nm_setting_dcb_get_app_fcoe_mode (NMSettingDcb *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), NULL);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->app_fcoe_mode;
}

/**
 * nm_setting_dcb_get_app_iscsi_flags:
 * @setting: the #NMSettingDcb
 *
 * Returns: the #NMSettingDcb:app-iscsi-flags property of the setting
 **/
NMSettingDcbFlags
nm_setting_dcb_get_app_iscsi_flags (NMSettingDcb *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->app_iscsi_flags;
}

/**
 * nm_setting_dcb_get_app_iscsi_priority:
 * @setting: the #NMSettingDcb
 *
 * Returns: the #NMSettingDcb:app-iscsi-priority property of the setting
 **/
gint
nm_setting_dcb_get_app_iscsi_priority (NMSettingDcb *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->app_iscsi_priority;
}

/**
 * nm_setting_dcb_get_app_fip_flags:
 * @setting: the #NMSettingDcb
 *
 * Returns: the #NMSettingDcb:app-fip-flags property of the setting
 **/
NMSettingDcbFlags
nm_setting_dcb_get_app_fip_flags (NMSettingDcb *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->app_fip_flags;
}

/**
 * nm_setting_dcb_get_app_fip_priority:
 * @setting: the #NMSettingDcb
 *
 * Returns: the #NMSettingDcb:app-fip-priority property of the setting
 **/
gint
nm_setting_dcb_get_app_fip_priority (NMSettingDcb *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->app_fip_priority;
}

/**
 * nm_setting_dcb_get_priority_flow_control_flags:
 * @setting: the #NMSettingDcb
 *
 * Returns: the #NMSettingDcb:priority-flow-control-flags property of the setting
 **/
NMSettingDcbFlags
nm_setting_dcb_get_priority_flow_control_flags (NMSettingDcb *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->pfc_flags;
}

/**
 * nm_setting_dcb_get_priority_flow_control:
 * @setting: the #NMSettingDcb
 * @user_priority: the User Priority (0 - 7) to retrieve flow control for
 *
 * Returns: %TRUE if flow control is enabled for the given @user_priority,
 * %FALSE if not enabled
 **/
gboolean
nm_setting_dcb_get_priority_flow_control (NMSettingDcb *setting, guint user_priority)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), FALSE);
	g_return_val_if_fail (user_priority <= 7, FALSE);

	return !!NM_SETTING_DCB_GET_PRIVATE (setting)->pfc[user_priority];
}

/**
 * nm_setting_dcb_set_priority_flow_control:
 * @setting: the #NMSettingDcb
 * @user_priority: the User Priority (0 - 7) to set flow control for
 * @enabled: %TRUE to enable flow control for this priority, %FALSE to disable it
 *
 * These values are only valid when #NMSettingDcb:priority-flow-control includes
 * the %NM_SETTING_DCB_FLAG_ENABLE flag.
 **/
void
nm_setting_dcb_set_priority_flow_control (NMSettingDcb *setting,
                                          guint user_priority,
                                          gboolean enabled)
{
	NMSettingDcbPrivate *priv;
	guint uint_enabled = enabled ? 1 : 0;

	g_return_if_fail (NM_IS_SETTING_DCB (setting));
	g_return_if_fail (user_priority <= 7);

	priv = NM_SETTING_DCB_GET_PRIVATE (setting);
	if (priv->pfc[user_priority] != uint_enabled) {
		priv->pfc[user_priority] = uint_enabled;
		g_object_notify (G_OBJECT (setting), NM_SETTING_DCB_PRIORITY_FLOW_CONTROL);
	}
}

/**
 * nm_setting_dcb_get_priority_group_flags:
 * @setting: the #NMSettingDcb
 *
 * Returns: the #NMSettingDcb:priority-group-flags property of the setting
 **/
NMSettingDcbFlags
nm_setting_dcb_get_priority_group_flags (NMSettingDcb *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->priority_group_flags;
}

/**
 * nm_setting_dcb_get_priority_group_id:
 * @setting: the #NMSettingDcb
 * @user_priority: the User Priority (0 - 7) to retrieve the group ID for
 *
 * Returns: the group number @user_priority is assigned to.  These values are
 * only valid when #NMSettingDcb:priority-group-flags includes the
 * %NM_SETTING_DCB_FLAG_ENABLE flag.
 **/
guint
nm_setting_dcb_get_priority_group_id (NMSettingDcb *setting, guint user_priority)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);
	g_return_val_if_fail (user_priority <= 7, 0);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->priority_group_id[user_priority];
}

/**
 * nm_setting_dcb_set_priority_group_id:
 * @setting: the #NMSettingDcb
 * @user_priority: the User Priority (0 - 7) to set flow control for
 * @group_id: the group (0 - 7) to assign @user_priority to, or 15 for the
 * unrestricted group.
 *
 * These values are only valid when #NMSettingDcb:priority-group-flags includes
 * the %NM_SETTING_DCB_FLAG_ENABLE flag.
 **/
void
nm_setting_dcb_set_priority_group_id (NMSettingDcb *setting,
                                      guint user_priority,
                                      guint group_id)
{
	NMSettingDcbPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_DCB (setting));
	g_return_if_fail (user_priority <= 7);
	g_return_if_fail (group_id <= 7 || group_id == 15);

	priv = NM_SETTING_DCB_GET_PRIVATE (setting);
	if (priv->priority_group_id[user_priority] != group_id) {
		priv->priority_group_id[user_priority] = group_id;
		g_object_notify (G_OBJECT (setting), NM_SETTING_DCB_PRIORITY_GROUP_ID);
	}
}

/**
 * nm_setting_dcb_get_priority_group_bandwidth:
 * @setting: the #NMSettingDcb
 * @group_id: the priority group (0 - 7) to retrieve the bandwidth percentage for
 *
 * Returns: the bandwidth percentage assigned to @group_id.  These values are
 * only valid when #NMSettingDcb:priority-group-flags includes the
 * %NM_SETTING_DCB_FLAG_ENABLE flag.
 **/
guint
nm_setting_dcb_get_priority_group_bandwidth (NMSettingDcb *setting, guint group_id)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);
	g_return_val_if_fail (group_id <= 7, FALSE);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->priority_group_bandwidth[group_id];
}

/**
 * nm_setting_dcb_set_priority_group_bandwidth:
 * @setting: the #NMSettingDcb
 * @group_id: the priority group (0 - 7) to set the bandwidth percentage for
 * @bandwidth_percent: the bandwidth percentage (0 - 100) to assign to @group_id to
 *
 * These values are only valid when #NMSettingDcb:priority-group-flags includes
 * the %NM_SETTING_DCB_FLAG_ENABLE flag.
 **/
void
nm_setting_dcb_set_priority_group_bandwidth (NMSettingDcb *setting,
                                             guint group_id,
                                             guint bandwidth_percent)
{
	NMSettingDcbPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_DCB (setting));
	g_return_if_fail (group_id <= 7);
	g_return_if_fail (bandwidth_percent <= 100);

	priv = NM_SETTING_DCB_GET_PRIVATE (setting);
	if (priv->priority_group_bandwidth[group_id] != bandwidth_percent) {
		priv->priority_group_bandwidth[group_id] = bandwidth_percent;
		g_object_notify (G_OBJECT (setting), NM_SETTING_DCB_PRIORITY_GROUP_BANDWIDTH);
	}
}

/**
 * nm_setting_dcb_get_priority_bandwidth:
 * @setting: the #NMSettingDcb
 * @user_priority: the User Priority (0 - 7) to retrieve the group bandwidth percentage for
 *
 * Returns: the allowed bandwidth percentage of @user_priority in its priority group.
 * These values are only valid when #NMSettingDcb:priority-group-flags includes the
 * %NM_SETTING_DCB_FLAG_ENABLE flag.
 **/
guint
nm_setting_dcb_get_priority_bandwidth (NMSettingDcb *setting, guint user_priority)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);
	g_return_val_if_fail (user_priority <= 7, FALSE);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->priority_bandwidth[user_priority];
}

/**
 * nm_setting_dcb_set_priority_bandwidth:
 * @setting: the #NMSettingDcb
 * @user_priority: the User Priority (0 - 7) to set the bandwidth percentage for
 * @bandwidth_percent: the bandwidth percentage (0 - 100) that @user_priority is
 * allowed to use within its priority group
 *
 * These values are only valid when #NMSettingDcb:priority-group-flags includes
 * the %NM_SETTING_DCB_FLAG_ENABLE flag.
 **/
void
nm_setting_dcb_set_priority_bandwidth (NMSettingDcb *setting,
                                       guint user_priority,
                                       guint bandwidth_percent)
{
	NMSettingDcbPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_DCB (setting));
	g_return_if_fail (user_priority <= 7);
	g_return_if_fail (bandwidth_percent <= 100);

	priv = NM_SETTING_DCB_GET_PRIVATE (setting);
	if (priv->priority_bandwidth[user_priority] != bandwidth_percent) {
		priv->priority_bandwidth[user_priority] = bandwidth_percent;
		g_object_notify (G_OBJECT (setting), NM_SETTING_DCB_PRIORITY_BANDWIDTH);
	}
}

/**
 * nm_setting_dcb_get_priority_strict_bandwidth:
 * @setting: the #NMSettingDcb
 * @user_priority: the User Priority (0 - 7) to retrieve strict bandwidth for
 *
 * Returns: %TRUE if @user_priority may use all of the bandwidth allocated to its
 * assigned group, or %FALSE if not. These values are only valid when
 * #NMSettingDcb:priority-group-flags includes the %NM_SETTING_DCB_FLAG_ENABLE flag.
 **/
gboolean
nm_setting_dcb_get_priority_strict_bandwidth (NMSettingDcb *setting, guint user_priority)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);
	g_return_val_if_fail (user_priority <= 7, FALSE);

	return !!NM_SETTING_DCB_GET_PRIVATE (setting)->priority_strict[user_priority];
}

/**
 * nm_setting_dcb_set_priority_strict_bandwidth:
 * @setting: the #NMSettingDcb
 * @user_priority: the User Priority (0 - 7) to set strict bandwidth for
 * @strict: %TRUE to allow @user_priority to use all the bandwidth allocated to
 * its priority group, or %FALSE if not
 *
 * These values are only valid when #NMSettingDcb:priority-group-flags includes
 * the %NM_SETTING_DCB_FLAG_ENABLE flag.
 **/
void
nm_setting_dcb_set_priority_strict_bandwidth (NMSettingDcb *setting,
                                              guint user_priority,
                                              gboolean strict)
{
	NMSettingDcbPrivate *priv;
	guint uint_strict = strict ? 1 : 0;

	g_return_if_fail (NM_IS_SETTING_DCB (setting));
	g_return_if_fail (user_priority <= 7);

	priv = NM_SETTING_DCB_GET_PRIVATE (setting);
	if (priv->priority_strict[user_priority] != uint_strict) {
		priv->priority_strict[user_priority] = uint_strict;
		g_object_notify (G_OBJECT (setting), NM_SETTING_DCB_PRIORITY_STRICT_BANDWIDTH);
	}
}

/**
 * nm_setting_dcb_get_priority_traffic_class:
 * @setting: the #NMSettingDcb
 * @user_priority: the User Priority (0 - 7) to retrieve the traffic class for
 *
 * Returns: the traffic class assigned to @user_priority. These values are only
 * valid when #NMSettingDcb:priority-group-flags includes the
 * %NM_SETTING_DCB_FLAG_ENABLE flag.
 **/
guint
nm_setting_dcb_get_priority_traffic_class (NMSettingDcb *setting, guint user_priority)
{
	g_return_val_if_fail (NM_IS_SETTING_DCB (setting), 0);
	g_return_val_if_fail (user_priority <= 7, FALSE);

	return NM_SETTING_DCB_GET_PRIVATE (setting)->priority_traffic_class[user_priority];
}

/**
 * nm_setting_dcb_set_priority_traffic_clas:
 * @setting: the #NMSettingDcb
 * @user_priority: the User Priority (0 - 7) to set the bandwidth percentage for
 * @traffic_class: the traffic_class (0 - 7) that @user_priority should map to
 *
 * These values are only valid when #NMSettingDcb:priority-group-flags includes
 * the %NM_SETTING_DCB_FLAG_ENABLE flag.
 **/
void
nm_setting_dcb_set_priority_traffic_class (NMSettingDcb *setting,
                                           guint user_priority,
                                           guint traffic_class)
{
	NMSettingDcbPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_DCB (setting));
	g_return_if_fail (user_priority <= 7);
	g_return_if_fail (traffic_class <= 7);

	priv = NM_SETTING_DCB_GET_PRIVATE (setting);
	if (priv->priority_traffic_class[user_priority] != traffic_class) {
		priv->priority_traffic_class[user_priority] = traffic_class;
		g_object_notify (G_OBJECT (setting), NM_SETTING_DCB_PRIORITY_TRAFFIC_CLASS);
	}
}

/*****************************************************************************/

#define DCB_FLAGS_ALL (NM_SETTING_DCB_FLAG_ENABLE | \
                       NM_SETTING_DCB_FLAG_ADVERTISE | \
                       NM_SETTING_DCB_FLAG_WILLING)

static gboolean
check_dcb_flags (NMSettingDcbFlags flags, const char *prop_name, GError **error)
{
	if (flags & ~DCB_FLAGS_ALL) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("flags invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_DCB_SETTING_NAME, prop_name);
		return FALSE;
	}

	if (!(flags & NM_SETTING_DCB_FLAG_ENABLE) && (flags & ~NM_SETTING_DCB_FLAG_ENABLE)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("flags invalid - disabled"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_DCB_SETTING_NAME, prop_name);
		return FALSE;
	}

	return TRUE;
}

static gboolean
check_uint_array (const guint *array,
                  guint len,
                  NMSettingDcbFlags flags,
                  guint max,
                  guint extra,
                  gboolean sum_pct,
                  const char *prop_name,
                  GError **error)
{
	guint i, sum = 0;

	/* Ensure each element is <= to max or equals extra */
	for (i = 0; i < len; i++) {
		if (!(flags & NM_SETTING_DCB_FLAG_ENABLE) && array[i]) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property invalid (not enabled)"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_DCB_SETTING_NAME, prop_name);
			return FALSE;
		}

		if ((array[i] > max) && (array[i] != extra)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("element invalid"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_DCB_SETTING_NAME, prop_name);
			return FALSE;
		}
		sum += array[i];
	}

	/* Verify sum of percentages */
	if (sum_pct) {
		if (flags & NM_SETTING_DCB_FLAG_ENABLE) {
			/* If the feature is enabled, sum must equal 100% */
			if (sum != 100) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("sum not 100%"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_DCB_SETTING_NAME, prop_name);
				return FALSE;
			}
		} else {
			/* If the feature is disabled, sum must equal 0%, which was checked
			 * by the for() loop above.
			 */
			g_assert_cmpint (sum, ==, 0);
		}
	}

	return TRUE;
}

static gboolean
check_priority (gint val,
                NMSettingDcbFlags flags,
                const char *prop_name,
                GError **error)
{
	if (!(flags & NM_SETTING_DCB_FLAG_ENABLE) && (val >= 0)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property invalid (not enabled)"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_DCB_SETTING_NAME, prop_name);
		return FALSE;
	}

	if (val < -1 || val > 7) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_DCB_SETTING_NAME, prop_name);
		return FALSE;
	}
	return TRUE;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingDcbPrivate *priv = NM_SETTING_DCB_GET_PRIVATE (setting);

	if (!check_dcb_flags (priv->app_fcoe_flags, NM_SETTING_DCB_APP_FCOE_FLAGS, error))
		return FALSE;

	if (!check_priority (priv->app_fcoe_priority, priv->app_fcoe_flags, NM_SETTING_DCB_APP_FCOE_PRIORITY, error))
		return FALSE;

	if (!priv->app_fcoe_mode) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_MISSING_PROPERTY,
		                     _("property missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_DCB_SETTING_NAME, NM_SETTING_DCB_APP_FCOE_MODE);
		return FALSE;
	}

	if (strcmp (priv->app_fcoe_mode, NM_SETTING_DCB_FCOE_MODE_FABRIC) &&
	    strcmp (priv->app_fcoe_mode, NM_SETTING_DCB_FCOE_MODE_VN2VN)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property invalid"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_DCB_SETTING_NAME, NM_SETTING_DCB_APP_FCOE_MODE);
		return FALSE;
	}

	if (!check_dcb_flags (priv->app_iscsi_flags, NM_SETTING_DCB_APP_ISCSI_FLAGS, error))
		return FALSE;

	if (!check_priority (priv->app_iscsi_priority, priv->app_iscsi_flags, NM_SETTING_DCB_APP_ISCSI_PRIORITY, error))
		return FALSE;

	if (!check_dcb_flags (priv->app_fip_flags, NM_SETTING_DCB_APP_FIP_FLAGS, error))
		return FALSE;

	if (!check_priority (priv->app_fip_priority, priv->app_fip_flags, NM_SETTING_DCB_APP_FIP_PRIORITY, error))
		return FALSE;

	if (!check_dcb_flags (priv->pfc_flags, NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS, error))
		return FALSE;

	if (!check_uint_array (priv->pfc, G_N_ELEMENTS (priv->pfc), priv->pfc_flags, 1, 0, FALSE, NM_SETTING_DCB_PRIORITY_FLOW_CONTROL, error))
		return FALSE;

	if (!check_dcb_flags (priv->priority_group_flags, NM_SETTING_DCB_PRIORITY_GROUP_FLAGS, error))
		return FALSE;

	if (!check_uint_array (priv->priority_group_id,
	                       G_N_ELEMENTS (priv->priority_group_id),
	                       priv->priority_group_flags,
	                       7,
	                       15,
	                       FALSE,
	                       NM_SETTING_DCB_PRIORITY_GROUP_ID,
	                       error))
		return FALSE;

	if (!check_uint_array (priv->priority_group_bandwidth,
	                       G_N_ELEMENTS (priv->priority_group_bandwidth),
	                       priv->priority_group_flags,
	                       100,
	                       0,
	                       TRUE,
	                       NM_SETTING_DCB_PRIORITY_GROUP_BANDWIDTH,
	                       error))
		return FALSE;

	/* FIXME: sum bandwidths in each group */
	if (!check_uint_array (priv->priority_bandwidth,
	                       G_N_ELEMENTS (priv->priority_bandwidth),
	                       priv->priority_group_flags,
	                       100,
	                       0,
	                       FALSE,
	                       NM_SETTING_DCB_PRIORITY_BANDWIDTH,
	                       error))
		return FALSE;

	if (!check_uint_array (priv->priority_strict,
	                       G_N_ELEMENTS (priv->priority_strict),
	                       priv->priority_group_flags,
	                       1,
	                       0,
	                       FALSE,
	                       NM_SETTING_DCB_PRIORITY_STRICT_BANDWIDTH,
	                       error))
		return FALSE;

	if (!check_uint_array (priv->priority_traffic_class,
	                       G_N_ELEMENTS (priv->priority_traffic_class),
	                       priv->priority_group_flags,
	                       7,
	                       0,
	                       FALSE,
	                       NM_SETTING_DCB_PRIORITY_TRAFFIC_CLASS,
	                       error))
		return FALSE;

	return TRUE;
}

/*****************************************************************************/

static void
nm_setting_dcb_init (NMSettingDcb *setting)
{
}

G_STATIC_ASSERT (sizeof (guint) == sizeof (gboolean));

static inline void
set_array_from_gvalue (const GValue *v, uint *a, size_t len)
{
	GArray *src = g_value_get_boxed (v);
	const guint total_len = len * sizeof (a[0]);

	memset (a, 0, total_len);
	if (src) {
		g_return_if_fail (g_array_get_element_size (src) == sizeof (a[0]));
		g_return_if_fail (src->len == len);
		memcpy (a, src->data, total_len);
	}
}
#define SET_ARRAY_FROM_GVALUE(v, a)  set_array_from_gvalue (v, a, G_N_ELEMENTS (a))

static inline void
set_gvalue_from_array (GValue *v, uint *a, size_t len)
{
	GArray *src = g_array_sized_new (FALSE, TRUE, sizeof (guint), len);

	g_array_append_vals (src, a, len);
	g_value_take_boxed (v, src);
}

#define SET_GVALUE_FROM_ARRAY(v, a) set_gvalue_from_array (v, a, G_N_ELEMENTS (a))

static GVariant *
_nm_setting_dcb_uint_array_to_dbus (const GValue *prop_value)
{
	GArray *src = g_value_get_boxed (prop_value);

	return g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32, src->data, src->len, sizeof (guint32));
}

static void
_nm_setting_dcb_uint_array_from_dbus (GVariant *dbus_value,
                                      GValue *prop_value)
{
	gconstpointer array;
	gsize length;

	array = g_variant_get_fixed_array (dbus_value, &length, sizeof (guint32));
	set_gvalue_from_array (prop_value, (guint *) array, length);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingDcbPrivate *priv = NM_SETTING_DCB_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_APP_FCOE_FLAGS:
		priv->app_fcoe_flags = g_value_get_flags (value);
		break;
	case PROP_APP_FCOE_PRIORITY:
		priv->app_fcoe_priority = g_value_get_int (value);
		break;
	case PROP_APP_FCOE_MODE:
		g_free (priv->app_fcoe_mode);
		priv->app_fcoe_mode = g_value_dup_string (value);
		break;
	case PROP_APP_ISCSI_FLAGS:
		priv->app_iscsi_flags = g_value_get_flags (value);
		break;
	case PROP_APP_ISCSI_PRIORITY:
		priv->app_iscsi_priority = g_value_get_int (value);
		break;
	case PROP_APP_FIP_FLAGS:
		priv->app_fip_flags = g_value_get_flags (value);
		break;
	case PROP_APP_FIP_PRIORITY:
		priv->app_fip_priority = g_value_get_int (value);
		break;
	case PROP_PFC_FLAGS:
		priv->pfc_flags = g_value_get_flags (value);
		break;
	case PROP_PFC:
		SET_ARRAY_FROM_GVALUE (value, priv->pfc);
		break;
	case PROP_PRIORITY_GROUP_FLAGS:
		priv->priority_group_flags = g_value_get_flags (value);
		break;
	case PROP_PRIORITY_GROUP_ID:
		SET_ARRAY_FROM_GVALUE (value, priv->priority_group_id);
		break;
	case PROP_PRIORITY_GROUP_BANDWIDTH:
		SET_ARRAY_FROM_GVALUE (value, priv->priority_group_bandwidth);
		break;
	case PROP_PRIORITY_BANDWIDTH:
		SET_ARRAY_FROM_GVALUE (value, priv->priority_bandwidth);
		break;
	case PROP_PRIORITY_STRICT:
		SET_ARRAY_FROM_GVALUE (value, priv->priority_strict);
		break;
	case PROP_PRIORITY_TRAFFIC_CLASS:
		SET_ARRAY_FROM_GVALUE (value, priv->priority_traffic_class);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingDcb *setting = NM_SETTING_DCB (object);
	NMSettingDcbPrivate *priv = NM_SETTING_DCB_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_APP_FCOE_FLAGS:
		g_value_set_flags (value, priv->app_fcoe_flags);
		break;
	case PROP_APP_FCOE_PRIORITY:
		g_value_set_int (value, priv->app_fcoe_priority);
		break;
	case PROP_APP_FCOE_MODE:
		g_value_set_string (value, priv->app_fcoe_mode);
		break;
	case PROP_APP_ISCSI_FLAGS:
		g_value_set_flags (value, priv->app_iscsi_flags);
		break;
	case PROP_APP_ISCSI_PRIORITY:
		g_value_set_int (value, priv->app_iscsi_priority);
		break;
	case PROP_APP_FIP_FLAGS:
		g_value_set_flags (value, priv->app_fip_flags);
		break;
	case PROP_APP_FIP_PRIORITY:
		g_value_set_int (value, priv->app_fip_priority);
		break;
	case PROP_PFC_FLAGS:
		g_value_set_flags (value, priv->pfc_flags);
		break;
	case PROP_PFC:
		SET_GVALUE_FROM_ARRAY (value, priv->pfc);
		break;
	case PROP_PRIORITY_GROUP_FLAGS:
		g_value_set_flags (value, priv->priority_group_flags);
		break;
	case PROP_PRIORITY_GROUP_ID:
		SET_GVALUE_FROM_ARRAY (value, priv->priority_group_id);
		break;
	case PROP_PRIORITY_GROUP_BANDWIDTH:
		SET_GVALUE_FROM_ARRAY (value, priv->priority_group_bandwidth);
		break;
	case PROP_PRIORITY_BANDWIDTH:
		SET_GVALUE_FROM_ARRAY (value, priv->priority_bandwidth);
		break;
	case PROP_PRIORITY_STRICT:
		SET_GVALUE_FROM_ARRAY (value, priv->priority_strict);
		break;
	case PROP_PRIORITY_TRAFFIC_CLASS:
		SET_GVALUE_FROM_ARRAY (value, priv->priority_traffic_class);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMSettingDcbPrivate *priv = NM_SETTING_DCB_GET_PRIVATE (object);

	g_free (priv->app_fcoe_mode);

	G_OBJECT_CLASS (nm_setting_dcb_parent_class)->finalize (object);
}

static void
nm_setting_dcb_class_init (NMSettingDcbClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingDcbPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;
	parent_class->verify       = verify;

	/* Properties */
	/**
	 * NMSettingDcb:app-fcoe-flags:
	 *
	 * Specifies the #NMSettingDcbFlags for the DCB FCoE application.  Flags may
	 * be any combination of %NM_SETTING_DCB_FLAG_ENABLE,
	 * %NM_SETTING_DCB_FLAG_ADVERTISE, and %NM_SETTING_DCB_FLAG_WILLING.
	 **/
	/* ---ifcfg-rh---
	 * property: app-fcoe-flags
	 * variable: DCB_APP_FCOE_ENABLE, DCB_APP_FCOE_ADVERTISE, DCB_APP_FCOE_WILLING
	 * description: FCOE flags.
	 * default: no
	 * example: DCB_APP_FCOE_ENABLE=yes DCB_APP_FCOE_ADVERTISE=yes
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_APP_FCOE_FLAGS,
		 g_param_spec_flags (NM_SETTING_DCB_APP_FCOE_FLAGS, "", "",
		                     NM_TYPE_SETTING_DCB_FLAGS,
		                     NM_SETTING_DCB_FLAG_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingDcb:app-fcoe-priority:
	 *
	 * The highest User Priority (0 - 7) which FCoE frames should use, or -1 for
	 * default priority.  Only used when the #NMSettingDcb:app-fcoe-flags
	 * property includes the %NM_SETTING_DCB_FLAG_ENABLE flag.
	 **/
	/* ---ifcfg-rh---
	 * property: app-fcoe-priority
	 * variable: DCB_APP_FCOE_PRIORITY
	 * values: 0 - 7
	 * description: Priority of FCoE frames.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_APP_FCOE_PRIORITY,
		 g_param_spec_int (NM_SETTING_DCB_APP_FCOE_PRIORITY, "", "",
		                   -1, 7, -1,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingDcb:app-fcoe-mode:
	 *
	 * The FCoE controller mode; either %NM_SETTING_DCB_FCOE_MODE_FABRIC
	 * (default) or %NM_SETTING_DCB_FCOE_MODE_VN2VN.
	 **/
	/* ---ifcfg-rh---
	 * property: app-fcoe-mode
	 * variable: DCB_APP_FCOE_MODE
	 * values: fabric, vn2vn
	 * default: fabric
	 * description: FCoE controller mode.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_APP_FCOE_MODE,
		 g_param_spec_string (NM_SETTING_DCB_APP_FCOE_MODE, "", "",
		                      NM_SETTING_DCB_FCOE_MODE_FABRIC,
		                      G_PARAM_READWRITE |
		                      G_PARAM_CONSTRUCT |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingDcb:app-iscsi-flags:
	 *
	 * Specifies the #NMSettingDcbFlags for the DCB iSCSI application.  Flags
	 * may be any combination of %NM_SETTING_DCB_FLAG_ENABLE,
	 * %NM_SETTING_DCB_FLAG_ADVERTISE, and %NM_SETTING_DCB_FLAG_WILLING.
	 **/
	/* ---ifcfg-rh---
	 * property: app-iscsi-flags
	 * variable: DCB_APP_ISCSI_ENABLE, DCB_APP_ISCSI_ADVERTISE, DCB_APP_ISCSI_WILLING
	 * default: no
	 * description: iSCSI flags.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_APP_ISCSI_FLAGS,
		 g_param_spec_flags (NM_SETTING_DCB_APP_ISCSI_FLAGS, "", "",
		                     NM_TYPE_SETTING_DCB_FLAGS,
		                     NM_SETTING_DCB_FLAG_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingDcb:app-iscsi-priority:
	 *
	 * The highest User Priority (0 - 7) which iSCSI frames should use, or -1
	 * for default priority. Only used when the #NMSettingDcb:app-iscsi-flags
	 * property includes the %NM_SETTING_DCB_FLAG_ENABLE flag.
	 **/
	/* ---ifcfg-rh---
	 * property: app-iscsi-priority
	 * variable: DCB_APP_ISCSI_PRIORITY
	 * values: 0 - 7
	 * description: Priority of iSCSI frames.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_APP_ISCSI_PRIORITY,
		 g_param_spec_int (NM_SETTING_DCB_APP_ISCSI_PRIORITY, "", "",
		                   -1, 7, -1,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingDcb:app-fip-flags:
	 *
	 * Specifies the #NMSettingDcbFlags for the DCB FIP application.  Flags may
	 * be any combination of %NM_SETTING_DCB_FLAG_ENABLE,
	 * %NM_SETTING_DCB_FLAG_ADVERTISE, and %NM_SETTING_DCB_FLAG_WILLING.
	 **/
	/* ---ifcfg-rh---
	 * property: app-fip-flags
	 * variable: DCB_APP_FIP_ENABLE, DCB_APP_FIP_ADVERTISE, DCB_APP_FIP_WILLING
	 * default: no
	 * description: FIP flags.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_APP_FIP_FLAGS,
		 g_param_spec_flags (NM_SETTING_DCB_APP_FIP_FLAGS, "", "",
		                     NM_TYPE_SETTING_DCB_FLAGS,
		                     NM_SETTING_DCB_FLAG_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingDcb:app-fip-priority:
	 *
	 * The highest User Priority (0 - 7) which FIP frames should use, or -1 for
	 * default priority.  Only used when the #NMSettingDcb:app-fip-flags
	 * property includes the %NM_SETTING_DCB_FLAG_ENABLE flag.
	 **/
	/* ---ifcfg-rh---
	 * property: app-fip-priority
	 * variable: DCB_APP_FIP_PRIORITY
	 * values: 0 - 7
	 * description: Priority of FIP frames.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_APP_FIP_PRIORITY,
		 g_param_spec_int (NM_SETTING_DCB_APP_FIP_PRIORITY, "", "",
		                   -1, 7, -1,
		                   G_PARAM_READWRITE |
		                   G_PARAM_CONSTRUCT |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingDcb:priority-flow-control-flags:
	 *
	 * Specifies the #NMSettingDcbFlags for DCB Priority Flow Control (PFC).
	 * Flags may be any combination of %NM_SETTING_DCB_FLAG_ENABLE,
	 * %NM_SETTING_DCB_FLAG_ADVERTISE, and %NM_SETTING_DCB_FLAG_WILLING.
	 **/
	/* ---ifcfg-rh---
	 * property: priority-flow-control-flags
	 * variable: DCB_PFC_ENABLE, DCB_PFC_ADVERTISE, DCB_PFC_WILLING
	 * default: no
	 * description: Priority flow control flags.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PFC_FLAGS,
		 g_param_spec_flags (NM_SETTING_DCB_PRIORITY_FLOW_CONTROL_FLAGS, "", "",
		                     NM_TYPE_SETTING_DCB_FLAGS,
		                     NM_SETTING_DCB_FLAG_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingDcb:priority-flow-control: (type GArray(gboolean))
	 *
	 * An array of 8 boolean values, where the array index corresponds to the User
	 * Priority (0 - 7) and the value indicates whether or not the corresponding
	 * priority should transmit priority pause.
	 **/
	/* ---ifcfg-rh---
	 * property: priority-flow-control
	 * variable: DCB_PFC_UP
	 * description: Priority flow control values. String of 8 "0" and "1", where "0".
	 *   means "do not transmit priority pause", "1" means "transmit pause".
	 * example: DCB_PFC_UP=01101110
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PFC,
		 g_param_spec_boxed (NM_SETTING_DCB_PRIORITY_FLOW_CONTROL, "", "",
		                     G_TYPE_ARRAY,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_DCB_PRIORITY_FLOW_CONTROL,
	                                      G_VARIANT_TYPE ("au"),
	                                      _nm_setting_dcb_uint_array_to_dbus,
	                                      _nm_setting_dcb_uint_array_from_dbus);

	/**
	 * NMSettingDcb:priority-group-flags:
	 *
	 * Specifies the #NMSettingDcbFlags for DCB Priority Groups.  Flags may be
	 * any combination of %NM_SETTING_DCB_FLAG_ENABLE,
	 * %NM_SETTING_DCB_FLAG_ADVERTISE, and %NM_SETTING_DCB_FLAG_WILLING.
	 **/
	/* ---ifcfg-rh---
	 * property: priority-group-flags
	 * variable: DCB_PG_ENABLE, DCB_PG_ADVERTISE, DCB_PG_WILLING
	 * default: no
	 * description: Priority groups flags.
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PRIORITY_GROUP_FLAGS,
		 g_param_spec_flags (NM_SETTING_DCB_PRIORITY_GROUP_FLAGS, "", "",
		                     NM_TYPE_SETTING_DCB_FLAGS,
		                     NM_SETTING_DCB_FLAG_NONE,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingDcb:priority-group-id: (type GArray(guint))
	 *
	 * An array of 8 uint values, where the array index corresponds to the User
	 * Priority (0 - 7) and the value indicates the Priority Group ID.  Allowed
	 * Priority Group ID values are 0 - 7 or 15 for the unrestricted group.
	 **/
	/* ---ifcfg-rh---
	 * property: priority-group-id
	 * variable: DCB_PG_ID
	 * description: Priority groups values. String of eight priorities (0 - 7) or "f"
	 *   (unrestricted).
	 * example: DCB_PG_ID=1205f173
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PRIORITY_GROUP_ID,
		 g_param_spec_boxed (NM_SETTING_DCB_PRIORITY_GROUP_ID, "", "",
		                     G_TYPE_ARRAY,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_DCB_PRIORITY_GROUP_ID,
	                                      G_VARIANT_TYPE ("au"),
	                                      _nm_setting_dcb_uint_array_to_dbus,
	                                      _nm_setting_dcb_uint_array_from_dbus);

	/**
	 * NMSettingDcb:priority-group-bandwidth: (type GArray(guint))
	 *
	 * An array of 8 uint values, where the array index corresponds to the
	 * Priority Group ID (0 - 7) and the value indicates the percentage of link
	 * bandwidth allocated to that group.  Allowed values are 0 - 100, and the
	 * sum of all values must total 100 percents.
	 **/
	/* ---ifcfg-rh---
	 * property: priority-group-bandwidth
	 * variable: DCB_PG_PCT
	 * description: Priority groups values. Eight bandwidths (in percent), separated with commas.
	 * example: DCB_PG_PCT=10,5,10,15,10,10,10,30
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PRIORITY_GROUP_BANDWIDTH,
		 g_param_spec_boxed (NM_SETTING_DCB_PRIORITY_GROUP_BANDWIDTH, "", "",
		                     G_TYPE_ARRAY,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_DCB_PRIORITY_GROUP_BANDWIDTH,
	                                      G_VARIANT_TYPE ("au"),
	                                      _nm_setting_dcb_uint_array_to_dbus,
	                                      _nm_setting_dcb_uint_array_from_dbus);

	/**
	 * NMSettingDcb:priority-bandwidth: (type GArray(guint))
	 *
	 * An array of 8 uint values, where the array index corresponds to the User
	 * Priority (0 - 7) and the value indicates the percentage of bandwidth of
	 * the priority's assigned group that the priority may use.  The sum of all
	 * percentages for priorities which belong to the same group must total 100
	 * percents.
	 **/
	/* ---ifcfg-rh---
	 * property: priority-bandwidth
	 * variable: DCB_PG_UPPCT
	 * description: Priority values. Eight bandwidths (in percent), separated with commas.
	 *   The sum of the numbers must be 100.
	 * example: DCB_PG_UPPCT=7,13,10,10,15,15,10,20
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PRIORITY_BANDWIDTH,
		 g_param_spec_boxed (NM_SETTING_DCB_PRIORITY_BANDWIDTH, "", "",
		                     G_TYPE_ARRAY,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_DCB_PRIORITY_BANDWIDTH,
	                                      G_VARIANT_TYPE ("au"),
	                                      _nm_setting_dcb_uint_array_to_dbus,
	                                      _nm_setting_dcb_uint_array_from_dbus);

	/**
	 * NMSettingDcb:priority-strict-bandwidth: (type GArray(gboolean))
	 *
	 * An array of 8 boolean values, where the array index corresponds to the User
	 * Priority (0 - 7) and the value indicates whether or not the priority may
	 * use all of the bandwidth allocated to its assigned group.
	 **/
	/* ---ifcfg-rh---
	 * property: priority-strict-bandwidth
	 * variable: DCB_PG_STRICT
	 * description: Priority values. String of eight "0" or "1", where "0" means
	 *   "may not utilize all bandwidth", "1" means "may utilize all bandwidth".
	 * example: DCB_PG_STRICT=01101110
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PRIORITY_STRICT,
		 g_param_spec_boxed (NM_SETTING_DCB_PRIORITY_STRICT_BANDWIDTH, "", "",
		                     G_TYPE_ARRAY,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_DCB_PRIORITY_STRICT_BANDWIDTH,
	                                      G_VARIANT_TYPE ("au"),
	                                      _nm_setting_dcb_uint_array_to_dbus,
	                                      _nm_setting_dcb_uint_array_from_dbus);

	/**
	 * NMSettingDcb:priority-traffic-class: (type GArray(guint))
	 *
	 * An array of 8 uint values, where the array index corresponds to the User
	 * Priority (0 - 7) and the value indicates the traffic class (0 - 7) to
	 * which the priority is mapped.
	 **/
	/* ---ifcfg-rh---
	 * property: priority-traffic-class
	 * variable: DCB_PG_UP2TC
	 * description: Priority values. String of eight trafic class values (0 - 7).
	 * example: DCB_PG_UP2TC=01623701
	 * ---end---
	 */
	g_object_class_install_property
		(object_class, PROP_PRIORITY_TRAFFIC_CLASS,
		 g_param_spec_boxed (NM_SETTING_DCB_PRIORITY_TRAFFIC_CLASS, "", "",
		                     G_TYPE_ARRAY,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class, NM_SETTING_DCB_PRIORITY_TRAFFIC_CLASS,
	                                      G_VARIANT_TYPE ("au"),
	                                      _nm_setting_dcb_uint_array_to_dbus,
	                                      _nm_setting_dcb_uint_array_from_dbus);
}
