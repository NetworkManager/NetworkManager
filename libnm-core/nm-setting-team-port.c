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
 * Copyright 2017 Red Hat, Inc.
 * Copyright 2013 Jiri Pirko <jiri@resnulli.us>
 */

#include "nm-default.h"

#include "nm-setting-team-port.h"

#include <ctype.h>
#include <stdlib.h>

#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-team-utils.h"

/**
 * SECTION:nm-setting-team-port
 * @short_description: Describes connection properties for team ports
 *
 * The #NMSettingTeamPort object is a #NMSetting subclass that describes
 * optional properties that apply to team ports.
 **/

/*****************************************************************************/

static GParamSpec *obj_properties[_NM_TEAM_ATTRIBUTE_PORT_NUM] = { NULL, };

typedef struct {
	NMTeamSetting *team_setting;
} NMSettingTeamPortPrivate;

G_DEFINE_TYPE (NMSettingTeamPort, nm_setting_team_port, NM_TYPE_SETTING)

#define NM_SETTING_TEAM_PORT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_TEAM_PORT, NMSettingTeamPortPrivate))

/*****************************************************************************/

NMTeamSetting *
_nm_setting_team_port_get_team_setting (NMSettingTeamPort *setting)
{
	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting;
}

/*****************************************************************************/

#define _maybe_changed(self, changed) \
	nm_team_setting_maybe_changed (NM_SETTING (_NM_ENSURE_TYPE (NMSettingTeamPort *, self)), (const GParamSpec *const*) obj_properties, (changed))

#define _maybe_changed_with_assert(self, changed) \
	G_STMT_START { \
		if (!_maybe_changed ((self), (changed))) \
			nm_assert_not_reached (); \
	} G_STMT_END

/*****************************************************************************/

/**
 * nm_setting_team_port_get_config:
 * @setting: the #NMSettingTeamPort
 *
 * Returns: the #NMSettingTeamPort:config property of the setting
 **/
const char *
nm_setting_team_port_get_config (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), NULL);

	return nm_team_setting_config_get (NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting);
}

/**
 * nm_setting_team_port_get_queue_id:
 * @setting: the #NMSettingTeamPort
 *
 * Returns: the #NMSettingTeamPort:queue_id property of the setting
 *
 * Since: 1.12
 **/
int
nm_setting_team_port_get_queue_id (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), -1);

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting->d.port.queue_id;
}

/**
 * nm_setting_team_port_get_prio:
 * @setting: the #NMSettingTeamPort
 *
 * Returns: the #NMSettingTeamPort:prio property of the setting
 *
 * Since: 1.12
 **/
int
nm_setting_team_port_get_prio (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), 0);

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting->d.port.prio;
}

/**
 * nm_setting_team_port_get_sticky:
 * @setting: the #NMSettingTeamPort
 *
 * Returns: the #NMSettingTeamPort:sticky property of the setting
 *
 * Since: 1.12
 **/
gboolean
nm_setting_team_port_get_sticky (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), FALSE);

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting->d.port.sticky;
}

/**
 * nm_setting_team_port_get_lacp_prio:
 * @setting: the #NMSettingTeamPort
 *
 * Returns: the #NMSettingTeamPort:lacp-prio property of the setting
 *
 * Since: 1.12
 **/
int
nm_setting_team_port_get_lacp_prio (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), 0);

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting->d.port.lacp_prio;
}

/**
 * nm_setting_team_port_get_lacp_key:
 * @setting: the #NMSettingTeamPort
 *
 * Returns: the #NMSettingTeamPort:lacp-key property of the setting
 *
 * Since: 1.12
 **/
int
nm_setting_team_port_get_lacp_key (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), 0);

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting->d.port.lacp_key;
}

/**
 * nm_setting_team_port_get_num_link_watchers:
 * @setting: the #NMSettingTeamPort
 *
 * Returns: the number of configured link watchers
 *
 * Since: 1.12
 **/
guint
nm_setting_team_port_get_num_link_watchers (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), 0);

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting->d.link_watchers->len;
}

/**
 * nm_setting_team_port_get_link_watcher:
 * @setting: the #NMSettingTeamPort
 * @idx: index number of the link watcher to return
 *
 * Returns: (transfer none): the link watcher at index @idx.
 *
 * Since: 1.12
 **/
NMTeamLinkWatcher *
nm_setting_team_port_get_link_watcher (NMSettingTeamPort *setting, guint idx)
{
	NMSettingTeamPortPrivate *priv;

	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), NULL);

	priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);

	g_return_val_if_fail (idx < priv->team_setting->d.link_watchers->len, NULL);

	return priv->team_setting->d.link_watchers->pdata[idx];
}

/**
 * nm_setting_team_port_add_link_watcher:
 * @setting: the #NMSettingTeamPort
 * @link_watcher: the link watcher to add
 *
 * Appends a new link watcher to the setting.
 *
 * Returns: %TRUE if the link watcher is added; %FALSE if an identical link
 * watcher was already there.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_team_port_add_link_watcher (NMSettingTeamPort *setting,
                                       NMTeamLinkWatcher *link_watcher)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), FALSE);
	g_return_val_if_fail (link_watcher != NULL, FALSE);

	return _maybe_changed (setting,
	                       nm_team_setting_value_link_watchers_add (NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting,
	                                                                link_watcher));
}

/**
 * nm_setting_team_port_remove_link_watcher:
 * @setting: the #NMSettingTeamPort
 * @idx: index number of the link watcher to remove
 *
 * Removes the link watcher at index #idx.
 *
 * Since: 1.12
 **/
void
nm_setting_team_port_remove_link_watcher (NMSettingTeamPort *setting, guint idx)
{
	NMSettingTeamPortPrivate *priv;

	g_return_if_fail (NM_IS_SETTING_TEAM_PORT (setting));

	priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);

	g_return_if_fail (idx < priv->team_setting->d.link_watchers->len);

	_maybe_changed_with_assert (setting,
	                            nm_team_setting_value_link_watchers_remove (priv->team_setting,
	                                                                        idx));
}

/**
 * nm_setting_team_port_remove_link_watcher_by_value:
 * @setting: the #NMSettingTeamPort
 * @link_watcher: the link watcher to remove
 *
 * Removes the link watcher entry matching link_watcher.
 *
 * Returns: %TRUE if the link watcher was found and removed, %FALSE otherwise.
 *
 * Since: 1.12
 **/
gboolean
nm_setting_team_port_remove_link_watcher_by_value (NMSettingTeamPort *setting,
                                                   NMTeamLinkWatcher *link_watcher)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), FALSE);
	g_return_val_if_fail (link_watcher, FALSE);

	return _maybe_changed (setting,
	                       nm_team_setting_value_link_watchers_remove_by_value (NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting,
	                                                                            link_watcher));
}

/**
 * nm_setting_team_port_clear_link_watchers:
 * @setting: the #NMSettingTeamPort
 *
 * Removes all configured link watchers.
 *
 * Since: 1.12
 **/
void
nm_setting_team_port_clear_link_watchers (NMSettingTeamPort *setting)
{
	g_return_if_fail (NM_IS_SETTING_TEAM_PORT (setting));

	_maybe_changed (setting,
	                nm_team_setting_value_link_watchers_set_list (NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting,
	                                                              NULL,
	                                                              0));
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);

	if (connection) {
		NMSettingConnection *s_con;
		const char *slave_type;

		s_con = nm_connection_get_setting_connection (connection);
		if (!s_con) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_MISSING_SETTING,
			             _("missing setting"));
			g_prefix_error (error, "%s: ", NM_SETTING_CONNECTION_SETTING_NAME);
			return FALSE;
		}

		slave_type = nm_setting_connection_get_slave_type (s_con);
		if (   slave_type
		    && strcmp (slave_type, NM_SETTING_TEAM_SETTING_NAME)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("A connection with a '%s' setting must have the slave-type set to '%s'. Instead it is '%s'"),
			             NM_SETTING_TEAM_PORT_SETTING_NAME,
			             NM_SETTING_TEAM_SETTING_NAME,
			             slave_type);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_CONNECTION_SETTING_NAME, NM_SETTING_CONNECTION_SLAVE_TYPE);
			return FALSE;
		}
	}

	if (!nm_team_setting_verify (priv->team_setting, error))
		return FALSE;

	return TRUE;
}

static NMTernary
compare_property (const NMSettInfoSetting *sett_info,
                  guint property_idx,
                  NMConnection *con_a,
                  NMSetting *set_a,
                  NMConnection *con_b,
                  NMSetting *set_b,
                  NMSettingCompareFlags flags)
{
	NMSettingTeamPortPrivate *a_priv;
	NMSettingTeamPortPrivate *b_priv;

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_TEAM_PORT_LINK_WATCHERS)) {

		if (NM_FLAGS_HAS (flags, NM_SETTING_COMPARE_FLAG_INFERRABLE))
			return NM_TERNARY_DEFAULT;
		if (!set_b)
			return TRUE;
		a_priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (set_a);
		b_priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (set_b);
		return nm_team_link_watchers_equal (a_priv->team_setting->d.link_watchers,
		                                    b_priv->team_setting->d.link_watchers,
		                                    TRUE);
	}

	if (nm_streq (sett_info->property_infos[property_idx].name, NM_SETTING_TEAM_PORT_CONFIG)) {
		if (set_b) {
			if (NM_FLAGS_HAS (flags, NM_SETTING_COMPARE_FLAG_INFERRABLE)) {
				/* If we are trying to match a connection in order to assume it (and thus
				 * @flags contains INFERRABLE), use the "relaxed" matching for team
				 * configuration. Otherwise, for all other purposes (including connection
				 * comparison before an update), resort to the default string comparison. */
				return TRUE;
			}

			a_priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (set_a);
			b_priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (set_b);

			return nm_streq0 (nm_team_setting_config_get (a_priv->team_setting),
			                  nm_team_setting_config_get (b_priv->team_setting));
		}

		return TRUE;
	}

	return NM_SETTING_CLASS (nm_setting_team_port_parent_class)->compare_property (sett_info,
	                                                                               property_idx,
	                                                                               con_a,
	                                                                               set_a,
	                                                                               con_b,
	                                                                               set_b,
	                                                                               flags);
}

static void
duplicate_copy_properties (const NMSettInfoSetting *sett_info,
                           NMSetting *src,
                           NMSetting *dst)
{
	_maybe_changed (NM_SETTING_TEAM_PORT (dst),
	                nm_team_setting_reset (NM_SETTING_TEAM_PORT_GET_PRIVATE (dst)->team_setting,
	                                       NM_SETTING_TEAM_PORT_GET_PRIVATE (src)->team_setting));
}

static gboolean
init_from_dbus (NMSetting *setting,
                GHashTable *keys,
                GVariant *setting_dict,
                GVariant *connection_dict,
                guint /* NMSettingParseFlags */ parse_flags,
                GError **error)
{
	guint32 changed = 0;
	gboolean success;

	success = nm_team_setting_reset_from_dbus (NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->team_setting,
	                                           setting_dict,
	                                           keys,
	                                           &changed,
	                                           parse_flags,
	                                           error);
	_maybe_changed (NM_SETTING_TEAM_PORT (setting), changed);
	return success;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingTeamPort *setting = NM_SETTING_TEAM_PORT (object);
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);

	switch (prop_id) {
	case NM_TEAM_ATTRIBUTE_CONFIG:
		g_value_set_string (value,
		                    nm_team_setting_config_get (priv->team_setting));
		break;
	case NM_TEAM_ATTRIBUTE_PORT_STICKY:
		g_value_set_boolean (value,
		                     nm_team_setting_value_get_bool (priv->team_setting,
		                                                     prop_id));
		break;
	case NM_TEAM_ATTRIBUTE_PORT_QUEUE_ID:
	case NM_TEAM_ATTRIBUTE_PORT_PRIO:
	case NM_TEAM_ATTRIBUTE_PORT_LACP_PRIO:
	case NM_TEAM_ATTRIBUTE_PORT_LACP_KEY:
		g_value_set_int (value,
		                 nm_team_setting_value_get_int32 (priv->team_setting,
		                                                  prop_id));
		break;
	case NM_TEAM_ATTRIBUTE_LINK_WATCHERS:
		g_value_take_boxed (value, _nm_utils_copy_array (priv->team_setting->d.link_watchers,
		                                                 (NMUtilsCopyFunc) _nm_team_link_watcher_ref,
		                                                 (GDestroyNotify) nm_team_link_watcher_unref));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingTeamPort *setting = NM_SETTING_TEAM_PORT (object);
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);
	guint32 changed;
	const GPtrArray *v_ptrarr;

	switch (prop_id) {
	case NM_TEAM_ATTRIBUTE_CONFIG:
		changed = nm_team_setting_config_set (priv->team_setting, g_value_get_string (value));
		break;
	case NM_TEAM_ATTRIBUTE_PORT_STICKY:
		changed = nm_team_setting_value_set_bool (priv->team_setting,
		                                          prop_id,
		                                          g_value_get_boolean (value));
		break;
	case NM_TEAM_ATTRIBUTE_PORT_QUEUE_ID:
	case NM_TEAM_ATTRIBUTE_PORT_PRIO:
	case NM_TEAM_ATTRIBUTE_PORT_LACP_PRIO:
	case NM_TEAM_ATTRIBUTE_PORT_LACP_KEY:
		changed = nm_team_setting_value_set_int32 (priv->team_setting,
		                                           prop_id,
		                                           g_value_get_int (value));
		break;
	case NM_TEAM_ATTRIBUTE_LINK_WATCHERS:
		v_ptrarr = g_value_get_boxed (value);
		changed = nm_team_setting_value_link_watchers_set_list (priv->team_setting,
		                                                        v_ptrarr ? (const NMTeamLinkWatcher *const*) v_ptrarr->pdata : NULL,
		                                                        v_ptrarr ? v_ptrarr->len                                     : 0u);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		return;
	}

	_maybe_changed (setting, changed & ~(((guint32) 1) << prop_id));
}

/*****************************************************************************/

static void
nm_setting_team_port_init (NMSettingTeamPort *setting)
{
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);

	priv->team_setting = nm_team_setting_new (TRUE, NULL);
}

/**
 * nm_setting_team_port_new:
 *
 * Creates a new #NMSettingTeamPort object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingTeamPort object
 **/
NMSetting *
nm_setting_team_port_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_TEAM_PORT, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (object);

	nm_team_setting_free (priv->team_setting);

	G_OBJECT_CLASS (nm_setting_team_port_parent_class)->finalize (object);
}

static void
nm_setting_team_port_class_init (NMSettingTeamPortClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	g_type_class_add_private (klass, sizeof (NMSettingTeamPortPrivate));

	object_class->get_property     = get_property;
	object_class->set_property     = set_property;
	object_class->finalize         = finalize;

	setting_class->compare_property          = compare_property;
	setting_class->verify                    = verify;
	setting_class->duplicate_copy_properties = duplicate_copy_properties;
	setting_class->init_from_dbus            = init_from_dbus;

#define _property_override(_properties_override, _param_spec, _variant_type, _is_link_watcher) \
	_properties_override_add ((_properties_override), \
	                          .param_spec          = (_param_spec), \
	                          .dbus_type           = G_VARIANT_TYPE (""_variant_type""), \
	                          .to_dbus_fcn         = _nm_team_settings_property_to_dbus, \
	                          .gprop_from_dbus_fcn = ((_is_link_watcher) ? _nm_team_settings_property_from_dbus_link_watchers : NULL))

	/**
	 * NMSettingTeamPort:config:
	 *
	 * The JSON configuration for the team port. The property should contain raw
	 * JSON configuration data suitable for teamd, because the value is passed
	 * directly to teamd. If not specified, the default configuration is
	 * used. See man teamd.conf for the format details.
	 **/
	/* ---ifcfg-rh---
	 * property: config
	 * variable: TEAM_PORT_CONFIG
	 * description: Team port configuration in JSON. See man teamd.conf for details.
	 * ---end---
	 */
	obj_properties[NM_TEAM_ATTRIBUTE_CONFIG] =
	    g_param_spec_string (NM_SETTING_TEAM_PORT_CONFIG, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_CONFIG], "s", FALSE);

	/**
	 * NMSettingTeamPort:queue-id:
	 *
	 * Corresponds to the teamd ports.PORTIFNAME.queue_id.
	 * When set to -1 means the parameter is skipped from the json config.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_PORT_QUEUE_ID] =
	    g_param_spec_int (NM_SETTING_TEAM_PORT_QUEUE_ID, "", "",
	                      G_MININT32, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_PORT_QUEUE_ID], "i", FALSE);

	/**
	 * NMSettingTeamPort:prio:
	 *
	 * Corresponds to the teamd ports.PORTIFNAME.prio.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_PORT_PRIO] =
	    g_param_spec_int (NM_SETTING_TEAM_PORT_PRIO, "", "",
	                      G_MININT32, G_MAXINT32, 0,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_PORT_PRIO], "i", FALSE);

	/**
	 * NMSettingTeamPort:sticky:
	 *
	 * Corresponds to the teamd ports.PORTIFNAME.sticky.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_PORT_STICKY] =
	    g_param_spec_boolean (NM_SETTING_TEAM_PORT_STICKY, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_PORT_STICKY], "b", FALSE);

	/**
	 * NMSettingTeamPort:lacp-prio:
	 *
	 * Corresponds to the teamd ports.PORTIFNAME.lacp_prio.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_PORT_LACP_PRIO] =
	    g_param_spec_int (NM_SETTING_TEAM_PORT_LACP_PRIO, "", "",
	                      G_MININT32, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_PORT_LACP_PRIO], "i", FALSE);

	/**
	 * NMSettingTeamPort:lacp-key:
	 *
	 * Corresponds to the teamd ports.PORTIFNAME.lacp_key.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_PORT_LACP_KEY] =
	    g_param_spec_int (NM_SETTING_TEAM_PORT_LACP_KEY, "", "",
	                      G_MININT32, G_MAXINT32, -1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_PORT_LACP_KEY], "i", FALSE);

	/**
	 * NMSettingTeamPort:link-watchers: (type GPtrArray(NMTeamLinkWatcher))
	 *
	 * Link watchers configuration for the connection: each link watcher is
	 * defined by a dictionary, whose keys depend upon the selected link
	 * watcher. Available link watchers are 'ethtool', 'nsna_ping' and
	 * 'arp_ping' and it is specified in the dictionary with the key 'name'.
	 * Available keys are:   ethtool: 'delay-up', 'delay-down', 'init-wait';
	 * nsna_ping: 'init-wait', 'interval', 'missed-max', 'target-host';
	 * arp_ping: all the ones in nsna_ping and 'source-host', 'validate-active',
	 * 'validate-inactive', 'send-always'. See teamd.conf man for more details.
	 *
	 * Since: 1.12
	 **/
	obj_properties[NM_TEAM_ATTRIBUTE_LINK_WATCHERS] =
	    g_param_spec_boxed (NM_SETTING_TEAM_PORT_LINK_WATCHERS, "", "",
	                        G_TYPE_PTR_ARRAY,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);
	_property_override (properties_override, obj_properties[NM_TEAM_ATTRIBUTE_LINK_WATCHERS], "aa{sv}", TRUE);

	g_object_class_install_properties (object_class, G_N_ELEMENTS (obj_properties), obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_TEAM_PORT,
	                               NULL, properties_override);
}
