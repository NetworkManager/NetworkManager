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
 * Copyright 2017 Red Hat, Inc.
 * Copyright 2013 Jiri Pirko <jiri@resnulli.us>
 */

#include "nm-default.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#include "nm-setting-team-port.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-connection-private.h"
#include "nm-setting-connection.h"

/**
 * SECTION:nm-setting-team-port
 * @short_description: Describes connection properties for team ports
 *
 * The #NMSettingTeamPort object is a #NMSetting subclass that describes
 * optional properties that apply to team ports.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingTeamPort, nm_setting_team_port, NM_TYPE_SETTING,
                         _nm_register_setting (TEAM_PORT, NM_SETTING_PRIORITY_AUX))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_TEAM_PORT)

#define NM_SETTING_TEAM_PORT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_TEAM_PORT, NMSettingTeamPortPrivate))

typedef struct {
	char *config;
	int queue_id;
	int prio;
	gboolean sticky;
	int lacp_prio;
	int lacp_key;
	GPtrArray *link_watchers; /* Array of NMTeamLinkWatcher */
} NMSettingTeamPortPrivate;

/* Keep aligned with _prop_to_keys[] */
enum {
	PROP_0,
	PROP_CONFIG,
	PROP_QUEUE_ID,
	PROP_PRIO,
	PROP_STICKY,
	PROP_LACP_PRIO,
	PROP_LACP_KEY,
	PROP_LINK_WATCHERS,
	LAST_PROP
};

/* Keep aligned with team-port properties enum */
static const _NMUtilsTeamPropertyKeys _prop_to_keys[LAST_PROP] = {
	[PROP_0] =             { NULL, NULL, NULL, 0 },
	[PROP_CONFIG] =        { NULL, NULL, NULL, 0 },
	[PROP_QUEUE_ID] =      { "queue_id", NULL, NULL, NM_SETTING_TEAM_PORT_QUEUE_ID_DEFAULT },
	[PROP_PRIO] =          { "prio", NULL, NULL, 0 },
	[PROP_STICKY] =        { "sticky", NULL, NULL, 0 },
	[PROP_LACP_PRIO] =     { "lacp_prio", NULL, NULL, NM_SETTING_TEAM_PORT_LACP_PRIO_DEFAULT },
	[PROP_LACP_KEY] =      { "lacp_key", NULL, NULL, 0 },
	[PROP_LINK_WATCHERS] = { "link_watch", NULL, NULL, 0 }
};

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

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->config;
}

/**
 * nm_setting_team_port_get_queue_id:
 * @setting: the #NMSettingTeamPort
 *
 * Returns: the #NMSettingTeamPort:queue_id property of the setting
 *
 * Since: 1.12
 **/
gint
nm_setting_team_port_get_queue_id (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), -1);

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->queue_id;
}

/**
 * nm_setting_team_port_get_prio:
 * @setting: the #NMSettingTeamPort
 *
 * Returns: the #NMSettingTeamPort:prio property of the setting
 *
 * Since: 1.12
 **/
gint
nm_setting_team_port_get_prio (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), 0);

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->prio;
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

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->sticky;
}

/**
 * nm_setting_team_port_get_lacp_prio:
 * @setting: the #NMSettingTeamPort
 *
 * Returns: the #NMSettingTeamPort:lacp-prio property of the setting
 *
 * Since: 1.12
 **/
gint
nm_setting_team_port_get_lacp_prio (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), 0);

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->lacp_prio;
}

/**
 * nm_setting_team_port_get_lacp_key:
 * @setting: the #NMSettingTeamPort
 *
 * Returns: the #NMSettingTeamPort:lacp-key property of the setting
 *
 * Since: 1.12
 **/
gint
nm_setting_team_port_get_lacp_key (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), 0);

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->lacp_key;
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
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);

	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), 0);

	return priv->link_watchers->len;
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
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);

	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), NULL);
	g_return_val_if_fail (idx < priv->link_watchers->len, NULL);

	return priv->link_watchers->pdata[idx];
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
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), FALSE);
	g_return_val_if_fail (link_watcher != NULL, FALSE);

	for (i = 0; i < priv->link_watchers->len; i++) {
		if (nm_team_link_watcher_equal (priv->link_watchers->pdata[i], link_watcher))
			return FALSE;
	}

	g_ptr_array_add (priv->link_watchers, nm_team_link_watcher_dup (link_watcher));
	g_object_notify (G_OBJECT (setting), NM_SETTING_TEAM_PORT_LINK_WATCHERS);
	return TRUE;
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
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_TEAM_PORT (setting));
	g_return_if_fail (idx < priv->link_watchers->len);

	g_ptr_array_remove_index (priv->link_watchers, idx);
	g_object_notify (G_OBJECT (setting), NM_SETTING_TEAM_PORT_LINK_WATCHERS);
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
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);
	guint i;

	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), FALSE);

	for (i = 0; i < priv->link_watchers->len; i++) {
		if (nm_team_link_watcher_equal (priv->link_watchers->pdata[i], link_watcher)) {
			g_ptr_array_remove_index (priv->link_watchers, i);
			g_object_notify (G_OBJECT (setting), NM_SETTING_TEAM_PORT_LINK_WATCHERS);
			return TRUE;
		}
	}
	return FALSE;
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
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);

	g_return_if_fail (NM_IS_SETTING_TEAM_PORT (setting));

	g_ptr_array_set_size (priv->link_watchers, 0);
	g_object_notify (G_OBJECT (setting), NM_SETTING_TEAM_PORT_LINK_WATCHERS);
}

static GVariant *
team_link_watchers_to_dbus (const GValue *prop_value)
{
	return _nm_utils_team_link_watchers_to_variant (g_value_get_boxed (prop_value));
}

static void
team_link_watchers_from_dbus (GVariant   *dbus_value,
                              GValue     *prop_value)
{
	g_value_take_boxed (prop_value, _nm_utils_team_link_watchers_from_variant (dbus_value));
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

	if (priv->config) {
		if (strlen (priv->config) > 1*1024*1024) {
			g_set_error (error, NM_CONNECTION_ERROR, NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("team config exceeds size limit"));
			g_prefix_error (error,
			                "%s.%s: ",
			                NM_SETTING_TEAM_PORT_SETTING_NAME,
			                NM_SETTING_TEAM_PORT_CONFIG);
			return FALSE;
		}

		if (!nm_utils_is_json_object (priv->config, error)) {
			g_prefix_error (error,
			                "%s.%s: ",
			                NM_SETTING_TEAM_PORT_SETTING_NAME,
			                NM_SETTING_TEAM_PORT_CONFIG);
			/* We treat an empty string as no config for compatibility. */
			return *priv->config ? FALSE : NM_SETTING_VERIFY_NORMALIZABLE;
		}
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
	NMSettingTeamPortPrivate *a_priv, *b_priv;
	guint i, j;

	/* If we are trying to match a connection in order to assume it (and thus
	 * @flags contains INFERRABLE), use the "relaxed" matching for team
	 * configuration. Otherwise, for all other purposes (including connection
	 * comparison before an update), resort to the default string comparison.
	 */
	if (   NM_FLAGS_HAS (flags, NM_SETTING_COMPARE_FLAG_INFERRABLE)
	    && nm_streq0 (prop_spec->name, NM_SETTING_TEAM_PORT_CONFIG)) {
		return _nm_utils_team_config_equal (NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->config,
		                                    NM_SETTING_TEAM_PORT_GET_PRIVATE (other)->config,
		                                    TRUE);
	}
	if (nm_streq0 (prop_spec->name, NM_SETTING_TEAM_PORT_LINK_WATCHERS)) {
		a_priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);
		b_priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (other);

		if (a_priv->link_watchers->len != b_priv->link_watchers->len)
			return FALSE;
		for (i = 0; i < a_priv->link_watchers->len; i++) {
			for (j = 0; j < b_priv->link_watchers->len; j++) {
				if (nm_team_link_watcher_equal (a_priv->link_watchers->pdata[i],
				                                b_priv->link_watchers->pdata[j])) {
					break;
				}
			}
			if (j == b_priv->link_watchers->len)
				return FALSE;
		}
		return TRUE;
	}

	/* Otherwise chain up to parent to handle generic compare */
	parent_class = NM_SETTING_CLASS (nm_setting_team_port_parent_class);
	return parent_class->compare_property (setting, other, prop_spec, flags);
}

static void
nm_setting_team_port_init (NMSettingTeamPort *setting)
{
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);

	priv->queue_id = NM_SETTING_TEAM_PORT_QUEUE_ID_DEFAULT;
	priv->lacp_prio = NM_SETTING_TEAM_PORT_LACP_PRIO_DEFAULT;
	priv->link_watchers = g_ptr_array_new_with_free_func ((GDestroyNotify) nm_team_link_watcher_unref);
}

#define JSON_TO_VAL(typ, id)   _nm_utils_json_extract_##typ (priv->config, _prop_to_keys[id], TRUE)

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (object);
	const GValue *align_value = NULL;
	gboolean align_config = FALSE;

	switch (prop_id) {
	case PROP_CONFIG:
		g_free (priv->config);
		priv->config = g_value_dup_string (value);
		priv->queue_id =  JSON_TO_VAL (int, PROP_QUEUE_ID);
		priv->prio =      JSON_TO_VAL (int, PROP_PRIO);
		priv->sticky =    JSON_TO_VAL (boolean, PROP_STICKY);
		priv->lacp_prio = JSON_TO_VAL (int, PROP_LACP_PRIO);
		priv->lacp_key =  JSON_TO_VAL (int, PROP_LACP_KEY);

		g_ptr_array_unref (priv->link_watchers);
		priv->link_watchers = JSON_TO_VAL (ptr_array, PROP_LINK_WATCHERS);
		break;
	case PROP_QUEUE_ID:
		if (priv->queue_id == g_value_get_int (value))
			break;
		priv->queue_id = g_value_get_int (value);
		if (priv->queue_id != NM_SETTING_TEAM_PORT_QUEUE_ID_DEFAULT)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_PRIO:
		if (priv->prio == g_value_get_int (value))
			break;
		priv->prio = g_value_get_int (value);
		if (priv->prio)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_STICKY:
		if (priv->sticky == g_value_get_boolean (value))
			break;
		priv->sticky = g_value_get_boolean (value);
		if (priv->sticky)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_LACP_PRIO:
		if (priv->lacp_prio == g_value_get_int (value))
			break;
		priv->lacp_prio = g_value_get_int (value);
		/* from libteam sources: lacp_prio default value is 0xff */
		if (priv->lacp_prio != NM_SETTING_TEAM_PORT_LACP_PRIO_DEFAULT)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_LACP_KEY:
		if (priv->lacp_key == g_value_get_int (value))
			break;
		priv->lacp_key = g_value_get_int (value);
		if (priv->lacp_key)
			align_value = value;
		align_config = TRUE;
		break;
	case PROP_LINK_WATCHERS:
		g_ptr_array_unref (priv->link_watchers);
		priv->link_watchers = _nm_utils_copy_array (g_value_get_boxed (value),
		                                            (NMUtilsCopyFunc) nm_team_link_watcher_dup,
		                                            (GDestroyNotify) nm_team_link_watcher_unref);
		if (priv->link_watchers->len)
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
	NMSettingTeamPort *setting = NM_SETTING_TEAM_PORT (object);
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_CONFIG:
		g_value_set_string (value, nm_setting_team_port_get_config (setting));
		break;
	case PROP_QUEUE_ID:
		g_value_set_int (value, priv->queue_id);
		break;
	case PROP_PRIO:
		g_value_set_int (value, priv->prio);
		break;
	case PROP_STICKY:
		g_value_set_boolean (value, priv->sticky);
		break;
	case PROP_LACP_PRIO:
		g_value_set_int (value, priv->lacp_prio);
		break;
	case PROP_LACP_KEY:
		g_value_set_int (value, priv->lacp_key);
		break;
	case PROP_LINK_WATCHERS:
		g_value_take_boxed (value, _nm_utils_copy_array (priv->link_watchers,
		                                                 (NMUtilsCopyFunc) nm_team_link_watcher_dup,
		                                                 (GDestroyNotify) nm_team_link_watcher_unref));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (object);

	g_free (priv->config);
	g_ptr_array_unref (priv->link_watchers);

	G_OBJECT_CLASS (nm_setting_team_port_parent_class)->finalize (object);
}

static void
nm_setting_team_port_class_init (NMSettingTeamPortClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingTeamPortPrivate));

	/* virtual methods */
	object_class->set_property     = set_property;
	object_class->get_property     = get_property;
	object_class->finalize         = finalize;
	parent_class->compare_property = compare_property;
	parent_class->verify           = verify;

	/* Properties */
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
	g_object_class_install_property
		(object_class, PROP_CONFIG,
		 g_param_spec_string (NM_SETTING_TEAM_PORT_CONFIG, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeamPort:queue-id:
	 *
	 * Corresponds to the teamd ports.PORTIFNAME.queue_id.
	 * When set to -1 means the parameter is skipped from the json config.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
		(object_class, PROP_QUEUE_ID,
		 g_param_spec_int (NM_SETTING_TEAM_PORT_QUEUE_ID, "", "",
		                   G_MININT32, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeamPort:prio:
	 *
	 * Corresponds to the teamd ports.PORTIFNAME.prio.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
		(object_class, PROP_PRIO,
		 g_param_spec_int (NM_SETTING_TEAM_PORT_PRIO, "", "",
		                   G_MININT32, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeamPort:sticky:
	 *
	 * Corresponds to the teamd ports.PORTIFNAME.sticky.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
		(object_class, PROP_STICKY,
		 g_param_spec_boolean (NM_SETTING_TEAM_PORT_STICKY, "", "",
		                       FALSE,
		                       G_PARAM_READWRITE |
		                       G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeamPort:lacp-prio:
	 *
	 * Corresponds to the teamd ports.PORTIFNAME.lacp_prio.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
		(object_class, PROP_LACP_PRIO,
		 g_param_spec_int (NM_SETTING_TEAM_PORT_LACP_PRIO, "", "",
		                   G_MININT32, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingTeamPort:lacp-key:
	 *
	 * Corresponds to the teamd ports.PORTIFNAME.lacp_key.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
		(object_class, PROP_LACP_KEY,
		 g_param_spec_int (NM_SETTING_TEAM_PORT_LACP_KEY, "", "",
		                   G_MININT32, G_MAXINT32, 0,
		                   G_PARAM_READWRITE |
		                   G_PARAM_STATIC_STRINGS));

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
	 * 'validate-incative', 'send-always'. See teamd.conf man for more details.
	 *
	 * Since: 1.12
	 **/
	g_object_class_install_property
		(object_class, PROP_LINK_WATCHERS,
		 g_param_spec_boxed (NM_SETTING_TEAM_PORT_LINK_WATCHERS, "", "",
		                     G_TYPE_PTR_ARRAY,
		                     G_PARAM_READWRITE |
		                     G_PARAM_STATIC_STRINGS));
	_nm_setting_class_transform_property (parent_class,
	                                      NM_SETTING_TEAM_PORT_LINK_WATCHERS,
	                                      G_VARIANT_TYPE ("aa{sv}"),
	                                      team_link_watchers_to_dbus,
	                                      team_link_watchers_from_dbus);

}
