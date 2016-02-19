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
#include <ctype.h>
#include <stdlib.h>

#include "nm-setting-team-port.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-connection-private.h"
#include "nm-setting-connection.h"
#include "nm-setting-team.h"

/**
 * SECTION:nm-setting-team-port
 * @short_description: Describes connection properties for team ports
 *
 * The #NMSettingTeamPort object is a #NMSetting subclass that describes
 * optional properties that apply to team ports.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingTeamPort, nm_setting_team_port, NM_TYPE_SETTING,
                         _nm_register_setting (TEAM_PORT, 3))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_TEAM_PORT)

#define NM_SETTING_TEAM_PORT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_TEAM_PORT, NMSettingTeamPortPrivate))

typedef struct {
	char *config;
} NMSettingTeamPortPrivate;

enum {
	PROP_0,
	PROP_CONFIG,
	LAST_PROP
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

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
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
	return TRUE;
}

static void
nm_setting_team_port_init (NMSettingTeamPort *setting)
{
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingTeamPortPrivate *priv = NM_SETTING_TEAM_PORT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_CONFIG:
		g_free (priv->config);
		priv->config = g_value_dup_string (value);
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
	NMSettingTeamPort *setting = NM_SETTING_TEAM_PORT (object);

	switch (prop_id) {
	case PROP_CONFIG:
		g_value_set_string (value, nm_setting_team_port_get_config (setting));
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

	G_OBJECT_CLASS (nm_setting_team_port_parent_class)->finalize (object);
}

static void
nm_setting_team_port_class_init (NMSettingTeamPortClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingTeamPortPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize = finalize;
	parent_class->verify       = verify;

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
}
