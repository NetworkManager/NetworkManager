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
#include <dbus/dbus-glib.h>

#include "nm-setting-team-port.h"
#include "nm-utils.h"
#include "nm-utils-private.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-team-port
 * @short_description: Describes connection properties for team ports
 * @include: nm-setting-team-port.h
 *
 * The #NMSettingTeamPort object is a #NMSetting subclass that describes
 * optional properties that apply to team ports.
 *
 * Since: 0.9.10
 **/

/**
 * nm_setting_team_port_error_quark:
 *
 * Registers an error quark for #NMSettingTeamPort if necessary.
 *
 * Returns: the error quark used for #NMSettingTeamPort errors.
 *
 * Since: 0.9.10
 **/
GQuark
nm_setting_team_port_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-team-port-error-quark");
	return quark;
}

G_DEFINE_TYPE_WITH_CODE (NMSettingTeamPort, nm_setting_team_port, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_TEAM_PORT_SETTING_NAME,
                                               g_define_type_id,
                                               3,
                                               NM_SETTING_TEAM_PORT_ERROR))
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
 *
 * Since: 0.9.10
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
 *
 * Since: 0.9.10
 **/
const char *
nm_setting_team_port_get_config (NMSettingTeamPort *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_TEAM_PORT (setting), NULL);

	return NM_SETTING_TEAM_PORT_GET_PRIVATE (setting)->config;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
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
	g_object_class_install_property
		(object_class, PROP_CONFIG,
		 g_param_spec_string (NM_SETTING_TEAM_PORT_CONFIG, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_INFERRABLE |
		                      G_PARAM_STATIC_STRINGS));
}
