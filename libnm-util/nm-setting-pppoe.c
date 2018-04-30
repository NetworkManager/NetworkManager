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
 * Copyright 2007 - 2013 Red Hat, Inc.
 * Copyright 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-setting-pppoe.h"
#include "nm-setting-ppp.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-pppoe
 * @short_description: Describes PPPoE connection properties
 * @include: nm-setting-pppoe.h
 *
 * The #NMSettingPPPOE object is a #NMSetting subclass that describes
 * properties necessary for connection to networks that require PPPoE connections
 * to provide IP transport, for example cable or DSL modems.
 **/

/**
 * nm_setting_pppoe_error_quark:
 *
 * Registers an error quark for #NMSettingPPPOE if necessary.
 *
 * Returns: the error quark used for #NMSettingPPPOE errors.
 **/
GQuark
nm_setting_pppoe_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-pppoe-error-quark");
	return quark;
}

G_DEFINE_TYPE_WITH_CODE (NMSettingPPPOE, nm_setting_pppoe, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_PPPOE_SETTING_NAME,
                                               g_define_type_id,
                                               3,
                                               NM_SETTING_PPPOE_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_PPPOE)

#define NM_SETTING_PPPOE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_PPPOE, NMSettingPPPOEPrivate))

typedef struct {
	char *service;
	char *username;
	char *password;
	NMSettingSecretFlags password_flags;
} NMSettingPPPOEPrivate;

enum {
	PROP_0,
	PROP_SERVICE,
	PROP_USERNAME,
	PROP_PASSWORD,
	PROP_PASSWORD_FLAGS,

	LAST_PROP
};

/**
 * nm_setting_pppoe_new:
 *
 * Creates a new #NMSettingPPPOE object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingPPPOE object
 **/
NMSetting *
nm_setting_pppoe_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_PPPOE, NULL);
}

/**
 * nm_setting_pppoe_get_service:
 * @setting: the #NMSettingPPPOE
 *
 * Returns: the #NMSettingPPPOE:service property of the setting
 **/
const char *
nm_setting_pppoe_get_service  (NMSettingPPPOE *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPPOE (setting), NULL);

	return NM_SETTING_PPPOE_GET_PRIVATE (setting)->service;
}

/**
 * nm_setting_pppoe_get_username:
 * @setting: the #NMSettingPPPOE
 *
 * Returns: the #NMSettingPPPOE:username property of the setting
 **/
const char *
nm_setting_pppoe_get_username (NMSettingPPPOE *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPPOE (setting), NULL);

	return NM_SETTING_PPPOE_GET_PRIVATE (setting)->username;
}

/**
 * nm_setting_pppoe_get_password:
 * @setting: the #NMSettingPPPOE
 *
 * Returns: the #NMSettingPPPOE:password property of the setting
 **/
const char *
nm_setting_pppoe_get_password (NMSettingPPPOE *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPPOE (setting), NULL);

	return NM_SETTING_PPPOE_GET_PRIVATE (setting)->password;
}

/**
 * nm_setting_pppoe_get_password_flags:
 * @setting: the #NMSettingPPPOE
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingPPPOE:password
 **/
NMSettingSecretFlags
nm_setting_pppoe_get_password_flags (NMSettingPPPOE *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_PPPOE (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_PPPOE_GET_PRIVATE (setting)->password_flags;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingPPPOEPrivate *priv = NM_SETTING_PPPOE_GET_PRIVATE (setting);

	if (!priv->username) {
		g_set_error_literal (error,
		                     NM_SETTING_PPPOE_ERROR,
		                     NM_SETTING_PPPOE_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_PPPOE_SETTING_NAME, NM_SETTING_PPPOE_USERNAME);
		return FALSE;
	} else if (!strlen (priv->username)) {
		g_set_error_literal (error,
		                     NM_SETTING_PPPOE_ERROR,
		                     NM_SETTING_PPPOE_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_PPPOE_SETTING_NAME, NM_SETTING_PPPOE_USERNAME);
		return FALSE;
	}

	if (priv->service && !strlen (priv->service)) {
		g_set_error_literal (error,
		                     NM_SETTING_PPPOE_ERROR,
		                     NM_SETTING_PPPOE_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_PPPOE_SETTING_NAME, NM_SETTING_PPPOE_SERVICE);
		return FALSE;
	}

	return TRUE;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingPPPOEPrivate *priv = NM_SETTING_PPPOE_GET_PRIVATE (setting);
	GPtrArray *secrets = NULL;

	if (priv->password)
		return NULL;

	if (!(priv->password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		secrets = g_ptr_array_sized_new (1);
		g_ptr_array_add (secrets, NM_SETTING_PPPOE_PASSWORD);
	}

	return secrets;
}

static void
nm_setting_pppoe_init (NMSettingPPPOE *setting)
{
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingPPPOEPrivate *priv = NM_SETTING_PPPOE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_SERVICE:
		g_free (priv->service);
		priv->service = g_value_dup_string (value);
		break;
	case PROP_USERNAME:
		g_free (priv->username);
		priv->username = g_value_dup_string (value);
		break;
	case PROP_PASSWORD:
		g_free (priv->password);
		priv->password = g_value_dup_string (value);
		break;
	case PROP_PASSWORD_FLAGS:
		priv->password_flags = g_value_get_uint (value);
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
	NMSettingPPPOE *setting = NM_SETTING_PPPOE (object);

	switch (prop_id) {
	case PROP_SERVICE:
		g_value_set_string (value, nm_setting_pppoe_get_service (setting));
		break;
	case PROP_USERNAME:
		g_value_set_string (value, nm_setting_pppoe_get_username (setting));
		break;
	case PROP_PASSWORD:
		g_value_set_string (value, nm_setting_pppoe_get_password (setting));
		break;
	case PROP_PASSWORD_FLAGS:
		g_value_set_uint (value, nm_setting_pppoe_get_password_flags (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMSettingPPPOEPrivate *priv = NM_SETTING_PPPOE_GET_PRIVATE (object);

	g_free (priv->username);
	g_free (priv->password);
	g_free (priv->service);

	G_OBJECT_CLASS (nm_setting_pppoe_parent_class)->finalize (object);
}

static void
nm_setting_pppoe_class_init (NMSettingPPPOEClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingPPPOEPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;
	parent_class->need_secrets = need_secrets;

	/* Properties */
	/**
	 * NMSettingPPPOE:service:
	 *
	 * If specified, instruct PPPoE to only initiate sessions with access
	 * concentrators that provide the specified service.  For most providers,
	 * this should be left blank.  It is only required if there are multiple
	 * access concentrators or a specific service is known to be required.
	 **/
	g_object_class_install_property
		(object_class, PROP_SERVICE,
		 g_param_spec_string (NM_SETTING_PPPOE_SERVICE, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPPOE:username:
	 *
	 * Username used to authenticate with the PPPoE service.
	 **/
	g_object_class_install_property
		(object_class, PROP_USERNAME,
		 g_param_spec_string (NM_SETTING_PPPOE_USERNAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPPOE:password:
	 *
	 * Password used to authenticate with the PPPoE service.
	 **/
	g_object_class_install_property
		(object_class, PROP_PASSWORD,
		 g_param_spec_string (NM_SETTING_PPPOE_PASSWORD, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingPPPOE:password-flags:
	 *
	 * Flags indicating how to handle the #NMSettingPPPOE:password property.
	 **/
	g_object_class_install_property
		(object_class, PROP_PASSWORD_FLAGS,
		 g_param_spec_uint (NM_SETTING_PPPOE_PASSWORD_FLAGS, "", "",
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    NM_SETTING_SECRET_FLAGS_ALL,
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));
}
