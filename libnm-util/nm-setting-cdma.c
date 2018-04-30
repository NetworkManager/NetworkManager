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
 */

#include "nm-default.h"

#include <string.h>

#include "nm-setting-cdma.h"
#include "nm-utils.h"
#include "nm-setting-private.h"

/**
 * SECTION:nm-setting-cdma
 * @short_description: Describes CDMA-based mobile broadband properties
 * @include: nm-setting-cdma.h
 *
 * The #NMSettingCdma object is a #NMSetting subclass that describes
 * properties that allow connections to IS-95-based mobile broadband
 * networks, including those using CDMA2000/EVDO technology.
 */

/**
 * nm_setting_cdma_error_quark:
 *
 * Registers an error quark for #NMSettingCdma if necessary.
 *
 * Returns: the error quark used for #NMSettingCdma errors.
 **/
GQuark
nm_setting_cdma_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-cdma-error-quark");
	return quark;
}

G_DEFINE_TYPE_WITH_CODE (NMSettingCdma, nm_setting_cdma, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_CDMA_SETTING_NAME,
                                               g_define_type_id,
                                               1,
                                               NM_SETTING_CDMA_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_CDMA)

#define NM_SETTING_CDMA_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_CDMA, NMSettingCdmaPrivate))

typedef struct {
	char *number; /* For dialing, duh */
	char *username;
	char *password;
	NMSettingSecretFlags password_flags;
} NMSettingCdmaPrivate;

enum {
	PROP_0,
	PROP_NUMBER,
	PROP_USERNAME,
	PROP_PASSWORD,
	PROP_PASSWORD_FLAGS,

	LAST_PROP
};

/**
 * nm_setting_cdma_new:
 *
 * Creates a new #NMSettingCdma object with default values.
 *
 * Returns: the new empty #NMSettingCdma object
 **/
NMSetting *
nm_setting_cdma_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_CDMA, NULL);
}

/**
 * nm_setting_cdma_get_number:
 * @setting: the #NMSettingCdma
 *
 * Returns: the #NMSettingCdma:number property of the setting
 **/
const char *
nm_setting_cdma_get_number (NMSettingCdma *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CDMA (setting), NULL);

	return NM_SETTING_CDMA_GET_PRIVATE (setting)->number;
}

/**
 * nm_setting_cdma_get_username:
 * @setting: the #NMSettingCdma
 *
 * Returns: the #NMSettingCdma:username property of the setting
 **/
const char *
nm_setting_cdma_get_username (NMSettingCdma *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CDMA (setting), NULL);

	return NM_SETTING_CDMA_GET_PRIVATE (setting)->username;
}

/**
 * nm_setting_cdma_get_password:
 * @setting: the #NMSettingCdma
 *
 * Returns: the #NMSettingCdma:password property of the setting
 **/
const char *
nm_setting_cdma_get_password (NMSettingCdma *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CDMA (setting), NULL);

	return NM_SETTING_CDMA_GET_PRIVATE (setting)->password;
}

/**
 * nm_setting_cdma_get_password_flags:
 * @setting: the #NMSettingCdma
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingCdma:password
 **/
NMSettingSecretFlags
nm_setting_cdma_get_password_flags (NMSettingCdma *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_CDMA (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_CDMA_GET_PRIVATE (setting)->password_flags;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingCdmaPrivate *priv = NM_SETTING_CDMA_GET_PRIVATE (setting);

	if (!priv->number) {
		g_set_error_literal (error,
		                     NM_SETTING_CDMA_ERROR,
		                     NM_SETTING_CDMA_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CDMA_SETTING_NAME, NM_SETTING_CDMA_NUMBER);
		return FALSE;
	} else if (!strlen (priv->number)) {
		g_set_error_literal (error,
		                     NM_SETTING_CDMA_ERROR,
		                     NM_SETTING_CDMA_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CDMA_SETTING_NAME, NM_SETTING_CDMA_NUMBER);
		return FALSE;
	}

	if (priv->username && !strlen (priv->username)) {
		g_set_error_literal (error,
		                     NM_SETTING_CDMA_ERROR,
		                     NM_SETTING_CDMA_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_CDMA_SETTING_NAME, NM_SETTING_CDMA_USERNAME);
		return FALSE;
	}

	return TRUE;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingCdmaPrivate *priv = NM_SETTING_CDMA_GET_PRIVATE (setting);
	GPtrArray *secrets = NULL;

	if (priv->password && *priv->password)
		return NULL;

	if (priv->username) {
		if (!(priv->password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
			secrets = g_ptr_array_sized_new (1);
			g_ptr_array_add (secrets, NM_SETTING_CDMA_PASSWORD);
		}
	}

	return secrets;
}

static void
nm_setting_cdma_init (NMSettingCdma *setting)
{
}

static void
finalize (GObject *object)
{
	NMSettingCdmaPrivate *priv = NM_SETTING_CDMA_GET_PRIVATE (object);

	g_free (priv->number);
	g_free (priv->username);
	g_free (priv->password);

	G_OBJECT_CLASS (nm_setting_cdma_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingCdmaPrivate *priv = NM_SETTING_CDMA_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_NUMBER:
		g_free (priv->number);
		priv->number = g_value_dup_string (value);
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
	NMSettingCdma *setting = NM_SETTING_CDMA (object);

	switch (prop_id) {
	case PROP_NUMBER:
		g_value_set_string (value, nm_setting_cdma_get_number (setting));
		break;
	case PROP_USERNAME:
		g_value_set_string (value, nm_setting_cdma_get_username (setting));
		break;
	case PROP_PASSWORD:
		g_value_set_string (value, nm_setting_cdma_get_password (setting));
		break;
	case PROP_PASSWORD_FLAGS:
		g_value_set_uint (value, nm_setting_cdma_get_password_flags (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_cdma_class_init (NMSettingCdmaClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingCdmaPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;
	parent_class->need_secrets = need_secrets;

	/* Properties */

	/**
	 * NMSettingCdma:number:
	 *
	 * The number to dial to establish the connection to the CDMA-based mobile
	 * broadband network, if any.  If not specified, the default number (#777)
	 * is used when required.
	 **/
	g_object_class_install_property
		(object_class, PROP_NUMBER,
		 g_param_spec_string (NM_SETTING_CDMA_NUMBER, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingCdma:username:
	 *
	 * The username used to authenticate with the network, if required.  Many
	 * providers do not require a username, or accept any username.  But if a
	 * username is required, it is specified here.
	 **/
	g_object_class_install_property
		(object_class, PROP_USERNAME,
		 g_param_spec_string (NM_SETTING_CDMA_USERNAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingCdma:password:
	 *
	 * The password used to authenticate with the network, if required.  Many
	 * providers do not require a password, or accept any password.  But if a
	 * password is required, it is specified here.
	 **/
	g_object_class_install_property
		(object_class, PROP_PASSWORD,
		 g_param_spec_string (NM_SETTING_CDMA_PASSWORD, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingCdma:password-flags:
	 *
	 * Flags indicating how to handle the #NMSettingCdma:password property.
	 **/
	g_object_class_install_property
		(object_class, PROP_PASSWORD_FLAGS,
		 g_param_spec_uint (NM_SETTING_CDMA_PASSWORD_FLAGS, "", "",
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    NM_SETTING_SECRET_FLAGS_ALL,
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));
}
