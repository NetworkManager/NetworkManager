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
 * Copyright 2011 - 2013 Red Hat, Inc.
 */

#include "nm-default.h"

#include <string.h>

#include "nm-setting-adsl.h"
#include "nm-setting-ppp.h"
#include "nm-setting-private.h"
#include "nm-utils.h"

/**
 * SECTION:nm-setting-adsl
 * @short_description: Describes ADSL-based properties
 * @include: nm-setting-adsl.h
 *
 * The #NMSettingAdsl object is a #NMSetting subclass that describes
 * properties of ADSL connections.
 */

/**
 * nm_setting_adsl_error_quark:
 *
 * Registers an error quark for #NMSettingAdsl if necessary.
 *
 * Returns: the error quark used for #NMSettingAdsl errors.
 **/
GQuark
nm_setting_adsl_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-adsl-error-quark");
	return quark;
}

G_DEFINE_TYPE_WITH_CODE (NMSettingAdsl, nm_setting_adsl, NM_TYPE_SETTING,
                         _nm_register_setting (NM_SETTING_ADSL_SETTING_NAME,
                                               g_define_type_id,
                                               1,
                                               NM_SETTING_ADSL_ERROR))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_ADSL)

#define NM_SETTING_ADSL_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_ADSL, NMSettingAdslPrivate))

typedef struct {
	char *  username;
	char *  password;
	NMSettingSecretFlags password_flags;
	char *  protocol;
	char *  encapsulation;
	guint32 vpi;
	guint32 vci;
} NMSettingAdslPrivate;

enum {
	PROP_0,
	PROP_USERNAME,
	PROP_PASSWORD,
	PROP_PASSWORD_FLAGS,
	PROP_PROTOCOL,
	PROP_ENCAPSULATION,
	PROP_VPI,
	PROP_VCI,

	LAST_PROP
};

/**
 * nm_setting_adsl_new:
 *
 * Creates a new #NMSettingAdsl object with default values.
 *
 * Returns: the new empty #NMSettingAdsl object
 **/
NMSetting *
nm_setting_adsl_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_ADSL, NULL);
}

/**
 * nm_setting_adsl_get_username:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:username property of the setting
 **/
const char *
nm_setting_adsl_get_username (NMSettingAdsl *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_ADSL (setting), NULL);

	return NM_SETTING_ADSL_GET_PRIVATE (setting)->username;
}

/**
 * nm_setting_adsl_get_password:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:password property of the setting
 **/
const char *
nm_setting_adsl_get_password (NMSettingAdsl *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_ADSL (setting), NULL);

	return NM_SETTING_ADSL_GET_PRIVATE (setting)->password;
}

/**
 * nm_setting_adsl_get_password_flags:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingAdsl:password
 **/
NMSettingSecretFlags
nm_setting_adsl_get_password_flags (NMSettingAdsl *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_ADSL (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_ADSL_GET_PRIVATE (setting)->password_flags;
}

/**
 * nm_setting_adsl_get_protocol:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:protocol property of the setting
 **/
const char *
nm_setting_adsl_get_protocol (NMSettingAdsl *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_ADSL (setting), NULL);

	return NM_SETTING_ADSL_GET_PRIVATE (setting)->protocol;
}

/**
 * nm_setting_adsl_get_encapsulation:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:encapsulation property of the setting
 **/
const char *
nm_setting_adsl_get_encapsulation (NMSettingAdsl *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_ADSL (setting), NULL);

	return NM_SETTING_ADSL_GET_PRIVATE (setting)->encapsulation;
}

/**
 * nm_setting_adsl_get_vpi:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:vpi property of the setting
 **/
guint32
nm_setting_adsl_get_vpi (NMSettingAdsl *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_ADSL (setting), 0);

	return NM_SETTING_ADSL_GET_PRIVATE (setting)->vpi;
}

/**
 * nm_setting_adsl_get_vci:
 * @setting: the #NMSettingAdsl
 *
 * Returns: the #NMSettingAdsl:vci property of the setting
 **/
guint32
nm_setting_adsl_get_vci (NMSettingAdsl *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_ADSL (setting), 0);

	return NM_SETTING_ADSL_GET_PRIVATE (setting)->vci;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingAdslPrivate *priv = NM_SETTING_ADSL_GET_PRIVATE (setting);

	if (!priv->username) {
		g_set_error_literal (error,
		                     NM_SETTING_ADSL_ERROR,
		                     NM_SETTING_ADSL_ERROR_MISSING_PROPERTY,
		                     _("property is missing"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_ADSL_SETTING_NAME, NM_SETTING_ADSL_USERNAME);
		return FALSE;
	} else if (!strlen (priv->username)) {
		g_set_error_literal (error,
		                     NM_SETTING_ADSL_ERROR,
		                     NM_SETTING_ADSL_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_ADSL_SETTING_NAME, NM_SETTING_ADSL_USERNAME);
		return FALSE;
	}

	if (   !priv->protocol
	    || (   strcmp (priv->protocol, NM_SETTING_ADSL_PROTOCOL_PPPOA)
	        && strcmp (priv->protocol, NM_SETTING_ADSL_PROTOCOL_PPPOE)
	        && strcmp (priv->protocol, NM_SETTING_ADSL_PROTOCOL_IPOATM))){
		g_set_error (error,
		             NM_SETTING_ADSL_ERROR,
		             NM_SETTING_ADSL_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->protocol ? priv->protocol : "(null)");
		g_prefix_error (error, "%s.%s: ", NM_SETTING_ADSL_SETTING_NAME, NM_SETTING_ADSL_PROTOCOL);
		return FALSE;
	}

	if (   priv->encapsulation
	    && (   strcmp (priv->encapsulation, NM_SETTING_ADSL_ENCAPSULATION_VCMUX)
	        && strcmp (priv->encapsulation, NM_SETTING_ADSL_ENCAPSULATION_LLC) )) {
		g_set_error (error,
		             NM_SETTING_ADSL_ERROR,
		             NM_SETTING_ADSL_ERROR_INVALID_PROPERTY,
		             _("'%s' is not a valid value for the property"),
		             priv->encapsulation);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_ADSL_SETTING_NAME, NM_SETTING_ADSL_ENCAPSULATION);
		return FALSE;
	}

	return TRUE;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingAdslPrivate *priv = NM_SETTING_ADSL_GET_PRIVATE (setting);
	GPtrArray *secrets = NULL;

	if (priv->password && *priv->password)
		return NULL;

	if (!(priv->password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		secrets = g_ptr_array_sized_new (1);
		g_ptr_array_add (secrets, NM_SETTING_ADSL_PASSWORD);
	}

	return secrets;
}

static void
nm_setting_adsl_init (NMSettingAdsl *setting)
{
}

static void
finalize (GObject *object)
{
	NMSettingAdslPrivate *priv = NM_SETTING_ADSL_GET_PRIVATE (object);

	g_free (priv->username);
	g_free (priv->password);
	g_free (priv->protocol);
	g_free (priv->encapsulation);

	G_OBJECT_CLASS (nm_setting_adsl_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingAdslPrivate *priv = NM_SETTING_ADSL_GET_PRIVATE (object);
	const char *str;

	switch (prop_id) {
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
	case PROP_PROTOCOL:
		g_free (priv->protocol);
		str = g_value_get_string (value);
		priv->protocol = str ? g_ascii_strdown (str, -1) : NULL;
		break;
	case PROP_ENCAPSULATION:
		g_free (priv->encapsulation);
		str = g_value_get_string (value);
		priv->encapsulation = str ? g_ascii_strdown (str, -1) : NULL;
		break;
	case PROP_VPI:
		priv->vpi = g_value_get_uint (value);
		break;
	case PROP_VCI:
		priv->vci = g_value_get_uint (value);
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
	NMSettingAdsl *setting = NM_SETTING_ADSL (object);

	switch (prop_id) {
	case PROP_USERNAME:
		g_value_set_string (value, nm_setting_adsl_get_username (setting));
		break;
	case PROP_PASSWORD:
		g_value_set_string (value, nm_setting_adsl_get_password (setting));
		break;
	case PROP_PASSWORD_FLAGS:
		g_value_set_uint (value, nm_setting_adsl_get_password_flags (setting));
		break;
	case PROP_PROTOCOL:
		g_value_set_string (value, nm_setting_adsl_get_protocol (setting));
		break;
	case PROP_ENCAPSULATION:
		g_value_set_string (value, nm_setting_adsl_get_encapsulation (setting));
		break;
	case PROP_VPI:
		g_value_set_uint (value, nm_setting_adsl_get_vpi (setting));
		break;
	case PROP_VCI:
		g_value_set_uint (value, nm_setting_adsl_get_vci (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_adsl_class_init (NMSettingAdslClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingAdslPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;
	parent_class->need_secrets = need_secrets;

	/* Properties */

	/**
	 * NMSettingAdsl:username:
	 *
	 * Username used to authenticate with the ADSL service.
	 **/
	g_object_class_install_property
		(object_class, PROP_USERNAME,
		 g_param_spec_string (NM_SETTING_ADSL_USERNAME, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingAdsl:password:
	 *
	 * Password used to authenticate with the ADSL service.
	 **/
	g_object_class_install_property
		(object_class, PROP_PASSWORD,
		 g_param_spec_string (NM_SETTING_ADSL_PASSWORD, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      NM_SETTING_PARAM_SECRET |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingAdsl:password-flags:
	 *
	 * Flags indicating how to handle the #NMSettingAdsl:password property.
	 **/
	g_object_class_install_property
		(object_class, PROP_PASSWORD_FLAGS,
		 g_param_spec_uint (NM_SETTING_ADSL_PASSWORD_FLAGS, "", "",
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    NM_SETTING_SECRET_FLAGS_ALL,
		                    NM_SETTING_SECRET_FLAG_NONE,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingAdsl:protocol:
	 *
	 * ADSL connection protocol.  Can be "pppoa", "pppoe" or "ipoatm".
	 **/
	g_object_class_install_property
		(object_class, PROP_PROTOCOL,
		 g_param_spec_string (NM_SETTING_ADSL_PROTOCOL, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingAdsl:encapsulation:
	 *
	 * Encapsulation of ADSL connection.  Can be "vcmux" or "llc".
	 **/
	g_object_class_install_property
		(object_class, PROP_ENCAPSULATION,
		 g_param_spec_string (NM_SETTING_ADSL_ENCAPSULATION, "", "",
		                      NULL,
		                      G_PARAM_READWRITE |
		                      G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingAdsl:vpi:
	 *
	 * VPI of ADSL connection
	 **/
	g_object_class_install_property
		(object_class, PROP_VPI,
		 g_param_spec_uint (NM_SETTING_ADSL_VPI, "", "",
		                    0, 65536, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));

	/**
	 * NMSettingAdsl:vci:
	 *
	 * VCI of ADSL connection
	 **/
	g_object_class_install_property
		(object_class, PROP_VCI,
		 g_param_spec_uint (NM_SETTING_ADSL_VCI, "", "",
		                    0, 65536, 0,
		                    G_PARAM_READWRITE |
		                    G_PARAM_STATIC_STRINGS));
}
