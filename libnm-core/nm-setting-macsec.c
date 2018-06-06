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
 */

#include "nm-default.h"

#include "nm-setting-macsec.h"

#include <stdlib.h>
#include <string.h>

#include "nm-utils.h"
#include "nm-core-types-internal.h"
#include "nm-setting-connection.h"
#include "nm-setting-private.h"
#include "nm-setting-wired.h"
#include "nm-connection-private.h"

/**
 * SECTION:nm-setting-macsec
 * @short_description: Describes connection properties for MACSEC interfaces
 *
 * The #NMSettingMacsec object is a #NMSetting subclass that describes properties
 * necessary for connection to MACsec (IEEE 802.1AE) interfaces.
 **/

G_DEFINE_TYPE_WITH_CODE (NMSettingMacsec, nm_setting_macsec, NM_TYPE_SETTING,
                         _nm_register_setting (MACSEC, NM_SETTING_PRIORITY_HW_BASE))
NM_SETTING_REGISTER_TYPE (NM_TYPE_SETTING_MACSEC)

#define NM_SETTING_MACSEC_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_MACSEC, NMSettingMacsecPrivate))

typedef struct {
	char *parent;
	NMSettingMacsecMode mode;
	bool encrypt:1;
	bool send_sci:1;
	char *mka_cak;
	NMSettingSecretFlags mka_cak_flags;
	char *mka_ckn;
	int port;
	NMSettingMacsecValidation validation;
} NMSettingMacsecPrivate;

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PARENT,
	PROP_MODE,
	PROP_ENCRYPT,
	PROP_MKA_CAK,
	PROP_MKA_CAK_FLAGS,
	PROP_MKA_CKN,
	PROP_PORT,
	PROP_VALIDATION,
	PROP_SEND_SCI,
);

/**
 * nm_setting_macsec_new:
 *
 * Creates a new #NMSettingMacsec object with default values.
 *
 * Returns: (transfer full): the new empty #NMSettingMacsec object
 *
 * Since: 1.6
 **/
NMSetting *
nm_setting_macsec_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_MACSEC, NULL);
}

/**
 * nm_setting_macsec_get_parent:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:parent property of the setting
 *
 * Since: 1.6
 **/
const char *
nm_setting_macsec_get_parent (NMSettingMacsec *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MACSEC (setting), NULL);
	return NM_SETTING_MACSEC_GET_PRIVATE (setting)->parent;
}

/**
 * nm_setting_macsec_get_mode:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:mode property of the setting
 *
 * Since: 1.6
 **/
NMSettingMacsecMode
nm_setting_macsec_get_mode (NMSettingMacsec *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MACSEC (setting), NM_SETTING_MACSEC_MODE_PSK);
	return NM_SETTING_MACSEC_GET_PRIVATE (setting)->mode;
}

/**
 * nm_setting_macsec_get_encrypt:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:encrypt property of the setting
 *
 * Since: 1.6
 **/
gboolean
nm_setting_macsec_get_encrypt (NMSettingMacsec *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MACSEC (setting), TRUE);
	return NM_SETTING_MACSEC_GET_PRIVATE (setting)->encrypt;
}

/**
 * nm_setting_macsec_get_mka_cak
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:mka-cak property of the setting
 *
 * Since: 1.6
 **/
const char *
nm_setting_macsec_get_mka_cak (NMSettingMacsec *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MACSEC (setting), NULL);
	return NM_SETTING_MACSEC_GET_PRIVATE (setting)->mka_cak;
}

/**
 * nm_setting_macsec_get_mka_cak_flags:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingMacsec:mka-cak
 *
 * Since: 1.6
 **/
NMSettingSecretFlags
nm_setting_macsec_get_mka_cak_flags (NMSettingMacsec *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MACSEC (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_MACSEC_GET_PRIVATE (setting)->mka_cak_flags;
}

/**
 * nm_setting_macsec_get_mka_ckn:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:mka-ckn property of the setting
 *
 * Since: 1.6
 **/
const char *
nm_setting_macsec_get_mka_ckn (NMSettingMacsec *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MACSEC (setting), NULL);
	return NM_SETTING_MACSEC_GET_PRIVATE (setting)->mka_ckn;
}

/**
 * nm_setting_macsec_get_port:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:port property of the setting
 *
 * Since: 1.6
 **/
int
nm_setting_macsec_get_port (NMSettingMacsec *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MACSEC (setting), 1);
	return NM_SETTING_MACSEC_GET_PRIVATE (setting)->port;
}

/**
 * nm_setting_macsec_get_validation:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:validation property of the setting
 *
 * Since: 1.6
 **/
NMSettingMacsecValidation
nm_setting_macsec_get_validation (NMSettingMacsec *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MACSEC (setting), NM_SETTING_MACSEC_VALIDATION_DISABLE);
	return NM_SETTING_MACSEC_GET_PRIVATE (setting)->validation;
}

/**
 * nm_setting_macsec_get_send_sci:
 * @setting: the #NMSettingMacsec
 *
 * Returns: the #NMSettingMacsec:send-sci property of the setting
 *
 * Since: 1.12
 **/
gboolean
nm_setting_macsec_get_send_sci (NMSettingMacsec *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_MACSEC (setting), TRUE);
	return NM_SETTING_MACSEC_GET_PRIVATE (setting)->send_sci;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingMacsecPrivate *priv = NM_SETTING_MACSEC_GET_PRIVATE (setting);
	GPtrArray *secrets = NULL;

	if (priv->mode == NM_SETTING_MACSEC_MODE_PSK) {
		if (   !priv->mka_cak
		    && !NM_FLAGS_HAS (priv->mka_cak_flags, NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
			secrets = g_ptr_array_sized_new (1);
			g_ptr_array_add (secrets, NM_SETTING_MACSEC_MKA_CAK);
		}
	}

	return secrets;
}

/*********************************************************************/

static gboolean
verify_macsec_key (const char *key, gboolean cak, GError **error)
{
	int req_len;

	if (!key || !key[0]) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("the key is empty"));
		return FALSE;
	}

	req_len = cak ?
	    NM_SETTING_MACSEC_MKA_CAK_LENGTH :
	    NM_SETTING_MACSEC_MKA_CKN_LENGTH;
	if (strlen (key) != req_len) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_INVALID_PROPERTY,
		             _("the key must be %d characters"), req_len);
		return FALSE;
	}

	if (!NM_STRCHAR_ALL (key, ch, g_ascii_isxdigit (ch))) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("the key contains non-hexadecimal characters"));
		return FALSE;
	}

	return TRUE;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingMacsecPrivate *priv = NM_SETTING_MACSEC_GET_PRIVATE (setting);
	NMSettingConnection *s_con = NULL;
	NMSettingWired *s_wired = NULL;
	NMSetting8021x *s_8021x = NULL;

	if (connection) {
		s_con = nm_connection_get_setting_connection (connection);
		s_wired = nm_connection_get_setting_wired (connection);
		s_8021x = nm_connection_get_setting_802_1x (connection);
	}

	if (priv->parent) {
		if (nm_utils_is_uuid (priv->parent)) {
			/* If we have an NMSettingConnection:master with slave-type="macsec",
			 * then it must be the same UUID.
			 */
			if (s_con) {
				const char *master = NULL, *slave_type = NULL;

				slave_type = nm_setting_connection_get_slave_type (s_con);
				if (!g_strcmp0 (slave_type, NM_SETTING_MACSEC_SETTING_NAME))
					master = nm_setting_connection_get_master (s_con);

				if (master && g_strcmp0 (priv->parent, master) != 0) {
					g_set_error (error,
					             NM_CONNECTION_ERROR,
					             NM_CONNECTION_ERROR_INVALID_PROPERTY,
					             _("'%s' value doesn't match '%s=%s'"),
					             priv->parent, NM_SETTING_CONNECTION_MASTER, master);
					g_prefix_error (error, "%s.%s: ", NM_SETTING_MACSEC_SETTING_NAME, NM_SETTING_MACSEC_PARENT);
					return FALSE;
				}
			}
		} else if (!nm_utils_iface_valid_name (priv->parent)) {
			/* parent must be either a UUID or an interface name */
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' is neither an UUID nor an interface name"),
			             priv->parent);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_MACSEC_SETTING_NAME, NM_SETTING_MACSEC_PARENT);
			return FALSE;
		}
	} else {
		/* If parent is NULL, the parent must be specified via
		 * NMSettingWired:mac-address.
		 */
		if (   connection
		    && (!s_wired || !nm_setting_wired_get_mac_address (s_wired))) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_MISSING_PROPERTY,
			             _("property is not specified and neither is '%s:%s'"),
			             NM_SETTING_WIRED_SETTING_NAME, NM_SETTING_WIRED_MAC_ADDRESS);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_MACSEC_SETTING_NAME, NM_SETTING_MACSEC_PARENT);
			return FALSE;
		}
	}

	if (priv->mode == NM_SETTING_MACSEC_MODE_PSK) {
		if (!verify_macsec_key (priv->mka_ckn, FALSE, error)) {
			g_prefix_error (error, "%s.%s: ", NM_SETTING_MACSEC_SETTING_NAME, NM_SETTING_MACSEC_MKA_CKN);
			return FALSE;
		}
	} else if (priv->mode == NM_SETTING_MACSEC_MODE_EAP) {
		if (!s_8021x) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_MISSING_SETTING,
			             _("EAP key management requires '%s' setting presence"),
			             NM_SETTING_802_1X_SETTING_NAME);
			g_prefix_error (error, "%s: ", NM_SETTING_MACSEC_SETTING_NAME);
			return FALSE;
		}
	}

	if (priv->port <= 0 || priv->port > 65534) {
		g_set_error (error,
		             NM_CONNECTION_ERROR,
		             NM_CONNECTION_ERROR_MISSING_PROPERTY,
		             _("invalid port %d"),
		             priv->port);
		g_prefix_error (error, "%s.%s: ", NM_SETTING_MACSEC_SETTING_NAME, NM_SETTING_MACSEC_PORT);
		return FALSE;
	}

	return TRUE;
}

static void
nm_setting_macsec_init (NMSettingMacsec *setting)
{
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMSettingMacsec *setting = NM_SETTING_MACSEC (object);
	NMSettingMacsecPrivate *priv = NM_SETTING_MACSEC_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_PARENT:
		g_free (priv->parent);
		priv->parent = g_value_dup_string (value);
		break;
	case PROP_MODE:
		priv->mode = g_value_get_int (value);
		break;
	case PROP_ENCRYPT:
		priv->encrypt = g_value_get_boolean (value);
		break;
	case PROP_MKA_CAK:
		g_free (priv->mka_cak);
		priv->mka_cak = g_value_dup_string (value);
		break;
	case PROP_MKA_CAK_FLAGS:
		priv->mka_cak_flags = g_value_get_flags (value);
		break;
	case PROP_MKA_CKN:
		g_free (priv->mka_ckn);
		priv->mka_ckn = g_value_dup_string (value);
		break;
	case PROP_PORT:
		priv->port = g_value_get_int (value);
		break;
	case PROP_VALIDATION:
		priv->validation = g_value_get_int (value);
		break;
	case PROP_SEND_SCI:
		priv->send_sci = g_value_get_boolean (value);
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
	NMSettingMacsec *setting = NM_SETTING_MACSEC (object);
	NMSettingMacsecPrivate *priv = NM_SETTING_MACSEC_GET_PRIVATE (setting);

	switch (prop_id) {
	case PROP_PARENT:
		g_value_set_string (value, priv->parent);
		break;
	case PROP_MODE:
		g_value_set_int (value, priv->mode);
		break;
	case PROP_ENCRYPT:
		g_value_set_boolean (value, priv->encrypt);
		break;
	case PROP_MKA_CAK:
		g_value_set_string (value, priv->mka_cak);
		break;
	case PROP_MKA_CAK_FLAGS:
		g_value_set_flags (value, priv->mka_cak_flags);
		break;
	case PROP_MKA_CKN:
		g_value_set_string (value, priv->mka_ckn);
		break;
	case PROP_PORT:
		g_value_set_int (value, priv->port);
		break;
	case PROP_VALIDATION:
		g_value_set_int (value, priv->validation);
		break;
	case PROP_SEND_SCI:
		g_value_set_boolean (value, priv->send_sci);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMSettingMacsec *setting = NM_SETTING_MACSEC (object);
	NMSettingMacsecPrivate *priv = NM_SETTING_MACSEC_GET_PRIVATE (setting);

	g_free (priv->parent);
	if (priv->mka_cak) {
		memset (priv->mka_cak, 0, strlen (priv->mka_cak));
		g_free (priv->mka_cak);
	}
	g_free (priv->mka_ckn);

	G_OBJECT_CLASS (nm_setting_macsec_parent_class)->finalize (object);
}

static void
nm_setting_macsec_class_init (NMSettingMacsecClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingMacsecPrivate));

	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;
	parent_class->need_secrets = need_secrets;

	/**
	 * NMSettingMacsec:parent:
	 *
	 * If given, specifies the parent interface name or parent connection UUID
	 * from which this MACSEC interface should be created.  If this property is
	 * not specified, the connection must contain an #NMSettingWired setting
	 * with a #NMSettingWired:mac-address property.
	 *
	 * Since: 1.6
	 **/
	obj_properties[PROP_PARENT] =
	    g_param_spec_string (NM_SETTING_MACSEC_PARENT, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         NM_SETTING_PARAM_INFERRABLE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingMacsec:mode:
	 *
	 * Specifies how the CAK (Connectivity Association Key) for MKA (MACsec Key
	 * Agreement) is obtained.
	 *
	 * Since: 1.6
	 **/
	obj_properties[PROP_MODE] =
	    g_param_spec_int (NM_SETTING_MACSEC_MODE, "", "",
	                      G_MININT, G_MAXINT, NM_SETTING_MACSEC_MODE_PSK,
	                      G_PARAM_READWRITE |
	                      G_PARAM_CONSTRUCT |
	                      NM_SETTING_PARAM_INFERRABLE |
	                      G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingMacsec:encrypt:
	 *
	 * Whether the transmitted traffic must be encrypted.
	 *
	 * Since: 1.6
	 **/
	obj_properties[PROP_ENCRYPT] =
	    g_param_spec_boolean (NM_SETTING_MACSEC_ENCRYPT, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingMacsec:mka-cak:
	 *
	 * The pre-shared CAK (Connectivity Association Key) for MACsec
	 * Key Agreement.
	 *
	 * Since: 1.6
	 **/
	obj_properties[PROP_MKA_CAK] =
	    g_param_spec_string (NM_SETTING_MACSEC_MKA_CAK, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingMacsec:mka-cak-flags:
	 *
	 * Flags indicating how to handle the #NMSettingMacsec:mka-cak
	 * property.
	 *
	 * Since: 1.6
	 **/
	obj_properties[PROP_MKA_CAK_FLAGS] =
	    g_param_spec_flags (NM_SETTING_MACSEC_MKA_CAK_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingMacsec:mka-ckn:
	 *
	 * The pre-shared CKN (Connectivity-association Key Name) for
	 * MACsec Key Agreement.
	 *
	 * Since: 1.6
	 **/
	obj_properties[PROP_MKA_CKN] =
	    g_param_spec_string (NM_SETTING_MACSEC_MKA_CKN, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_CONSTRUCT |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingMacsec:port:
	 *
	 * The port component of the SCI (Secure Channel Identifier), between 1 and 65534.
	 *
	 * Since: 1.6
	 **/
	obj_properties[PROP_PORT] =
	    g_param_spec_int (NM_SETTING_MACSEC_PORT, "", "",
	                      1, 65534, 1,
	                      G_PARAM_READWRITE |
	                      G_PARAM_CONSTRUCT |
	                      NM_SETTING_PARAM_INFERRABLE |
	                      G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingMacsec:validation:
	 *
	 * Specifies the validation mode for incoming frames.
	 *
	 * Since: 1.6
	 **/
	obj_properties[PROP_VALIDATION] =
	    g_param_spec_int (NM_SETTING_MACSEC_VALIDATION, "", "",
	                      G_MININT, G_MAXINT, NM_SETTING_MACSEC_VALIDATION_STRICT,
	                      G_PARAM_READWRITE |
	                      G_PARAM_CONSTRUCT |
	                      NM_SETTING_PARAM_INFERRABLE |
	                      G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingMacsec:send-sci:
	 *
	 * Specifies whether the SCI (Secure Channel Identifier) is included
	 * in every packet.
	 *
	 * Since: 1.12
	 **/
	obj_properties[PROP_SEND_SCI] =
	    g_param_spec_boolean (NM_SETTING_MACSEC_SEND_SCI, "", "",
	                          TRUE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);
}
