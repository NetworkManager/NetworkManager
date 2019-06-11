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

#include "nm-setting-gsm.h"

#include "nm-utils.h"
#include "nm-setting-private.h"
#include "nm-core-enum-types.h"

/**
 * SECTION:nm-setting-gsm
 * @short_description: Describes GSM/3GPP-based mobile broadband properties
 *
 * The #NMSettingGsm object is a #NMSetting subclass that describes
 * properties that allow connections to 3GPP-based mobile broadband
 * networks, including those using GPRS/EDGE and UMTS/HSPA technology.
 */

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_NUMBER,
	PROP_USERNAME,
	PROP_PASSWORD,
	PROP_PASSWORD_FLAGS,
	PROP_APN,
	PROP_NETWORK_ID,
	PROP_PIN,
	PROP_PIN_FLAGS,
	PROP_HOME_ONLY,
	PROP_DEVICE_ID,
	PROP_SIM_ID,
	PROP_SIM_OPERATOR_ID,
	PROP_MTU,
);

typedef struct {
	char *number; /* For dialing, duh */
	char *username;
	char *password;
	NMSettingSecretFlags password_flags;

	/* Restrict connection to certain devices or SIMs */
	char *device_id;
	char *sim_id;
	char *sim_operator_id;

	char *apn; /* NULL for dynamic */
	char *network_id; /* for manual registration or NULL for automatic */

	char *pin;
	NMSettingSecretFlags pin_flags;

	gboolean home_only;
	guint32 mtu;
} NMSettingGsmPrivate;

G_DEFINE_TYPE (NMSettingGsm, nm_setting_gsm, NM_TYPE_SETTING)

#define NM_SETTING_GSM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_GSM, NMSettingGsmPrivate))

/*****************************************************************************/

/**
 * nm_setting_gsm_get_number:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:number property of the setting
 *
 * Deprecated: 1.16:  user-provided values for this setting are no longer used.
 **/
const char *
nm_setting_gsm_get_number (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->number;
}

/**
 * nm_setting_gsm_get_username:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:username property of the setting
 **/
const char *
nm_setting_gsm_get_username (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->username;
}

/**
 * nm_setting_gsm_get_password:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:password property of the setting
 **/
const char *
nm_setting_gsm_get_password (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->password;
}

/**
 * nm_setting_gsm_get_password_flags:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingGsm:password
 **/
NMSettingSecretFlags
nm_setting_gsm_get_password_flags (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->password_flags;
}

/**
 * nm_setting_gsm_get_apn:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:apn property of the setting
 **/
const char *
nm_setting_gsm_get_apn (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->apn;
}

/**
 * nm_setting_gsm_get_network_id:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:network-id property of the setting
 **/
const char *
nm_setting_gsm_get_network_id (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->network_id;
}

/**
 * nm_setting_gsm_get_pin:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:pin property of the setting
 **/
const char *
nm_setting_gsm_get_pin (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->pin;
}

/**
 * nm_setting_gsm_get_pin_flags:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingSecretFlags pertaining to the #NMSettingGsm:pin
 **/
NMSettingSecretFlags
nm_setting_gsm_get_pin_flags (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NM_SETTING_SECRET_FLAG_NONE);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->pin_flags;
}

/**
 * nm_setting_gsm_get_home_only:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:home-only property of the setting
 **/
gboolean
nm_setting_gsm_get_home_only (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), FALSE);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->home_only;
}

/**
 * nm_setting_gsm_get_device_id:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:device-id property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_gsm_get_device_id (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->device_id;
}

/**
 * nm_setting_gsm_get_sim_id:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:sim-id property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_gsm_get_sim_id (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->sim_id;
}

/**
 * nm_setting_gsm_get_sim_operator_id:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:sim-operator-id property of the setting
 *
 * Since: 1.2
 **/
const char *
nm_setting_gsm_get_sim_operator_id (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->sim_operator_id;
}

/**
 * nm_setting_gsm_get_mtu:
 * @setting: the #NMSettingGsm
 *
 * Returns: the #NMSettingGsm:mtu property of the setting
 *
 * Since: 1.8
 **/
guint32
nm_setting_gsm_get_mtu (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), 0);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->mtu;
}

static gboolean
verify (NMSetting *setting, NMConnection *connection, GError **error)
{
	NMSettingGsmPrivate *priv = NM_SETTING_GSM_GET_PRIVATE (setting);

	if (priv->number && !priv->number[0]) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_NUMBER);
		return FALSE;
	}

	if (priv->apn) {
		guint32 apn_len = strlen (priv->apn);
		guint32 i;

		if (apn_len < 1 || apn_len > 64) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("property value '%s' is empty or too long (>64)"),
			             priv->apn);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_APN);
			return FALSE;
		}

		/* APNs roughly follow the same rules as DNS domain names.  Allowed
		 * characters are a-z, 0-9, . and -.  GSM 03.03 Section 9.1 states:
		 *
		 *   The syntax of the APN shall follow the Name Syntax defined in
		 *   RFC 2181 [14] and RFC 1035 [15]. The APN consists of one or
		 *   more labels. Each label is coded as one octet length field
		 *   followed by that number of octets coded as 8 bit ASCII characters.
		 *   Following RFC 1035 [15] the labels should consist only of the
		 *   alphabetic characters (A-Z and a-z), digits (0-9) and the
		 *   dash (-). The case of alphabetic characters is not significant.
		 *
		 * A dot (.) is commonly used to separate parts of the APN, and
		 * apparently the underscore (_) is used as well.  RFC 2181 indicates
		 * that no restrictions of any kind are placed on DNS labels, and thus
		 * it would appear that none are placed on APNs either, but many modems
		 * and networks will fail to accept APNs that include odd characters
		 * like space ( ) and such.
		 */
		for (i = 0; i < apn_len; i++) {
			if (   !g_ascii_isalnum (priv->apn[i])
			    && (priv->apn[i] != '.')
			    && (priv->apn[i] != '_')
			    && (priv->apn[i] != '-')) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("'%s' contains invalid char(s) (use [A-Za-z._-])"),
				             priv->apn);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_APN);
				return FALSE;
			}
		}
	}

	if (priv->username && !strlen (priv->username)) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_USERNAME);
		return FALSE;
	}

	if (priv->network_id) {
		guint32 nid_len = strlen (priv->network_id);
		guint32 i;

		/* Accept both 5 and 6 digit MCC/MNC codes */
		if ((nid_len < 5) || (nid_len > 6)) {
			g_set_error (error,
			             NM_CONNECTION_ERROR,
			             NM_CONNECTION_ERROR_INVALID_PROPERTY,
			             _("'%s' length is invalid (should be 5 or 6 digits)"),
			             priv->network_id);
			g_prefix_error (error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_NETWORK_ID);
			return FALSE;
		}

		for (i = 0; i < nid_len; i++) {
			if (!g_ascii_isdigit (priv->network_id[i])) {
				g_set_error (error,
				             NM_CONNECTION_ERROR,
				             NM_CONNECTION_ERROR_INVALID_PROPERTY,
				             _("'%s' is not a number"),
				             priv->network_id);
				g_prefix_error (error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_NETWORK_ID);
				return FALSE;
			}
		}
	}

	if (priv->device_id && !priv->device_id[0]) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_DEVICE_ID);
		return FALSE;
	}

	if (priv->sim_id && !priv->sim_id[0]) {
		g_set_error_literal (error,
		                     NM_CONNECTION_ERROR,
		                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
		                     _("property is empty"));
		g_prefix_error (error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_SIM_ID);
		return FALSE;
	}

	if (priv->sim_operator_id) {
		size_t len = strlen (priv->sim_operator_id);
		const char *p = priv->sim_operator_id;

		if (len == 0 || (len != 5 && len != 6)) {
			g_set_error_literal (error,
			                     NM_CONNECTION_ERROR,
			                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
			                     _("property is empty or wrong size"));
			g_prefix_error (error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_SIM_OPERATOR_ID);
			return FALSE;
		}

		while (p && *p) {
			if (!g_ascii_isdigit (*p++)) {
				g_set_error_literal (error,
				                     NM_CONNECTION_ERROR,
				                     NM_CONNECTION_ERROR_INVALID_PROPERTY,
				                     _("property must contain only digits"));
				g_prefix_error (error, "%s.%s: ", NM_SETTING_GSM_SETTING_NAME, NM_SETTING_GSM_SIM_OPERATOR_ID);
				return FALSE;
			}
		}
	}

	return TRUE;
}

static gboolean
verify_secrets (NMSetting *setting, NMConnection *connection, GError **error)
{
	return _nm_setting_verify_secret_string (NM_SETTING_GSM_GET_PRIVATE (setting)->password,
	                                         NM_SETTING_GSM_SETTING_NAME,
	                                         NM_SETTING_GSM_PASSWORD,
	                                         error);
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingGsmPrivate *priv = NM_SETTING_GSM_GET_PRIVATE (setting);
	GPtrArray *secrets = NULL;

	if (priv->password && *priv->password)
		return NULL;

	if (priv->username) {
		if (!(priv->password_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
			secrets = g_ptr_array_sized_new (1);
			g_ptr_array_add (secrets, NM_SETTING_GSM_PASSWORD);
		}
	}

	return secrets;
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMSettingGsm *setting = NM_SETTING_GSM (object);

	switch (prop_id) {
	case PROP_NUMBER:
		g_value_set_string (value, nm_setting_gsm_get_number (setting));
		break;
	case PROP_USERNAME:
		g_value_set_string (value, nm_setting_gsm_get_username (setting));
		break;
	case PROP_PASSWORD:
		g_value_set_string (value, nm_setting_gsm_get_password (setting));
		break;
	case PROP_PASSWORD_FLAGS:
		g_value_set_flags (value, nm_setting_gsm_get_password_flags (setting));
		break;
	case PROP_APN:
		g_value_set_string (value, nm_setting_gsm_get_apn (setting));
		break;
	case PROP_NETWORK_ID:
		g_value_set_string (value, nm_setting_gsm_get_network_id (setting));
		break;
	case PROP_PIN:
		g_value_set_string (value, nm_setting_gsm_get_pin (setting));
		break;
	case PROP_PIN_FLAGS:
		g_value_set_flags (value, nm_setting_gsm_get_pin_flags (setting));
		break;
	case PROP_HOME_ONLY:
		g_value_set_boolean (value, nm_setting_gsm_get_home_only (setting));
		break;
	case PROP_DEVICE_ID:
		g_value_set_string (value, nm_setting_gsm_get_device_id (setting));
		break;
	case PROP_SIM_ID:
		g_value_set_string (value, nm_setting_gsm_get_sim_id (setting));
		break;
	case PROP_SIM_OPERATOR_ID:
		g_value_set_string (value, nm_setting_gsm_get_sim_operator_id (setting));
		break;
	case PROP_MTU:
		g_value_set_uint (value, nm_setting_gsm_get_mtu (setting));
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
	NMSettingGsmPrivate *priv = NM_SETTING_GSM_GET_PRIVATE (object);
	char *tmp;

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
		priv->password_flags = g_value_get_flags (value);
		break;
	case PROP_APN:
		g_free (priv->apn);
		priv->apn = NULL;
		tmp = g_value_dup_string (value);
		if (tmp)
			priv->apn = g_strstrip (tmp);
		break;
	case PROP_NETWORK_ID:
		g_free (priv->network_id);
		priv->network_id = NULL;
		tmp = g_value_dup_string (value);
		if (tmp)
			priv->network_id = g_strstrip (tmp);
		break;
	case PROP_PIN:
		g_free (priv->pin);
		priv->pin = g_value_dup_string (value);
		break;
	case PROP_PIN_FLAGS:
		priv->pin_flags = g_value_get_flags (value);
		break;
	case PROP_HOME_ONLY:
		priv->home_only = g_value_get_boolean (value);
		break;
	case PROP_DEVICE_ID:
		g_free (priv->device_id);
		priv->device_id = g_value_dup_string (value);
		break;
	case PROP_SIM_ID:
		g_free (priv->sim_id);
		priv->sim_id = g_value_dup_string (value);
		break;
	case PROP_SIM_OPERATOR_ID:
		g_free (priv->sim_operator_id);
		priv->sim_operator_id = g_value_dup_string (value);
		break;
	case PROP_MTU:
		priv->mtu = g_value_get_uint (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_setting_gsm_init (NMSettingGsm *setting)
{
}

/**
 * nm_setting_gsm_new:
 *
 * Creates a new #NMSettingGsm object with default values.
 *
 * Returns: the new empty #NMSettingGsm object
 **/
NMSetting *
nm_setting_gsm_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_GSM, NULL);
}

static void
finalize (GObject *object)
{
	NMSettingGsmPrivate *priv = NM_SETTING_GSM_GET_PRIVATE (object);

	g_free (priv->number);
	g_free (priv->username);
	g_free (priv->password);
	g_free (priv->apn);
	g_free (priv->network_id);
	g_free (priv->pin);
	g_free (priv->device_id);
	g_free (priv->sim_id);
	g_free (priv->sim_operator_id);

	G_OBJECT_CLASS (nm_setting_gsm_parent_class)->finalize (object);
}

static void
nm_setting_gsm_class_init (NMSettingGsmClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMSettingClass *setting_class = NM_SETTING_CLASS (klass);
	GArray *properties_override = _nm_sett_info_property_override_create_array ();

	g_type_class_add_private (klass, sizeof (NMSettingGsmPrivate));

	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize     = finalize;

	setting_class->verify         = verify;
	setting_class->verify_secrets = verify_secrets;
	setting_class->need_secrets   = need_secrets;

	/**
	 * NMSettingGsm:number:
	 *
	 * Legacy setting that used to help establishing PPP data sessions for
	 * GSM-based modems.
	 *
	 * Deprecated: 1.16: user-provided values for this setting are no longer used.
	 **/
	obj_properties[PROP_NUMBER] =
	    g_param_spec_string (NM_SETTING_GSM_NUMBER, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:username:
	 *
	 * The username used to authenticate with the network, if required.  Many
	 * providers do not require a username, or accept any username.  But if a
	 * username is required, it is specified here.
	 **/
	obj_properties[PROP_USERNAME] =
	    g_param_spec_string (NM_SETTING_GSM_USERNAME, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:password:
	 *
	 * The password used to authenticate with the network, if required.  Many
	 * providers do not require a password, or accept any password.  But if a
	 * password is required, it is specified here.
	 **/
	obj_properties[PROP_PASSWORD] =
	    g_param_spec_string (NM_SETTING_GSM_PASSWORD, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:password-flags:
	 *
	 * Flags indicating how to handle the #NMSettingGsm:password property.
	 **/
	obj_properties[PROP_PASSWORD_FLAGS] =
	    g_param_spec_flags (NM_SETTING_GSM_PASSWORD_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:apn:
	 *
	 * The GPRS Access Point Name specifying the APN used when establishing a
	 * data session with the GSM-based network.  The APN often determines how
	 * the user will be billed for their network usage and whether the user has
	 * access to the Internet or just a provider-specific walled-garden, so it
	 * is important to use the correct APN for the user's mobile broadband plan.
	 * The APN may only be composed of the characters a-z, 0-9, ., and - per GSM
	 * 03.60 Section 14.9.
	 **/
	obj_properties[PROP_APN] =
	    g_param_spec_string (NM_SETTING_GSM_APN, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:network-id:
	 *
	 * The Network ID (GSM LAI format, ie MCC-MNC) to force specific network
	 * registration.  If the Network ID is specified, NetworkManager will
	 * attempt to force the device to register only on the specified network.
	 * This can be used to ensure that the device does not roam when direct
	 * roaming control of the device is not otherwise possible.
	 **/
	obj_properties[PROP_NETWORK_ID] =
	    g_param_spec_string (NM_SETTING_GSM_NETWORK_ID, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:pin:
	 *
	 * If the SIM is locked with a PIN it must be unlocked before any other
	 * operations are requested.  Specify the PIN here to allow operation of the
	 * device.
	 **/
	obj_properties[PROP_PIN] =
	    g_param_spec_string (NM_SETTING_GSM_PIN, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         NM_SETTING_PARAM_SECRET |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:pin-flags:
	 *
	 * Flags indicating how to handle the #NMSettingGsm:pin property.
	 **/
	obj_properties[PROP_PIN_FLAGS] =
	    g_param_spec_flags (NM_SETTING_GSM_PIN_FLAGS, "", "",
	                        NM_TYPE_SETTING_SECRET_FLAGS,
	                        NM_SETTING_SECRET_FLAG_NONE,
	                        G_PARAM_READWRITE |
	                        G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:home-only:
	 *
	 * When %TRUE, only connections to the home network will be allowed.
	 * Connections to roaming networks will not be made.
	 **/
	obj_properties[PROP_HOME_ONLY] =
	    g_param_spec_boolean (NM_SETTING_GSM_HOME_ONLY, "", "",
	                          FALSE,
	                          G_PARAM_READWRITE |
	                          G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:device-id:
	 *
	 * The device unique identifier (as given by the WWAN management service)
	 * which this connection applies to.  If given, the connection will only
	 * apply to the specified device.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_DEVICE_ID] =
	    g_param_spec_string (NM_SETTING_GSM_DEVICE_ID, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:sim-id:
	 *
	 * The SIM card unique identifier (as given by the WWAN management service)
	 * which this connection applies to.  If given, the connection will apply
	 * to any device also allowed by #NMSettingGsm:device-id which contains a
	 * SIM card matching the given identifier.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_SIM_ID] =
	    g_param_spec_string (NM_SETTING_GSM_SIM_ID, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:sim-operator-id:
	 *
	 * A MCC/MNC string like "310260" or "21601" identifying the specific
	 * mobile network operator which this connection applies to.  If given,
	 * the connection will apply to any device also allowed by
	 * #NMSettingGsm:device-id and #NMSettingGsm:sim-id which contains a SIM
	 * card provisioned by the given operator.
	 *
	 * Since: 1.2
	 **/
	obj_properties[PROP_SIM_OPERATOR_ID] =
	    g_param_spec_string (NM_SETTING_GSM_SIM_OPERATOR_ID, "", "",
	                         NULL,
	                         G_PARAM_READWRITE |
	                         G_PARAM_STATIC_STRINGS);

	/**
	 * NMSettingGsm:mtu:
	 *
	 * If non-zero, only transmit packets of the specified size or smaller,
	 * breaking larger packets up into multiple frames.
	 *
	 * Since: 1.8
	 **/
	obj_properties[PROP_MTU] =
	    g_param_spec_uint (NM_SETTING_GSM_MTU, "", "",
	                       0, G_MAXUINT32, 0,
	                       G_PARAM_READWRITE |
	                       G_PARAM_CONSTRUCT |
	                       NM_SETTING_PARAM_FUZZY_IGNORE |
	                       G_PARAM_STATIC_STRINGS);

	/* Ignore incoming deprecated properties */
	_properties_override_add_dbus_only (properties_override,
	                                    "allowed-bands",
	                                    G_VARIANT_TYPE_UINT32,
	                                    NULL,
	                                    NULL);

	_properties_override_add_dbus_only (properties_override,
	                                    "network-type",
	                                    G_VARIANT_TYPE_INT32,
	                                    NULL,
	                                    NULL);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	_nm_setting_class_commit_full (setting_class, NM_META_SETTING_TYPE_GSM,
	                               NULL, properties_override);
}
