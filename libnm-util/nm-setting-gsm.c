/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

/*
 * Dan Williams <dcbw@redhat.com>
 * Tambet Ingo <tambet@gmail.com>
 *
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
 * (C) Copyright 2007 - 2010 Red Hat, Inc.
 * (C) Copyright 2007 - 2008 Novell, Inc.
 */

#include <string.h>
#include <ctype.h>
#include "nm-setting-gsm.h"
#include "nm-setting-serial.h"
#include "nm-utils.h"

GQuark
nm_setting_gsm_error_quark (void)
{
	static GQuark quark;

	if (G_UNLIKELY (!quark))
		quark = g_quark_from_static_string ("nm-setting-gsm-error-quark");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

GType
nm_setting_gsm_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Unknown error. */
			ENUM_ENTRY (NM_SETTING_GSM_ERROR_UNKNOWN, "UnknownError"),
			/* The specified property was invalid. */
			ENUM_ENTRY (NM_SETTING_GSM_ERROR_INVALID_PROPERTY, "InvalidProperty"),
			/* The specified property was missing and is required. */
			ENUM_ENTRY (NM_SETTING_GSM_ERROR_MISSING_PROPERTY, "MissingProperty"),
			/* The required serial setting is missing */
			ENUM_ENTRY (NM_SETTING_GSM_ERROR_MISSING_SERIAL_SETTING, "MissingSerialSetting"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMSettingGsmError", values);
	}
	return etype;
}


G_DEFINE_TYPE (NMSettingGsm, nm_setting_gsm, NM_TYPE_SETTING)

#define NM_SETTING_GSM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SETTING_GSM, NMSettingGsmPrivate))

typedef struct {
	char *number; /* For dialing, duh */
	char *username;
	char *password;

	char *apn; /* NULL for dynamic */
	char *network_id; /* for manual registration or NULL for automatic */
	int network_type; /* One of the NM_SETTING_GSM_NETWORK_TYPE_* */
	guint32 allowed_bands;     /* A bitfield of NM_SETTING_GSM_BAND_* */

	char *pin;

	gboolean home_only;
} NMSettingGsmPrivate;

enum {
	PROP_0,
	PROP_NUMBER,
	PROP_USERNAME,
	PROP_PASSWORD,
	PROP_APN,
	PROP_NETWORK_ID,
	PROP_NETWORK_TYPE,
	PROP_BAND,
	PROP_PIN,
	PROP_PUK,
	PROP_ALLOWED_BANDS,
	PROP_HOME_ONLY,

	LAST_PROP
};

NMSetting *
nm_setting_gsm_new (void)
{
	return (NMSetting *) g_object_new (NM_TYPE_SETTING_GSM, NULL);
}

static gint
find_setting_by_name (gconstpointer a, gconstpointer b)
{
	NMSetting *setting = NM_SETTING (a);
	const char *str = (const char *) b;

	return strcmp (nm_setting_get_name (setting), str);
}

const char *
nm_setting_gsm_get_number (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->number;
}

const char *
nm_setting_gsm_get_username (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->username;
}

const char *
nm_setting_gsm_get_password (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->password;
}

const char *
nm_setting_gsm_get_apn (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->apn;
}

const char *
nm_setting_gsm_get_network_id (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->network_id;
}

int
nm_setting_gsm_get_network_type (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), -1);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->network_type;
}

int
nm_setting_gsm_get_band (NMSettingGsm *setting)
{
	g_warning ("Tried to get deprecated property " NM_SETTING_GSM_SETTING_NAME "/" NM_SETTING_GSM_BAND);
	return -1;
}

guint32
nm_setting_gsm_get_allowed_bands (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NM_SETTING_GSM_BAND_UNKNOWN);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->allowed_bands;
}

const char *
nm_setting_gsm_get_pin (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), NULL);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->pin;
}

const char *
nm_setting_gsm_get_puk (NMSettingGsm *setting)
{
	g_warning ("Tried to get deprecated property " NM_SETTING_GSM_SETTING_NAME "/" NM_SETTING_GSM_PUK);
	return NULL;
}

gboolean
nm_setting_gsm_get_home_only (NMSettingGsm *setting)
{
	g_return_val_if_fail (NM_IS_SETTING_GSM (setting), FALSE);

	return NM_SETTING_GSM_GET_PRIVATE (setting)->home_only;
}

static gboolean
verify (NMSetting *setting, GSList *all_settings, GError **error)
{
	NMSettingGsmPrivate *priv = NM_SETTING_GSM_GET_PRIVATE (setting);

	/* Serial connections require a PPP setting */
	if (all_settings && 
	    !g_slist_find_custom (all_settings, NM_SETTING_SERIAL_SETTING_NAME, find_setting_by_name)) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_MISSING_SERIAL_SETTING,
		             NULL);
		return FALSE;
	}

	if (!priv->number) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_MISSING_PROPERTY,
		             NM_SETTING_GSM_NUMBER);
		return FALSE;
	} else if (!strlen (priv->number)) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_INVALID_PROPERTY,
		             NM_SETTING_GSM_NUMBER);
		return FALSE;
	}

	if (priv->apn && (strlen (priv->apn) < 1 || strchr (priv->apn, '"'))) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_INVALID_PROPERTY,
		             NM_SETTING_GSM_APN);
		return FALSE;
	}

	if (priv->username && !strlen (priv->username)) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_INVALID_PROPERTY,
		             NM_SETTING_GSM_USERNAME);
		return FALSE;
	}

	if (priv->password && !strlen (priv->password)) {
		g_set_error (error,
		             NM_SETTING_GSM_ERROR,
		             NM_SETTING_GSM_ERROR_INVALID_PROPERTY,
		             NM_SETTING_GSM_USERNAME);
		return FALSE;
	}

	if (priv->network_id) {
		guint32 nid_len = strlen (priv->network_id);
		guint32 i;

		/* Accept both 5 and 6 digit MCC/MNC codes */
		if ((nid_len < 5) || (nid_len > 6)) {
			g_set_error (error,
			             NM_SETTING_GSM_ERROR,
			             NM_SETTING_GSM_ERROR_INVALID_PROPERTY,
			             NM_SETTING_GSM_NETWORK_ID);
			return FALSE;
		}

		for (i = 0; i < nid_len; i++) {
			if (!isdigit (priv->network_id[i])) {
				g_set_error (error,
				             NM_SETTING_GSM_ERROR,
				             NM_SETTING_GSM_ERROR_INVALID_PROPERTY,
				             NM_SETTING_GSM_NETWORK_ID);
				return FALSE;
			}
		}
	}

	return TRUE;
}

static GPtrArray *
need_secrets (NMSetting *setting)
{
	NMSettingGsmPrivate *priv = NM_SETTING_GSM_GET_PRIVATE (setting);
	GPtrArray *secrets = NULL;

	if (priv->password)
		return NULL;

	if (priv->username) {
		secrets = g_ptr_array_sized_new (1);
		g_ptr_array_add (secrets, NM_SETTING_GSM_PASSWORD);
	}

	return secrets;
}

static void
nm_setting_gsm_init (NMSettingGsm *setting)
{
	g_object_set (setting, NM_SETTING_NAME, NM_SETTING_GSM_SETTING_NAME, NULL);
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

	G_OBJECT_CLASS (nm_setting_gsm_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMSettingGsmPrivate *priv = NM_SETTING_GSM_GET_PRIVATE (object);
	const char *str;

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
	case PROP_APN:
		g_free (priv->apn);
		priv->apn = g_value_dup_string (value);
		break;
	case PROP_NETWORK_ID:
		g_free (priv->network_id);
		priv->network_id = g_value_dup_string (value);
		break;
	case PROP_NETWORK_TYPE:
		priv->network_type = g_value_get_int (value);
		break;
	case PROP_BAND:
		if (g_value_get_int (value) != -1)
			g_warning ("Tried to set deprecated property " NM_SETTING_GSM_SETTING_NAME "/" NM_SETTING_GSM_BAND);
		break;
	case PROP_ALLOWED_BANDS:
		priv->allowed_bands = g_value_get_uint (value);
		break;
	case PROP_PIN:
		g_free (priv->pin);
		priv->pin = g_value_dup_string (value);
		break;
	case PROP_PUK:
		str = g_value_get_string (value);
		if (str && strlen (str))
			g_warning ("Tried to set deprecated property " NM_SETTING_GSM_SETTING_NAME "/" NM_SETTING_GSM_PUK);
		break;
	case PROP_HOME_ONLY:
		priv->home_only = g_value_get_boolean (value);
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
	case PROP_APN:
		g_value_set_string (value, nm_setting_gsm_get_apn (setting));
		break;
	case PROP_NETWORK_ID:
		g_value_set_string (value, nm_setting_gsm_get_network_id (setting));
		break;
	case PROP_NETWORK_TYPE:
		g_value_set_int (value, nm_setting_gsm_get_network_type (setting));
		break;
	case PROP_ALLOWED_BANDS:
		g_value_set_uint (value, nm_setting_gsm_get_allowed_bands (setting));
		break;
	case PROP_PIN:
		g_value_set_string (value, nm_setting_gsm_get_pin (setting));
		break;
	case PROP_PUK:
		/* deprecated */
		g_value_set_string (value, NULL);
		break;
	case PROP_BAND:
		/* deprecated */
		g_value_set_int (value, -1);
		break;
	case PROP_HOME_ONLY:
		g_value_set_boolean (value, nm_setting_gsm_get_home_only (setting));
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_setting_gsm_class_init (NMSettingGsmClass *setting_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (setting_class);
	NMSettingClass *parent_class = NM_SETTING_CLASS (setting_class);

	g_type_class_add_private (setting_class, sizeof (NMSettingGsmPrivate));

	/* virtual methods */
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->finalize     = finalize;
	parent_class->verify       = verify;
	parent_class->need_secrets = need_secrets;

	/* Properties */

	/**
	 * NMSettingGsm:number:
	 *
	 * Number to dial when establishing a PPP data session with the GSM-based
	 * mobile broadband network.  In most cases, leave the number blank and a
	 * number selecting the APN specified in the 'apn' property will be used
	 * automatically when required.
	 **/
	g_object_class_install_property
		(object_class, PROP_NUMBER,
		 g_param_spec_string (NM_SETTING_GSM_NUMBER,
						  "Number",
						  "Number to dial when establishing a PPP data session "
						  "with the GSM-based mobile broadband network.  In most "
						  "cases, leave the number blank and a number selecting "
						  "the APN specified in the 'apn' property will be used "
						  "automatically when required.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingGsm:username:
	 *
	 * The username used to authenticate with the network, if required.  Many
	 * providers do not require a username, or accept any username.  But if a
	 * username is required, it is specified here.
	 **/
	g_object_class_install_property
		(object_class, PROP_USERNAME,
		 g_param_spec_string (NM_SETTING_GSM_USERNAME,
						  "Username",
						  "Username used to authenticate with the network, if "
						  "required.  Note that many providers do not require "
						  "a username or accept any username.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingGsm:password:
	 *
	 * The password used to authenticate with the network, if required.  Many
	 * providers do not require a password, or accept any password.  But if a
	 * password is required, it is specified here.
	 **/
	g_object_class_install_property
		(object_class, PROP_PASSWORD,
		 g_param_spec_string (NM_SETTING_GSM_PASSWORD,
						  "Password",
						  "Password used to authenticate with the network, if "
						  "required.  Note that many providers do not require "
						  "a password or accept any password.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSettingGsm:apn:
	 *
	 * The GPRS Access Point Name specifying the APN used when establishing a
	 * data session with the GSM-based network.  The APN often determines how
	 * the user will be billed for their network usage and whether the user has
	 * access to the Internet or just a provider-specific walled-garden, so it
	 * is important to use the correct APN for the user's mobile broadband plan.
	 **/
	g_object_class_install_property
		(object_class, PROP_APN,
		 g_param_spec_string (NM_SETTING_GSM_APN,
						  "APN",
						  "The GPRS Access Point Name specifying the APN used "
						  "when establishing a data session with the GSM-based "
						  "network.  The APN often determines how the user will "
						  "be billed for their network usage and whether the "
						  "user has access to the Internet or just a provider-"
						  "specific walled-garden, so it is important to use "
						  "the correct APN for the user's mobile broadband "
						  "plan.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingGsm:network-id:
	 *
	 * The Network ID (GSM LAI format, ie MCC-MNC) to force specific network
	 * registration.  If the Network ID is specified, NetworkManager will
	 * attempt to force the device to register only on the specified network.
	 * This can be used to ensure that the device does not roam when direct
	 * roaming control of the device is not otherwise possible.
	 **/
	g_object_class_install_property
		(object_class, PROP_NETWORK_ID,
		 g_param_spec_string (NM_SETTING_GSM_NETWORK_ID,
						  "Network ID",
						  "The Network ID (GSM LAI format, ie MCC-MNC) to force "
						  "specific network registration.  If the Network ID is "
						  "specified, NetworkManager will attempt to force the "
						  "device to register only on the specified network.  "
						  "This can be used to ensure that the device does not "
						  "roam when direct roaming control of the device is "
						  "not otherwise possible.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingGsm:network-type:
	 *
	 * Network preference to force the device to only use specific network
	 * technologies.  The permitted values are: -1: any, 0: 3G only,
	 * 1: GPRS/EDGE only, 2: prefer 3G, and 3: prefer 2G.  Note that not all
	 * devices allow network preference control.
	 **/
	g_object_class_install_property
		(object_class, PROP_NETWORK_TYPE,
		 g_param_spec_int (NM_SETTING_GSM_NETWORK_TYPE,
					    "Network type",
					    "Network preference to force the device to only use "
					    "specific network technologies.  The permitted values "
					    "are: -1: any, 0: 3G only, 1: GPRS/EDGE only, "
					    "2: prefer 3G, and 3: prefer 2G.  Note that not all "
					    "devices allow network preference control.",
					    NM_SETTING_GSM_NETWORK_TYPE_ANY,
					    NM_SETTING_GSM_NETWORK_TYPE_PREFER_GPRS_EDGE,
					    NM_SETTING_GSM_NETWORK_TYPE_ANY,
					    G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingGsm:allowed-bands:
	 *
	 * Bitfield of allowed frequency bands.  Note that not all devices allow
	 * frequency band control.
	 **/
	g_object_class_install_property
		(object_class, PROP_ALLOWED_BANDS,
		 g_param_spec_uint (NM_SETTING_GSM_ALLOWED_BANDS,
		                    "Allowed Bands",
		                    "Bitfield of allowed frequency bands.  Note that "
		                    "not all devices allow frequency band control.",
		                    NM_SETTING_GSM_BAND_UNKNOWN,
		                    NM_SETTING_GSM_BAND_UNKNOWN
		                     || NM_SETTING_GSM_BAND_ANY
		                     || NM_SETTING_GSM_BAND_EGSM
		                     || NM_SETTING_GSM_BAND_DCS
		                     || NM_SETTING_GSM_BAND_PCS
		                     || NM_SETTING_GSM_BAND_G850
		                     || NM_SETTING_GSM_BAND_U2100
		                     || NM_SETTING_GSM_BAND_U1800
		                     || NM_SETTING_GSM_BAND_U17IV
		                     || NM_SETTING_GSM_BAND_U800
		                     || NM_SETTING_GSM_BAND_U850
		                     || NM_SETTING_GSM_BAND_U900
		                     || NM_SETTING_GSM_BAND_U17IX
		                     || NM_SETTING_GSM_BAND_U1900,
		                    NM_SETTING_GSM_BAND_ANY,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));

	/**
	 * NMSettingGsm:pin:
	 *
	 * If the SIM is locked with a PIN it must be unlocked before any other
	 * operations are requested.  Specify the PIN here to allow operation of
	 * the device.
	 **/
	g_object_class_install_property
		(object_class, PROP_PIN,
		 g_param_spec_string (NM_SETTING_GSM_PIN,
						  "PIN",
						  "If the SIM is locked with a PIN it must be unlocked "
						  "before any other operations are requested.  Specify "
						  "the PIN here to allow operation of the device.",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSettingGsm:home-only:
	 *
	 * When TRUE, only connections to the home network will be allowed.
	 * Connections to roaming networks will not be made.
	 **/
	g_object_class_install_property
		(object_class, PROP_HOME_ONLY,
		 g_param_spec_boolean (NM_SETTING_GSM_HOME_ONLY,
						  "PIN",
						  "When TRUE, only connections to the home network will "
						  "be allowed.  Connections to roaming networks will "
						  "not be made.",
						  FALSE,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE));

	/* Deprecated properties */
	/**
	 * NMSettingGsm:puk:
	 *
	 * DEPRECATED
	 **/
	g_object_class_install_property
		(object_class, PROP_PUK,
		 g_param_spec_string (NM_SETTING_GSM_PUK,
						  "PUK (DEPRECATED and UNUSED)",
						  "PUK (DEPRECATED and UNUSED)",
						  NULL,
						  G_PARAM_READWRITE | NM_SETTING_PARAM_SERIALIZE | NM_SETTING_PARAM_SECRET));

	/**
	 * NMSettingGsm:band:
	 *
	 * DEPRECATED
	 **/
	g_object_class_install_property
		(object_class, PROP_BAND,
		 g_param_spec_int (NM_SETTING_GSM_BAND,
		                    "Band (DEPRECATED and UNUSED)",
		                    "Band (DEPRECATED and UNUSED)",
		                    -1, 5, -1,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT | NM_SETTING_PARAM_SERIALIZE));
}
