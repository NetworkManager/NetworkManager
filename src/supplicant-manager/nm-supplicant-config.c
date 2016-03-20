/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2006 - 2012 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <stdlib.h>

#include "nm-supplicant-config.h"
#include "nm-supplicant-settings-verify.h"
#include "nm-setting.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"

#define NM_SUPPLICANT_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                             NM_TYPE_SUPPLICANT_CONFIG, \
                                             NMSupplicantConfigPrivate))

G_DEFINE_TYPE (NMSupplicantConfig, nm_supplicant_config, G_TYPE_OBJECT)

typedef struct {
	char *value;
	guint32 len;
	OptType type;
} ConfigOption;

typedef struct
{
	GHashTable *config;
	GHashTable *blobs;
	guint32    ap_scan;
	NMSettingMacRandomization mac_randomization;
	gboolean   fast_required;
	gboolean   dispose_has_run;
} NMSupplicantConfigPrivate;

NMSupplicantConfig *
nm_supplicant_config_new (void)
{
	return g_object_new (NM_TYPE_SUPPLICANT_CONFIG, NULL);
}

static void
config_option_free (ConfigOption *opt)
{
	g_free (opt->value);
	g_slice_free (ConfigOption, opt);
}

static void
blob_free (GByteArray *array)
{
	g_byte_array_free (array, TRUE);
}

static void
nm_supplicant_config_init (NMSupplicantConfig * self)
{
	NMSupplicantConfigPrivate *priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	priv->config = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                      (GDestroyNotify) g_free,
	                                      (GDestroyNotify) config_option_free);

	priv->blobs = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                     (GDestroyNotify) g_free,
	                                     (GDestroyNotify) blob_free);

	priv->ap_scan = 1;
	priv->mac_randomization = NM_SETTING_MAC_RANDOMIZATION_DEFAULT;
	priv->dispose_has_run = FALSE;
}

static gboolean
nm_supplicant_config_add_option_with_type (NMSupplicantConfig *self,
                                           const char *key,
                                           const char *value,
                                           gint32 len,
                                           OptType opt_type,
                                           gboolean secret,
                                           GError **error)
{
	NMSupplicantConfigPrivate *priv;
	ConfigOption *old_opt;
	ConfigOption *opt;
	OptType type;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	nm_assert (!error || !*error);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	if (len < 0)
		len = strlen (value);

	if (opt_type != TYPE_INVALID)
		type = opt_type;
	else {
		type = nm_supplicant_settings_verify_setting (key, value, len);
		if (type == TYPE_INVALID) {
			char buf[255];
			memset (&buf[0], 0, sizeof (buf));
			memcpy (&buf[0], value, len > 254 ? 254 : len);
			g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
			             "key '%s' and/or value '%s' invalid", key, secret ? "<omitted>" : buf);
			return FALSE;
		}
	}

	old_opt = (ConfigOption *) g_hash_table_lookup (priv->config, key);
	if (old_opt) {
		g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
		             "key '%s' already configured", key);
		return FALSE;
	}

	opt = g_slice_new0 (ConfigOption);
	opt->value = g_malloc (len + 1);
	memcpy (opt->value, value, len);
	opt->value[len] = '\0';

	opt->len = len;
	opt->type = type;

	{
		char buf[255];
		memset (&buf[0], 0, sizeof (buf));
		memcpy (&buf[0], opt->value, opt->len > 254 ? 254 : opt->len);
		nm_log_info (LOGD_SUPPLICANT, "Config: added '%s' value '%s'", key, secret ? "<omitted>" : &buf[0]);
	}

	g_hash_table_insert (priv->config, g_strdup (key), opt);

	return TRUE;
}

static gboolean
nm_supplicant_config_add_option (NMSupplicantConfig *self,
                                 const char *key,
                                 const char *value,
                                 gint32 len,
                                 gboolean secret,
                                 GError **error)
{
	return nm_supplicant_config_add_option_with_type (self, key, value, len, TYPE_INVALID, secret, error);
}

static gboolean
nm_supplicant_config_add_blob (NMSupplicantConfig *self,
                               const char *key,
                               GBytes *value,
                               const char *blobid,
                               GError **error)
{
	NMSupplicantConfigPrivate *priv;
	ConfigOption *old_opt;
	ConfigOption *opt;
	OptType type;
	GByteArray *blob;
	const guint8 *data;
	gsize data_len;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);
	g_return_val_if_fail (blobid != NULL, FALSE);

	data = g_bytes_get_data (value, &data_len);
	g_return_val_if_fail (data_len > 0, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	type = nm_supplicant_settings_verify_setting (key, (const char *) data, data_len);
	if (type == TYPE_INVALID) {
		g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
		             "key '%s' and/or its contained value is invalid", key);
		return FALSE;
	}

	old_opt = (ConfigOption *) g_hash_table_lookup (priv->config, key);
	if (old_opt) {
		g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
		             "key '%s' already configured", key);
		return FALSE;
	}

	blob = g_byte_array_sized_new (data_len);
	g_byte_array_append (blob, data, data_len);

	opt = g_slice_new0 (ConfigOption);
	opt->value = g_strdup_printf ("blob://%s", blobid);
	opt->len = strlen (opt->value);
	opt->type = type;

	nm_log_info (LOGD_SUPPLICANT, "Config: added '%s' value '%s'", key, opt->value);

	g_hash_table_insert (priv->config, g_strdup (key), opt);
	g_hash_table_insert (priv->blobs, g_strdup (blobid), blob);

	return TRUE;
}

static gboolean
nm_supplicant_config_add_blob_for_connection (NMSupplicantConfig *self,
                                              GBytes *field,
                                              const char *name,
                                              const char *con_uid,
                                              GError **error)
{
	if (field && g_bytes_get_size (field)) {
		gs_free char *uid = NULL;
		char *p;

		uid = g_strdup_printf ("%s-%s", con_uid, name);
		for (p = uid; *p; p++) {
			if (*p == '/')
				*p = '-';
		}
		if (!nm_supplicant_config_add_blob (self, name, field, uid, error))
			return FALSE;
	}
	return TRUE;
}

static void
nm_supplicant_config_finalize (GObject *object)
{
	/* Complete object destruction */
	g_hash_table_destroy (NM_SUPPLICANT_CONFIG_GET_PRIVATE (object)->config);
	g_hash_table_destroy (NM_SUPPLICANT_CONFIG_GET_PRIVATE (object)->blobs);

	/* Chain up to the parent class */
	G_OBJECT_CLASS (nm_supplicant_config_parent_class)->finalize (object);
}


static void
nm_supplicant_config_class_init (NMSupplicantConfigClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = nm_supplicant_config_finalize;

	g_type_class_add_private (object_class, sizeof (NMSupplicantConfigPrivate));
}

guint32
nm_supplicant_config_get_ap_scan (NMSupplicantConfig * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), 1);

	return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->ap_scan;
}

const char *
nm_supplicant_config_get_mac_randomization (NMSupplicantConfig *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), 0);

	/**
	 * mac_addr - MAC address policy default
	 *
	 * 0 = use permanent MAC address
	 * 1 = use random MAC address for each ESS connection
	 * 2 = like 1, but maintain OUI (with local admin bit set)
	 *
	 * By default, permanent MAC address is used unless policy is changed by
	 * the per-network mac_addr parameter.
	 */

	switch (NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->mac_randomization) {
	case NM_SETTING_MAC_RANDOMIZATION_ALWAYS:
		return "1";
	case NM_SETTING_MAC_RANDOMIZATION_NEVER:
	case NM_SETTING_MAC_RANDOMIZATION_DEFAULT:
	default:
		return "0";
	}
}

gboolean
nm_supplicant_config_fast_required (NMSupplicantConfig *self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);

	return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->fast_required;
}

GVariant *
nm_supplicant_config_to_variant (NMSupplicantConfig *self)
{
	NMSupplicantConfigPrivate *priv;
	GVariantBuilder builder;
	GHashTableIter iter;
	ConfigOption *option;
	const char *key;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), NULL);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	g_hash_table_iter_init (&iter, priv->config);
	while (g_hash_table_iter_next (&iter, (gpointer) &key, (gpointer) &option)) {
		switch (option->type) {
		case TYPE_INT:
			g_variant_builder_add (&builder, "{sv}", key, g_variant_new_int32 (atoi (option->value)));
			break;
		case TYPE_BYTES:
		case TYPE_UTF8:
			g_variant_builder_add (&builder, "{sv}",
			                       key,
			                       g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
			                                                  option->value, option->len, 1));
			break;
		case TYPE_KEYWORD:
		case TYPE_STRING:
			g_variant_builder_add (&builder, "{sv}", key, g_variant_new_string (option->value));
			break;
		default:
			break;
		}
	}

	return g_variant_builder_end (&builder);
}

GHashTable *
nm_supplicant_config_get_blobs (NMSupplicantConfig * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), NULL);

	return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->blobs;
}

static const char *
wifi_freqs_to_string (gboolean bg_band)
{
	static const char *str_2ghz = NULL;
	static const char *str_5ghz = NULL;
	const char *str;

	str = bg_band ? str_2ghz : str_5ghz;

	if (G_UNLIKELY (str == NULL)) {
		GString *tmp;
		const guint *freqs;
		int i;

		freqs = bg_band ? nm_utils_wifi_2ghz_freqs () : nm_utils_wifi_5ghz_freqs ();
		tmp = g_string_sized_new (bg_band ? 70 : 225);
		for (i = 0; freqs[i]; i++)
			g_string_append_printf (tmp, i == 0 ? "%d" : " %d", freqs[i]);
		str = g_string_free (tmp, FALSE);
		if (bg_band)
			str_2ghz = str;
		else
			str_5ghz = str;
	}
	return str;
}

gboolean
nm_supplicant_config_add_setting_wireless (NMSupplicantConfig * self,
                                           NMSettingWireless * setting,
                                           guint32 fixed_freq,
                                           NMSupplicantFeature mac_randomization_support,
                                           NMSettingMacRandomization mac_randomization_fallback,
                                           GError **error)
{
	NMSupplicantConfigPrivate *priv;
	gboolean is_adhoc, is_ap;
	const char *mode, *band;
	guint32 channel;
	GBytes *ssid;
	const char *bssid;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (setting != NULL, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	mode = nm_setting_wireless_get_mode (setting);
	is_adhoc = (mode && !strcmp (mode, "adhoc")) ? TRUE : FALSE;
	is_ap = (mode && !strcmp (mode, "ap")) ? TRUE : FALSE;
	if (is_adhoc || is_ap)
		priv->ap_scan = 2;
	else
		priv->ap_scan = 1;

	ssid = nm_setting_wireless_get_ssid (setting);
	if (!nm_supplicant_config_add_option (self, "ssid",
	                                      (char *) g_bytes_get_data (ssid, NULL),
	                                      g_bytes_get_size (ssid),
	                                      FALSE,
	                                      error))
		return FALSE;

	if (is_adhoc) {
		if (!nm_supplicant_config_add_option (self, "mode", "1", -1, FALSE, error))
			return FALSE;
	}

	if (is_ap) {
		if (!nm_supplicant_config_add_option (self, "mode", "2", -1, FALSE, error))
			return FALSE;
	}

	if ((is_adhoc || is_ap) && fixed_freq) {
		gs_free char *str_freq = NULL;

		str_freq = g_strdup_printf ("%u", fixed_freq);
		if (!nm_supplicant_config_add_option (self, "frequency", str_freq, -1, FALSE, error))
			return FALSE;
	}

	/* Except for Ad-Hoc and Hotspot, request that the driver probe for the
	 * specific SSID we want to associate with.
	 */
	if (!(is_adhoc || is_ap)) {
		if (!nm_supplicant_config_add_option (self, "scan_ssid", "1", -1, FALSE, error))
			return FALSE;
	}

	bssid = nm_setting_wireless_get_bssid (setting);
	if (bssid) {
		if (!nm_supplicant_config_add_option (self, "bssid",
		                                      bssid, strlen (bssid),
		                                      FALSE,
		                                      error))
			return FALSE;
	}

	band = nm_setting_wireless_get_band (setting);
	channel = nm_setting_wireless_get_channel (setting);
	if (band) {
		if (channel) {
			guint32 freq;
			gs_free char *str_freq = NULL;

			freq = nm_utils_wifi_channel_to_freq (channel, band);
			str_freq = g_strdup_printf ("%u", freq);
			if (!nm_supplicant_config_add_option (self, "freq_list", str_freq, -1, FALSE, error))
				return FALSE;
		} else {
			const char *freqs = NULL;

			if (!strcmp (band, "a"))
				freqs = wifi_freqs_to_string (FALSE);
			else if (!strcmp (band, "bg"))
				freqs = wifi_freqs_to_string (TRUE);

			if (freqs && !nm_supplicant_config_add_option (self, "freq_list", freqs, strlen (freqs), FALSE, error))
				return FALSE;
		}
	}

	priv->mac_randomization = nm_setting_wireless_get_mac_address_randomization (setting);
	if (priv->mac_randomization == NM_SETTING_MAC_RANDOMIZATION_DEFAULT) {
		priv->mac_randomization = mac_randomization_fallback;
		if (priv->mac_randomization == NM_SETTING_MAC_RANDOMIZATION_DEFAULT) {
			/* Don't use randomization, unless explicitly enabled.
			 * Randomization can work badly with captive portals. */
			priv->mac_randomization = NM_SETTING_MAC_RANDOMIZATION_NEVER;
		}
	}

	if (   priv->mac_randomization != NM_SETTING_MAC_RANDOMIZATION_NEVER
	    && mac_randomization_support != NM_SUPPLICANT_FEATURE_YES) {
		g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
		             "cannot enable mac-randomization due to missing supplicant support");
		return FALSE;
	}

	return TRUE;
}

static gboolean
add_string_val (NMSupplicantConfig *self,
                const char *field,
                const char *name,
                gboolean ucase,
                gboolean secret,
                GError **error)
{

	if (field) {
		gs_free char *value = NULL;

		if (ucase) {
			value = g_ascii_strup (field, -1);
			field = value;
		}
		return nm_supplicant_config_add_option (self, name, field, strlen (field), secret, error);
	}
	return TRUE;
}

#define ADD_STRING_LIST_VAL(self, setting, setting_name, field, field_plural, name, separator, ucase, secret, error) \
	({ \
		typeof (*(setting)) *_setting = (setting); \
		gboolean _success = TRUE; \
		\
		if (nm_setting_##setting_name##_get_num_##field_plural (_setting)) { \
			const char _separator = (separator); \
			GString *_str = g_string_new (NULL); \
			guint _k, _n; \
			\
			_n = nm_setting_##setting_name##_get_num_##field_plural (_setting); \
			for (_k = 0; _k < _n; _k++) { \
				const char *item = nm_setting_##setting_name##_get_##field (_setting, _k); \
				\
				if (!_str->len) { \
					g_string_append (_str, item); \
				} else { \
					g_string_append_c (_str, _separator); \
					g_string_append (_str, item); \
				} \
			} \
			if ((ucase)) \
				g_string_ascii_up (_str); \
			if (_str->len) { \
				if (!nm_supplicant_config_add_option ((self), (name), _str->str, -1, (secret), (error))) \
					_success = FALSE; \
			} \
			g_string_free (_str, TRUE); \
		} \
		_success; \
	})

static void
wep128_passphrase_hash (const char *input,
                        size_t input_len,
                        guint8 *out_digest,
                        size_t *out_digest_len)
{
	GChecksum *sum;
	guint8 data[64];
	int i;

	g_return_if_fail (out_digest != NULL);
	g_return_if_fail (out_digest_len != NULL);
	g_return_if_fail (*out_digest_len >= 16);

	/* Get at least 64 bytes by repeating the passphrase into the buffer */
	for (i = 0; i < sizeof (data); i++)
		data[i] = input[i % input_len];

	sum = g_checksum_new (G_CHECKSUM_MD5);
	g_assert (sum);
	g_checksum_update (sum, data, sizeof (data));
	g_checksum_get_digest (sum, out_digest, out_digest_len);
	g_checksum_free (sum);

	g_assert (*out_digest_len == 16);
	/* WEP104 keys are 13 bytes in length (26 hex characters) */
	*out_digest_len = 13;
}

static gboolean
add_wep_key (NMSupplicantConfig *self,
             const char *key,
             const char *name,
             NMWepKeyType wep_type,
             GError **error)
{
	size_t key_len = key ? strlen (key) : 0;

	if (!key || !key_len)
		return TRUE;

	if (wep_type == NM_WEP_KEY_TYPE_UNKNOWN) {
		if (nm_utils_wep_key_valid (key, NM_WEP_KEY_TYPE_KEY))
			wep_type = NM_WEP_KEY_TYPE_KEY;
		else if (nm_utils_wep_key_valid (key, NM_WEP_KEY_TYPE_PASSPHRASE))
			wep_type = NM_WEP_KEY_TYPE_PASSPHRASE;
	}

	if (   (wep_type == NM_WEP_KEY_TYPE_UNKNOWN)
	    || (wep_type == NM_WEP_KEY_TYPE_KEY)) {
		if ((key_len == 10) || (key_len == 26)) {
			gs_unref_bytes GBytes *bytes = NULL;

			bytes = nm_utils_hexstr2bin (key);
			if (!bytes) {
				g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
				             "cannot add wep-key %s to suplicant config because key is not hex",
				             name);
				return FALSE;
			}
			if (!nm_supplicant_config_add_option (self,
			                                      name,
			                                      g_bytes_get_data (bytes, NULL),
			                                      g_bytes_get_size (bytes),
			                                      TRUE,
			                                      error))
				return FALSE;
		} else if ((key_len == 5) || (key_len == 13)) {
			if (!nm_supplicant_config_add_option (self, name, key, key_len, TRUE, error))
				return FALSE;
		} else {
			g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
			             "Cannot add wep-key %s to suplicant config because key-length %u is invalid",
			             name, (guint) key_len);
			return FALSE;
		}
	} else if (wep_type == NM_WEP_KEY_TYPE_PASSPHRASE) {
		guint8 digest[16];
		size_t digest_len = sizeof (digest);

		wep128_passphrase_hash (key, key_len, digest, &digest_len);
		if (!nm_supplicant_config_add_option (self, name, (const char *) digest, digest_len, TRUE, error))
			return FALSE;
	}

	return TRUE;
}

gboolean
nm_supplicant_config_add_setting_wireless_security (NMSupplicantConfig *self,
                                                    NMSettingWirelessSecurity *setting,
                                                    NMSetting8021x *setting_8021x,
                                                    const char *con_uuid,
                                                    guint32 mtu,
                                                    GError **error)
{
	const char *key_mgmt, *auth_alg;
	const char *psk;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (setting != NULL, FALSE);
	g_return_val_if_fail (con_uuid != NULL, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (setting);
	if (!add_string_val (self, key_mgmt, "key_mgmt", TRUE, FALSE, error))
		return FALSE;

	auth_alg = nm_setting_wireless_security_get_auth_alg (setting);
	if (!add_string_val (self, auth_alg, "auth_alg", TRUE, FALSE, error))
		return FALSE;

	psk = nm_setting_wireless_security_get_psk (setting);
	if (psk) {
		size_t psk_len = strlen (psk);

		if (psk_len == 64) {
			gs_unref_bytes GBytes *bytes = NULL;

			/* Hex PSK */
			bytes = nm_utils_hexstr2bin (psk);
			if (!bytes) {
				g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
				             "Cannot add psk to supplicant config due to invalid hex");
				return FALSE;
			}

			if (!nm_supplicant_config_add_option (self,
			                                      "psk",
			                                      g_bytes_get_data (bytes, NULL),
			                                      g_bytes_get_size (bytes),
			                                      TRUE,
			                                      error))
				return FALSE;
		} else if (psk_len >= 8 && psk_len <= 63) {
			/* Use TYPE_STRING here so that it gets pushed to the
			 * supplicant as a string, and therefore gets quoted,
			 * and therefore the supplicant will interpret it as a
			 * passphrase and not a hex key.
			 */
			if (!nm_supplicant_config_add_option_with_type (self, "psk", psk, -1, TYPE_STRING, TRUE, error))
				return FALSE;
		} else {
			g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
			             "Cannot add psk to supplicant config due to invalid PSK length %u (not between 8 and 63 characters)",
			             (guint) psk_len);
			return FALSE;
		}
	}

	/* Only WPA-specific things when using WPA */
	if (   !strcmp (key_mgmt, "wpa-none")
	    || !strcmp (key_mgmt, "wpa-psk")
	    || !strcmp (key_mgmt, "wpa-eap")) {
		if (!ADD_STRING_LIST_VAL (self, setting, wireless_security, proto, protos, "proto", ' ', TRUE, FALSE, error))
			return FALSE;
		if (!ADD_STRING_LIST_VAL (self, setting, wireless_security, pairwise, pairwise, "pairwise", ' ', TRUE, FALSE, error))
			return FALSE;
		if (!ADD_STRING_LIST_VAL (self, setting, wireless_security, group, groups, "group", ' ', TRUE, FALSE, error))
			return FALSE;
	}

	/* WEP keys if required */
	if (!strcmp (key_mgmt, "none")) {
		NMWepKeyType wep_type = nm_setting_wireless_security_get_wep_key_type (setting);
		const char *wep0 = nm_setting_wireless_security_get_wep_key (setting, 0);
		const char *wep1 = nm_setting_wireless_security_get_wep_key (setting, 1);
		const char *wep2 = nm_setting_wireless_security_get_wep_key (setting, 2);
		const char *wep3 = nm_setting_wireless_security_get_wep_key (setting, 3);

		if (!add_wep_key (self, wep0, "wep_key0", wep_type, error))
			return FALSE;
		if (!add_wep_key (self, wep1, "wep_key1", wep_type, error))
			return FALSE;
		if (!add_wep_key (self, wep2, "wep_key2", wep_type, error))
			return FALSE;
		if (!add_wep_key (self, wep3, "wep_key3", wep_type, error))
			return FALSE;

		if (wep0 || wep1 || wep2 || wep3) {
			gs_free char *value = NULL;

			value = g_strdup_printf ("%d", nm_setting_wireless_security_get_wep_tx_keyidx (setting));
			if (!nm_supplicant_config_add_option (self, "wep_tx_keyidx", value, -1, FALSE, error))
				return FALSE;
		}
	}

	if (auth_alg && !strcmp (auth_alg, "leap")) {
		/* LEAP */
		if (!strcmp (key_mgmt, "ieee8021x")) {
			const char *tmp;

			tmp = nm_setting_wireless_security_get_leap_username (setting);
			if (!add_string_val (self, tmp, "identity", FALSE, FALSE, error))
				return FALSE;

			tmp = nm_setting_wireless_security_get_leap_password (setting);
			if (!add_string_val (self, tmp, "password", FALSE, TRUE, error))
				return FALSE;

			if (!add_string_val (self, "leap", "eap", TRUE, FALSE, error))
				return FALSE;
		} else {
			g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
			             "Invalid key-mgmt \"%s\" for leap", key_mgmt);
			return FALSE;
		}
	} else {
		/* 802.1x for Dynamic WEP and WPA-Enterprise */
		if (!strcmp (key_mgmt, "ieee8021x") || !strcmp (key_mgmt, "wpa-eap")) {
			if (!setting_8021x) {
				g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
				             "Cannot set key-mgmt %s with missing 8021x setting", key_mgmt);
				return FALSE;
			}
			if (!nm_supplicant_config_add_setting_8021x (self, setting_8021x, con_uuid, mtu, FALSE, error))
				return FALSE;
		}

		if (!strcmp (key_mgmt, "wpa-eap")) {
			/* If using WPA Enterprise, enable optimized background scanning
			 * to ensure roaming within an ESS works well.
			 */
			if (!nm_supplicant_config_add_option (self, "bgscan", "simple:30:-65:300", -1, FALSE, error))
				return FALSE;

			/* When using WPA-Enterprise, we want to use Proactive Key Caching (also
			 * called Opportunistic Key Caching) to avoid full EAP exchanges when
			 * roaming between access points in the same mobility group.
			 */
			if (!nm_supplicant_config_add_option (self, "proactive_key_caching", "1", -1, FALSE, error))
				return FALSE;
		}
	}

	return TRUE;
}

gboolean
nm_supplicant_config_add_setting_8021x (NMSupplicantConfig *self,
                                        NMSetting8021x *setting,
                                        const char *con_uuid,
                                        guint32 mtu,
                                        gboolean wired,
                                        GError **error)
{
	NMSupplicantConfigPrivate *priv;
	char *tmp;
	const char *peapver, *value, *path;
	gboolean added;
	GString *phase1, *phase2;
	GBytes *bytes;
	gboolean fast = FALSE;
	guint32 i, num_eap;
	gboolean fast_provisoning_allowed = FALSE;
	const char *ca_path_override = NULL, *ca_cert_override = NULL;
	guint32 frag, hdrs;
	gs_free char *frag_str = NULL;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (setting != NULL, FALSE);
	g_return_val_if_fail (con_uuid != NULL, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	value = nm_setting_802_1x_get_password (setting);
	if (value) {
		if (!add_string_val (self, value, "password", FALSE, TRUE, error))
			return FALSE;
	} else {
		bytes = nm_setting_802_1x_get_password_raw (setting);
		if (bytes) {
			if (!nm_supplicant_config_add_option (self,
			                                      "password",
			                                      (const char *) g_bytes_get_data (bytes, NULL),
			                                      g_bytes_get_size (bytes),
			                                      TRUE,
			                                      error))
				return FALSE;
		}
	}
	value = nm_setting_802_1x_get_pin (setting);
	if (!add_string_val (self, value, "pin", FALSE, TRUE, error))
		return FALSE;

	if (wired) {
		if (!add_string_val (self, "IEEE8021X", "key_mgmt", FALSE, FALSE, error))
			return FALSE;
		/* Wired 802.1x must always use eapol_flags=0 */
		if (!add_string_val (self, "0", "eapol_flags", FALSE, FALSE, error))
			return FALSE;
		priv->ap_scan = 0;
	}

	if (!ADD_STRING_LIST_VAL (self, setting, 802_1x, eap_method, eap_methods, "eap", ' ', TRUE, FALSE, error))
		return FALSE;

	/* Check EAP method for special handling: PEAP + GTC, FAST */
	num_eap = nm_setting_802_1x_get_num_eap_methods (setting);
	for (i = 0; i < num_eap; i++) {
		const char *method = nm_setting_802_1x_get_eap_method (setting, i);

		if (method && (strcasecmp (method, "fast") == 0)) {
			fast = TRUE;
			priv->fast_required = TRUE;
		}
	}

	/* Adjust the fragment size according to MTU, but do not set it higher than 1280-14
	 * for better compatibility */
	hdrs = 14; /* EAPOL + EAP-TLS */
	frag = 1280 - hdrs;
	if (mtu > hdrs)
		frag = CLAMP (mtu - hdrs, 100, frag);
	frag_str = g_strdup_printf ("%u", frag);

	if (!nm_supplicant_config_add_option (self, "fragment_size", frag_str, -1, FALSE, error))
		return FALSE;

	phase1 = g_string_new (NULL);
	peapver = nm_setting_802_1x_get_phase1_peapver (setting);
	if (peapver) {
		if (!strcmp (peapver, "0"))
			g_string_append (phase1, "peapver=0");
		else if (!strcmp (peapver, "1"))
			g_string_append (phase1, "peapver=1");
	}

	if (nm_setting_802_1x_get_phase1_peaplabel (setting)) {
		if (phase1->len)
			g_string_append_c (phase1, ' ');
		g_string_append_printf (phase1, "peaplabel=%s", nm_setting_802_1x_get_phase1_peaplabel (setting));
	}

	value = nm_setting_802_1x_get_phase1_fast_provisioning (setting);
	if (value) {
		if (phase1->len)
			g_string_append_c (phase1, ' ');
		g_string_append_printf (phase1, "fast_provisioning=%s", value);

		if (strcmp (value, "0") != 0)
			fast_provisoning_allowed = TRUE;
	}

	if (phase1->len) {
		if (!add_string_val (self, phase1->str, "phase1", FALSE, FALSE, error)) {
			g_string_free (phase1, TRUE);
			return FALSE;
		}
	}
	g_string_free (phase1, TRUE);

	phase2 = g_string_new (NULL);
	if (nm_setting_802_1x_get_phase2_auth (setting) && !fast_provisoning_allowed) {
		tmp = g_ascii_strup (nm_setting_802_1x_get_phase2_auth (setting), -1);
		g_string_append_printf (phase2, "auth=%s", tmp);
		g_free (tmp);
	}

	if (nm_setting_802_1x_get_phase2_autheap (setting)) {
		if (phase2->len)
			g_string_append_c (phase2, ' ');
		tmp = g_ascii_strup (nm_setting_802_1x_get_phase2_autheap (setting), -1);
		g_string_append_printf (phase2, "autheap=%s", tmp);
		g_free (tmp);
	}

	if (phase2->len) {
		if (!add_string_val (self, phase2->str, "phase2", FALSE, FALSE, error)) {
			g_string_free (phase2, TRUE);
			return FALSE;
		}
	}
	g_string_free (phase2, TRUE);

	/* PAC file */
	path = nm_setting_802_1x_get_pac_file (setting);
	if (path) {
		if (!add_string_val (self, path, "pac_file", FALSE, FALSE, error))
			return FALSE;
	} else {
		/* PAC file is not specified.
		 * If provisioning is allowed, use an blob format.
		 */
		if (fast_provisoning_allowed) {
			gs_free char *blob_name = NULL;

			blob_name = g_strdup_printf ("blob://pac-blob-%s", con_uuid);
			if (!add_string_val (self, blob_name, "pac_file", FALSE, FALSE, error))
				return FALSE;
		} else {
			/* This is only error for EAP-FAST; don't disturb other methods. */
			if (fast) {
				g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
				             "EAP-FAST error: no PAC file provided and "
				             "automatic PAC provisioning is disabled");
				return FALSE;
			}
		}
	}

	/* If user wants to use system CA certs, either populate ca_path (if the path
	 * is a directory) or ca_cert (the path is a file name) */
	if (nm_setting_802_1x_get_system_ca_certs (setting)) {
		if (g_file_test (SYSTEM_CA_PATH, G_FILE_TEST_IS_DIR))
			ca_path_override = SYSTEM_CA_PATH;
		else
			ca_cert_override = SYSTEM_CA_PATH;
	}

	/* CA path */
	path = nm_setting_802_1x_get_ca_path (setting);
	path = ca_path_override ? ca_path_override : path;
	if (path) {
		if (!add_string_val (self, path, "ca_path", FALSE, FALSE, error))
			return FALSE;
	}

	/* Phase2 CA path */
	path = nm_setting_802_1x_get_phase2_ca_path (setting);
	path = ca_path_override ? ca_path_override : path;
	if (path) {
		if (!add_string_val (self, path, "ca_path2", FALSE, FALSE, error))
			return FALSE;
	}

	/* CA certificate */
	if (ca_cert_override) {
		if (!add_string_val (self, ca_cert_override, "ca_cert", FALSE, FALSE, error))
			return FALSE;
	} else {
		switch (nm_setting_802_1x_get_ca_cert_scheme (setting)) {
		case NM_SETTING_802_1X_CK_SCHEME_BLOB:
			bytes = nm_setting_802_1x_get_ca_cert_blob (setting);
			if (!nm_supplicant_config_add_blob_for_connection (self, bytes, "ca_cert", con_uuid, error))
				return FALSE;
			break;
		case NM_SETTING_802_1X_CK_SCHEME_PATH:
			path = nm_setting_802_1x_get_ca_cert_path (setting);
			if (!add_string_val (self, path, "ca_cert", FALSE, FALSE, error))
				return FALSE;
			break;
		default:
			break;
		}
	}

	/* Phase 2 CA certificate */
	if (ca_cert_override) {
		if (!add_string_val (self, ca_cert_override, "ca_cert2", FALSE, FALSE, error))
			return FALSE;
	} else {
		switch (nm_setting_802_1x_get_phase2_ca_cert_scheme (setting)) {
		case NM_SETTING_802_1X_CK_SCHEME_BLOB:
			bytes = nm_setting_802_1x_get_phase2_ca_cert_blob (setting);
			if (!nm_supplicant_config_add_blob_for_connection (self, bytes, "ca_cert2", con_uuid, error))
				return FALSE;
			break;
		case NM_SETTING_802_1X_CK_SCHEME_PATH:
			path = nm_setting_802_1x_get_phase2_ca_cert_path (setting);
			if (!add_string_val (self, path, "ca_cert2", FALSE, FALSE, error))
				return FALSE;
			break;
		default:
			break;
		}
	}

	/* Subject match */
	value = nm_setting_802_1x_get_subject_match (setting);
	if (!add_string_val (self, value, "subject_match", FALSE, FALSE, error))
		return FALSE;
	value = nm_setting_802_1x_get_phase2_subject_match (setting);
	if (!add_string_val (self, value, "subject_match2", FALSE, FALSE, error))
		return FALSE;

	/* altSubjectName match */
	if (!ADD_STRING_LIST_VAL (self, setting, 802_1x, altsubject_match, altsubject_matches, "altsubject_match", ';', FALSE, FALSE, error))
		return FALSE;
	if (!ADD_STRING_LIST_VAL (self, setting, 802_1x, phase2_altsubject_match, phase2_altsubject_matches, "altsubject_match2", ';', FALSE, FALSE, error))
		return FALSE;

	/* Domain suffix match */
	value = nm_setting_802_1x_get_domain_suffix_match (setting);
	if (!add_string_val (self, value, "domain_suffix_match", FALSE, FALSE, error))
		return FALSE;
	value = nm_setting_802_1x_get_phase2_domain_suffix_match (setting);
	if (!add_string_val (self, value, "domain_suffix_match2", FALSE, FALSE, error))
		return FALSE;

	/* Private key */
	added = FALSE;
	switch (nm_setting_802_1x_get_private_key_scheme (setting)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		bytes = nm_setting_802_1x_get_private_key_blob (setting);
		if (!nm_supplicant_config_add_blob_for_connection (self, bytes, "private_key", con_uuid, error))
			return FALSE;
		added = TRUE;
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		path = nm_setting_802_1x_get_private_key_path (setting);
		if (!add_string_val (self, path, "private_key", FALSE, FALSE, error))
			return FALSE;
		added = TRUE;
		break;
	default:
		break;
	}

	if (added) {
		NMSetting8021xCKFormat format;
		NMSetting8021xCKScheme scheme;

		format = nm_setting_802_1x_get_private_key_format (setting);
		scheme = nm_setting_802_1x_get_private_key_scheme (setting);

		if (   scheme == NM_SETTING_802_1X_CK_SCHEME_PATH
		    || format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
			/* Only add the private key password for PKCS#12 blobs and
			 * all path schemes, since in both of these cases the private key
			 * isn't decrypted at all.
			 */
			value = nm_setting_802_1x_get_private_key_password (setting);
			if (!add_string_val (self, value, "private_key_passwd", FALSE, TRUE, error))
				return FALSE;
		}

		if (format != NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
			/* Only add the client cert if the private key is not PKCS#12, as
			 * wpa_supplicant configuration directs us to do.
			 */
			switch (nm_setting_802_1x_get_client_cert_scheme (setting)) {
			case NM_SETTING_802_1X_CK_SCHEME_BLOB:
				bytes = nm_setting_802_1x_get_client_cert_blob (setting);
				if (!nm_supplicant_config_add_blob_for_connection (self, bytes, "client_cert", con_uuid, error))
					return FALSE;
				break;
			case NM_SETTING_802_1X_CK_SCHEME_PATH:
				path = nm_setting_802_1x_get_client_cert_path (setting);
				if (!add_string_val (self, path, "client_cert", FALSE, FALSE, error))
					return FALSE;
				break;
			default:
				break;
			}
		}
	}

	/* Phase 2 private key */
	added = FALSE;
	switch (nm_setting_802_1x_get_phase2_private_key_scheme (setting)) {
	case NM_SETTING_802_1X_CK_SCHEME_BLOB:
		bytes = nm_setting_802_1x_get_phase2_private_key_blob (setting);
		if (!nm_supplicant_config_add_blob_for_connection (self, bytes, "private_key2", con_uuid, error))
			return FALSE;
		added = TRUE;
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PATH:
		path = nm_setting_802_1x_get_phase2_private_key_path (setting);
		if (!add_string_val (self, path, "private_key2", FALSE, FALSE, error))
			return FALSE;
		added = TRUE;
		break;
	default:
		break;
	}

	if (added) {
		NMSetting8021xCKFormat format;
		NMSetting8021xCKScheme scheme;

		format = nm_setting_802_1x_get_phase2_private_key_format (setting);
		scheme = nm_setting_802_1x_get_phase2_private_key_scheme (setting);

		if (   scheme == NM_SETTING_802_1X_CK_SCHEME_PATH
		    || format == NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
			/* Only add the private key password for PKCS#12 blobs and
			 * all path schemes, since in both of these cases the private key
			 * isn't decrypted at all.
			 */
			value = nm_setting_802_1x_get_phase2_private_key_password (setting);
			if (!add_string_val (self, value, "private_key2_passwd", FALSE, TRUE, error))
				return FALSE;
		}

		if (format != NM_SETTING_802_1X_CK_FORMAT_PKCS12) {
			/* Only add the client cert if the private key is not PKCS#12, as
			 * wpa_supplicant configuration directs us to do.
			 */
			switch (nm_setting_802_1x_get_phase2_client_cert_scheme (setting)) {
			case NM_SETTING_802_1X_CK_SCHEME_BLOB:
				bytes = nm_setting_802_1x_get_phase2_client_cert_blob (setting);
				if (!nm_supplicant_config_add_blob_for_connection (self, bytes, "client_cert2", con_uuid, error))
					return FALSE;
				break;
			case NM_SETTING_802_1X_CK_SCHEME_PATH:
				path = nm_setting_802_1x_get_phase2_client_cert_path (setting);
				if (!add_string_val (self, path, "client_cert2", FALSE, FALSE, error))
					return FALSE;
				break;
			default:
				break;
			}
		}
	}

	value = nm_setting_802_1x_get_identity (setting);
	if (!add_string_val (self, value, "identity", FALSE, FALSE, error))
		return FALSE;
	value = nm_setting_802_1x_get_anonymous_identity (setting);
	if (!add_string_val (self, value, "anonymous_identity", FALSE, FALSE, error))
		return FALSE;

	return TRUE;
}

gboolean
nm_supplicant_config_add_no_security (NMSupplicantConfig *self, GError **error)
{
	return nm_supplicant_config_add_option (self, "key_mgmt", "NONE", -1, FALSE, error);
}

