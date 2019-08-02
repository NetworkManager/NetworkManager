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

#include "nm-supplicant-config.h"

#include <stdlib.h>

#include "nm-core-internal.h"

#include "nm-supplicant-settings-verify.h"
#include "nm-setting.h"
#include "nm-auth-subject.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-setting-ip4-config.h"

typedef struct {
	char *value;
	guint32 len;
	OptType type;
} ConfigOption;

/*****************************************************************************/

typedef struct {
	GHashTable *config;
	GHashTable *blobs;
	guint32    ap_scan;
	gboolean   fast_required;
	gboolean   dispose_has_run;
	gboolean   support_pmf;
	gboolean   support_fils;
	gboolean   support_ft;
	gboolean   support_sha384;
} NMSupplicantConfigPrivate;

struct _NMSupplicantConfig {
	GObject parent;
	NMSupplicantConfigPrivate _priv;
};

struct _NMSupplicantConfigClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMSupplicantConfig, nm_supplicant_config, G_TYPE_OBJECT)

#define NM_SUPPLICANT_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMSupplicantConfig, NM_IS_SUPPLICANT_CONFIG)

/*****************************************************************************/

NMSupplicantConfig *
nm_supplicant_config_new (gboolean support_pmf, gboolean support_fils,
                          gboolean support_ft, gboolean support_sha384)
{
	NMSupplicantConfigPrivate *priv;
	NMSupplicantConfig *self;

	self = g_object_new (NM_TYPE_SUPPLICANT_CONFIG, NULL);
	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	priv->support_pmf = support_pmf;
	priv->support_fils = support_fils;
	priv->support_ft = support_ft;
	priv->support_sha384 = support_sha384;

	return self;
}

static void
config_option_free (ConfigOption *opt)
{
	g_free (opt->value);
	g_slice_free (ConfigOption, opt);
}

static void
nm_supplicant_config_init (NMSupplicantConfig * self)
{
	NMSupplicantConfigPrivate *priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	priv->config = g_hash_table_new_full (nm_str_hash, g_str_equal,
	                                      g_free,
	                                      (GDestroyNotify) config_option_free);

	priv->blobs = g_hash_table_new_full (nm_str_hash, g_str_equal,
	                                     g_free,
	                                     (GDestroyNotify) g_bytes_unref);

	priv->ap_scan = 1;
	priv->dispose_has_run = FALSE;
}

static gboolean
nm_supplicant_config_add_option_with_type (NMSupplicantConfig *self,
                                           const char *key,
                                           const char *value,
                                           gint32 len,
                                           OptType opt_type,
                                           const char *hidden,
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
			gs_free char *str_free = NULL;
			const char *str;

			str = nm_utils_buf_utf8safe_escape (value, len, NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL, &str_free);

			str = nm_strquote_a (255, str);

			g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
			             "key '%s' and/or value %s invalid",
			             key,
			             hidden ?: str);
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
		nm_log_info (LOGD_SUPPLICANT, "Config: added '%s' value '%s'", key, hidden ?: &buf[0]);
	}

	g_hash_table_insert (priv->config, g_strdup (key), opt);

	return TRUE;
}

static gboolean
nm_supplicant_config_add_option (NMSupplicantConfig *self,
                                 const char *key,
                                 const char *value,
                                 gint32 len,
                                 const char *hidden,
                                 GError **error)
{
	return nm_supplicant_config_add_option_with_type (self, key, value, len, TYPE_INVALID, hidden, error);
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

	opt = g_slice_new0 (ConfigOption);
	opt->value = g_strdup_printf ("blob://%s", blobid);
	opt->len = strlen (opt->value);
	opt->type = type;

	nm_log_info (LOGD_SUPPLICANT, "Config: added '%s' value '%s'", key, opt->value);

	g_hash_table_insert (priv->config, g_strdup (key), opt);
	g_hash_table_insert (priv->blobs,
	                     g_strdup (blobid),
	                     g_bytes_ref (value));

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
	NMSupplicantConfigPrivate *priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE ((NMSupplicantConfig *) object);

	g_hash_table_destroy (priv->config);
	g_hash_table_destroy (priv->blobs);

	G_OBJECT_CLASS (nm_supplicant_config_parent_class)->finalize (object);
}

static void
nm_supplicant_config_class_init (NMSupplicantConfigClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = nm_supplicant_config_finalize;
}

guint32
nm_supplicant_config_get_ap_scan (NMSupplicantConfig * self)
{
	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), 1);

	return NM_SUPPLICANT_CONFIG_GET_PRIVATE (self)->ap_scan;
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
nm_supplicant_config_add_setting_macsec (NMSupplicantConfig * self,
                                         NMSettingMacsec * setting,
                                         GError **error)
{
	const char *value;
	char buf[32];
	int port;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (setting != NULL, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (!nm_supplicant_config_add_option (self, "macsec_policy", "1", -1, NULL, error))
		return FALSE;

	value = nm_setting_macsec_get_encrypt (setting) ? "0" : "1";
	if (!nm_supplicant_config_add_option (self, "macsec_integ_only", value, -1, NULL, error))
		return FALSE;

	port = nm_setting_macsec_get_port (setting);
	if (port > 0 && port < 65534) {
		snprintf (buf, sizeof (buf), "%d", port);
		if (!nm_supplicant_config_add_option (self, "macsec_port", buf, -1, NULL, error))
			return FALSE;
	}

	if (nm_setting_macsec_get_mode (setting) == NM_SETTING_MACSEC_MODE_PSK) {
		guint8 buffer_cak[NM_SETTING_MACSEC_MKA_CAK_LENGTH/2];
		guint8 buffer_ckn[NM_SETTING_MACSEC_MKA_CKN_LENGTH/2];

		if (!nm_supplicant_config_add_option (self, "key_mgmt", "NONE", -1, NULL, error))
			return FALSE;

		value = nm_setting_macsec_get_mka_cak (setting);
		if (   !value
		    || !nm_utils_hexstr2bin_buf (value,
		                                 FALSE,
		                                 FALSE,
		                                 NULL,
		                                 buffer_cak)) {
			g_set_error_literal (error,
			                     NM_SUPPLICANT_ERROR,
			                     NM_SUPPLICANT_ERROR_CONFIG,
			                     value ? "invalid MKA CAK" : "missing MKA CAK");
			return FALSE;
		}
		if (!nm_supplicant_config_add_option (self,
		                                      "mka_cak",
		                                      (char *) buffer_cak,
		                                      sizeof (buffer_cak),
		                                      "<hidden>",
		                                      error))
			return FALSE;

		value = nm_setting_macsec_get_mka_ckn (setting);
		if (   !value
		    || !nm_utils_hexstr2bin_buf (value,
		                                 FALSE,
		                                 FALSE,
		                                 NULL,
		                                 buffer_ckn)) {
			g_set_error_literal (error,
			                     NM_SUPPLICANT_ERROR,
			                     NM_SUPPLICANT_ERROR_CONFIG,
			                     value ? "invalid MKA CKN" : "missing MKA CKN");
			return FALSE;
		}
		if (!nm_supplicant_config_add_option (self,
		                                      "mka_ckn",
		                                      (char *) buffer_ckn,
		                                      sizeof (buffer_ckn),
		                                      NULL,
		                                      error))
			return FALSE;
	}

	return TRUE;
}

gboolean
nm_supplicant_config_add_setting_wireless (NMSupplicantConfig * self,
                                           NMSettingWireless * setting,
                                           guint32 fixed_freq,
                                           GError **error)
{
	NMSupplicantConfigPrivate *priv;
	gboolean is_adhoc, is_ap, is_mesh;
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
	is_mesh = (mode && !strcmp (mode, "mesh")) ? TRUE : FALSE;
	if (is_adhoc || is_ap)
		priv->ap_scan = 2;
	else
		priv->ap_scan = 1;

	ssid = nm_setting_wireless_get_ssid (setting);
	if (!nm_supplicant_config_add_option (self, "ssid",
	                                      (char *) g_bytes_get_data (ssid, NULL),
	                                      g_bytes_get_size (ssid),
	                                      NULL,
	                                      error))
		return FALSE;

	if (is_adhoc) {
		if (!nm_supplicant_config_add_option (self, "mode", "1", -1, NULL, error))
			return FALSE;
	}

	if (is_ap) {
		if (!nm_supplicant_config_add_option (self, "mode", "2", -1, NULL, error))
			return FALSE;

		if (   nm_setting_wireless_get_hidden (setting)
		    && !nm_supplicant_config_add_option (self,
		                                         "ignore_broadcast_ssid", "1",
		                                         -1, NULL, error))
			return FALSE;
	}

	if (is_mesh) {
		if (!nm_supplicant_config_add_option (self, "mode", "5", -1, NULL, error))
			return FALSE;
	}

	if ((is_adhoc || is_ap || is_mesh) && fixed_freq) {
		gs_free char *str_freq = NULL;

		str_freq = g_strdup_printf ("%u", fixed_freq);
		if (!nm_supplicant_config_add_option (self, "frequency", str_freq, -1, NULL, error))
			return FALSE;
	}

	/* Except for Ad-Hoc, Hotspot and Mesh, request that the driver probe for the
	 * specific SSID we want to associate with.
	 */
	if (!(is_adhoc || is_ap || is_mesh)) {
		if (!nm_supplicant_config_add_option (self, "scan_ssid", "1", -1, NULL, error))
			return FALSE;
	}

	bssid = nm_setting_wireless_get_bssid (setting);
	if (bssid) {
		if (!nm_supplicant_config_add_option (self, "bssid",
		                                      bssid, strlen (bssid),
		                                      NULL,
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
			if (!nm_supplicant_config_add_option (self, "freq_list", str_freq, -1, NULL, error))
				return FALSE;
		} else {
			const char *freqs = NULL;

			if (!strcmp (band, "a"))
				freqs = wifi_freqs_to_string (FALSE);
			else if (!strcmp (band, "bg"))
				freqs = wifi_freqs_to_string (TRUE);

			if (freqs && !nm_supplicant_config_add_option (self, "freq_list", freqs, strlen (freqs), NULL, error))
				return FALSE;
		}
	}

	return TRUE;
}

gboolean
nm_supplicant_config_add_bgscan (NMSupplicantConfig *self,
                                 NMConnection *connection,
                                 GError **error)
{
	NMSettingWireless *s_wifi;
	NMSettingWirelessSecurity *s_wsec;
	const char *bgscan;

	s_wifi = nm_connection_get_setting_wireless (connection);
	g_assert (s_wifi);

	/* Don't scan when a shared connection (either AP or Ad-Hoc) is active;
	 * it will disrupt connected clients.
	 */
	if (NM_IN_STRSET (nm_setting_wireless_get_mode (s_wifi),
	                  NM_SETTING_WIRELESS_MODE_AP,
	                  NM_SETTING_WIRELESS_MODE_ADHOC))
		return TRUE;

	/* Don't scan when the connection is locked to a specific AP, since
	 * intra-ESS roaming (which requires periodic scanning) isn't being
	 * used due to the specific AP lock. (bgo #513820)
	 */
	if (nm_setting_wireless_get_bssid (s_wifi))
		return TRUE;

	/* Default to a very long bgscan interval when signal is OK on the assumption
	 * that either (a) there aren't multiple APs and we don't need roaming, or
	 * (b) since EAP/802.1x isn't used and thus there are fewer steps to fail
	 * during a roam, we can wait longer before scanning for roam candidates.
	 */
	bgscan = "simple:30:-80:86400";

	/* If using WPA Enterprise or Dynamic WEP use a shorter bgscan interval on
	 * the assumption that this is a multi-AP ESS in which we want more reliable
	 * roaming between APs.  Thus trigger scans when the signal is still somewhat
	 * OK so we have an up-to-date roam candidate list when the signal gets bad.
	 */
	s_wsec = nm_connection_get_setting_wireless_security (connection);
	if (s_wsec) {
		if (NM_IN_STRSET (nm_setting_wireless_security_get_key_mgmt (s_wsec),
		                  "ieee8021x",
		                  "wpa-eap"))
			bgscan = "simple:30:-65:300";
	}

	return nm_supplicant_config_add_option (self, "bgscan", bgscan, -1, FALSE, error);
}

static gboolean
add_string_val (NMSupplicantConfig *self,
                const char *field,
                const char *name,
                gboolean ucase,
                const char *hidden,
                GError **error)
{

	if (field) {
		gs_free char *value = NULL;

		if (ucase) {
			value = g_ascii_strup (field, -1);
			field = value;
		}
		return nm_supplicant_config_add_option (self, name, field, strlen (field), hidden, error);
	}
	return TRUE;
}

#define ADD_STRING_LIST_VAL(self, setting, setting_name, field, field_plural, name, separator, ucase, hidden, error) \
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
				if (!nm_supplicant_config_add_option ((self), (name), _str->str, -1, (hidden), (error))) \
					_success = FALSE; \
			} \
			g_string_free (_str, TRUE); \
		} \
		_success; \
	})

static void
wep128_passphrase_hash (const char *input,
                        gsize input_len,
                        guint8 *digest /* 13 bytes */)
{
	nm_auto_free_checksum GChecksum *sum = NULL;
	guint8 md5[NM_UTILS_CHECKSUM_LENGTH_MD5];
	guint8 data[64];
	int i;

	nm_assert (input);
	nm_assert (input_len);
	nm_assert (digest);

	/* Get at least 64 bytes by repeating the passphrase into the buffer */
	for (i = 0; i < sizeof (data); i++)
		data[i] = input[i % input_len];

	sum = g_checksum_new (G_CHECKSUM_MD5);
	g_checksum_update (sum, data, sizeof (data));
	nm_utils_checksum_get_digest (sum, md5);

	/* WEP104 keys are 13 bytes in length (26 hex characters) */
	memcpy (digest, md5, 13);
}

static gboolean
add_wep_key (NMSupplicantConfig *self,
             const char *key,
             const char *name,
             NMWepKeyType wep_type,
             GError **error)
{
	gsize key_len;

	if (   !key
	    || (key_len = strlen (key)) == 0)
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
			guint8 buffer[26/2];

			if (!nm_utils_hexstr2bin_full (key,
			                               FALSE,
			                               FALSE,
			                               NULL,
			                               key_len / 2,
			                               buffer,
			                               sizeof (buffer),
			                               NULL)) {
				g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
				             "cannot add wep-key %s to suplicant config because key is not hex",
				             name);
				return FALSE;
			}
			if (!nm_supplicant_config_add_option (self,
			                                      name,
			                                      (char *) buffer,
			                                      key_len / 2,
			                                      "<hidden>",
			                                      error))
				return FALSE;
		} else if ((key_len == 5) || (key_len == 13)) {
			if (!nm_supplicant_config_add_option (self, name, key, key_len, "<hidden>", error))
				return FALSE;
		} else {
			g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
			             "Cannot add wep-key %s to suplicant config because key-length %u is invalid",
			             name, (guint) key_len);
			return FALSE;
		}
	} else if (wep_type == NM_WEP_KEY_TYPE_PASSPHRASE) {
		guint8 digest[13];

		wep128_passphrase_hash (key, key_len, digest);
		if (!nm_supplicant_config_add_option (self, name, (const char *) digest, sizeof (digest), "<hidden>", error))
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
                                                    NMSettingWirelessSecurityPmf pmf,
                                                    NMSettingWirelessSecurityFils fils,
                                                    GError **error)
{
	NMSupplicantConfigPrivate *priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);
	nm_auto_free_gstring GString *key_mgmt_conf = NULL;
	const char *key_mgmt, *auth_alg;
	const char *psk;
	gboolean set_pmf;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (setting != NULL, FALSE);
	g_return_val_if_fail (con_uuid != NULL, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* Check if we actually support FILS */
	if (!priv->support_fils) {
		if (fils == NM_SETTING_WIRELESS_SECURITY_FILS_REQUIRED) {
			g_set_error_literal (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
			                     "Supplicant does not support FILS");
			return FALSE;
		} else if (fils == NM_SETTING_WIRELESS_SECURITY_FILS_OPTIONAL)
			fils = NM_SETTING_WIRELESS_SECURITY_FILS_DISABLE;
	}

	key_mgmt = nm_setting_wireless_security_get_key_mgmt (setting);
	key_mgmt_conf = g_string_new (key_mgmt);
	if (nm_streq (key_mgmt, "wpa-psk")) {
		if (priv->support_pmf)
			g_string_append (key_mgmt_conf, " wpa-psk-sha256");
		if (priv->support_ft)
			g_string_append (key_mgmt_conf, " ft-psk");
	} else if (nm_streq (key_mgmt, "wpa-eap")) {
		if (priv->support_pmf)
			g_string_append (key_mgmt_conf, " wpa-eap-sha256");
		if (priv->support_ft)
			g_string_append (key_mgmt_conf, " ft-eap");
		if (priv->support_ft && priv->support_sha384)
			g_string_append (key_mgmt_conf, " ft-eap-sha384");
		switch (fils) {
		case NM_SETTING_WIRELESS_SECURITY_FILS_REQUIRED:
			g_string_truncate (key_mgmt_conf, 0);
			if (!priv->support_pmf)
				g_string_assign (key_mgmt_conf, "fils-sha256 fils-sha384");
			/* fall-through */
		case NM_SETTING_WIRELESS_SECURITY_FILS_OPTIONAL:
			if (priv->support_pmf)
				g_string_append (key_mgmt_conf, " fils-sha256 fils-sha384");
			if (priv->support_pmf && priv->support_ft)
				g_string_append (key_mgmt_conf, " ft-fils-sha256");
			if (priv->support_pmf && priv->support_ft & priv->support_sha384)
				g_string_append (key_mgmt_conf, " ft-fils-sha384");
			break;
		default:
			break;
		}
	} else if (nm_streq (key_mgmt, "sae")) {
		if (priv->support_ft)
			g_string_append (key_mgmt_conf, " ft-sae");
	}

	if (!add_string_val (self, key_mgmt_conf->str, "key_mgmt", TRUE, NULL, error))
		return FALSE;

	auth_alg = nm_setting_wireless_security_get_auth_alg (setting);
	if (!add_string_val (self, auth_alg, "auth_alg", TRUE, NULL, error))
		return FALSE;

	psk = nm_setting_wireless_security_get_psk (setting);
	if (psk) {
		size_t psk_len = strlen (psk);


		if (psk_len >= 8 && psk_len <= 63) {
			/* Use TYPE_STRING here so that it gets pushed to the
			 * supplicant as a string, and therefore gets quoted,
			 * and therefore the supplicant will interpret it as a
			 * passphrase and not a hex key.
			 */
			if (!nm_supplicant_config_add_option_with_type (self, "psk", psk, -1, TYPE_STRING, "<hidden>", error))
				return FALSE;
		} else if (nm_streq (key_mgmt, "sae")) {
			/* If the SAE password doesn't comply with WPA-PSK limitation,
			 * we need to call it "sae_password" instead of "psk".
			 */
			if (!nm_supplicant_config_add_option_with_type (self, "sae_password", psk, -1, TYPE_STRING, "<hidden>", error))
				return FALSE;
		} else if (psk_len == 64) {
			guint8 buffer[32];

			/* Hex PSK */
			if (!nm_utils_hexstr2bin_buf (psk,
			                              FALSE,
			                              FALSE,
			                              NULL,
			                              buffer)) {
				g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
				             "Cannot add psk to supplicant config due to invalid hex");
				return FALSE;
			}
			if (!nm_supplicant_config_add_option (self,
			                                      "psk",
			                                      (char *) buffer,
			                                      sizeof (buffer),
			                                      "<hidden>",
			                                      error))
				return FALSE;
		} else {
			g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
			             "Cannot add psk to supplicant config due to invalid PSK length %u (not between 8 and 63 characters)",
			             (guint) psk_len);
			return FALSE;
		}
	}

	/* Don't try to enable PMF on non-WPA networks */
	if (!NM_IN_STRSET (key_mgmt, "wpa-eap", "wpa-psk"))
		pmf = NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE;

	/* Check if we actually support PMF */
	set_pmf = TRUE;
	if (!priv->support_pmf) {
		if (pmf == NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED) {
			g_set_error_literal (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
			                     "Supplicant does not support PMF");
			return FALSE;
		}
		set_pmf = FALSE;
	}

	/* Only WPA-specific things when using WPA */
	if (   !strcmp (key_mgmt, "wpa-none")
	    || !strcmp (key_mgmt, "wpa-psk")
	    || !strcmp (key_mgmt, "wpa-eap")
	    || !strcmp (key_mgmt, "sae")) {
		if (!ADD_STRING_LIST_VAL (self, setting, wireless_security, proto, protos, "proto", ' ', TRUE, NULL, error))
			return FALSE;
		if (!ADD_STRING_LIST_VAL (self, setting, wireless_security, pairwise, pairwise, "pairwise", ' ', TRUE, NULL, error))
			return FALSE;
		if (!ADD_STRING_LIST_VAL (self, setting, wireless_security, group, groups, "group", ' ', TRUE, NULL, error))
			return FALSE;

		if (   set_pmf
		    && !nm_streq (key_mgmt, "wpa-none")
		    && NM_IN_SET (pmf,
		                  NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE,
		                  NM_SETTING_WIRELESS_SECURITY_PMF_REQUIRED)) {
			if (!nm_supplicant_config_add_option (self,
			                                      "ieee80211w",
			                                      pmf == NM_SETTING_WIRELESS_SECURITY_PMF_DISABLE ? "0" : "2",
			                                      -1,
			                                      NULL,
			                                      error))
				return FALSE;
		}
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
			if (!nm_supplicant_config_add_option (self, "wep_tx_keyidx", value, -1, NULL, error))
				return FALSE;
		}
	}

	if (auth_alg && !strcmp (auth_alg, "leap")) {
		/* LEAP */
		if (!strcmp (key_mgmt, "ieee8021x")) {
			const char *tmp;

			tmp = nm_setting_wireless_security_get_leap_username (setting);
			if (!add_string_val (self, tmp, "identity", FALSE, NULL, error))
				return FALSE;

			tmp = nm_setting_wireless_security_get_leap_password (setting);
			if (!add_string_val (self, tmp, "password", FALSE, "<hidden>", error))
				return FALSE;

			if (!add_string_val (self, "leap", "eap", TRUE, NULL, error))
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
			/* When using WPA-Enterprise, we want to use Proactive Key Caching (also
			 * called Opportunistic Key Caching) to avoid full EAP exchanges when
			 * roaming between access points in the same mobility group.
			 */
			if (!nm_supplicant_config_add_option (self, "proactive_key_caching", "1", -1, NULL, error))
				return FALSE;
		}
	}

	return TRUE;
}

static gboolean
add_pkcs11_uri_with_pin (NMSupplicantConfig *self,
                         const char *name,
                         const char *uri,
                         const char *pin,
                         const NMSettingSecretFlags pin_flags,
                         GError **error)
{
	gs_strfreev char **split = NULL;
	gs_free char *tmp = NULL;
	gs_free char *tmp_log = NULL;
	gs_free char *pin_qattr = NULL;
	char *escaped = NULL;

	if (uri == NULL)
		return TRUE;

	/* We ignore the attributes -- RFC 7512 suggests that some of them
	 * might be unsafe and we want to be on the safe side. Also, we're
	 * installing our attributes, so this makes things a bit easier for us. */
	split = g_strsplit (uri, "&", 2);
	if (split[1])
		nm_log_info (LOGD_SUPPLICANT, "URI attributes ignored");

	/* Fill in the PIN if required. */
	if (pin) {
		escaped = g_uri_escape_string (pin, NULL, TRUE);
		pin_qattr = g_strdup_printf ("pin-value=%s", escaped);
		g_free (escaped);
	} else if (!(pin_flags & NM_SETTING_SECRET_FLAG_NOT_REQUIRED)) {
		/* Include an empty PIN to indicate the login is still needed.
		 * Probably a token that has a PIN path and the actual PIN will
		 * be entered using a protected path. */
		pin_qattr = g_strdup ("pin-value=");
	}

	tmp = g_strdup_printf ("%s%s%s", split[0],
	                       (pin_qattr ? "?" : ""),
	                       (pin_qattr ?: ""));

	tmp_log = g_strdup_printf ("%s%s%s", split[0],
	                           (pin_qattr ? "?" : ""),
	                           (pin_qattr ? "pin-value=<hidden>" : ""));

	return add_string_val (self, tmp, name, FALSE, tmp_log, error);
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
	NMSetting8021xAuthFlags phase1_auth_flags;
	nm_auto_free_gstring GString *eap_str = NULL;

	g_return_val_if_fail (NM_IS_SUPPLICANT_CONFIG (self), FALSE);
	g_return_val_if_fail (setting != NULL, FALSE);
	g_return_val_if_fail (con_uuid != NULL, FALSE);

	priv = NM_SUPPLICANT_CONFIG_GET_PRIVATE (self);

	value = nm_setting_802_1x_get_password (setting);
	if (value) {
		if (!add_string_val (self, value, "password", FALSE, "<hidden>", error))
			return FALSE;
	} else {
		bytes = nm_setting_802_1x_get_password_raw (setting);
		if (bytes) {
			if (!nm_supplicant_config_add_option (self,
			                                      "password",
			                                      (const char *) g_bytes_get_data (bytes, NULL),
			                                      g_bytes_get_size (bytes),
			                                      "<hidden>",
			                                      error))
				return FALSE;
		}
	}
	value = nm_setting_802_1x_get_pin (setting);
	if (!add_string_val (self, value, "pin", FALSE, "<hidden>", error))
		return FALSE;

	if (wired) {
		if (!add_string_val (self, "IEEE8021X", "key_mgmt", FALSE, NULL, error))
			return FALSE;
		/* Wired 802.1x must always use eapol_flags=0 */
		if (!add_string_val (self, "0", "eapol_flags", FALSE, NULL, error))
			return FALSE;
		priv->ap_scan = 0;
	}

	/* Build the "eap" option string while we check for EAP methods needing
	 * special handling: PEAP + GTC, FAST, external */
	eap_str = g_string_new (NULL);
	num_eap = nm_setting_802_1x_get_num_eap_methods (setting);
	for (i = 0; i < num_eap; i++) {
		const char *method = nm_setting_802_1x_get_eap_method (setting, i);

		if (nm_streq (method, "fast")) {
			fast = TRUE;
			priv->fast_required = TRUE;
		}

		if (nm_streq (method, "external")) {
			if (num_eap == 1) {
				g_set_error (error, NM_SUPPLICANT_ERROR, NM_SUPPLICANT_ERROR_CONFIG,
				             "Connection settings managed externally to NM, connection"
				             " cannot be used with wpa_supplicant");
				return FALSE;
			}
			continue;
		}

		if (eap_str->len)
			g_string_append_c (eap_str, ' ');
		g_string_append (eap_str, method);
	}

	g_string_ascii_up (eap_str);
	if (   eap_str->len
	    && !nm_supplicant_config_add_option (self, "eap", eap_str->str, -1, NULL, error))
		return FALSE;

	/* Adjust the fragment size according to MTU, but do not set it higher than 1280-14
	 * for better compatibility */
	hdrs = 14; /* EAPOL + EAP-TLS */
	frag = 1280 - hdrs;
	if (mtu > hdrs)
		frag = CLAMP (mtu - hdrs, 100, frag);
	frag_str = g_strdup_printf ("%u", frag);

	if (!nm_supplicant_config_add_option (self, "fragment_size", frag_str, -1, NULL, error))
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

	phase1_auth_flags = nm_setting_802_1x_get_phase1_auth_flags (setting);
	if (NM_FLAGS_HAS (phase1_auth_flags, NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_0_DISABLE))
		g_string_append_printf (phase1, "%stls_disable_tlsv1_0=1", (phase1->len ? " " : ""));
	if (NM_FLAGS_HAS (phase1_auth_flags, NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_1_DISABLE))
		g_string_append_printf (phase1, "%stls_disable_tlsv1_1=1", (phase1->len ? " " : ""));
	if (NM_FLAGS_HAS (phase1_auth_flags, NM_SETTING_802_1X_AUTH_FLAGS_TLS_1_2_DISABLE))
		g_string_append_printf (phase1, "%stls_disable_tlsv1_2=1", (phase1->len ? " " : ""));

	if (phase1->len) {
		if (!add_string_val (self, phase1->str, "phase1", FALSE, NULL, error)) {
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
		if (!add_string_val (self, phase2->str, "phase2", FALSE, NULL, error)) {
			g_string_free (phase2, TRUE);
			return FALSE;
		}
	}
	g_string_free (phase2, TRUE);

	/* PAC file */
	path = nm_setting_802_1x_get_pac_file (setting);
	if (path) {
		if (!add_string_val (self, path, "pac_file", FALSE, NULL, error))
			return FALSE;
	} else {
		/* PAC file is not specified.
		 * If provisioning is allowed, use an blob format.
		 */
		if (fast_provisoning_allowed) {
			gs_free char *blob_name = NULL;

			blob_name = g_strdup_printf ("blob://pac-blob-%s", con_uuid);
			if (!add_string_val (self, blob_name, "pac_file", FALSE, NULL, error))
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
	path = ca_path_override ?: path;
	if (path) {
		if (!add_string_val (self, path, "ca_path", FALSE, NULL, error))
			return FALSE;
	}

	/* Phase2 CA path */
	path = nm_setting_802_1x_get_phase2_ca_path (setting);
	path = ca_path_override ?: path;
	if (path) {
		if (!add_string_val (self, path, "ca_path2", FALSE, NULL, error))
			return FALSE;
	}

	/* CA certificate */
	if (ca_cert_override) {
		if (!add_string_val (self, ca_cert_override, "ca_cert", FALSE, NULL, error))
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
			if (!add_string_val (self, path, "ca_cert", FALSE, NULL, error))
				return FALSE;
			break;
		case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
			if (!add_pkcs11_uri_with_pin (self, "ca_cert",
			                              nm_setting_802_1x_get_ca_cert_uri (setting),
			                              nm_setting_802_1x_get_ca_cert_password (setting),
			                              nm_setting_802_1x_get_ca_cert_password_flags (setting),
			                              error)) {
				return FALSE;
			}
			break;
		default:
			break;
		}
	}

	/* Phase 2 CA certificate */
	if (ca_cert_override) {
		if (!add_string_val (self, ca_cert_override, "ca_cert2", FALSE, NULL, error))
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
			if (!add_string_val (self, path, "ca_cert2", FALSE, NULL, error))
				return FALSE;
			break;
		case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
			if (!add_pkcs11_uri_with_pin (self, "ca_cert2",
			                              nm_setting_802_1x_get_phase2_ca_cert_uri (setting),
			                              nm_setting_802_1x_get_phase2_ca_cert_password (setting),
			                              nm_setting_802_1x_get_phase2_ca_cert_password_flags (setting),
			                              error)) {
				return FALSE;
			}
			break;
		default:
			break;
		}
	}

	/* Subject match */
	value = nm_setting_802_1x_get_subject_match (setting);
	if (!add_string_val (self, value, "subject_match", FALSE, NULL, error))
		return FALSE;
	value = nm_setting_802_1x_get_phase2_subject_match (setting);
	if (!add_string_val (self, value, "subject_match2", FALSE, NULL, error))
		return FALSE;

	/* altSubjectName match */
	if (!ADD_STRING_LIST_VAL (self, setting, 802_1x, altsubject_match, altsubject_matches, "altsubject_match", ';', FALSE, NULL, error))
		return FALSE;
	if (!ADD_STRING_LIST_VAL (self, setting, 802_1x, phase2_altsubject_match, phase2_altsubject_matches, "altsubject_match2", ';', FALSE, NULL, error))
		return FALSE;

	/* Domain suffix match */
	value = nm_setting_802_1x_get_domain_suffix_match (setting);
	if (!add_string_val (self, value, "domain_suffix_match", FALSE, NULL, error))
		return FALSE;
	value = nm_setting_802_1x_get_phase2_domain_suffix_match (setting);
	if (!add_string_val (self, value, "domain_suffix_match2", FALSE, NULL, error))
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
		if (!add_string_val (self, path, "private_key", FALSE, NULL, error))
			return FALSE;
		added = TRUE;
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		if (!add_pkcs11_uri_with_pin (self, "private_key",
		                              nm_setting_802_1x_get_private_key_uri (setting),
		                              nm_setting_802_1x_get_private_key_password (setting),
		                              nm_setting_802_1x_get_private_key_password_flags (setting),
		                              error)) {
			return FALSE;
		}
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
			if (!add_string_val (self, value, "private_key_passwd", FALSE, "<hidden>", error))
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
				if (!add_string_val (self, path, "client_cert", FALSE, NULL, error))
					return FALSE;
				break;
			case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
				if (!add_pkcs11_uri_with_pin (self, "client_cert",
				                              nm_setting_802_1x_get_client_cert_uri (setting),
				                              nm_setting_802_1x_get_client_cert_password (setting),
				                              nm_setting_802_1x_get_client_cert_password_flags (setting),
				                              error)) {
					return FALSE;
				}
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
		if (!add_string_val (self, path, "private_key2", FALSE, NULL, error))
			return FALSE;
		added = TRUE;
		break;
	case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
		if (!add_pkcs11_uri_with_pin (self, "private_key2",
		                              nm_setting_802_1x_get_phase2_private_key_uri (setting),
		                              nm_setting_802_1x_get_phase2_private_key_password (setting),
		                              nm_setting_802_1x_get_phase2_private_key_password_flags (setting),
		                              error)) {
			return FALSE;
		}
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
			if (!add_string_val (self, value, "private_key2_passwd", FALSE, "<hidden>", error))
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
				if (!add_string_val (self, path, "client_cert2", FALSE, NULL, error))
					return FALSE;
				break;
			case NM_SETTING_802_1X_CK_SCHEME_PKCS11:
				if (!add_pkcs11_uri_with_pin (self, "client_cert2",
				                              nm_setting_802_1x_get_phase2_client_cert_uri (setting),
				                              nm_setting_802_1x_get_phase2_client_cert_password (setting),
				                              nm_setting_802_1x_get_phase2_client_cert_password_flags (setting),
				                              error)) {
					return FALSE;
				}
				break;
			default:
				break;
			}
		}
	}

	value = nm_setting_802_1x_get_identity (setting);
	if (!add_string_val (self, value, "identity", FALSE, NULL, error))
		return FALSE;
	value = nm_setting_802_1x_get_anonymous_identity (setting);
	if (!add_string_val (self, value, "anonymous_identity", FALSE, NULL, error))
		return FALSE;

	return TRUE;
}

gboolean
nm_supplicant_config_add_no_security (NMSupplicantConfig *self, GError **error)
{
	return nm_supplicant_config_add_option (self, "key_mgmt", "NONE", -1, NULL, error);
}

