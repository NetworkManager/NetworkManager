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
 */

#include "nm-default.h"

#include "nm-supplicant-settings-verify.h"

#include <stdio.h>
#include <stdlib.h>

struct Opt {
	const char *     key;
	const OptType    type;
	const gint32     int_low;  /* Inclusive */
	const gint32     int_high; /* Inclusive; max length for strings */
	const gboolean   str_allowed_multiple;
	const char *const*str_allowed;
};

static gboolean validate_type_int     (const struct Opt * opt,
                                       const char * value,
                                       const guint32 len);

static gboolean validate_type_bytes   (const struct Opt * opt,
                                       const char * value,
                                       const guint32 len);

static gboolean validate_type_utf8    (const struct Opt *opt,
                                       const char * value,
                                       const guint32 len);

static gboolean validate_type_keyword (const struct Opt * opt,
                                       const char * value,
                                       const guint32 len);

typedef gboolean (*validate_func)(const struct Opt *, const char *, const guint32);

struct validate_entry {
	const OptType  type;
	const validate_func func;
};

static const struct validate_entry validate_table[] = {
	{ TYPE_INT,     validate_type_int     },
	{ TYPE_BYTES,   validate_type_bytes   },
	{ TYPE_UTF8,    validate_type_utf8    },
	{ TYPE_KEYWORD, validate_type_keyword },
};

static const char *const pairwise_allowed[] = { "CCMP", "TKIP", "NONE", NULL };
static const char *const group_allowed[] =    { "CCMP", "TKIP", "WEP104", "WEP40", NULL };
static const char *const proto_allowed[] =    { "WPA", "RSN", NULL };
static const char *const key_mgmt_allowed[] = { "WPA-PSK", "WPA-PSK-SHA256", "FT-PSK",
                                                "WPA-EAP", "WPA-EAP-SHA256", "FT-EAP", "FT-EAP-SHA384",
                                                "FILS-SHA256", "FILS-SHA384",
                                                "IEEE8021X", "SAE",
                                                "NONE", NULL };
static const char *const auth_alg_allowed[] = { "OPEN", "SHARED", "LEAP", NULL };
static const char *const eap_allowed[] =      { "LEAP", "MD5", "TLS", "PEAP", "TTLS", "SIM",
                                                "PSK", "FAST", "PWD", NULL };

static const char *const phase1_allowed[] =   { "peapver=0", "peapver=1", "peaplabel=1",
                                                "peap_outer_success=0", "include_tls_length=1",
                                                "sim_min_num_chal=3", "fast_provisioning=0",
                                                "fast_provisioning=1", "fast_provisioning=2",
                                                "fast_provisioning=3", "tls_disable_tlsv1_0=0",
                                                "tls_disable_tlsv1_0=1", "tls_disable_tlsv1_1=0",
                                                "tls_disable_tlsv1_1=1", "tls_disable_tlsv1_2=0",
                                                "tls_disable_tlsv1_2=1", NULL };
static const char *const phase2_allowed[] =   { "auth=PAP", "auth=CHAP", "auth=MSCHAP",
                                                "auth=MSCHAPV2", "auth=GTC", "auth=OTP",
                                                "auth=MD5", "auth=TLS", "autheap=MD5",
                                                "autheap=MSCHAPV2", "autheap=OTP",
                                                "autheap=GTC", "autheap=TLS", NULL };

static const struct Opt opt_table[] = {
	{ "ssid",               TYPE_BYTES,   0, 32,FALSE,  NULL },
	{ "bssid",              TYPE_KEYWORD, 0, 0, FALSE,  NULL },
	{ "scan_ssid",          TYPE_INT,     0, 1, FALSE,  NULL },
	{ "frequency",          TYPE_INT,     2412, 5825, FALSE,  NULL },
	{ "auth_alg",           TYPE_KEYWORD, 0, 0, FALSE,  auth_alg_allowed },
	{ "psk",                TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "pairwise",           TYPE_KEYWORD, 0, 0, FALSE,  pairwise_allowed },
	{ "group",              TYPE_KEYWORD, 0, 0, FALSE,  group_allowed },
	{ "proto",              TYPE_KEYWORD, 0, 0, FALSE,  proto_allowed },
	{ "key_mgmt",           TYPE_KEYWORD, 0, 0, FALSE,  key_mgmt_allowed },
	{ "wep_key0",           TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "wep_key1",           TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "wep_key2",           TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "wep_key3",           TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "wep_tx_keyidx",      TYPE_INT,     0, 3, FALSE,  NULL },
	{ "eapol_flags",        TYPE_INT,     0, 3, FALSE,  NULL },
	{ "eap",                TYPE_KEYWORD, 0, 0, FALSE,  eap_allowed },
	{ "identity",           TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "password",           TYPE_UTF8,    0, 0, FALSE,  NULL },
	{ "ca_path",            TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "subject_match",      TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "altsubject_match",   TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "domain_suffix_match",TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "ca_cert",            TYPE_BYTES,   0, 65536, FALSE,  NULL },
	{ "client_cert",        TYPE_BYTES,   0, 65536, FALSE,  NULL },
	{ "private_key",        TYPE_BYTES,   0, 65536, FALSE,  NULL },
	{ "private_key_passwd", TYPE_BYTES,   0, 1024, FALSE,  NULL },
	{ "phase1",             TYPE_KEYWORD, 0, 0, TRUE, phase1_allowed },
	{ "phase2",             TYPE_KEYWORD, 0, 0, TRUE, phase2_allowed },
	{ "anonymous_identity", TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "ca_path2",           TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "subject_match2",     TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "altsubject_match2",  TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "domain_suffix_match2", TYPE_BYTES, 0, 0, FALSE,  NULL },
	{ "ca_cert2",           TYPE_BYTES,   0, 65536, FALSE,  NULL },
	{ "client_cert2",       TYPE_BYTES,   0, 65536, FALSE,  NULL },
	{ "private_key2",       TYPE_BYTES,   0, 65536, FALSE,  NULL },
	{ "private_key2_passwd",TYPE_BYTES,   0, 1024, FALSE,  NULL },
	{ "pin",                TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "pcsc",               TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "nai",                TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "eappsk",             TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "pac_file",           TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "engine",             TYPE_INT,     0, 1, FALSE,  NULL },
	{ "engine_id",          TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "key_id",             TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "fragment_size",      TYPE_INT,     1, 2000, FALSE,  NULL },
	{ "proactive_key_caching", TYPE_INT,  0, 1, FALSE,  NULL },
	{ "bgscan",             TYPE_BYTES,   0, 0, FALSE,  NULL },
	{ "pac_file",           TYPE_BYTES,   0, 1024, FALSE,  NULL },
	{ "freq_list",          TYPE_KEYWORD, 0, 0, FALSE,  NULL },
	{ "macsec_policy",      TYPE_INT,     0, 1, FALSE, NULL },
	{ "macsec_integ_only",  TYPE_INT,     0, 1, FALSE, NULL },
	{ "mka_cak",            TYPE_BYTES,   0, 65536, FALSE, NULL },
	{ "mka_ckn",            TYPE_BYTES,   0, 65536, FALSE, NULL },
	{ "macsec_port",        TYPE_INT,     1, 65534, FALSE, NULL },
	{ "ieee80211w",         TYPE_INT,     0, 2, FALSE, NULL },
	{ "ignore_broadcast_ssid", TYPE_INT,  0, 2, FALSE, NULL },
};

static gboolean
validate_type_int (const struct Opt * opt,
                   const char * value,
                   const guint32 len)
{
	gint64 v;

	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	v = _nm_utils_ascii_str_to_int64 (value, 10, opt->int_low, opt->int_high, G_MININT64);
	return v != G_MININT64 || errno == 0;
}

static gboolean
validate_type_bytes (const struct Opt * opt,
                     const char * value,
                     const guint32 len)
{
	guint32 check_len;

	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	check_len = opt->int_high ?: 255;
	if (len > check_len)
		return FALSE;

	return TRUE;
}

static gboolean
validate_type_utf8 (const struct Opt *opt,
                    const char * value,
                    const guint32 len)
{
	guint32 check_len;

	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	check_len = opt->int_high ?: 255;
	/* Note that we deliberately don't validate the UTF-8, because
	   some "UTF-8" fields, such as 8021x.password, do not actually
	   have to be valid UTF-8 */
	if (g_utf8_strlen (value, len) > check_len)
		return FALSE;

	return TRUE;
}

static gboolean
validate_type_keyword (const struct Opt * opt,
                       const char * value,
                       const guint32 len)
{
	gs_free char *value_free = NULL;

	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	/* Allow everything */
	if (!opt->str_allowed)
		return TRUE;

	value = nm_strndup_a (300, value, len, &value_free);

	/* validate each space-separated word in 'value' */

	while (TRUE) {
		char *s;

		while (value[0] == ' ')
			value++;

		if (value[0] == '\0')
			return TRUE;

		s = strchr (value, ' ');
		if (s) {
			s[0] = '\0';
			s++;
		}

		if (nm_utils_strv_find_first ((char **) opt->str_allowed, -1, value) < 0)
			return FALSE;

		if (!s)
			return TRUE;

		value = s;
	}
}

OptType
nm_supplicant_settings_verify_setting (const char * key,
                                       const char * value,
                                       const guint32 len)
{
	OptType type = TYPE_INVALID;
	int opt_count = sizeof (opt_table) / sizeof (opt_table[0]);
	int val_count = sizeof (validate_table) / sizeof (validate_table[0]);
	int i, j;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	if (strcmp (key, "mode") == 0) {
		if (len != 1)
			return TYPE_INVALID;
		if (!NM_IN_SET (value[0], '1', '2', '5'))
			return TYPE_INVALID;
		return TYPE_INT;
	}

	for (i = 0; i < opt_count; i++) {
		if (strcmp (opt_table[i].key, key) != 0)
			continue;

		for (j = 0; j < val_count; j++) {
			if (validate_table[j].type == opt_table[i].type) {
				if ((*(validate_table[j].func))(&opt_table[i], value, len)) {
					type = opt_table[i].type;
					break;
				}
			}
		}
	}

	return type;
}

