// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2006 - 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-supplicant-settings-verify.h"

#include <stdio.h>
#include <stdlib.h>

struct Opt {
	const char *key;
	const NMSupplOptType type;
	const gint32 int_low;  /* Inclusive */
	const gint32 int_high; /* Inclusive; max length for strings */
	const gboolean str_allowed_multiple;
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
	const NMSupplOptType  type;
	const validate_func func;
};

static const struct validate_entry validate_table[] = {
	{ NM_SUPPL_OPT_TYPE_INT,     validate_type_int     },
	{ NM_SUPPL_OPT_TYPE_BYTES,   validate_type_bytes   },
	{ NM_SUPPL_OPT_TYPE_UTF8,    validate_type_utf8    },
	{ NM_SUPPL_OPT_TYPE_KEYWORD, validate_type_keyword },
};

static const struct Opt opt_table[] = {
	{ "ssid",                  NM_SUPPL_OPT_TYPE_BYTES,   0,    32,    FALSE, NULL },
	{ "bssid",                 NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     FALSE, NULL },
	{ "scan_ssid",             NM_SUPPL_OPT_TYPE_INT,     0,    1,     FALSE, NULL },
	{ "frequency",             NM_SUPPL_OPT_TYPE_INT,     2412, 5825,  FALSE, NULL },
	{ "auth_alg",              NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     FALSE, NM_MAKE_STRV (
	                                                                            "OPEN",
	                                                                            "SHARED",
	                                                                            "LEAP",
	                                                                          ) },
	{ "psk",                   NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "pairwise",              NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     FALSE, NM_MAKE_STRV (
	                                                                            "CCMP",
	                                                                            "TKIP",
	                                                                            "NONE",
	                                                                          ) },
	{ "group",                 NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     FALSE, NM_MAKE_STRV (
	                                                                            "CCMP",
	                                                                            "TKIP",
	                                                                            "WEP104",
	                                                                            "WEP40",
	                                                                          ) },
	{ "proto",                 NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     FALSE, NM_MAKE_STRV (
	                                                                            "WPA",
	                                                                            "RSN",
	                                                                          ) },
	{ "key_mgmt",              NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     FALSE, NM_MAKE_STRV (
	                                                                            "WPA-PSK",
	                                                                            "WPA-PSK-SHA256",
	                                                                            "FT-PSK",
	                                                                            "WPA-EAP",
	                                                                            "WPA-EAP-SHA256",
	                                                                            "FT-EAP",
	                                                                            "FT-EAP-SHA384",
	                                                                            "FILS-SHA256",
	                                                                            "FILS-SHA384",
	                                                                            "FT-FILS-SHA256",
	                                                                            "FT-FILS-SHA384",
	                                                                            "IEEE8021X",
	                                                                            "SAE",
	                                                                            "FT-SAE",
	                                                                            "OWE",
	                                                                            "NONE",
	                                                                          ) },
	{ "wep_key0",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "wep_key1",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "wep_key2",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "wep_key3",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "wep_tx_keyidx",         NM_SUPPL_OPT_TYPE_INT,     0,    3,     FALSE, NULL },
	{ "eapol_flags",           NM_SUPPL_OPT_TYPE_INT,     0,    3,     FALSE, NULL },
	{ "eap",                   NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     FALSE, NM_MAKE_STRV (
	                                                                            "LEAP",
	                                                                            "MD5",
	                                                                            "TLS",
	                                                                            "PEAP",
	                                                                            "TTLS",
	                                                                            "SIM",
	                                                                            "PSK",
	                                                                            "FAST",
	                                                                            "PWD",
	                                                                          ) },
	{ "identity",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "password",              NM_SUPPL_OPT_TYPE_UTF8,    0,    0,     FALSE, NULL },
	{ "ca_path",               NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "subject_match",         NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "altsubject_match",      NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "domain_suffix_match",   NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "domain_match",          NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "ca_cert",               NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, FALSE, NULL },
	{ "client_cert",           NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, FALSE, NULL },
	{ "private_key",           NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, FALSE, NULL },
	{ "private_key_passwd",    NM_SUPPL_OPT_TYPE_BYTES,   0,    1024,  FALSE, NULL },
	{ "phase1",                NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     TRUE,  NM_MAKE_STRV (
	                                                                            "peapver=0",
	                                                                            "peapver=1",
	                                                                            "peaplabel=1",
	                                                                            "peap_outer_success=0",
	                                                                            "include_tls_length=1",
	                                                                            "sim_min_num_chal=3",
	                                                                            "fast_provisioning=0",
	                                                                            "fast_provisioning=1",
	                                                                            "fast_provisioning=2",
	                                                                            "fast_provisioning=3",
	                                                                            "tls_disable_tlsv1_0=0",
	                                                                            "tls_disable_tlsv1_0=1",
	                                                                            "tls_disable_tlsv1_1=0",
	                                                                            "tls_disable_tlsv1_1=1",
	                                                                            "tls_disable_tlsv1_2=0",
	                                                                            "tls_disable_tlsv1_2=1",
	                                                                          ) },
	{ "phase2",                NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     TRUE,  NM_MAKE_STRV (
	                                                                            "auth=PAP",
	                                                                            "auth=CHAP",
	                                                                            "auth=MSCHAP",
	                                                                            "auth=MSCHAPV2",
	                                                                            "auth=GTC",
	                                                                            "auth=OTP",
	                                                                            "auth=MD5",
	                                                                            "auth=TLS",
	                                                                            "autheap=MD5",
	                                                                            "autheap=MSCHAPV2",
	                                                                            "autheap=OTP",
	                                                                            "autheap=GTC",
	                                                                            "autheap=TLS",
	                                                                          ) },
	{ "anonymous_identity",    NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "ca_path2",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "subject_match2",        NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "altsubject_match2",     NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "domain_suffix_match2",  NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "domain_match2",         NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "ca_cert2",              NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, FALSE, NULL },
	{ "client_cert2",          NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, FALSE, NULL },
	{ "private_key2",          NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, FALSE, NULL },
	{ "private_key2_passwd",   NM_SUPPL_OPT_TYPE_BYTES,   0,    1024,  FALSE, NULL },
	{ "pin",                   NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "pcsc",                  NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "nai",                   NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "eappsk",                NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "pac_file",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "engine",                NM_SUPPL_OPT_TYPE_INT,     0,    1,     FALSE, NULL },
	{ "engine_id",             NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "key_id",                NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "fragment_size",         NM_SUPPL_OPT_TYPE_INT,     1,    2000,  FALSE, NULL },
	{ "proactive_key_caching", NM_SUPPL_OPT_TYPE_INT,     0,    1,     FALSE, NULL },
	{ "bgscan",                NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     FALSE, NULL },
	{ "freq_list",             NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     FALSE, NULL },
	{ "macsec_policy",         NM_SUPPL_OPT_TYPE_INT,     0,    1,     FALSE, NULL },
	{ "macsec_integ_only",     NM_SUPPL_OPT_TYPE_INT,     0,    1,     FALSE, NULL },
	{ "mka_cak",               NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, FALSE, NULL },
	{ "mka_ckn",               NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, FALSE, NULL },
	{ "macsec_port",           NM_SUPPL_OPT_TYPE_INT,     1,    65534, FALSE, NULL },
	{ "ieee80211w",            NM_SUPPL_OPT_TYPE_INT,     0,    2,     FALSE, NULL },
	{ "ignore_broadcast_ssid", NM_SUPPL_OPT_TYPE_INT,     0,    2,     FALSE, NULL },
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

NMSupplOptType
nm_supplicant_settings_verify_setting (const char * key,
                                       const char * value,
                                       const guint32 len)
{
	NMSupplOptType type = NM_SUPPL_OPT_TYPE_INVALID;
	int opt_count = sizeof (opt_table) / sizeof (opt_table[0]);
	int val_count = sizeof (validate_table) / sizeof (validate_table[0]);
	int i, j;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	if (strcmp (key, "mode") == 0) {
		if (len != 1)
			return NM_SUPPL_OPT_TYPE_INVALID;
		if (!NM_IN_SET (value[0], '1', '2', '5'))
			return NM_SUPPL_OPT_TYPE_INVALID;
		return NM_SUPPL_OPT_TYPE_INT;
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

