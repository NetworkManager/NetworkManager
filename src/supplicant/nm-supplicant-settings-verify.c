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
	const guint32 int_low;  /* Inclusive */
	const guint32 int_high; /* Inclusive; max length for strings */
	const char *const*str_allowed;
};

typedef gboolean (*validate_func) (const struct Opt *, const char *, const guint32);

static const struct Opt opt_table[] = {
	{ "altsubject_match",      NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "altsubject_match2",     NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "anonymous_identity",    NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "auth_alg",              NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     NM_MAKE_STRV (
	                                                                     "OPEN",
	                                                                     "SHARED",
	                                                                     "LEAP",
	                                                                   ) },
	{ "bgscan",                NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "bssid",                 NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     NULL },
	{ "ca_cert",               NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, NULL },
	{ "ca_cert2",              NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, NULL },
	{ "ca_path",               NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "ca_path2",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "client_cert",           NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, NULL },
	{ "client_cert2",          NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, NULL },
	{ "domain_match",          NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "domain_match2",         NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "domain_suffix_match",   NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "domain_suffix_match2",  NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "eap",                   NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     NM_MAKE_STRV (
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
	{ "eapol_flags",           NM_SUPPL_OPT_TYPE_INT,     0,    3,     NULL },
	{ "eappsk",                NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "engine",                NM_SUPPL_OPT_TYPE_INT,     0,    1,     NULL },
	{ "engine_id",             NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "fragment_size",         NM_SUPPL_OPT_TYPE_INT,     1,    2000,  NULL },
	{ "freq_list",             NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     NULL },
	{ "frequency",             NM_SUPPL_OPT_TYPE_INT,     2412, 5825,  NULL },
	{ "group",                 NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     NM_MAKE_STRV (
	                                                                     "CCMP",
	                                                                     "TKIP",
	                                                                     "WEP104",
	                                                                     "WEP40",
	                                                                   ) },
	{ "identity",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "ieee80211w",            NM_SUPPL_OPT_TYPE_INT,     0,    2,     NULL },
	{ "ignore_broadcast_ssid", NM_SUPPL_OPT_TYPE_INT,     0,    2,     NULL },
	{ "key_id",                NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "key_mgmt",              NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     NM_MAKE_STRV (
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
	{ "macsec_integ_only",     NM_SUPPL_OPT_TYPE_INT,     0,    1,     NULL },
	{ "macsec_policy",         NM_SUPPL_OPT_TYPE_INT,     0,    1,     NULL },
	{ "macsec_port",           NM_SUPPL_OPT_TYPE_INT,     1,    65534, NULL },
	{ "mka_cak",               NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, NULL },
	{ "mka_ckn",               NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, NULL },
	{ "nai",                   NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "pac_file",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "pairwise",              NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     NM_MAKE_STRV (
	                                                                     "CCMP",
	                                                                     "TKIP",
	                                                                     "NONE",
	                                                                   ) },
	{ "password",              NM_SUPPL_OPT_TYPE_UTF8,    0,    0,     NULL },
	{ "pcsc",                  NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "phase1",                NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     NM_MAKE_STRV (
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
	{ "phase2",                NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     NM_MAKE_STRV (
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
	{ "pin",                   NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "private_key",           NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, NULL },
	{ "private_key2",          NM_SUPPL_OPT_TYPE_BYTES,   0,    65536, NULL },
	{ "private_key2_passwd",   NM_SUPPL_OPT_TYPE_BYTES,   0,    1024,  NULL },
	{ "private_key_passwd",    NM_SUPPL_OPT_TYPE_BYTES,   0,    1024,  NULL },
	{ "proactive_key_caching", NM_SUPPL_OPT_TYPE_INT,     0,    1,     NULL },
	{ "proto",                 NM_SUPPL_OPT_TYPE_KEYWORD, 0,    0,     NM_MAKE_STRV (
	                                                                     "WPA",
	                                                                     "RSN",
	                                                                   ) },
	{ "psk",                   NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "scan_ssid",             NM_SUPPL_OPT_TYPE_INT,     0,    1,     NULL },
	{ "ssid",                  NM_SUPPL_OPT_TYPE_BYTES,   0,    32,    NULL },
	{ "subject_match",         NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "subject_match2",        NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "wep_key0",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "wep_key1",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "wep_key2",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "wep_key3",              NM_SUPPL_OPT_TYPE_BYTES,   0,    0,     NULL },
	{ "wep_tx_keyidx",         NM_SUPPL_OPT_TYPE_INT,     0,    3,     NULL },
};

static gboolean
validate_type_int (const struct Opt * opt,
                   const char * value,
                   const guint32 len)
{
	gint64 v;

	nm_assert (opt);
	nm_assert (value);

	v = _nm_utils_ascii_str_to_int64 (value, 10, opt->int_low, opt->int_high, G_MININT64);
	return v != G_MININT64 || errno == 0;
}

static gboolean
validate_type_bytes (const struct Opt * opt,
                     const char * value,
                     const guint32 len)
{
	guint32 check_len;

	nm_assert (opt);
	nm_assert (value);

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

	nm_assert (opt);
	nm_assert (value);

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

	nm_assert (opt);
	nm_assert (value);

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
nm_supplicant_settings_verify_setting (const char *key,
                                       const char *value,
                                       const guint32 len)
{
	static const validate_func validate_table[_NM_SUPPL_OPT_TYPE_NUM - 1] = {
		[NM_SUPPL_OPT_TYPE_INT     - 1] = validate_type_int,
		[NM_SUPPL_OPT_TYPE_BYTES   - 1] = validate_type_bytes,
		[NM_SUPPL_OPT_TYPE_UTF8    - 1] = validate_type_utf8,
		[NM_SUPPL_OPT_TYPE_KEYWORD - 1] = validate_type_keyword,
	};
	const struct Opt *opt;
	gssize opt_idx;

	g_return_val_if_fail (key, FALSE);
	g_return_val_if_fail (value, FALSE);

	if (NM_MORE_ASSERT_ONCE (5)) {
		gsize i;

		for (i = 0; i < G_N_ELEMENTS (opt_table); i++) {
			opt = &opt_table[i];

			nm_assert (opt->key);
			nm_assert (opt->type > NM_SUPPL_OPT_TYPE_INVALID);
			nm_assert (opt->type < _NM_SUPPL_OPT_TYPE_NUM);
			if (i > 0)
				nm_assert (strcmp (opt[-1].key, opt->key) < 0);
			nm_assert (validate_table[opt->type - 1]);

			nm_assert (   !opt->str_allowed
			           || (opt->type == NM_SUPPL_OPT_TYPE_KEYWORD));
			nm_assert (   !opt->str_allowed
			           || NM_PTRARRAY_LEN (opt->str_allowed) > 0);

			nm_assert (   opt->int_low == 0
			           || opt->type == NM_SUPPL_OPT_TYPE_INT);

			nm_assert (   opt->int_high == 0
			           || NM_IN_SET (opt->type, NM_SUPPL_OPT_TYPE_INT,
			                                    NM_SUPPL_OPT_TYPE_UTF8,
			                                    NM_SUPPL_OPT_TYPE_BYTES));

			nm_assert (   opt->type != NM_SUPPL_OPT_TYPE_INT
			           || opt->int_low < opt->int_high);
		}
	}

	opt_idx = nm_utils_array_find_binary_search (opt_table,
	                                             sizeof (opt_table[0]),
	                                             G_N_ELEMENTS (opt_table),
	                                             &key,
	                                             nm_strcmp_p_with_data,
	                                             NULL);
	if (opt_idx < 0) {
		if (nm_streq (key, "mode")) {
			if (len != 1)
				return NM_SUPPL_OPT_TYPE_INVALID;
			if (!NM_IN_SET (value[0], '1', '2', '5'))
				return NM_SUPPL_OPT_TYPE_INVALID;
			return NM_SUPPL_OPT_TYPE_INT;
		}
		return NM_SUPPL_OPT_TYPE_INVALID;
	}

	opt = &opt_table[opt_idx];
	if (!((validate_table[opt->type - 1]) (opt, value, len)))
		return NM_SUPPL_OPT_TYPE_INVALID;

	return opt->type;
}
