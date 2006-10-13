/* NetworkManager -- Network link manager
 *
 * Dan Williams <dcbw@redhat.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2006 Red Hat, Inc.
 */

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "nm-supplicant-settings-verify.h"

enum OptType {
	TYPE_INT = 0,
	TYPE_STRING,
	TYPE_KEYWORD
};

struct Opt {
	const char *       key;
	const enum OptType type;
	const gint32       int_low;  /* Inclusive */
	const gint32       int_high; /* Inclusive */
	const gboolean     str_allowed_multiple;
	const char **      str_allowed;
};


static gboolean validate_type_int (const struct Opt * opt, const char * value);
static gboolean validate_type_string (const struct Opt * opt, const char * value);
static gboolean validate_type_keyword (const struct Opt * opt, const char * value);

typedef gboolean (*validate_func)(const struct Opt *, const char *);

struct validate_entry {
	const enum OptType  type;
	const validate_func func;
};

static const struct validate_entry validate_table[] = {
	{ TYPE_INT, validate_type_int },
	{ TYPE_STRING, validate_type_string },
	{ TYPE_KEYWORD, validate_type_keyword },
};


const char * pairwise_allowed[] = { "CCMP", "TKIP", "NONE", NULL };
const char * group_allowed[] =    { "CCMP", "TKIP", "WEP104", "WEP40", NULL };
const char * proto_allowed[] =    { "WPA", "RSN", NULL };
const char * key_mgmt_allowed[] = { "WPA-PSK", "WPA-EAP", "IEEE8021X",
                                    "NONE", NULL };
const char * auth_alg_allowed[] = { "OPEN", "SHARED", "LEAP", NULL };
const char * eap_allowed[] =      { "MD5", "TLS", "PEAP", "TTLS", "SIM",
                                    "PSK", NULL };
const char * phase1_allowed[] =   {"peapver=0", "peapver=1", "peaplabel=1",
                                    "peap_outer_success=0", "include_tls_length=1",
                                    "sim_min_num_chal=3", NULL };
const char * phase2_allowed[] =   {"auth=MSCHAPV2", "auth=PAP", "autheap=TLS",
                                   "autheap=MSCHAPV2", "autheap=MD5", NULL };

static const struct Opt opt_table[] = {
	{ "ssid",               TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "bssid",              TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "scan_ssid",          TYPE_INT,     0, 1, FALSE,  NULL },
	{ "mode",               TYPE_INT,     0, 1, FALSE,  NULL },
	{ "auth_alg",           TYPE_KEYWORD, 0, 0, FALSE,  auth_alg_allowed },
	{ "psk",                TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "pairwise",           TYPE_KEYWORD, 0, 0, FALSE,  pairwise_allowed },
	{ "group",              TYPE_KEYWORD, 0, 0, FALSE,  group_allowed },
	{ "proto",              TYPE_KEYWORD, 0, 0, FALSE,  proto_allowed },
	{ "key_mgmt",           TYPE_KEYWORD, 0, 0, FALSE,  key_mgmt_allowed },
	{ "wep_key0",           TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "wep_key1",           TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "wep_key2",           TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "wep_key3",           TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "wep_tx_keyidx",      TYPE_INT,     0, 3, FALSE,  NULL },
	{ "eapol_flags",        TYPE_INT,     0, 3, FALSE,  NULL },
	{ "eap",                TYPE_KEYWORD, 0, 0, FALSE,  eap_allowed },
	{ "identity",           TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "password",           TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "ca_cert",            TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "client_cert",        TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "private_key",        TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "private_key_passwd", TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "phase1",             TYPE_KEYWORD, 0, 0, TRUE, phase1_allowed },
	{ "phase2",             TYPE_KEYWORD, 0, 0, TRUE, phase2_allowed },
	{ "anonymous_identity", TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "ca_cert2",           TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "client_cert2",       TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "private_key2",       TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "private_key2_passwd",TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "pin",                TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "pcsc",               TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "nai",                TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "eappsk",             TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "pac_file",           TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "engine",             TYPE_INT,     0, 1, FALSE,  NULL },
	{ "engine_id",          TYPE_STRING,  0, 0, FALSE,  NULL },
	{ "key_id",             TYPE_STRING,  0, 0, FALSE,  NULL },
};


static gboolean
validate_type_int (const struct Opt * opt, const char * value)
{
	long int intval;

	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	errno = 0;
	intval = strtol (value, NULL, 10);
	if (errno != 0)
		return FALSE;

	/* strtol returns a long, but we are dealing with ints */
	if (intval > INT_MAX || intval < INT_MIN)
		return FALSE;
	if (intval > opt->int_high || intval < opt->int_low)
		return FALSE;

	return TRUE;
}

static gboolean
validate_type_string (const struct Opt * opt, const char * value)
{
	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	/* FIXME: what can we do with a string other than length? */
	if (strlen (value) > PATH_MAX)
		return FALSE;

	return TRUE;
}

static gboolean
validate_type_keyword (const struct Opt * opt, const char * value)
{
	char **		allowed;
	gchar **	candidates = NULL;
	char **		candidate;
	gboolean	found = FALSE;

	g_return_val_if_fail (opt != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	candidates = g_strsplit (value, " ", 0);
	if (!candidates)
		goto out;

	/* validate each space-separated word in 'value' */
	for (candidate = candidates; *candidate; candidate++, found = FALSE) {
		for (allowed = (char **) opt->str_allowed; *allowed; allowed++) {
			if (strcmp (*candidate, *allowed) == 0) {
				found = TRUE;
				break;
			}
		}
		if (!found)
			break;
	}

out:
	g_strfreev (candidates);
	return found;
}

gboolean
nm_supplicant_settings_verify_setting (const char * key,
                                       const char * value)
{
	gboolean valid = FALSE;
	int opt_count = sizeof (opt_table) / sizeof (opt_table[0]);
	int val_count = sizeof (validate_table) / sizeof (validate_table[0]);
	int i, j;

	g_return_val_if_fail (key != NULL, FALSE);
	g_return_val_if_fail (value != NULL, FALSE);

	for (i = 0; i < opt_count && !valid; i++) {
		if (strcmp (opt_table[i].key, key) != 0)
			continue;

		for (j = 0; j < val_count; j++) {
			if (validate_table[j].type == opt_table[i].type) {
				valid = (*(validate_table[j].func))(&opt_table[i], value);
				break;
			}
		}
	}

	return valid;
}
