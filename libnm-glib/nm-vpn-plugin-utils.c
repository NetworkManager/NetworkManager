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
 * Copyright 2011 Red Hat, Inc.
 */

#include "nm-default.h"

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "nm-vpn-plugin-utils.h"
#include "nm-vpn-plugin.h"
#include "nm-setting-private.h"
#include "nm-dbus-glib-types.h"

#define DATA_KEY_TAG "DATA_KEY="
#define DATA_VAL_TAG "DATA_VAL="
#define SECRET_KEY_TAG "SECRET_KEY="
#define SECRET_VAL_TAG "SECRET_VAL="

static void
free_secret (gpointer data)
{
	char *secret = data;

	memset (secret, 0, strlen (secret));
	g_free (secret);
}

/**
 * nm_vpn_plugin_utils_read_vpn_details:
 * @fd: file descriptor to read from, usually stdin (0)
 * @out_data: (out) (transfer full): on successful return, a hash table
 * (mapping char*:char*) containing the key/value pairs of VPN data items
 * @out_secrets: (out) (transfer full): on successful return, a hash table
 * (mapping char*:char*) containing the key/value pairsof VPN secrets
 *
 * Parses key/value pairs from a file descriptor (normally stdin) passed by
 * an applet when the applet calls the authentication dialog of the VPN plugin.
 *
 * Returns: %TRUE if reading values was successful, %FALSE if not
 **/
gboolean
nm_vpn_plugin_utils_read_vpn_details (int fd,
                                      GHashTable **out_data,
                                      GHashTable **out_secrets)
{
	GHashTable *data, *secrets;
	gboolean success = FALSE;
	char *key = NULL, *val = NULL;
	GString *line;
	char c;

	if (out_data)
		g_return_val_if_fail (*out_data == NULL, FALSE);
	if (out_secrets)
		g_return_val_if_fail (*out_secrets == NULL, FALSE);

	data = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
	secrets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, free_secret);

	line = g_string_new (NULL);

	/* Read stdin for data and secret items until we get a DONE */
	while (1) {
		ssize_t nr;
		GHashTable *hash = NULL;

		nr = read (fd, &c, 1);
		if (nr == -1) {
			if (errno == EAGAIN) {
				g_usleep (100);
				continue;
			}
			break;
		}

		if (c != '\n') {
			g_string_append_c (line, c);
			continue;
		}

		/* Check for the finish marker */
		if (strcmp (line->str, "DONE") == 0)
			break;

		/* Otherwise it's a data/secret item */
		if (strncmp (line->str, DATA_KEY_TAG, strlen (DATA_KEY_TAG)) == 0) {
			hash = data;
			key = g_strdup (line->str + strlen (DATA_KEY_TAG));
		} else if (strncmp (line->str, DATA_VAL_TAG, strlen (DATA_VAL_TAG)) == 0) {
			hash = data;
			val = g_strdup (line->str + strlen (DATA_VAL_TAG));
		} else if (strncmp (line->str, SECRET_KEY_TAG, strlen (SECRET_KEY_TAG)) == 0) {
			hash = secrets;
			key = g_strdup (line->str + strlen (SECRET_KEY_TAG));
		} else if (strncmp (line->str, SECRET_VAL_TAG, strlen (SECRET_VAL_TAG)) == 0) {
			hash = secrets;
			val = g_strdup (line->str + strlen (SECRET_VAL_TAG));
		}
		g_string_truncate (line, 0);

		if (key && val && hash) {
			g_hash_table_insert (hash, key, val);
			key = NULL;
			val = NULL;
			success = TRUE;  /* Got at least one value */
		}
	}

	if (success) {
		if (out_data)
			*out_data = data;
		else
			g_hash_table_destroy (data);

		if (out_secrets)
			*out_secrets = secrets;
		else
			g_hash_table_destroy (secrets);
	} else {
		g_hash_table_destroy (data);
		g_hash_table_destroy (secrets);
	}

	g_string_free (line, TRUE);
	return success;
}

/**
 * nm_vpn_plugin_utils_get_secret_flags:
 * @data: hash table containing VPN key/value pair data items
 * @secret_name: VPN secret key name for which to retrieve flags for
 * @out_flags: (out): on success, the flags associated with @secret_name
 *
 * Given a VPN secret key name, attempts to find the corresponding flags data
 * item in @data.  If found, converts the flags data item to
 * #NMSettingSecretFlags and returns it.
 *
 * Returns: %TRUE if the flag data item was found and successfully converted
 * to flags, %FALSE if not
 **/
gboolean
nm_vpn_plugin_utils_get_secret_flags (GHashTable *data,
                                      const char *secret_name,
                                      NMSettingSecretFlags *out_flags)
{
	char *flag_name;
	const char *val;
	unsigned long tmp;
	gboolean success = FALSE;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (secret_name != NULL, FALSE);
	g_return_val_if_fail (out_flags != NULL, FALSE);
	g_return_val_if_fail (*out_flags == NM_SETTING_SECRET_FLAG_NONE, FALSE);

	flag_name = g_strdup_printf ("%s-flags", secret_name);

	/* Try new flags value first */
	val = g_hash_table_lookup (data, flag_name);
	if (val) {
		errno = 0;
		tmp = strtoul (val, NULL, 10);
		if (errno == 0 && tmp <= NM_SETTING_SECRET_FLAGS_ALL) {
			*out_flags = (NMSettingSecretFlags) tmp;
			success = TRUE;
		}
	}

	g_free (flag_name);
	return success;
}
