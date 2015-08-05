/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Mu Qiao <qiaomuf@gmail.com>
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
 * Copyright (C) 1999-2010 Gentoo Foundation, Inc.
 */

#include "config.h"

#include <string.h>
#include <stdlib.h>
#include <nm-system-config-interface.h>
#include "nm-default.h"
#include "wpa_parser.h"
#include "net_parser.h"
#include "net_utils.h"

/* Security information */
static GHashTable *wsec_table = NULL;

/* Global information used for writing */
static GHashTable *wsec_global_table = NULL;

static gboolean wpa_parser_data_changed = FALSE;

static long
wpa_get_long (GHashTable *table, const char *key)
{
	return atol (g_hash_table_lookup (table, key));
}

static void
destroy_security (GHashTable * network)
{
	gpointer key, value;
	GHashTableIter iter;

	g_return_if_fail (network);
	g_hash_table_iter_init (&iter, network);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		g_free (key);
		g_free (value);
	}

	g_hash_table_destroy (network);
}

static GHashTable *
add_security (GHashTable *security)
{
	GHashTable *oldsecurity;
	const char *ssid, *value;
	char *ssid_key;
	gboolean is_hex_ssid;

	/* Every security information should have a ssid */
	ssid = g_hash_table_lookup (security, "ssid");
	if (!ssid) {
		destroy_security (security);
		return NULL;
	}

	/* Hex format begins with " */
	is_hex_ssid = (ssid[0] != '"');
	if ((value = g_hash_table_lookup (security, "disabled")) != NULL) {
		if (strcmp (value, "1") == 0)
			return NULL;
	}

	/* Default priority is 1 */
	if (g_hash_table_lookup (security, "priority") == NULL)
		g_hash_table_insert (security, g_strdup ("priority"),
				     g_strdup ("1"));

	oldsecurity = g_hash_table_lookup (wsec_table, ssid);
	/* Security with lower priority will be ignored */
	if (oldsecurity != NULL) {
		if (wpa_get_long (oldsecurity, "priority") >=
		    wpa_get_long (security, "priority")) {
			destroy_security (security);
			return NULL;
		} else {
			g_hash_table_remove (wsec_table, ssid);
			destroy_security (oldsecurity);
		}
	}

	/* format ssid */
	ssid_key =
	    is_hex_ssid ? g_strdup_printf ("0x%s",
					   ssid) :
	    strip_string (g_strdup (ssid), '"');
	g_hash_table_insert (wsec_table, ssid_key, security);
	return security;
}

static void
add_key_value (GHashTable * network, gchar * line)
{
	gchar **key_value;

	if (g_str_has_prefix (line, "network={"))
		line += 9;
	strip_string (line, '{');
	strip_string (line, '}');
	if (line[0] == '\0')
		return;
	key_value = g_strsplit (line, "=", 2);
	if (g_strv_length (key_value) != 2) {
		g_strfreev (key_value);
		return;
	}
	g_strstrip (key_value[0]);
	g_strstrip (key_value[1]);

	/* Reserve quotes for psk, wep_key, ssid
	 * Quotes will determine whether they are hex format */
	if (strcmp (key_value[0], "psk") != 0
	    && !g_str_has_prefix (key_value[0], "wep_key")
	    && strcmp (key_value[0], "ssid") != 0)
		strip_string (key_value[1], '"');
	g_hash_table_insert (network, g_strdup (key_value[0]),
			     g_strdup (key_value[1]));
	g_strfreev (key_value);
}

static void
add_one_wep_key (GHashTable * table, int key_num, gchar * one_wep_key)
{
	if (one_wep_key[0] == 's') {
		//asc key
		g_hash_table_insert (table,
				     g_strdup_printf ("wep_key%d", key_num - 1),
				     g_strdup_printf ("\"%s\"",
						      one_wep_key + 2));
	} else {
		gchar buf[30];
		int i = 0, j = 0;

		//hex key
		while (one_wep_key[i] != '\0') {
			if (one_wep_key[i] != '-')
				buf[j++] = one_wep_key[i];
			i++;
		}
		buf[j] = '\0';
		g_hash_table_insert (table,
				     g_strdup_printf ("wep_key%d", key_num - 1),
				     g_strdup (buf));

	}
}

/* Reading wep security information from /etc/conf.d/net.
 * This should not be used in future, use wpa_supplicant instead. */
static void
add_keys_from_net (void)
{
	GList *names = ifnet_get_connection_names ();
	GList *iter = names;
	gchar *wep_keys = "(\\[([1-4])\\]\\s+(s:\\w{5}|s:\\w{13}|"
	    "([\\da-fA-F]{4}\\-){2}[\\da-fA-F]{2}|"
	    "([\\da-fA-F]{4}\\-){6}[\\da-fA-F]{2})\\s+)";
	gchar *key_method =
	    "\\s+key\\s+\\[([1-4])\\]\\s+enc\\s+(open|restricted)";
	GRegex *regex_keys = g_regex_new (wep_keys, 0, 0, NULL);
	GRegex *regex_method = g_regex_new (key_method, 0, 0, NULL);
	GMatchInfo *keys_info;
	GMatchInfo *method_info;

	while (iter) {
		gchar *conn_name = iter->data;
		GHashTable *table;
		const char *key_str;

		if ((key_str = ifnet_get_data (conn_name, "key")) == NULL) {
			iter = g_list_next (iter);
			continue;
		}

		wpa_add_security (conn_name);
		table = _get_hash_table (conn_name);
		/* Give lowest priority */
		wpa_set_data (conn_name, "priority", "0");
		g_regex_match (regex_keys, key_str, 0, &keys_info);
		/* add wep keys */
		while (g_match_info_matches (keys_info)) {
			gchar *key_num = g_match_info_fetch (keys_info, 2);
			gchar *one_wep_key = g_match_info_fetch (keys_info, 3);

			add_one_wep_key (table, atoi (key_num), one_wep_key);
			g_free (key_num);
			g_free (one_wep_key);
			g_match_info_next (keys_info, NULL);
		}
		g_match_info_free (keys_info);

		g_regex_match (regex_method, key_str, 0, &method_info);
		/* set default key index and auth alg */
		if (g_match_info_matches (method_info)) {
			gchar *default_idx =
			    g_match_info_fetch (method_info, 1);
			gchar *method = g_match_info_fetch (method_info, 2);

			default_idx[0]--;
			g_hash_table_insert (table, g_strdup ("wep_tx_keyidx"),
					     default_idx);
			g_hash_table_insert (table, g_strdup ("auth_alg"),
					     g_ascii_strup (method, -1));
		}
		g_match_info_free (method_info);
		add_security (table);
		iter = g_list_next (iter);
	}
	g_list_free (names);
	g_regex_unref (regex_keys);
	g_regex_unref (regex_method);
}

static void
add_global_data (gchar * line)
{
	gchar **key_value;

	g_strstrip (line);
	key_value = g_strsplit (line, "=", 2);
	if (g_strv_length (key_value) != 2) {
		nm_log_warn (LOGD_SETTINGS, "Can't handle this line: %s\n", line);
		g_strfreev (key_value);
		return;
	}
	g_hash_table_insert (wsec_global_table,
			     g_strdup (g_strstrip (key_value[0])),
			     g_strdup (g_strstrip (key_value[1])));
	g_strfreev (key_value);
}

void
wpa_parser_init (const char *wpa_supplicant_conf)
{
	GIOChannel *channel = NULL;
	gchar *line;
	gboolean complete = FALSE;

	wpa_parser_data_changed = FALSE;
	wsec_table = g_hash_table_new (g_str_hash, g_str_equal);
	wsec_global_table = g_hash_table_new (g_str_hash, g_str_equal);

	if (g_file_test (wpa_supplicant_conf, G_FILE_TEST_IS_REGULAR))
		channel =
		    g_io_channel_new_file (wpa_supplicant_conf, "r", NULL);
	if (channel == NULL) {
		nm_log_warn (LOGD_SETTINGS, "Can't open %s for wireless security",
		             wpa_supplicant_conf);
		return;
	}

	while (g_io_channel_read_line (channel, &line, NULL, NULL, NULL)
	       != G_IO_STATUS_EOF) {
		g_strstrip (line);
		if (line[0] != '#' && line[0] != '\0') {
			if (strstr (line, "network={") == NULL) {
				add_global_data (line);
				g_free (line);
				continue;
			} else {
				GHashTable *network =
				    g_hash_table_new (g_str_hash, g_str_equal);

				do {
					gchar *quote_start, *quote_end = NULL, *comment;

					if (line[0] == '#' || line[0] == '\0') {
						g_free (line);
						continue;
					}
					/* ignore inline comments unless inside
					   a double-quoted string */
					if ((quote_start = strchr (line, '"')) != NULL)
						quote_end = strrchr (quote_start + 1, '"');
					if ((comment = strchr ((quote_end != NULL) ?
					                       quote_end : line, '#')) != NULL)
						*comment = '\0';
					if (strstr (line, "}") != NULL)
						complete = TRUE;
					add_key_value (network, line);
					g_free (line);
				} while (complete == FALSE
					 &&
					 g_io_channel_read_line
					 (channel, &line, NULL,
					  NULL, NULL) != G_IO_STATUS_EOF);
				add_security (network);
				//EOF in inner loop
				if (complete == FALSE) {
					g_free (line);
					break;
				}
				complete = FALSE;
			}
		} else
			g_free (line);
	}

	g_io_channel_shutdown (channel, FALSE, NULL);
	g_io_channel_unref (channel);

	add_keys_from_net ();
}

const char *
wpa_get_value (const char *ssid, const char *key)
{
	GHashTable *target = g_hash_table_lookup (wsec_table, ssid);

	if (target)
		return g_hash_table_lookup (target, key);
	return NULL;
}

gboolean
exist_ssid (const char *ssid)
{
	return g_hash_table_lookup (wsec_table, ssid) != NULL;
}

GHashTable *
_get_hash_table (const char *ssid)
{
	return g_hash_table_lookup (wsec_table, ssid);
}

static gchar *quoted_keys[] =
    { "identity", "cert", "private", "phase", "password", NULL };

/* tell whether the key needs quotes when writing is performed */
static gboolean
need_quote (gchar * key)
{
	int i = 0;

	while (quoted_keys[i] != NULL) {
		if (strstr (key, quoted_keys[i]))
			return TRUE;
		i++;
	}
	return FALSE;
}

gboolean
wpa_flush_to_file (const char *config_file)
{
	GIOChannel *channel;
	GError **error = NULL;
	gpointer key, value, ssid, security;
	GHashTableIter iter, iter_security;
	gchar *out_line;
	gsize bytes_written;
	gboolean result = FALSE;

	if (!wpa_parser_data_changed)
		return TRUE;
	if (!wsec_table || !wsec_global_table)
		return FALSE;

	backup_file (config_file);

	channel = g_io_channel_new_file (config_file, "w", NULL);
	if (!channel) {
		nm_log_warn (LOGD_SETTINGS, "Can't open file %s for writing", config_file);
		return FALSE;
	}
	g_hash_table_iter_init (&iter, wsec_global_table);
	nm_log_info (LOGD_SETTINGS, "Writing to %s", config_file);
	g_io_channel_write_chars (channel,
				  "#Generated by NetworkManager\n"
				  "###### Global Configuration ######\n",
				  -1, &bytes_written, error);

	/* Writing global information */
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		out_line =
		    g_strdup_printf ("%s=%s\n", (gchar *) key, (gchar *) value);
		g_io_channel_write_chars (channel, out_line, -1, &bytes_written,
					  error);
		if (bytes_written == 0 || (error && *error))
			break;
		g_free (out_line);
	}
	if (error && *error) {
		nm_log_warn (LOGD_SETTINGS, "Found error: %s", (*error)->message);
		goto done;
	}
	g_io_channel_write_chars (channel,
				  "\n###### Security Configuration ######\n",
				  -1, &bytes_written, error);

	g_hash_table_iter_init (&iter, wsec_table);
	/* Writing security */
	while (g_hash_table_iter_next (&iter, &ssid, &security)) {
		g_hash_table_iter_init (&iter_security,
					(GHashTable *) security);
		g_io_channel_write_chars (channel, "network={\n", -1,
					  &bytes_written, error);
		while (g_hash_table_iter_next (&iter_security, &key, &value)) {
			out_line =
			    g_strdup_printf (need_quote ((gchar *) key) ?
					     "\t%s=\"%s\"\n" : "\t%s=%s\n",
					     (gchar *) key, (gchar *) value);
			g_io_channel_write_chars (channel, out_line, -1,
						  &bytes_written, error);
			if (bytes_written == 0 || (error && *error))
				break;
			g_free (out_line);
		}
		g_io_channel_write_chars (channel,
					  "}\n\n", -1, &bytes_written, error);

	}
	if (error && *error) {
		nm_log_warn (LOGD_SETTINGS, "Found error: %s", (*error)->message);
		goto done;
	}
	g_io_channel_flush (channel, error);

	if (error && *error) {
		nm_log_warn (LOGD_SETTINGS, "Found error: %s", (*error)->message);
		goto done;
	}
	wpa_parser_data_changed = FALSE;
	result = TRUE;
done:
	g_io_channel_shutdown (channel, FALSE, NULL);
	g_io_channel_unref (channel);
	return result;
}

/* If value is NULL, this method will delete old key value pair */
void
wpa_set_data (const char *ssid, const char *key, const char *value)
{
	gpointer old_key = NULL, old_value = NULL;
	GHashTable *security = g_hash_table_lookup (wsec_table, ssid);
	gchar * stripped = NULL;

	g_return_if_fail (security != NULL);

	if (value){
		stripped = g_strdup(value);
		if (strcmp (key, "ssid") != 0 && strcmp (key, "psk") != 0
			&& !g_str_has_prefix (key, "wep_key"))
			strip_string (stripped, '"');
	}

	/* Remove old key value pairs */
	if (g_hash_table_lookup_extended
	    (security, key, &old_key, &old_value)) {
		if (stripped && !strcmp(old_value, stripped)){
			g_free (stripped);
			return;
		}
		g_hash_table_remove (security, old_key);
		g_free (old_key);
		g_free (old_value);
	} else if (!value)
		return;

	/* Add new key value */
	if (stripped)
		g_hash_table_insert (security, g_strdup (key), stripped);
	wpa_parser_data_changed = TRUE;
}

gboolean
wpa_has_security (const char *ssid)
{
	return g_hash_table_lookup (wsec_table, ssid) != NULL;
}

gboolean
wpa_add_security (const char *ssid)
{
	if (wpa_has_security (ssid))
		return TRUE;
	else {
		GHashTable *security =
		    g_hash_table_new (g_str_hash, g_str_equal);
		gchar *ssid_i;

		nm_log_info (LOGD_SETTINGS, "Adding security for %s", ssid);
		if (g_str_has_prefix (ssid, "0x")) {
			/* hex ssid */
			ssid_i = g_strdup (ssid + 2);
		} else {
			/* ascii ssid requires quotes */
			ssid_i = g_strdup_printf ("\"%s\"", ssid);
		}
		g_hash_table_insert (security, strdup ("ssid"), ssid_i);
		g_hash_table_insert (security, strdup ("priority"),
				     strdup ("1"));
		g_hash_table_insert (wsec_table, g_strdup (ssid), security);
		wpa_parser_data_changed = TRUE;
		return TRUE;
	}
}

gboolean
wpa_delete_security (const char *ssid)
{
	gpointer old_key, old_value;

	g_return_val_if_fail (wsec_table != NULL && ssid != NULL, FALSE);
	nm_log_info (LOGD_SETTINGS, "Deleting security for %s", ssid);
	if (!g_hash_table_lookup_extended
	    (wsec_table, ssid, &old_key, &old_value))
		return FALSE;
	g_hash_table_remove (wsec_table, old_key);
	g_free (old_key);
	destroy_security ((GHashTable *) old_value);
	wpa_parser_data_changed = TRUE;
	return TRUE;

}

void
wpa_parser_destroy (void)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;

	/* Destroy security */
	if (wsec_table) {
		g_hash_table_iter_init (&iter, wsec_table);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			destroy_security ((GHashTable *) value);
			g_free (key);
		}

		g_hash_table_destroy (wsec_table);
		wsec_table = NULL;
	}

	/* Destroy global data */
	if (wsec_global_table) {
		g_hash_table_iter_init (&iter, wsec_global_table);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			g_free (key);
			g_free (value);
		}

		g_hash_table_destroy (wsec_global_table);
		wsec_global_table = NULL;
	}
}
