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
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <nm-settings-plugin.h>
#include "nm-default.h"

#include "plugin.h"
#include "nm-platform.h"

#include "net_parser.h"
#include "net_utils.h"

/* Save all the connection information */
static GHashTable *conn_table;

/* Save global settings which are used for writing*/
static GHashTable *global_settings_table;

/* Save functions */
static GList *functions_list;

/* Used to decide whether to write changes to file*/
static gboolean net_parser_data_changed = FALSE;

static GHashTable *
add_new_connection_config (const gchar * type, const gchar * name)
{
	GHashTable *new_conn;
	gchar *new_name;

	if (!name)
		return NULL;

	/* Return existing connection */
	if ((new_conn = g_hash_table_lookup (conn_table, name)) != NULL)
		return new_conn;
	new_conn = g_hash_table_new (g_str_hash, g_str_equal);
	new_name = g_strdup (name);
	g_hash_table_insert (new_conn, g_strdup ("name"), new_name);
	g_hash_table_insert (new_conn, g_strdup ("type"), g_strdup (type));
	g_hash_table_insert (conn_table, new_name, new_conn);
	return new_conn;
}

gboolean
ifnet_add_network (const char *name, const char *type)
{
	if (ifnet_has_network (name))
		return TRUE;
	if (add_new_connection_config (type, name)) {
		nm_log_info (LOGD_SETTINGS, "Adding network for %s", name);
		net_parser_data_changed = TRUE;
		return TRUE;
	}
	return FALSE;
}

gboolean
ifnet_has_network (const char *conn_name)
{
	return g_hash_table_lookup (conn_table, conn_name) != NULL;
}

static GHashTable *
get_connection_config (const char *name)
{
	return g_hash_table_lookup (conn_table, name);
}

/* Ignored name won't be treated as wireless ssid */
static gchar *ignore_name[] = {
	"vlan", "bond", "atm", "ath", "ippp", "vpn", "tap", "tun", "1",
	"br", "nas", "6to4", "timeout", "kvm", "force", NULL
};

static gboolean
ignore_connection_name (const char *name)
{
	gboolean result = FALSE;
	guint i = 0;

	/* check ignore_name list */
	while (ignore_name[i] != NULL) {
		if (g_ascii_strncasecmp
		    (name, ignore_name[i], strlen (ignore_name[i])) == 0) {
			return TRUE;
		}
		i++;
	}
	/* Ignore mac address based configuration */
	if (strlen (name) == 12 && is_hex (name))
		result = TRUE;
	return result;
}

static gboolean
is_global_setting (char *key)
{
	static gchar *global_settings[] = { "wpa_supplicant_", NULL };
	int i;

	for (i = 0; global_settings[i] != NULL; i++) {
		if (strstr (key, global_settings[i]))
			return 1;
	}
	return 0;
}

/* Parse a complete line */
/* Connection type is determined here */
static void
init_block_by_line (gchar * buf)
{
	gchar **key_value;
	gchar *pos;
	gchar *data;
	gchar *tmp;
	GHashTable *conn;

	key_value = g_strsplit (buf, "=", 2);
	if (g_strv_length (key_value) != 2) {
		nm_log_warn (LOGD_SETTINGS, "Can't handle this line: %s\n", buf);
		g_strfreev (key_value);
		return;
	}
	pos = g_strrstr (key_value[0], "_");
	if (pos == NULL || is_global_setting (key_value[0])) {
		/* global data */
		data = g_strdup (key_value[1]);
		tmp = strip_string (data, '"');
		strip_string (tmp, '\'');
		nm_log_info (LOGD_SETTINGS, "global:%s-%s\n", key_value[0], tmp);
		g_hash_table_insert (global_settings_table, g_strdup (key_value[0]), g_strdup (tmp));
		g_strfreev (key_value);
		g_free (data);
		return;
	}
	*pos++ = '\0';
	if ((conn = get_connection_config (pos)) == NULL) {
		if (g_ascii_strncasecmp (pos, "eth", 3) == 0
		    && strlen (pos) == 4)
			/* wired connection */
			conn = add_new_connection_config ("wired", pos);
		else if (g_ascii_strncasecmp (pos, "ppp", 3) == 0
			 && strlen (pos) == 4)
			/* pppoe connection */
			conn = add_new_connection_config ("ppp", pos);
		else if (ignore_connection_name (pos)) {
			/* ignored connection */
			conn = add_new_connection_config ("ignore", pos);
		} else {
			int ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, pos);

			if (ifindex && nm_platform_link_get_type (NM_PLATFORM_GET, ifindex) != NM_LINK_TYPE_WIFI)
				/* wired connection */
				conn = add_new_connection_config ("wired", pos);
			else
				/* wireless connection */
				conn = add_new_connection_config ("wireless", pos);
		}
	}
	data = g_strdup (key_value[1]);
	tmp = strip_string (data, '"');
	strip_string (tmp, '\'');
	if (conn)
		g_hash_table_insert (conn, strip_string (g_strdup (key_value[0]), ' '),
				     g_strdup (tmp));
	g_free (data);
	g_strfreev (key_value);
}

static void
destroy_connection_config (GHashTable * conn)
{
	gpointer key, value;
	GHashTableIter iter;

	g_hash_table_iter_init (&iter, conn);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		g_free (key);
		g_free (value);
	}

	g_hash_table_destroy (conn);
}

static void
strip_function (GIOChannel * channel, gchar * line)
{

	int counter = 0;
	gchar *p, *tmp;
	gboolean begin = FALSE;
	GString *function_str = g_string_new (line);

	g_string_append (function_str, "\n");
	while (1) {
		p = line;
		while (*p != '\0') {
			if (*p == '{') {
				counter++;
				begin = TRUE;
			} else if (*p == '}')
				counter--;
			p++;
		}
		if (begin && counter == 0) {
			g_free (line);
			goto done;
		}
		while (1) {
			g_free (line);
			if (g_io_channel_read_line
			    (channel, &line, NULL, NULL,
			     NULL) == G_IO_STATUS_EOF)
				goto done;
			g_string_append (function_str, line);
			tmp = g_strdup (line);
			g_strstrip (tmp);
			if (tmp[0] != '#' && tmp[0] != '\0') {
				g_free (tmp);
				break;
			} else
				g_free (tmp);
		}
	}
done:
	functions_list =
	    g_list_append (functions_list, g_strdup (function_str->str));
	g_string_free (function_str, TRUE);
}

static gboolean
is_function (gchar * line)
{
	static gchar *func_names[] =
	    { "preup", "predown", "postup", "postdown", "failup", "faildown",
		NULL,
	};
	int i;

	for (i = 0; func_names[i]; i++) {
		if (g_str_has_prefix (line, func_names[i])) {
			nm_log_info (LOGD_SETTINGS, "Ignoring function: %s", func_names[i]);
			return TRUE;
		}
	}
	return FALSE;
}

static void
append_line (GString *buf, gchar* line)
{
	gchar *pos = NULL;

	if ((pos = strchr (line, '#')) != NULL)
		*pos = '\0';
	g_strstrip (line);

	if (line[0] != '\0')
		g_string_append_printf (buf, " %s", line);
	g_free (line);
}

gboolean
ifnet_init (gchar * config_file)
{
	GIOChannel *channel = NULL;
	gchar *line;

	/* Handle multiple lines with brackets */
	gboolean complete = TRUE;

	gboolean openrc_style = TRUE;

	/* line buffer */
	GString *buf;

	net_parser_data_changed = FALSE;

	conn_table = g_hash_table_new (g_str_hash, g_str_equal);
	global_settings_table = g_hash_table_new (g_str_hash, g_str_equal);
	functions_list = NULL;

	if (g_file_test (config_file, G_FILE_TEST_IS_REGULAR))
		channel = g_io_channel_new_file (config_file, "r", NULL);
	if (channel == NULL) {
		nm_log_warn (LOGD_SETTINGS, "Can't open %s", config_file);
		return FALSE;
	}

	buf = g_string_new (NULL);
	while (g_io_channel_read_line
	       (channel, &line, NULL, NULL, NULL) != G_IO_STATUS_EOF) {
		g_strstrip (line);
		/* convert multiple lines to a complete line and
		 * pass it to init_block_by_line() */
		if (is_function (line)) {
			strip_function (channel, line);
			continue;
		}

		// New openrc style, bash arrays are not allowed. We only care about '"'
		if (openrc_style && line[0] != '#' && line[0] != '\0'
				&& !strchr (line, '(') && !strchr (line, ')')) {
			gchar *tmp = line;

			while ((tmp = strchr (tmp, '"')) != NULL) {
				complete = !complete;
				++tmp;
			}

			append_line (buf, line);
			// Add "(separator) for routes. It will be easier for later parsing
			if (strstr (buf->str, "via"))
				g_string_append_printf (buf, "\"");

			if (!complete)
				continue;

			strip_string (buf->str, '"');

			init_block_by_line (buf->str);
			g_string_free (buf, TRUE);
			buf = g_string_new (NULL);
		}
		// Old bash arrays for baselayout-1, to be deleted
		else if (line[0] != '#' && line[0] != '\0') {
			if (!complete) {
				complete =
				    g_strrstr (line,
					       ")") == NULL ? FALSE : TRUE;

				append_line (buf, line);
				if (!complete) {
					openrc_style = FALSE;
					continue;
				}
				else {
					openrc_style = TRUE;
				}
			} else {
				complete =
				    (g_strrstr (line, "(") != NULL
				     && g_strrstr (line, ")") != NULL)
				    || g_strrstr (line, "(") == NULL;

				append_line (buf, line);
				if (!complete)
				{
					openrc_style = FALSE;
					continue;
				} else {
					openrc_style = TRUE;
				}
			}
			init_block_by_line (buf->str);
			g_string_free (buf, TRUE);
			buf = g_string_new (NULL);
		} else
			/* Blank line or comment line */
			g_free (line);
	}

	g_string_free (buf, TRUE);
	g_io_channel_shutdown (channel, FALSE, NULL);
	g_io_channel_unref (channel);
	return TRUE;
}

const char *
ifnet_get_data (const char *conn_name, const char *key)
{
	GHashTable *conn;

	g_return_val_if_fail (conn_name && key, NULL);

	conn = g_hash_table_lookup (conn_table, conn_name);

	if (conn)
		return g_hash_table_lookup (conn, key);
	return NULL;
}

/* format ip values for comparison */
static gchar*
format_ip_for_comparison (const gchar * value)
{
	gchar **ipset;
	guint length, i;
	GString *formated_string = g_string_new (NULL);
	gchar *formatted = NULL;

	ipset = g_strsplit (value, "\"", 0);
	length = g_strv_length (ipset);

	for (i = 0; i < length; i++)
	{
		strip_string (ipset[i], ' ');
		if (ipset[i][0] != '\0')
			g_string_append_printf (formated_string,
						"%s ", ipset[i]);
	}
	formatted = g_strdup (formated_string->str);
	formatted[formated_string->len - 1] = '\0';

	g_string_free (formated_string, TRUE);
	g_strfreev (ipset);

	return formatted;
}

void
ifnet_set_data (const char *conn_name, const char *key, const char *value)
{
	gpointer old_key = NULL, old_value = NULL;
	GHashTable *conn = g_hash_table_lookup (conn_table, conn_name);
	gchar * stripped = NULL;

	if (!conn) {
		nm_log_warn (LOGD_SETTINGS, "%s does not exist!", conn_name);
		return;
	}
	if (value){
		stripped = g_strdup (value);
		strip_string (stripped, '"');
	}
	/* Remove existing key value pair */
	if (g_hash_table_lookup_extended (conn, key, &old_key, &old_value)) {

		/* This ugly hack is due to baselayout compatibility. We have to
		 * deal with different ip format. So sometimes we have the same ips
		 * but different strings.
		 */
		if (stripped &&
			(!strcmp (key, "config")
			|| !strcmp (key, "routes")
			|| !strcmp (key, "pppd")
			|| !strcmp (key, "chat")))
		{
			gchar *old_ips = format_ip_for_comparison (old_value);
			gchar *new_ips = format_ip_for_comparison (value);
			if(!strcmp (old_ips, new_ips))
			{
				g_free (stripped);
				g_free (old_ips);
				g_free (new_ips);
				return;
			}
			g_free (old_ips);
			g_free (new_ips);
		}

		if (stripped && !strcmp (old_value, stripped)) {
			g_free (stripped);
			return;
		}
		g_hash_table_remove (conn, old_key);
		g_free (old_key);
		g_free (old_value);
	} else if (!value)
		return;
	if (stripped)
		g_hash_table_insert (conn, g_strdup (key), stripped);
	net_parser_data_changed = TRUE;
}

// Remember to free return value
const char *
ifnet_get_global_data (const gchar * key)
{
	return g_hash_table_lookup (global_settings_table, key);
}

// Return names of legal connections
GList *
ifnet_get_connection_names (void)
{
	GList *names = g_hash_table_get_keys (conn_table);
	GList *result = NULL;

	while (names) {
		if (!ignore_connection_name (names->data))
			result = g_list_prepend (result, names->data);
		names = names->next;
	}
	g_list_free (names);
	return g_list_reverse (result);
}

/* format IP and route for writing */
static void
format_ips (gchar * value, gchar ** out_line, gchar * key, gchar * name)
{
	gchar **ipset;
	guint length, i;
	GString *formated_string = g_string_new (NULL);

	strip_string (value, '(');
	strip_string (value, ')');
	strip_string (value, '"');
	ipset = g_strsplit (value, "\"", 0);
	length = g_strv_length (ipset);

	//only one line
	if (length < 2) {
		*out_line =
		    g_strdup_printf ("%s_%s=\"%s\"\n", key, name, value);
		goto done;
	}
	// Multiple lines
	g_string_append_printf (formated_string, "%s_%s=\"\n", key, name);
	for (i = 0; i < length; i++)
	{
		strip_string (ipset[i], ' ');
		if (ipset[i][0] != '\0')
			g_string_append_printf (formated_string,
						"%s\n", ipset[i]);
	}
	g_string_append (formated_string, "\"\n");
	*out_line = g_strdup (formated_string->str);
done:
	g_string_free (formated_string, TRUE);
	g_strfreev (ipset);
}

gboolean
ifnet_flush_to_file (const char *config_file, gchar **out_backup)
{
	GIOChannel *channel;
	GError **error = NULL;
	gpointer key, value, name, network;
	GHashTableIter iter, iter_network;
	GList *list_iter;
	gchar *out_line = NULL;
	gsize bytes_written;
	gboolean result = FALSE;
	gchar *backup;

	if (!net_parser_data_changed)
		return TRUE;
	if (!conn_table || !global_settings_table)
		return FALSE;

	backup = backup_file (config_file);

	channel = g_io_channel_new_file (config_file, "w", NULL);
	if (!channel) {
		nm_log_warn (LOGD_SETTINGS, "Can't open file %s for writing", config_file);
		g_free (backup);
		return FALSE;
	}
	g_hash_table_iter_init (&iter, global_settings_table);
	nm_log_info (LOGD_SETTINGS, "Writing to %s", config_file);
	g_io_channel_write_chars (channel,
				  "#Generated by NetworkManager\n"
				  "###### Global Configuration ######\n",
				  -1, &bytes_written, error);
	/* Writing global data */
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		out_line =
		    g_strdup_printf ("%s=\"%s\"\n", (gchar *) key, (gchar *) value);
		g_io_channel_write_chars (channel, out_line, -1,
					  &bytes_written, error);
		if (bytes_written == 0 || (error && *error))
			break;
		g_free (out_line);
	}
	if (error && *error) {
		nm_log_warn (LOGD_SETTINGS, "Found error: %s", (*error)->message);
		goto done;
	}

	/* Writing connection data */
	g_io_channel_write_chars (channel,
				  "\n###### Connection Configuration ######\n",
				  -1, &bytes_written, error);
	g_hash_table_iter_init (&iter, conn_table);
	while (g_hash_table_iter_next (&iter, &name, &network)) {
		g_hash_table_iter_init (&iter_network, (GHashTable *) network);
		g_io_channel_write_chars (channel,
					  "#----------------------------------\n",
					  -1, &bytes_written, error);

		while (g_hash_table_iter_next (&iter_network, &key, &value)) {
			if (!g_str_has_prefix ((gchar *) key, "name")
			    && !g_str_has_prefix ((gchar *) key, "type")) {
				/* These keys contain brackets */
				if (strcmp
				    ((gchar *) key,
				     "config") == 0
				    || strcmp ((gchar *) key,
					       "routes") == 0
				    || strcmp ((gchar *) key,
					       "pppd") == 0
				    || strcmp ((gchar *) key, "chat") == 0)
					format_ips (value, &out_line, (gchar *)
						    key, (gchar *)
						    name);
				else
					out_line =
					    g_strdup_printf
					    ("%s_%s=\"%s\"\n",
					     (gchar *) key,
					     (gchar *) name, (gchar *) value);
				g_io_channel_write_chars
				    (channel, out_line, -1,
				     &bytes_written, error);
				if (bytes_written == 0 || (error && *error))
					break;
				g_free (out_line);
			}
		}
	}
	if (error && *error) {
		nm_log_warn (LOGD_SETTINGS, "Found error: %s", (*error)->message);
		goto done;
	}

	/* Writing reserved functions */
	if (functions_list) {
		g_io_channel_write_chars (channel,
					  "\n###### Reserved Functions ######\n",
					  -1, &bytes_written, error);
		/* Writing functions */
		for (list_iter = functions_list; list_iter;
		     list_iter = g_list_next (list_iter)) {
			out_line =
			    g_strdup_printf ("%s\n", (gchar *) list_iter->data);
			g_io_channel_write_chars (channel, out_line, -1,
						  &bytes_written, error);
			if (bytes_written == 0 || (error && *error))
				break;
			g_free (out_line);
		}
		if (error && *error) {
			nm_log_warn (LOGD_SETTINGS, "Found error: %s", (*error)->message);
			goto done;
		}
	}

	g_io_channel_flush (channel, error);
	if (error && *error) {
		nm_log_warn (LOGD_SETTINGS, "Found error: %s", (*error)->message);
		goto done;
	}
	result = TRUE;
	net_parser_data_changed = FALSE;

done:
	if (result && out_backup)
		*out_backup = backup;
	else
		g_free (backup);

	g_io_channel_shutdown (channel, FALSE, NULL);
	g_io_channel_unref (channel);
	return result;
}

gboolean
ifnet_delete_network (const char *conn_name)
{
	GHashTable *network = NULL;

	g_return_val_if_fail (conn_table != NULL && conn_name != NULL, FALSE);
	nm_log_info (LOGD_SETTINGS, "Deleting network for %s", conn_name);
	network = g_hash_table_lookup (conn_table, conn_name);
	if (!network)
		return FALSE;
	g_hash_table_remove (conn_table, conn_name);
	destroy_connection_config (network);
	net_parser_data_changed = TRUE;
	return TRUE;
}

void
ifnet_destroy (void)
{
	GHashTableIter iter;
	gpointer key;
	gpointer value;
	GList *list_iter;

	/* Destroy connection setting */
	if (conn_table) {
		g_hash_table_iter_init (&iter, conn_table);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			destroy_connection_config ((GHashTable *)
						   value);
		}
		g_hash_table_destroy (conn_table);
		conn_table = NULL;
	}

	/* Destroy global data */
	if (global_settings_table) {
		g_hash_table_iter_init (&iter, global_settings_table);
		while (g_hash_table_iter_next (&iter, &key, &value)) {
			g_free (key);
			g_free (value);
		}
		g_hash_table_destroy (global_settings_table);
		global_settings_table = NULL;
	}
	for (list_iter = functions_list; list_iter;
	     list_iter = g_list_next (list_iter))
		g_free (list_iter->data);
	g_list_free (functions_list);
}
