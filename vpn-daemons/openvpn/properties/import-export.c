/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/***************************************************************************
 *
 * Copyright (C) 2008 Dan Williams, <dcbw@redhat.com>
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
 **************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#include <glib/gi18n-lib.h>

#include <nm-setting-vpn.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>

#include "import-export.h"
#include "nm-openvpn.h"
#include "../src/nm-openvpn-service.h"

#define CLIENT_TAG "client"
#define DEV_TAG "dev"
#define PROTO_TAG "proto"
#define REMOTE_TAG "remote"
#define CA_TAG "ca"
#define CERT_TAG "cert"
#define KEY_TAG "key"
#define CIPHER_TAG "cipher"
#define COMP_TAG "comp-lzo"
#define IFCONFIG_TAG "ifconfig"
#define SECRET_TAG "secret"
#define AUTH_USER_PASS_TAG "auth-user-pass"
#define TLS_AUTH_TAG "tls-auth"

static gboolean
handle_path_item (const char *line,
                  const char *tag,
                  const char *key,
                  GHashTable *hash,
                  char **leftover)
{
	char *tmp, *file, *unquoted, *p;
	gboolean quoted = FALSE;

	if (leftover)
		g_return_val_if_fail (*leftover == NULL, FALSE);

	if (strncmp (line, tag, strlen (tag)))
		return FALSE;

	tmp = g_strdup (line + strlen (tag));
	file = g_strstrip (tmp);
	if (!strlen (file))
		goto out;

	/* Simple unquote */
	if ((file[0] == '"') || (file[0] == '\'')) {
		quoted = TRUE;
		file++;
	}

	/* Unquote stuff using openvpn unquoting rules */
	unquoted = g_malloc0 (strlen (file) + 1);
	for (p = unquoted; *file; file++, p++) {
		if (quoted && ((*file == '"') || (*file == '\'')))
			break;
		else if (!quoted && isspace (*file))
			break;

		if (*file == '\\' && *(file+1) == '\\')
			*p = *(++file);
		else if (*file == '\\' && *(file+1) == '"')
			*p = *(++file);
		else if (*file == '\\' && *(file+1) == ' ')
			*p = *(++file);
		else
			*p = *file;
	}
	if (leftover && *file)
		*leftover = file + 1;

	g_hash_table_insert (hash, g_strdup (key), g_strdup (unquoted));
	g_free (unquoted);

out:
	g_free (tmp);
	return TRUE;
}

static char **
get_args (const char *line)
{
	char **split, **sanitized, **tmp, **tmp2;

	split = g_strsplit_set (line, " \t", 0);
	sanitized = g_malloc0 (sizeof (char *) * (g_strv_length (split) + 1));

	for (tmp = split, tmp2 = sanitized; *tmp; tmp++) {
		if (strlen (*tmp))
			*tmp2++ = g_strdup (*tmp);
	}

	g_strfreev (split);
	return sanitized;
}

static void
handle_direction (const char *tag, const char *key, char *leftover, GHashTable *hash)
{
	glong direction;

	if (!leftover)
		return;

	leftover = g_strstrip (leftover);
	if (!strlen (leftover))
		return;

	errno = 0;
	direction = strtol (leftover, NULL, 10);
	if (errno == 0) {
		if (direction == 0)
			g_hash_table_insert (hash, g_strdup (key), g_strdup ("0"));
		else if (direction == 1)
			g_hash_table_insert (hash, g_strdup (key), g_strdup ("1"));
	} else
		g_warning ("%s: unknown %s direction '%s'", __func__, tag, leftover);
}

NMConnection *
do_import (const char *path, char **lines, GError **error)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVPN *s_vpn;
	char *last_dot;
	char **line;
	gboolean have_client = FALSE, have_remote = FALSE;
	gboolean have_pass = FALSE, have_sk = FALSE;
	const char *ctype = NULL;

	connection = nm_connection_new ();
	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());
	nm_connection_add_setting (connection, NM_SETTING (s_con));

	s_vpn = NM_SETTING_VPN (nm_setting_vpn_new ());
	s_vpn->service_type = g_strdup (NM_DBUS_SERVICE_OPENVPN);

	s_con->id = g_path_get_basename (path);
	last_dot = strrchr (s_con->id, '.');
	if (last_dot)
		*last_dot = '\0';

	for (line = lines; *line; line++) {
		char *comment, **items, *leftover = NULL;

		if ((comment = strchr (*line, '#')))
			*comment = '\0';
		if ((comment = strchr (*line, ';')))
			*comment = '\0';
		if (!strlen (*line))
			continue;

		if (!strncmp (*line, CLIENT_TAG, strlen (CLIENT_TAG)))
			have_client = TRUE;

		if (!strncmp (*line, DEV_TAG, strlen (DEV_TAG))) {
			if (strstr (*line, "tun")) {
				/* ignore; default is tun */
			} else if (strstr (*line, "tap")) {
				g_hash_table_insert (s_vpn->data,
				                     g_strdup (NM_OPENVPN_KEY_TAP_DEV),
				                     g_strdup ("yes"));
			} else
				g_warning ("%s: unknown dev option '%s'", __func__, *line);

			continue;
		}

		if (!strncmp (*line, PROTO_TAG, strlen (PROTO_TAG))) {
			if (strstr (*line, "udp")) {
				/* ignore; udp is default */
			} else if (strstr (*line, "tcp")) {
				g_hash_table_insert (s_vpn->data,
				                     g_strdup (NM_OPENVPN_KEY_PROTO_TCP),
				                     g_strdup ("yes"));
			} else
				g_warning ("%s: unknown proto option '%s'", __func__, *line);

			continue;
		}

		if (!strncmp (*line, COMP_TAG, strlen (COMP_TAG))) {
			g_hash_table_insert (s_vpn->data,
			                     g_strdup (NM_OPENVPN_KEY_COMP_LZO),
			                     g_strdup ("yes"));
			continue;
		}

		if (!strncmp (*line, REMOTE_TAG, strlen (REMOTE_TAG))) {
			items = get_args (*line + strlen (REMOTE_TAG));
			if (!items)
				continue;

			if (g_strv_length (items) >= 1) {
				g_hash_table_insert (s_vpn->data,
				                     g_strdup (NM_OPENVPN_KEY_REMOTE),
				                     g_strdup (items[0]));
				have_remote = TRUE;

				if (g_strv_length (items) >= 2) {
					glong port;

					errno = 0;
					port = strtol (items[1], NULL, 10);
					if ((errno == 0) && (port > 0) && (port < 65536)) {
						g_hash_table_insert (s_vpn->data,
						                     g_strdup (NM_OPENVPN_KEY_PORT),
						                     g_strdup_printf ("%d", (guint32) port));
					} else
						g_warning ("%s: invalid remote port in option '%s'", __func__, *line);
				}
			}
			g_strfreev (items);

			if (!g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_REMOTE))
				g_warning ("%s: unknown remote option '%s'", __func__, *line);
			continue;
		}

		if (handle_path_item (*line, CA_TAG, NM_OPENVPN_KEY_CA, s_vpn->data, NULL))
			continue;

		if (handle_path_item (*line, CERT_TAG, NM_OPENVPN_KEY_CERT, s_vpn->data, NULL))
			continue;

		if (handle_path_item (*line, KEY_TAG, NM_OPENVPN_KEY_KEY, s_vpn->data, NULL))
			continue;

		if (handle_path_item (*line, SECRET_TAG, NM_OPENVPN_KEY_STATIC_KEY,
		                      s_vpn->data, &leftover)) {
			handle_direction ("secret",
			                  NM_OPENVPN_KEY_STATIC_KEY_DIRECTION,
			                  leftover,
			                  s_vpn->data);
			continue;
		}

		if (handle_path_item (*line, TLS_AUTH_TAG, NM_OPENVPN_KEY_TA,
		                      s_vpn->data, &leftover)) {
			handle_direction ("tls-auth",
			                  NM_OPENVPN_KEY_TA_DIR,
			                  leftover,
			                  s_vpn->data);
			continue;
		}

		if (!strncmp (*line, CIPHER_TAG, strlen (CIPHER_TAG))) {
			items = get_args (*line + strlen (CIPHER_TAG));
			if (!items)
				continue;

			if (g_strv_length (items)) {
				g_hash_table_insert (s_vpn->data,
				                     g_strdup (NM_OPENVPN_KEY_CIPHER),
				                     g_strdup (items[0]));
			}
			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, IFCONFIG_TAG, strlen (IFCONFIG_TAG))) {
			items = get_args (*line + strlen (IFCONFIG_TAG));
			if (!items)
				continue;

			if (g_strv_length (items) == 2) {
				g_hash_table_insert (s_vpn->data,
				                     g_strdup (NM_OPENVPN_KEY_LOCAL_IP),
				                     g_strdup (items[0]));
				g_hash_table_insert (s_vpn->data,
				                     g_strdup (NM_OPENVPN_KEY_REMOTE_IP),
				                     g_strdup (items[1]));
			} else
				g_warning ("%s: unknown ifconfig option '%s'", __func__, *line);
			g_strfreev (items);
			continue;
		}

		if (!strncmp (*line, AUTH_USER_PASS_TAG, strlen (AUTH_USER_PASS_TAG)))
			have_pass = TRUE;
	}

	if (g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_STATIC_KEY))
		have_sk = TRUE;

	if (!have_client && !have_sk) {
		g_set_error (error,
		             OPENVPN_PLUGIN_UI_ERROR,
		             OPENVPN_PLUGIN_UI_ERROR_FILE_NOT_OPENVPN,
		             "The file to import wasn't a valid OpenVPN client configuration.");
		g_object_unref (connection);
		connection = NULL;
	} else if (!have_remote) {
		g_set_error (error,
		             OPENVPN_PLUGIN_UI_ERROR,
		             OPENVPN_PLUGIN_UI_ERROR_FILE_NOT_OPENVPN,
		             "The file to import wasn't a valid OpenVPN configure (no remote).");
		g_object_unref (connection);
		connection = NULL;
	} else {
		gboolean have_certs = FALSE, have_ca = FALSE;

		if (g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_CA))
			have_ca = TRUE;

		if (   have_ca
		    && g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_CERT)
		    && g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_KEY))
			have_certs = TRUE;

		/* Determine connection type */
		if (have_pass) {
			if (have_certs)
				ctype = NM_OPENVPN_CONTYPE_PASSWORD_TLS;
			else if (have_ca)
				ctype = NM_OPENVPN_CONTYPE_PASSWORD;
		} else if (have_certs) {
			ctype = NM_OPENVPN_CONTYPE_TLS;
		} else if (have_sk)
			ctype = NM_OPENVPN_CONTYPE_STATIC_KEY;

		if (!ctype)
			ctype = NM_OPENVPN_CONTYPE_TLS;

		g_hash_table_insert (s_vpn->data,
		                     g_strdup (NM_OPENVPN_KEY_CONNECTION_TYPE),
		                     g_strdup (ctype));
	}

	nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	return connection;
}

gboolean
do_export (const char *path, NMConnection *connection, GError **error)
{
	return FALSE;
}


