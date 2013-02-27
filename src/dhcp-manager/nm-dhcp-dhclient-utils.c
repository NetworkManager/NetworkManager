/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 * Copyright (C) 2011 Red Hat, Inc.
 */

#include <config.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <string.h>
#include <ctype.h>

#include "nm-dhcp-dhclient-utils.h"

#define CLIENTID_TAG            "send dhcp-client-identifier"
#define CLIENTID_FORMAT         CLIENTID_TAG " \"%s\"; # added by NetworkManager"
#define CLIENTID_FORMAT_OCTETS  CLIENTID_TAG " %s; # added by NetworkManager"

#define HOSTNAME4_TAG    "send host-name"
#define HOSTNAME4_FORMAT HOSTNAME4_TAG " \"%s\"; # added by NetworkManager"

#define HOSTNAME6_TAG    "send fqdn.fqdn"
#define HOSTNAME6_FORMAT HOSTNAME6_TAG " \"%s\"; # added by NetworkManager"

#define ALSOREQ_TAG "also request "

static void
add_also_request (GPtrArray *array, const char *item)
{
	int i;

	for (i = 0; i < array->len; i++) {
		if (!strcmp (g_ptr_array_index (array, i), item))
			return;
	}
	g_ptr_array_add (array, g_strdup (item));
}

static void
add_hostname (GString *str, const char *format, const char *hostname)
{
	char *plain_hostname, *dot;

	if (hostname) {
		plain_hostname = g_strdup (hostname);
		dot = strchr (plain_hostname, '.');
		/* get rid of the domain */
		if (dot)
			*dot = '\0';

		g_string_append_printf (str, format, plain_hostname);
		g_free (plain_hostname);
	}
}

static void
add_ip4_config (GString *str, NMSettingIP4Config *s_ip4, const char *hostname)
{
	if (s_ip4) {
		const char *tmp;

		tmp = nm_setting_ip4_config_get_dhcp_client_id (s_ip4);
		if (tmp) {
			gboolean is_octets = TRUE;
			const char *p = tmp;

			while (*p) {
				if (!g_ascii_isxdigit (*p) && (*p != ':')) {
					is_octets = FALSE;
					break;
				}
				p++;
			}

			/* If the client ID is just hex digits and : then don't use quotes,
			 * because dhclient expects either a quoted ASCII string, or a byte
			 * array formated as hex octets separated by :
			 */
			if (is_octets)
				g_string_append_printf (str, CLIENTID_FORMAT_OCTETS "\n", tmp);
			else
				g_string_append_printf (str, CLIENTID_FORMAT "\n", tmp);
		}
	}

	add_hostname (str, HOSTNAME4_FORMAT "\n", hostname);

	g_string_append_c (str, '\n');

	/* Define options for classless static routes */
	g_string_append (str,
	                 "option rfc3442-classless-static-routes code 121 = array of unsigned integer 8;\n");
	g_string_append (str,
	                 "option ms-classless-static-routes code 249 = array of unsigned integer 8;\n");
	/* Web Proxy Auto-Discovery option (bgo #368423) */
	g_string_append (str, "option wpad code 252 = string;\n");

	g_string_append_c (str, '\n');
}

static void
add_ip6_config (GString *str, NMSettingIP6Config *s_ip6, const char *hostname)
{
	add_hostname (str, HOSTNAME6_FORMAT "\n", hostname);
	g_string_append (str,
	                 "send fqdn.encoded on;\n"
	                 "send fqdn.no-client-update on;\n"
	                 "send fqdn.server-update on;\n");
}

char *
nm_dhcp_dhclient_create_config (const char *interface,
                                gboolean is_ip6,
                                NMSettingIP4Config *s_ip4,
                                NMSettingIP6Config *s_ip6,
                                guint8 *anycast_addr,
                                const char *hostname,
                                const char *orig_path,
                                const char *orig_contents)
{
	GString *new_contents;
	GPtrArray *alsoreq;
	int i;

	new_contents = g_string_new (_("# Created by NetworkManager\n"));
	alsoreq = g_ptr_array_sized_new (5);

	if (orig_contents) {
		char **lines, **line;
		gboolean in_alsoreq = FALSE;

		g_string_append_printf (new_contents, _("# Merged from %s\n\n"), orig_path);

		lines = g_strsplit_set (orig_contents, "\n\r", 0);
		for (line = lines; lines && *line; line++) {
			char *p = *line;

			if (!strlen (g_strstrip (p)))
				continue;

			/* Override config file "dhcp-client-id" and use one from the
			 * connection.
			 */
			if (   s_ip4
			    && nm_setting_ip4_config_get_dhcp_client_id (s_ip4)
			    && !strncmp (p, CLIENTID_TAG, strlen (CLIENTID_TAG)))
				continue;

			/* Override config file hostname and use one from the connection */
			if (hostname) {
				if (strncmp (p, HOSTNAME4_TAG, strlen (HOSTNAME4_TAG)) == 0)
					continue;
				if (strncmp (p, HOSTNAME6_TAG, strlen (HOSTNAME6_TAG)) == 0)
					continue;
			}

			/* Ignore 'script' since we pass our own */
			if (g_str_has_prefix (p, "script "))
				continue;

			/* Check for "also require" */
			if (!strncmp (p, ALSOREQ_TAG, strlen (ALSOREQ_TAG))) {
				in_alsoreq = TRUE;
				p += strlen (ALSOREQ_TAG);
			}

			if (in_alsoreq) {
				char **areq, **aiter;

				/* Grab each 'also require' option and save for later */
				areq = g_strsplit_set (p, "\t ,", -1);
				for (aiter = areq; aiter && *aiter; aiter++) {
					if (!strlen (g_strstrip (*aiter)))
						continue;

					if (*aiter[0] == ';') {
						/* all done */
						in_alsoreq = FALSE;
						break;
					}

					if (!g_ascii_isalnum ((*aiter)[0]))
						continue;

					if ((*aiter)[strlen (*aiter) - 1] == ';') {
						/* Remove the EOL marker */
						(*aiter)[strlen (*aiter) - 1] = '\0';
						in_alsoreq = FALSE;
					}

					add_also_request (alsoreq, *aiter);
				}

				if (areq)
					g_strfreev (areq);

				continue;
			}

			/* Existing configuration line is OK, add it to new configuration */
			g_string_append (new_contents, *line);
			g_string_append_c (new_contents, '\n');
		}

		if (lines)
			g_strfreev (lines);
	} else
		g_string_append_c (new_contents, '\n');

	if (is_ip6) {
		add_ip6_config (new_contents, s_ip6, hostname);
		add_also_request (alsoreq, "dhcp6.name-servers");
		add_also_request (alsoreq, "dhcp6.domain-search");
		add_also_request (alsoreq, "dhcp6.client-id");
		add_also_request (alsoreq, "dhcp6.server-id");
	} else {
		add_ip4_config (new_contents, s_ip4, hostname);
		add_also_request (alsoreq, "rfc3442-classless-static-routes");
		add_also_request (alsoreq, "ms-classless-static-routes");
		add_also_request (alsoreq, "static-routes");
		add_also_request (alsoreq, "wpad");
		add_also_request (alsoreq, "ntp-servers");
	}

	/* And add it to the dhclient configuration */
	for (i = 0; i < alsoreq->len; i++) {
		char *t = g_ptr_array_index (alsoreq, i);

		g_string_append_printf (new_contents, "also request %s;\n", t);
		g_free (t);
	}
	g_ptr_array_free (alsoreq, TRUE);

	g_string_append_c (new_contents, '\n');

	if (anycast_addr) {
		g_string_append_printf (new_contents, "interface \"%s\" {\n"
		                        " initial-interval 1; \n"
		                        " anycast-mac ethernet %02x:%02x:%02x:%02x:%02x:%02x;\n"
		                        "}\n",
		                        interface,
		                        anycast_addr[0], anycast_addr[1],
		                        anycast_addr[2], anycast_addr[3],
		                        anycast_addr[4], anycast_addr[5]);
	}

	return g_string_free (new_contents, FALSE);
}

/* Roughly follow what dhclient's quotify_buf() and pretty_escape() functions do */
char *
nm_dhcp_dhclient_escape_duid (const GByteArray *duid)
{
	char *escaped;
	const guint8 *s = duid->data;
	char *d;

	d = escaped = g_malloc0 ((duid->len * 4) + 1);
	while (s < (duid->data + duid->len)) {
		if (!g_ascii_isprint (*s)) {
			*d++ = '\\';
			*d++ = '0' + ((*s >> 6) & 0x7);
			*d++ = '0' + ((*s >> 3) & 0x7);
			*d++ = '0' + (*s++ & 0x7);
		} else if (*s == '"' || *s == '\'' || *s == '$' ||
		           *s == '`' || *s == '\\' || *s == '|' ||
		           *s == '&') {
			*d++ = '\\';
			*d++ = *s++;
		} else
			*d++ = *s++;
	}
	return escaped;
}

static inline gboolean
isoctal (const guint8 *p)
{
	return (   p[0] >= '0' && p[0] <= '3'
	        && p[1] >= '0' && p[1] <= '7'
	        && p[2] >= '0' && p[2] <= '7');
}

GByteArray *
nm_dhcp_dhclient_unescape_duid (const char *duid)
{
	GByteArray *unescaped;
	const guint8 *p = (const guint8 *) duid;
	guint i, len;
	guint8 octal;

	len = strlen (duid);
	unescaped = g_byte_array_sized_new (len);
	for (i = 0; i < len; i++) {
		if (p[i] == '\\') {
			i++;
			if (isdigit (p[i])) {
				/* Octal escape sequence */
				if (i + 2 >= len || !isoctal (p + i))
					goto error;
				octal = ((p[i] - '0') << 6) + ((p[i + 1] - '0') << 3) + (p[i + 2] - '0');
				g_byte_array_append (unescaped, &octal, 1);
				i += 2;
			} else {
				/* One of ", ', $, `, \, |, or & */
				g_warn_if_fail (p[i] == '"' || p[i] == '\'' || p[i] == '$' ||
				                p[i] == '`' || p[i] == '\\' || p[i] == '|' ||
				                p[i] == '&');
				g_byte_array_append (unescaped, &p[i], 1);
			}
		} else
			g_byte_array_append (unescaped, &p[i], 1);
	}

	return unescaped;

error:
	g_byte_array_free (unescaped, TRUE);
	return NULL;
}

#define DUID_PREFIX "default-duid \""

GByteArray *
nm_dhcp_dhclient_read_duid (const char *leasefile, GError **error)
{
	GByteArray *duid = NULL;
	char *contents;
	char **line, **split, *p, *e;

	if (!g_file_test (leasefile, G_FILE_TEST_EXISTS))
		return NULL;

	if (!g_file_get_contents (leasefile, &contents, NULL, error))
		return NULL;

	split = g_strsplit_set (contents, "\n\r", -1);
	for (line = split; line && *line && (duid == NULL); line++) {
		p = g_strstrip (*line);
		if (g_str_has_prefix (p, DUID_PREFIX)) {
			p += strlen (DUID_PREFIX);

			/* look for trailing "; */
			e = p + strlen (p) - 2;
			if (strcmp (e, "\";") != 0)
				continue;
			*e = '\0';

			duid = nm_dhcp_dhclient_unescape_duid (p);
		}
	}
	g_free (contents);
	g_strfreev (split);

	return duid;
}

gboolean
nm_dhcp_dhclient_save_duid (const char *leasefile,
                            const char *escaped_duid,
                            GError **error)
{
	char **lines = NULL, **iter, *l;
	GString *s;
	gboolean success;
	gsize len = 0;

	g_return_val_if_fail (leasefile != NULL, FALSE);
	g_return_val_if_fail (escaped_duid != NULL, FALSE);

	if (g_file_test (leasefile, G_FILE_TEST_EXISTS)) {
		char *contents = NULL;

		if (!g_file_get_contents (leasefile, &contents, &len, error)) {
			g_prefix_error (error, "failed to read lease file %s: ", leasefile);
			return FALSE;
		}

		/* If the file already contains an uncommented DUID, leave it */
		g_assert (contents);
		lines = g_strsplit_set (contents, "\n\r", -1);
		g_free (contents);
		for (iter = lines; iter && *iter; iter++) {
			l = *iter;
			while (g_ascii_isspace (*l))
				l++;
			if (g_str_has_prefix (l, DUID_PREFIX)) {
				g_strfreev (lines);
				return TRUE;
			}
		}
	}

	s = g_string_sized_new (len + 50);
	g_string_append_printf (s, DUID_PREFIX "%s\";\n", escaped_duid);

	/* Preserve existing leasefile contents */
	if (lines) {
		for (iter = lines; iter && *iter; iter++)
			g_string_append (s, *iter[0] ? *iter : "\n");
		g_strfreev (lines);
	}

	success = g_file_set_contents (leasefile, s->str, -1, error);
	if (!success)
		g_prefix_error (error, "failed to set DUID in lease file %s: ", leasefile);

	g_string_free (s, TRUE);
	return success;
}

