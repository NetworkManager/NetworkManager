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

