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

#include "nm-default.h"

#include "nm-dhcp-dhclient-utils.h"

#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "nm-utils/nm-dedup-multi.h"

#include "nm-dhcp-utils.h"
#include "nm-ip4-config.h"
#include "nm-utils.h"
#include "platform/nm-platform.h"
#include "NetworkManagerUtils.h"

#define TIMEOUT_TAG      "timeout "
#define RETRY_TAG        "retry "
#define CLIENTID_TAG     "send dhcp-client-identifier"

#define HOSTNAME4_TAG    "send host-name"
#define HOSTNAME4_FORMAT HOSTNAME4_TAG " \"%s\"; # added by NetworkManager"

#define FQDN_TAG_PREFIX  "send fqdn."
#define FQDN_TAG         FQDN_TAG_PREFIX "fqdn"
#define FQDN_FORMAT      FQDN_TAG " \"%s\"; # added by NetworkManager"

#define ALSOREQ_TAG "also request "
#define REQ_TAG "request "

static void
add_request (GPtrArray *array, const char *item)
{
	int i;

	for (i = 0; i < array->len; i++) {
		if (!strcmp (g_ptr_array_index (array, i), item))
			return;
	}
	g_ptr_array_add (array, g_strdup (item));
}

static gboolean
grab_request_options (GPtrArray *store, const char* line)
{
	char **areq, **aiter;
	gboolean end = FALSE;

	/* Grab each 'request' or 'also request'  option and save for later */
	areq = g_strsplit_set (line, "\t ,", -1);
	for (aiter = areq; aiter && *aiter; aiter++) {
		if (!strlen (g_strstrip (*aiter)))
			continue;

		if (*aiter[0] == ';') {
			/* all done */
			end = TRUE;
			break;
		}

		if (!g_ascii_isalnum ((*aiter)[0]))
			continue;

		if ((*aiter)[strlen (*aiter) - 1] == ';') {
			/* Remove the EOL marker */
			(*aiter)[strlen (*aiter) - 1] = '\0';
			end = TRUE;
		}

		add_request (store, *aiter);
	}

	if (areq)
		g_strfreev (areq);

	return end;
}

static void
add_hostname4 (GString *str, const char *hostname, gboolean use_fqdn)
{
	if (hostname) {
		if (use_fqdn) {
			g_string_append_printf (str, FQDN_FORMAT "\n", hostname);
			g_string_append (str,
			                 "send fqdn.encoded on;\n"
			                 "send fqdn.server-update on;\n");
		} else
			g_string_append_printf (str, HOSTNAME4_FORMAT "\n", hostname);
	}
}

static void
add_ip4_config (GString *str, GBytes *client_id, const char *hostname, gboolean use_fqdn)
{
	if (client_id) {
		const char *p;
		gsize l;
		guint i;

		p = g_bytes_get_data (client_id, &l);
		g_assert (p);

		/* Allow type 0 (non-hardware address) to be represented as a string
		 * as long as all the characters are printable.
		 */
		for (i = 1; (p[0] == 0) && i < l; i++) {
			if (!g_ascii_isprint (p[i]) || p[i] == '\\' || p[i] == '"')
				break;
		}

		g_string_append (str, CLIENTID_TAG " ");
		if (i < l) {
			/* Unprintable; convert to a hex string */
			for (i = 0; i < l; i++) {
				if (i > 0)
					g_string_append_c (str, ':');
				g_string_append_printf (str, "%02x", (guint8) p[i]);
			}
		} else {
			/* Printable; just add to the line with type 0 */
			g_string_append_c (str, '"');
			g_string_append (str, "\\x00");
			g_string_append_len (str, p + 1, l - 1);
			g_string_append_c (str, '"');
		}
		g_string_append (str, "; # added by NetworkManager\n");
	}

	add_hostname4 (str, hostname, use_fqdn);

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
add_hostname6 (GString *str, const char *hostname)
{
	if (hostname) {
		g_string_append_printf (str, FQDN_FORMAT "\n", hostname);
		g_string_append (str,
		                 "send fqdn.server-update on;\n");
		g_string_append_c (str, '\n');
	}
}

static GBytes *
read_client_id (const char *str)
{
	gs_free char *s = NULL;
	char *p;
	int i = 0, j = 0;

	nm_assert (!strncmp (str, CLIENTID_TAG, NM_STRLEN (CLIENTID_TAG)));
	str += NM_STRLEN (CLIENTID_TAG);

	if (!g_ascii_isspace (*str))
		return NULL;
	while (g_ascii_isspace (*str))
		str++;

	if (*str == '"') {
		/* Parse string literal with escape sequences */
		s = g_strdup (str + 1);
		p = strrchr (s, '"');
		if (p)
			*p = '\0';
		else
			return NULL;

		if (!s[0])
			return NULL;

		while (s[i]) {
			if (   s[i] == '\\'
			    && s[i + 1] == 'x'
			    && g_ascii_isxdigit (s[i + 2])
			    && g_ascii_isxdigit (s[i + 3])) {
				s[j++] =  (g_ascii_xdigit_value (s[i + 2]) << 4)
				         + g_ascii_xdigit_value (s[i + 3]);
				i += 4;
				continue;
			}
			if (   s[i] == '\\'
			    && s[i + 1] >= '0' && s[i + 1] <= '7'
			    && s[1 + 2] >= '0' && s[i + 2] <= '7'
			    && s[1 + 3] >= '0' && s[i + 3] <= '7') {
				s[j++] =    ((s[i + 1] - '0') << 6)
				          + ((s[i + 2] - '0') << 3)
				          + ( s[i + 3] - '0');
				i += 4;
				continue;
			}
			s[j++] = s[i++];
		}
		return g_bytes_new_take (g_steal_pointer (&s), j);
	}

	/* Otherwise, try to read a hexadecimal sequence */
	s = g_strdup (str);
	g_strchomp (s);
	if (s[strlen (s) - 1] == ';')
		s[strlen (s) - 1] = '\0';

	return nm_utils_hexstr2bin (s);
}

GBytes *
nm_dhcp_dhclient_get_client_id_from_config_file (const char *path)
{
	gs_free char *contents = NULL;
	gs_strfreev char **lines = NULL;
	char **line;

	g_return_val_if_fail (path != NULL, NULL);

	if (!g_file_test (path, G_FILE_TEST_EXISTS))
		return NULL;

	if (!g_file_get_contents (path, &contents, NULL, NULL))
		return NULL;

	lines = g_strsplit_set (contents, "\n\r", 0);
	for (line = lines; lines && *line; line++) {
		if (!strncmp (*line, CLIENTID_TAG, NM_STRLEN (CLIENTID_TAG)))
			return read_client_id (*line);
	}
	return NULL;
}

static gboolean
read_interface (const char *line, char *interface, guint size)
{
	gs_free char *dup = g_strdup (line + NM_STRLEN ("interface"));
	char *ptr = dup, *end;

	while (g_ascii_isspace (*ptr))
		ptr++;

	if (*ptr == '"') {
		ptr++;
		end = strchr (ptr, '"');
		if (!end)
			return FALSE;
		*end = '\0';
	} else {
		end = strchr (ptr, ' ');
		if (!end)
			end = strchr (ptr, '{');
		if (!end)
			return FALSE;
		*end = '\0';
	}

	if (   ptr[0] == '\0'
	    || strlen (ptr) + 1 > size)
		return FALSE;

	snprintf (interface, size, "%s", ptr);

	return TRUE;
}

char *
nm_dhcp_dhclient_create_config (const char *interface,
                                int addr_family,
                                GBytes *client_id,
                                const char *anycast_addr,
                                const char *hostname,
                                guint32 timeout,
                                gboolean use_fqdn,
                                const char *orig_path,
                                const char *orig_contents,
                                GBytes **out_new_client_id)
{
	GString *new_contents;
	GPtrArray *fqdn_opts, *reqs;
	gboolean reset_reqlist = FALSE;
	int i;

	g_return_val_if_fail (!anycast_addr || nm_utils_hwaddr_valid (anycast_addr, ETH_ALEN), NULL);
	g_return_val_if_fail (NM_IN_SET (addr_family, AF_INET, AF_INET6), NULL);
	nm_assert (!out_new_client_id || !*out_new_client_id);

	new_contents = g_string_new (_("# Created by NetworkManager\n"));
	fqdn_opts = g_ptr_array_sized_new (5);
	reqs = g_ptr_array_new_full (5, g_free);

	if (orig_contents) {
		char **lines, **line;
		gboolean in_alsoreq = FALSE;
		gboolean in_req = FALSE;
		char intf[IFNAMSIZ];

		g_string_append_printf (new_contents, _("# Merged from %s\n\n"), orig_path);
		intf[0] = '\0';

		lines = g_strsplit_set (orig_contents, "\n\r", 0);
		for (line = lines; lines && *line; line++) {
			char *p = *line;

			if (!strlen (g_strstrip (p)))
				continue;

			if (   !intf[0]
			    && g_str_has_prefix (p, "interface")
			    && !in_req) {
				if (read_interface (p, intf, sizeof (intf)))
					continue;
			}

			if (intf[0] && strchr (p, '}')) {
				intf[0] = '\0';
				continue;
			}

			if (intf[0] && !nm_streq (intf, interface))
				continue;

			/* Some timing parameters in dhclient should not be imported (timeout, retry).
			 * The retry parameter will be simply not used as we will exit on first failure.
			 * The timeout one instead may affect NetworkManager behavior: if the timeout
			 * elapses before dhcp-timeout dhclient will report failure and cause NM to
			 * fail the dhcp process before dhcp-timeout. So, always skip importing timeout
			 * as we will need to add one greater than dhcp-timeout.
			 */
			if (   !strncmp (p, TIMEOUT_TAG, strlen (TIMEOUT_TAG))
			    || !strncmp (p, RETRY_TAG, strlen (RETRY_TAG)))
				continue;

			if (!strncmp (p, CLIENTID_TAG, strlen (CLIENTID_TAG))) {
				/* Override config file "dhcp-client-id" and use one from the connection */
				if (client_id)
					continue;

				/* Otherwise capture and return the existing client id */
				if (out_new_client_id)
					g_clear_pointer (out_new_client_id, g_bytes_unref);
				NM_SET_OUT (out_new_client_id, read_client_id (p));
			}

			/* Override config file hostname and use one from the connection */
			if (hostname) {
				if (strncmp (p, HOSTNAME4_TAG, strlen (HOSTNAME4_TAG)) == 0)
					continue;
				if (strncmp (p, FQDN_TAG, strlen (FQDN_TAG)) == 0)
					continue;
			}

			/* To let user's FQDN options (except "fqdn.fqdn") override the
			 * default ones set by NM, add them later
			 */
			if (!strncmp (p, FQDN_TAG_PREFIX, NM_STRLEN (FQDN_TAG_PREFIX))) {
				g_ptr_array_add (fqdn_opts, g_strdup (p + NM_STRLEN (FQDN_TAG_PREFIX)));
				continue;
			}

			/* Ignore 'script' since we pass our own */
			if (g_str_has_prefix (p, "script "))
				continue;

			/* Check for "request" */
			if (!strncmp (p, REQ_TAG, strlen (REQ_TAG))) {
				in_req = TRUE;
				p += strlen (REQ_TAG);
				g_ptr_array_set_size (reqs, 0);
				reset_reqlist = TRUE;
			}

			/* Save all request options for later use */
			if (in_req) {
				in_req = !grab_request_options (reqs, p);
				continue;
			}

			/* Check for "also require" */
			if (!strncmp (p, ALSOREQ_TAG, strlen (ALSOREQ_TAG))) {
				in_alsoreq = TRUE;
				p += strlen (ALSOREQ_TAG);
			}

			if (in_alsoreq) {
				in_alsoreq = !grab_request_options (reqs, p);
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

	/* ensure dhclient timeout is greater than dhcp-timeout: as dhclient timeout default value is
	 * 60 seconds, we need this only if dhcp-timeout is greater than 60.
	 */
	if (timeout >= 60) {
		timeout = timeout < G_MAXINT32 ? timeout + 1 : G_MAXINT32;
		g_string_append_printf (new_contents, "timeout %u;\n", timeout);
	}

	if (addr_family == AF_INET) {
		add_ip4_config (new_contents, client_id, hostname, use_fqdn);
		add_request (reqs, "rfc3442-classless-static-routes");
		add_request (reqs, "ms-classless-static-routes");
		add_request (reqs, "static-routes");
		add_request (reqs, "wpad");
		add_request (reqs, "ntp-servers");
	} else {
		add_hostname6 (new_contents, hostname);
		add_request (reqs, "dhcp6.name-servers");
		add_request (reqs, "dhcp6.domain-search");
		add_request (reqs, "dhcp6.client-id");
	}

	if (reset_reqlist)
		g_string_append (new_contents, "request; # override dhclient defaults\n");
	/* And add it to the dhclient configuration */
	for (i = 0; i < reqs->len; i++)
		g_string_append_printf (new_contents, "also request %s;\n", (char *) reqs->pdata[i]);
	g_ptr_array_free (reqs, TRUE);

	for (i = 0; i < fqdn_opts->len; i++) {
		char *t = g_ptr_array_index (fqdn_opts, i);

		if (i == 0)
			g_string_append_printf (new_contents, "\n# FQDN options from %s\n", orig_path);
		g_string_append_printf (new_contents, FQDN_TAG_PREFIX "%s\n", t);
		g_free (t);
	}
	g_ptr_array_free (fqdn_opts, TRUE);

	g_string_append_c (new_contents, '\n');

	if (anycast_addr) {
		g_string_append_printf (new_contents, "interface \"%s\" {\n"
		                        " initial-interval 1; \n"
		                        " anycast-mac ethernet %s;\n"
		                        "}\n",
		                        interface, anycast_addr);
	}

	return g_string_free (new_contents, FALSE);
}

/* Roughly follow what dhclient's quotify_buf() and pretty_escape() functions do */
char *
nm_dhcp_dhclient_escape_duid (GBytes *duid)
{
	char *escaped;
	const guint8 *s, *s0;
	gsize len;
	char *d;

	g_return_val_if_fail (duid, NULL);

	s0 = g_bytes_get_data (duid, &len);
	s = s0;

	d = escaped = g_malloc ((len * 4) + 1);
	while (s < (s0 + len)) {
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
	*d++ = '\0';
	return escaped;
}

static inline gboolean
isoctal (const guint8 *p)
{
	return (   p[0] >= '0' && p[0] <= '3'
	        && p[1] >= '0' && p[1] <= '7'
	        && p[2] >= '0' && p[2] <= '7');
}

GBytes *
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

	return g_byte_array_free_to_bytes (unescaped);

error:
	g_byte_array_free (unescaped, TRUE);
	return NULL;
}

#define DUID_PREFIX "default-duid \""

GBytes *
nm_dhcp_dhclient_read_duid (const char *leasefile, GError **error)
{
	GBytes *duid = NULL;
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
	gs_strfreev char **lines = NULL;
	char **iter, *l;
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

		g_assert (contents);
		lines = g_strsplit_set (contents, "\n\r", -1);
		g_free (contents);
	}

	s = g_string_sized_new (len + 50);
	g_string_append_printf (s, DUID_PREFIX "%s\";\n", escaped_duid);

	/* Preserve existing leasefile contents */
	if (lines) {
		for (iter = lines; iter && *iter; iter++) {
			l = *iter;
			while (g_ascii_isspace (*l))
				l++;
			/* If we find an uncommented DUID in the file, check if
			 * equal to the one we are going to write: if so, no need
			 * to update the lease file, otherwise skip the old DUID.
			 */
			if (g_str_has_prefix (l, DUID_PREFIX)) {
				gs_strfreev char **split = NULL;

				split = g_strsplit (l, "\"", -1);
				if (nm_streq0 (split[1], escaped_duid)) {
					g_string_free (s, TRUE);
					return TRUE;
				}
				continue;
			}

			if (*iter[0])
				g_string_append (s, *iter);
			/* avoid to add an extra '\n' at the end of file */
			if ((iter[1]) != NULL)
				g_string_append_c (s, '\n');
		}
	}

	success = g_file_set_contents (leasefile, s->str, -1, error);
	if (!success)
		g_prefix_error (error, "failed to set DUID in lease file %s: ", leasefile);

	g_string_free (s, TRUE);
	return success;
}
