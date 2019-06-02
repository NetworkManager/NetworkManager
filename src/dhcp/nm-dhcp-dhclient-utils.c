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

#include <ctype.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "nm-glib-aux/nm-dedup-multi.h"

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
	guint i;

	for (i = 0; i < array->len; i++) {
		if (nm_streq (array->pdata[i], item))
			return;
	}
	g_ptr_array_add (array, g_strdup (item));
}

static gboolean
grab_request_options (GPtrArray *store, const char* line)
{
	gs_free const char **line_v = NULL;
	gsize i;

	/* Grab each 'request' or 'also request'  option and save for later */
	line_v = nm_utils_strsplit_set (line, "\t ,");
	for (i = 0; line_v && line_v[i]; i++) {
		const char *ss = nm_str_skip_leading_spaces (line_v[i]);
		gsize l;
		gboolean end = FALSE;

		if (!ss[0])
			continue;
		if (ss[0] == ';') {
			/* all done */
			return TRUE;
		}

		if (!g_ascii_isalnum (ss[0]))
			continue;

		l = strlen (ss);

		while (   l > 0
		       && g_ascii_isspace (ss[l - 1])) {
			((char *) ss)[l - 1] = '\0';
			l--;
		}
		if (   l > 0
		    && ss[l - 1] == ';') {
			/* Remove the EOL marker */
			((char *) ss)[l - 1] = '\0';
			end = TRUE;
		}

		if (ss[0])
			add_request (store, ss);

		if (end)
			return TRUE;
	}

	return FALSE;
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
	nm_auto_free_gstring GString *new_contents = NULL;
	gs_unref_ptrarray GPtrArray *fqdn_opts = NULL;
	gs_unref_ptrarray GPtrArray *reqs = NULL;
	gboolean reset_reqlist = FALSE;
	int i;

	g_return_val_if_fail (!anycast_addr || nm_utils_hwaddr_valid (anycast_addr, ETH_ALEN), NULL);
	g_return_val_if_fail (NM_IN_SET (addr_family, AF_INET, AF_INET6), NULL);
	nm_assert (!out_new_client_id || !*out_new_client_id);

	new_contents = g_string_new (_("# Created by NetworkManager\n"));
	reqs = g_ptr_array_new_full (5, g_free);

	if (orig_contents) {
		gs_free const char **lines = NULL;
		gsize line_i;
		int nest = 0;
		gboolean in_alsoreq = FALSE;
		gboolean in_req = FALSE;
		char intf[IFNAMSIZ];

		g_string_append_printf (new_contents, _("# Merged from %s\n\n"), orig_path);
		intf[0] = '\0';

		lines = nm_utils_strsplit_set (orig_contents, "\n\r");
		for (line_i = 0; lines && lines[line_i]; line_i++) {
			const char *line = nm_str_skip_leading_spaces (lines[line_i]);
			const char *p;

			if (line[0] == '\0')
				continue;

			g_strchomp ((char *) line);

			p = line;
			if (in_req) {
				/* pass */
			} else if (strchr (p, '{')) {
				nest++;
				if (   !intf[0]
				    && NM_STR_HAS_PREFIX (p, "interface"))
					if (read_interface (p, intf, sizeof (intf)))
						continue;
			} else if (strchr (p, '}')) {
				if (nest)
					nest--;
				intf[0] = '\0';
				continue;
			}

			if (nest && !intf[0])
				continue;

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
				if (!fqdn_opts)
					fqdn_opts = g_ptr_array_new_full (5, g_free);
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
			g_string_append (new_contents, line);
			g_string_append_c (new_contents, '\n');
		}
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
		add_request (reqs, "root-path");
	} else {
		add_hostname6 (new_contents, hostname);
		add_request (reqs, "dhcp6.name-servers");
		add_request (reqs, "dhcp6.domain-search");

		/* FIXME: internal client does not support requesting client-id option. Does this even work? */
		add_request (reqs, "dhcp6.client-id");
	}

	if (reset_reqlist)
		g_string_append (new_contents, "request; # override dhclient defaults\n");
	/* And add it to the dhclient configuration */
	for (i = 0; i < reqs->len; i++)
		g_string_append_printf (new_contents, "also request %s;\n", (char *) reqs->pdata[i]);

	if (fqdn_opts) {
		for (i = 0; i < fqdn_opts->len; i++) {
			const char *t = fqdn_opts->pdata[i];

			if (i == 0)
				g_string_append_printf (new_contents, "\n# FQDN options from %s\n", orig_path);
			g_string_append_printf (new_contents, FQDN_TAG_PREFIX "%s\n", t);
		}
	}

	g_string_append_c (new_contents, '\n');

	if (anycast_addr) {
		g_string_append_printf (new_contents, "interface \"%s\" {\n"
		                        " initial-interval 1; \n"
		                        " anycast-mac ethernet %s;\n"
		                        "}\n",
		                        interface, anycast_addr);
	}

	return g_string_free (g_steal_pointer (&new_contents), FALSE);
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

static gboolean
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

	/* FIXME: it's wrong to have an "unescape-duid" function. dhclient
	 * defines a file format with escaping. So we need a general unescape
	 * function that can handle dhclient syntax. */

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
				/* FIXME: don't warn on untrusted data. Either signal an error, or accept
				 * it silently. */

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

/* Beware: @error may be unset even if the function returns %NULL. */
GBytes *
nm_dhcp_dhclient_read_duid (const char *leasefile, GError **error)
{
	gs_free char *contents = NULL;
	gs_free const char **contents_v = NULL;
	gsize i;

	if (!g_file_test (leasefile, G_FILE_TEST_EXISTS))
		return NULL;

	if (!g_file_get_contents (leasefile, &contents, NULL, error))
		return NULL;

	contents_v = nm_utils_strsplit_set (contents, "\n\r");
	for (i = 0; contents_v && contents_v[i]; i++) {
		const char *p = nm_str_skip_leading_spaces (contents_v[i]);
		GBytes *duid;

		if (!NM_STR_HAS_PREFIX (p, DUID_PREFIX))
			continue;

		p += NM_STRLEN (DUID_PREFIX);

		g_strchomp ((char *) p);

		if (!NM_STR_HAS_SUFFIX (p, "\";"))
			continue;

		((char *) p)[strlen (p) - 2] = '\0';

		duid = nm_dhcp_dhclient_unescape_duid (p);
		if (duid)
			return duid;
	}

	return NULL;
}

gboolean
nm_dhcp_dhclient_save_duid (const char *leasefile,
                            GBytes *duid,
                            GError **error)
{
	gs_free char *escaped_duid = NULL;
	gs_free const char **lines = NULL;
	nm_auto_free_gstring GString *s = NULL;
	const char *const*iter;
	gsize len = 0;

	g_return_val_if_fail (leasefile != NULL, FALSE);
	if (!duid) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN,
		                            "missing duid");
		g_return_val_if_reached (FALSE);
	}

	escaped_duid = nm_dhcp_dhclient_escape_duid (duid);
	nm_assert (escaped_duid);

	if (g_file_test (leasefile, G_FILE_TEST_EXISTS)) {
		gs_free char *contents = NULL;

		if (!g_file_get_contents (leasefile, &contents, &len, error)) {
			g_prefix_error (error, "failed to read lease file %s: ", leasefile);
			return FALSE;
		}

		lines = nm_utils_strsplit_set_with_empty (contents, "\n\r");
	}

	s = g_string_sized_new (len + 50);
	g_string_append_printf (s, DUID_PREFIX "%s\";\n", escaped_duid);

	/* Preserve existing leasefile contents */
	if (lines) {
		for (iter = lines; *iter; iter++) {
			const char *str = *iter;
			const char *l;

			/* If we find an uncommented DUID in the file, check if
			 * equal to the one we are going to write: if so, no need
			 * to update the lease file, otherwise skip the old DUID.
			 */
			l = nm_str_skip_leading_spaces (str);
			if (g_str_has_prefix (l, DUID_PREFIX)) {
				gs_strfreev char **split = NULL;

				split = g_strsplit (l, "\"", -1);
				if (   split[0]
				    && nm_streq0 (split[1], escaped_duid))
					return TRUE;

				continue;
			}

			if (str)
				g_string_append (s, str);
			/* avoid to add an extra '\n' at the end of file */
			if ((iter[1]) != NULL)
				g_string_append_c (s, '\n');
		}
	}

	if (!g_file_set_contents (leasefile, s->str, -1, error)) {
		g_prefix_error (error, "failed to set DUID in lease file %s: ", leasefile);
		return FALSE;
	}

	return TRUE;
}
