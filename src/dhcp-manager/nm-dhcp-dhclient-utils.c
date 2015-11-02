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

#include "config.h"

#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "nm-default.h"
#include "nm-dhcp-dhclient-utils.h"
#include "nm-dhcp-utils.h"
#include "nm-ip4-config.h"
#include "nm-utils.h"
#include "nm-platform.h"
#include "NetworkManagerUtils.h"
#include "nm-macros-internal.h"

#define CLIENTID_TAG            "send dhcp-client-identifier"

#define HOSTNAME4_TAG    "send host-name"
#define HOSTNAME4_FORMAT HOSTNAME4_TAG " \"%s\"; # added by NetworkManager"

#define FQDN_TAG    "send fqdn.fqdn"
#define FQDN_FORMAT FQDN_TAG " \"%s\"; # added by NetworkManager"

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
add_hostname4 (GString *str, const char *format, const char *hostname)
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
add_ip4_config (GString *str, GBytes *client_id, const char *hostname)
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
			if (!g_ascii_isprint (p[i]))
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
			/* Printable; just add to the line minus the 'type' */
			g_string_append_c (str, '"');
			g_string_append_len (str, p + 1, l - 1);
			g_string_append_c (str, '"');
		}
		g_string_append (str, "; # added by NetworkManager\n");
	}

	add_hostname4 (str, HOSTNAME4_FORMAT "\n", hostname);

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
	/* dhclient only supports the fqdn.fqdn for DHCPv6 and requires a fully-
	 * qualified name for this option, so we must require one here too.
	 */
	if (hostname && strchr (hostname, '.')) {
		g_string_append_printf (str, FQDN_FORMAT "\n", hostname);
		g_string_append (str,
		                 "send fqdn.encoded on;\n"
		                 "send fqdn.server-update on;\n");
		g_string_append_c (str, '\n');
	}
}

static GBytes *
read_client_id (const char *str)
{
	gs_free char *s = NULL;
	char *p;

	g_assert (!strncmp (str, CLIENTID_TAG, STRLEN (CLIENTID_TAG)));

	str += STRLEN (CLIENTID_TAG);
	while (g_ascii_isspace (*str))
		str++;

	if (*str == '"') {
		s = g_strdup (str + 1);
		p = strrchr (s, '"');
		if (p)
			*p = '\0';
		else
			return NULL;
	} else
		s = g_strdup (str);

	g_strchomp (s);
	if (s[strlen (s) - 1] == ';')
		s[strlen (s) - 1] = '\0';

	return nm_dhcp_utils_client_id_string_to_bytes (s);
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
		if (!strncmp (*line, CLIENTID_TAG, STRLEN (CLIENTID_TAG)))
			return read_client_id (*line);
	}
	return NULL;
}

char *
nm_dhcp_dhclient_create_config (const char *interface,
                                gboolean is_ip6,
                                GBytes *client_id,
                                const char *anycast_addr,
                                const char *hostname,
                                const char *orig_path,
                                const char *orig_contents,
                                GBytes **out_new_client_id)
{
	GString *new_contents;
	GPtrArray *alsoreq;
	int i;

	g_return_val_if_fail (!anycast_addr || nm_utils_hwaddr_valid (anycast_addr, ETH_ALEN), NULL);

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

			if (!strncmp (p, CLIENTID_TAG, strlen (CLIENTID_TAG))) {
				/* Override config file "dhcp-client-id" and use one from the connection */
				if (client_id)
					continue;

				/* Otherwise capture and return the existing client id */
				if (out_new_client_id)
					*out_new_client_id = read_client_id (p);
			}

			/* Override config file hostname and use one from the connection */
			if (hostname) {
				if (strncmp (p, HOSTNAME4_TAG, strlen (HOSTNAME4_TAG)) == 0)
					continue;
				if (strncmp (p, FQDN_TAG, strlen (FQDN_TAG)) == 0)
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
		add_hostname6 (new_contents, hostname);
		add_also_request (alsoreq, "dhcp6.name-servers");
		add_also_request (alsoreq, "dhcp6.domain-search");
		add_also_request (alsoreq, "dhcp6.client-id");
	} else {
		add_ip4_config (new_contents, client_id, hostname);
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
		                        " anycast-mac ethernet %s;\n"
		                        "}\n",
		                        interface, anycast_addr);
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

static void
add_lease_option (GHashTable *hash, char *line)
{
	char *spc;
	size_t len;

	/* Find the space after "option" */
	spc = strchr (line, ' ');
	if (!spc)
		return;

	/* Find the option tag's data, which is after the second space */
	if (g_str_has_prefix (line, "option ")) {
		while (g_ascii_isspace (*spc))
			spc++;
		spc = strchr (spc + 1, ' ');
		if (!spc)
			return;
	}

	/* Split the line at the space */
	*spc = '\0';
	spc++;

	/* Kill the ';' at the end of the line, if any */
	len = strlen (spc);
	if (*(spc + len - 1) == ';')
		*(spc + len - 1) = '\0';

	/* Strip leading quote */
	while (g_ascii_isspace (*spc))
		spc++;
	if (*spc == '"')
		spc++;

	/* Strip trailing quote */
	len = strlen (spc);
	if (len > 0 && spc[len - 1] == '"')
		spc[len - 1] = '\0';

	if (spc[0])
		g_hash_table_insert (hash, g_strdup (line), g_strdup (spc));
}

#define LEASE_INVALID    G_MININT64
static GTimeSpan
lease_validity_span (const char *str_expire, GDateTime *now)
{
	GDateTime *expire = NULL;
	struct tm expire_tm;
	GTimeSpan span;

	g_return_val_if_fail (now != NULL, LEASE_INVALID);
	g_return_val_if_fail (str_expire != NULL, LEASE_INVALID);

	/* Skip initial number (day of week?) */
	if (!isdigit (*str_expire++))
		return LEASE_INVALID;
	if (!isspace (*str_expire++))
		return LEASE_INVALID;
	/* Read lease expiration (in UTC) */
	if (!strptime (str_expire, "%t%Y/%m/%d %H:%M:%S", &expire_tm))
		return LEASE_INVALID;

	expire = g_date_time_new_utc (expire_tm.tm_year + 1900,
	                              expire_tm.tm_mon + 1,
	                              expire_tm.tm_mday,
	                              expire_tm.tm_hour,
	                              expire_tm.tm_min,
	                              expire_tm.tm_sec);
	if (!expire)
		return LEASE_INVALID;

	span = g_date_time_difference (expire, now);
	g_date_time_unref (expire);

	/* GDateTime only supports a range of less then 10000 years, so span can
	 * not overflow or be equal to LEASE_INVALID */
	return span;
}

/**
 * nm_dhcp_dhclient_read_lease_ip_configs:
 * @iface: the interface name to match leases with
 * @ifindex: interface index of @iface
 * @contents: the contents of a dhclient leasefile
 * @ipv6: whether to read IPv4 or IPv6 leases
 * @now: the current UTC date/time; pass %NULL to automatically use current
 *  UTC time.  Testcases may need a different value for 'now'
 *
 * Reads dhclient leases from @contents and parses them into either
 * #NMIP4Config or #NMIP6Config objects depending on the value of @ipv6.
 *
 * Returns: a #GSList of #NMIP4Config objects (if @ipv6 is %FALSE) or a list of
 * #NMIP6Config objects (if @ipv6 is %TRUE) containing the lease data.
 */
GSList *
nm_dhcp_dhclient_read_lease_ip_configs (const char *iface,
                                        int ifindex,
                                        const char *contents,
                                        gboolean ipv6,
                                        GDateTime *now)
{
	GSList *parsed = NULL, *iter, *leases = NULL;
	char **line, **split = NULL;
	GHashTable *hash = NULL;
	gint32 now_monotonic_ts;

	g_return_val_if_fail (contents != NULL, NULL);

	split = g_strsplit_set (contents, "\n\r", -1);
	if (!split)
		return NULL;

	for (line = split; line && *line; line++) {
		*line = g_strstrip (*line);

		if (*line[0] == '#') {
			/* Comment */
		} else if (!strcmp (*line, "}")) {
			/* Lease ends */
			parsed = g_slist_append (parsed, hash);
			hash = NULL;
		} else if (!strcmp (*line, "lease {")) {
			/* Beginning of a new lease */
			if (hash) {
				/* Ignore malformed lease that doesn't end before new one starts */
				g_hash_table_destroy (hash);
			}

			hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
		} else if (hash && strlen (*line))
			add_lease_option (hash, *line);
	}
	g_strfreev (split);

	/* Check if the last lease in the file was properly ended */
	if (hash) {
		/* Ignore malformed lease that doesn't end before new one starts */
		g_hash_table_destroy (hash);
		hash = NULL;
	}

	if (now)
		g_date_time_ref (now);
	else
		now = g_date_time_new_now_utc ();
	now_monotonic_ts = nm_utils_get_monotonic_timestamp_s ();

	for (iter = parsed; iter; iter = g_slist_next (iter)) {
		NMIP4Config *ip4;
		NMPlatformIP4Address address;
		const char *value;
		GTimeSpan expiry;
		guint32 tmp, gw = 0;

		hash = iter->data;

		/* Make sure this lease is for the interface we want */
		value = g_hash_table_lookup (hash, "interface");
		if (!value || strcmp (value, iface))
			continue;

		value = g_hash_table_lookup (hash, "expire");
		if (!value)
			continue;
		expiry = lease_validity_span (value, now);
		if (expiry == LEASE_INVALID)
			continue;

		/* scale expiry to seconds (and CLAMP into the range of guint32) */
		expiry = CLAMP (expiry / G_TIME_SPAN_SECOND, 0, NM_PLATFORM_LIFETIME_PERMANENT-1);
		if (expiry <= 0) {
			/* the address is already expired. Don't even add it. */
			continue;
		}

		memset (&address, 0, sizeof (address));

		/* IP4 address */
		value = g_hash_table_lookup (hash, "fixed-address");
		if (!value)
			continue;
		if (!inet_pton (AF_INET, value, &address.address))
			continue;
		address.peer_address = address.address;

		/* Gateway */
		value = g_hash_table_lookup (hash, "option routers");
		if (!value)
			continue;
		if (!inet_pton (AF_INET, value, &gw))
			continue;

		/* Netmask */
		value = g_hash_table_lookup (hash, "option subnet-mask");
		if (value && inet_pton (AF_INET, value, &tmp))
			address.plen = nm_utils_ip4_netmask_to_prefix (tmp);

		/* Get default netmask for the IP according to appropriate class. */
		if (!address.plen)
			address.plen = nm_utils_ip4_get_default_prefix (address.address);

		address.timestamp = now_monotonic_ts;
		address.lifetime = address.preferred = expiry;
		address.source = NM_IP_CONFIG_SOURCE_DHCP;

		ip4 = nm_ip4_config_new (ifindex);
		nm_ip4_config_add_address (ip4, &address);
		nm_ip4_config_set_gateway (ip4, gw);

		value = g_hash_table_lookup (hash, "option domain-name-servers");
		if (value) {
			char **dns, **dns_iter;

			dns = g_strsplit_set (value, ",", -1);
			for (dns_iter = dns; dns_iter && *dns_iter; dns_iter++) {
				if (inet_pton (AF_INET, *dns_iter, &tmp))
					nm_ip4_config_add_nameserver (ip4, tmp);
			}
			if (dns)
				g_strfreev (dns);
		}

		value = g_hash_table_lookup (hash, "option domain-name");
		if (value && value[0])
			nm_ip4_config_add_domain (ip4, value);

		/* FIXME: static routes */

		leases = g_slist_append (leases, ip4);
	}

	g_date_time_unref (now);
	g_slist_free_full (parsed, (GDestroyNotify) g_hash_table_destroy);
	return leases;
}

