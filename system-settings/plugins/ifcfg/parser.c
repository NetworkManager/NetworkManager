/* NetworkManager system settings service
 *
 * Søren Sandmann <sandmann@daimi.au.dk>
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
 * (C) Copyright 2007 Red Hat, Inc.
 */

#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <glib.h>

#include <nm-connection.h>
#include <NetworkManager.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-wired.h>

#include "shvar.h"
#include "parser.h"
#include "plugin.h"

char *
parser_get_current_profile_name (void)
{
	shvarFile *	file;
	char *		buf;

	if (!(file = svNewFile (SYSCONFDIR"/sysconfig/network")))
		return NULL;

	buf = svGetValue (file, "CURRENT_PROFILE");
	if (!buf)
		buf = strdup ("default");
	svCloseFile (file);

	return buf;
}

static gboolean
get_int (const char *str, int *value)
{
	char *e;

	*value = strtol (str, &e, 0);
	if (*e != '\0')
		return FALSE;

	return TRUE;
}

static NMSetting *
make_connection_setting (const char *file, shvarFile *ifcfg, const char *type)
{
	NMSettingConnection *s_con;
	char *basename = NULL;
	int len;

	basename = g_path_get_basename (file);
	if (!basename)
		goto error;
	len = strlen (basename);

	if (len < strlen (IFCFG_TAG) + 1)
		goto error;

	if (strncmp (basename, IFCFG_TAG, strlen (IFCFG_TAG)))
		goto error;

	/* ignore .bak files */
	if ((len > 4) && !strcmp (basename + len - 4, BAK_TAG))
		goto error;

	s_con = NM_SETTING_CONNECTION (nm_setting_connection_new ());

	s_con->id = g_strdup_printf ("System %s", basename + strlen (IFCFG_TAG));
	s_con->type = g_strdup (type);
	s_con->autoconnect = TRUE;

	return (NMSetting *) s_con;

error:
	g_free (basename);
	return NULL;
}

#define SEARCH_TAG "search "
#define NS_TAG "nameserver "

static void
read_profile_resolv_conf (NMSettingIP4Config *s_ip4)
{
	char *file;
	char *profile;
	char *contents = NULL;
	char **lines = NULL;
	char **line;

	profile = parser_get_current_profile_name ();
	if (!profile)
		return;

	file = g_strdup_printf ("/etc/sysconfig/networking/profiles/%s/resolv.conf", profile);
	g_free (profile);
	if (!file)
		return;

	if (!g_file_get_contents (file, &contents, NULL, NULL))
		goto out;

	lines = g_strsplit (contents, "\n", 0);
	if (!lines || !*lines)
		goto out;

	s_ip4->dns = g_array_new (FALSE, FALSE, sizeof (guint32));

	for (line = lines; *line; line++) {
		if (!strncmp (*line, SEARCH_TAG, strlen (SEARCH_TAG))) {
			char **searches;

			if (s_ip4->dns_search)
				continue;

			searches = g_strsplit (*line + strlen (SEARCH_TAG), " ", 0);
			if (searches) {
				char **item;
				for (item = searches; *item; item++)
					s_ip4->dns_search = g_slist_append (s_ip4->dns_search, *item);
				g_free (searches);
			}
		} else if (!strncmp (*line, NS_TAG, strlen (NS_TAG))) {
			char *pdns = g_strdup (*line + strlen (NS_TAG));
			struct in_addr dns;

			pdns = g_strstrip (pdns);
			if (inet_pton (AF_INET, pdns, &dns)) {
				g_array_append_val (s_ip4->dns, dns.s_addr);
			} else
				g_warning ("Invalid IP4 DNS server address '%s'", pdns);
			g_free (pdns);
		}
	}

out:
	if (lines)
		g_strfreev (lines);
	g_free (file);
}

static NMSetting *
make_ip4_setting (shvarFile *ifcfg)
{
	NMSettingIP4Config *s_ip4;
	char *value;
	NMSettingIP4Address tmp = { 0, 0, 0 };
	char *ip4 = NULL, *gw = NULL, *mask = NULL;
	gboolean manual = TRUE;

	value = svGetValue (ifcfg, "BOOTPROTO");
	if (!value)
		return NULL;

	if (!strcmp (value, "bootp") || !strcmp (value, "dhcp")) {
		manual = FALSE;
		return NULL;
	}

	ip4 = svGetValue (ifcfg, "IPADDR");
	if (ip4) {
		struct in_addr ip4_addr;
		if (inet_pton (AF_INET, ip4, &ip4_addr))
			tmp.address = ip4_addr.s_addr;
		else
			g_warning ("Invalid IP4 address '%s'", ip4);
		g_free (ip4);
	}

	gw = svGetValue (ifcfg, "GATEWAY");
	if (gw) {
		struct in_addr gw_addr;
		if (inet_pton (AF_INET, gw, &gw_addr))
			tmp.gateway = gw_addr.s_addr;
		else
			g_warning ("Invalid IP4 gateway '%s'", gw);
		g_free (gw);
	}

	mask = svGetValue (ifcfg, "NETMASK");
	if (mask) {
		struct in_addr mask_addr;
		if (inet_pton (AF_INET, mask, &mask_addr))
			tmp.netmask = mask_addr.s_addr;
		else
			g_warning ("Invalid IP4 netmask '%s'", mask);
		g_free (mask);
	}

	s_ip4 = (NMSettingIP4Config *) nm_setting_ip4_config_new ();
	s_ip4->manual = manual;
	if (tmp.address || tmp.netmask || tmp.gateway) {
		NMSettingIP4Address *addr;
		addr = g_new0 (NMSettingIP4Address, 1);
		memcpy (addr, &tmp, sizeof (NMSettingIP4Address));
		s_ip4->addresses = g_slist_append (s_ip4->addresses, addr);
	}

	read_profile_resolv_conf (s_ip4);

	return (NMSetting *) s_ip4;
}


static NMSetting *
make_wired_setting (shvarFile *ifcfg)
{
	NMSettingWired *s_wired;
	char *value;
	int mtu;

	s_wired = (NMSettingWired *) nm_setting_wired_new ();

	value = svGetValue (ifcfg, "MTU");
	if (value) {
		if (get_int (value, &mtu)) {
			if (mtu >= 0 && mtu < 65536)
				s_wired->mtu = mtu;
		} else {
			g_warning ("Invalid MTU '%s'", value);
		}
		g_free (value);
	}

	return (NMSetting *) s_wired;
}

static NMConnection *
wired_connection_from_ifcfg (const char *file, shvarFile *ifcfg)
{
	NMConnection *connection = NULL;
	NMSetting *con_setting = NULL;
	NMSetting *wired_setting = NULL;

	g_return_val_if_fail (file != NULL, NULL);
	g_return_val_if_fail (ifcfg != NULL, NULL);

	connection = nm_connection_new ();
	if (!connection) {
		g_warning ("Failed to allocate new connection for %s.", file);
		return NULL;
	}

	con_setting = make_connection_setting (file, ifcfg, NM_SETTING_WIRED_SETTING_NAME);
	if (!con_setting) {
		g_warning ("Failed to create connection setting.");
		goto error;
	}
	nm_connection_add_setting (connection, con_setting);

	wired_setting = make_wired_setting (ifcfg);
	if (!wired_setting) {
		g_warning ("Failed to create wired setting.");
		goto error;
	}
	nm_connection_add_setting (connection, wired_setting);

	if (!nm_connection_verify (connection)) {
		g_warning ("Connection from %s was invalid.", file);
		goto error;
	}

	return connection;

error:
	g_object_unref (connection);
	if (con_setting)
		g_object_unref (con_setting);
	if (wired_setting)
		g_object_unref (wired_setting);
	return NULL;
}
	
NMConnection *
parser_parse_file (const char *file,
                   char **err)
{
	NMConnection *connection = NULL;
	shvarFile *parsed;
	char *type;
	char *nmc = NULL;

	g_return_val_if_fail (file != NULL, NULL);

	parsed = svNewFile(file);
	if (!parsed) {
		*err = g_strdup_printf ("Couldn't parse file '%s'", file);
		return NULL;
	}

	type = svGetValue (parsed, "TYPE");
	if (!type) {
		*err = g_strdup_printf ("File '%s' didn't have a TYPE key.", file);
		goto done;
	}

	nmc = svGetValue (parsed, "NM_CONTROLLED");
	if (nmc) {
		char *lower;

		lower = g_ascii_strdown (nmc, -1);
		g_free (nmc);

		if (!strcmp (lower, "no") || !strcmp (lower, "n") || !strcmp (lower, "false")) {
			g_free (lower);
			g_message ("Ignoring connection '%s' because NM_CONTROLLED was false", file);
			goto done;
		}
		g_free (lower);
	}

	if (!strcmp (type, "Ethernet")) {
		connection = wired_connection_from_ifcfg (file, parsed);
	} else if (!strcmp (type, "Wireless")) {
//		connection = wireless_connection_from_ifcfg (file, parsed);
	}
	g_free (type);

	if (connection) {
		NMSetting *s_ip4;

		s_ip4 = make_ip4_setting (parsed);
		if (s_ip4)
			nm_connection_add_setting (connection, s_ip4);
	}

done:
	svCloseFile (parsed);
	return connection;
}

