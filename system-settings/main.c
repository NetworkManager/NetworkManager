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

#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>

#include <nm-connection.h>
#include <nm-settings.h>
#include <NetworkManager.h>
#include <nm-setting-connection.h>
#include <nm-setting-ip4-config.h>
#include <nm-setting-wired.h>

#include "dbus-settings.h"
#include "shvar.h"

#define SYSCONFDIR "/etc"
#define PROFILE_DIR SYSCONFDIR "/sysconfig/networking/profiles/"

typedef struct Application
{
	DBusConnection *connection;
	DBusGConnection *g_connection;
	DBusGProxy *bus_proxy;
	gboolean started;

	NMSysconfigSettings *settings;
	char *profile_path;
	GMainLoop *loop;
} Application;


static gboolean dbus_init (Application *app);
static void dbus_cleanup (Application *app);
static gboolean start_dbus_service (Application *app);
static void destroy_cb (DBusGProxy *proxy, gpointer user_data);

static gboolean
get_int (const char *str, int *value)
{
	char *e;

	*value = strtol (str, &e, 0);
	if (*e != '\0')
		return FALSE;

	return TRUE;
}

#define IFCFG_TAG "ifcfg-"
#define BAK_TAG ".bak"

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

static char *
get_current_profile_name (void)
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

	profile = get_current_profile_name ();
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
	
static NMSysconfigConnectionSettings *
parse_file (Application *app,
            const char *file,
            char **err)
{
	NMSysconfigConnectionSettings *sys_connection = NULL;
	NMConnection *connection = NULL;
	shvarFile *parsed;
	char *type;
	char *nmc = NULL;

	g_return_val_if_fail (app != NULL, NULL);
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

nm_connection_dump (connection);
		sys_connection = nm_sysconfig_connection_settings_new (connection, app->g_connection);
	}

done:
	svCloseFile (parsed);
	return sys_connection;
}

static gboolean
parse_files (gpointer data)
{
	Application *app = data;
	gboolean added = FALSE;
	GDir *dir;
	const char *item;

	dir = g_dir_open (app->profile_path, 0, NULL);
	if (!dir) {
		g_warning ("Couldn't access network profile directory '%s'.", app->profile_path);
		goto out;
	}

	while ((item = g_dir_read_name (dir))) {
		NMSysconfigConnectionSettings *connection;
		char *err = NULL;
		char *filename;

		if (strncmp (item, IFCFG_TAG, strlen (IFCFG_TAG)))
			continue;

		filename = g_build_filename (app->profile_path, item, NULL);
		if (!filename)
			continue;

		g_print ("Parsing %s ... \n", filename);

		if ((connection = parse_file (app, filename, &err))) {
			NMSettingConnection *s_con;

			s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection->connection, NM_TYPE_SETTING_CONNECTION));
			g_assert (s_con);
			g_assert (s_con->id);

			g_print ("    adding connection '%s'\n", s_con->id);
			nm_sysconfig_settings_add_connection (app->settings, connection);
			added = TRUE;
		} else {
			g_print ("   error: %s\n", err ? err : "(unknown)");
		}

		g_free (filename);
	}
	g_dir_close (dir);

out:
	if (!added) {
		g_print ("Warning: No useable configurations found\n");
		g_main_loop_quit (app->loop);
	}

	return FALSE;
}

/* ------------------------------------------------------------------------- */

static gboolean
dbus_reconnect (gpointer user_data)
{
	Application *app = (Application *) user_data;

	if (dbus_init (app)) {
		if (start_dbus_service (app)) {
			g_message ("reconnected to the system bus.");
			return TRUE;
		}
	}

	dbus_cleanup (app);
	return FALSE;
}

static void
dbus_cleanup (Application *app)
{
	if (app->g_connection) {
		dbus_g_connection_unref (app->g_connection);
		app->g_connection = NULL;
		app->connection = NULL;
	}

	if (app->bus_proxy) {
		g_signal_handlers_disconnect_by_func (app->bus_proxy, destroy_cb, app);
		g_object_unref (app->bus_proxy);
		app->bus_proxy = NULL;
	}

	app->started = FALSE;
}

static void
destroy_cb (DBusGProxy *proxy, gpointer user_data)
{
	Application *app = (Application *) user_data;

	/* Clean up existing connection */
	g_warning ("disconnected by the system bus.");
	dbus_cleanup (app);

	g_timeout_add (3000, dbus_reconnect, app);
}

static gboolean
start_dbus_service (Application *app)
{
	int request_name_result;
	GError *err = NULL;

	if (app->started) {
		g_warning ("Service has already started.");
		return FALSE;
	}

	if (!dbus_g_proxy_call (app->bus_proxy, "RequestName", &err,
							G_TYPE_STRING, NM_DBUS_SERVICE_SYSTEM_SETTINGS,
							G_TYPE_UINT, DBUS_NAME_FLAG_DO_NOT_QUEUE,
							G_TYPE_INVALID,
							G_TYPE_UINT, &request_name_result,
							G_TYPE_INVALID)) {
		g_warning ("Could not acquire the NetworkManagerSystemSettings service.\n"
		           "  Message: '%s'", err->message);
		g_error_free (err);
		goto out;
	}

	if (request_name_result != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		g_warning ("Could not acquire the NetworkManagerSystemSettings service "
		           "as it is already taken.  Return: %d",
		           request_name_result);
		goto out;
	}

	app->started = TRUE;

out:
	if (!app->started)
		dbus_cleanup (app);

	return app->started;
}

static gboolean
dbus_init (Application *app)
{
	GError *err = NULL;
	
	dbus_connection_set_change_sigpipe (TRUE);

	app->g_connection = dbus_g_bus_get (DBUS_BUS_SYSTEM, &err);
	if (!app->g_connection) {
		g_warning ("Could not get the system bus.  Make sure "
		           "the message bus daemon is running!  Message: %s",
		           err->message);
		g_error_free (err);
		return FALSE;
	}

	app->connection = dbus_g_connection_get_connection (app->g_connection);
	dbus_connection_set_exit_on_disconnect (app->connection, FALSE);

	app->bus_proxy = dbus_g_proxy_new_for_name (app->g_connection,
	                                            "org.freedesktop.DBus",
	                                            "/org/freedesktop/DBus",
	                                            "org.freedesktop.DBus");
	if (!app->bus_proxy) {
		g_warning ("Could not get the DBus object!");
		goto error;
	}

	g_signal_connect (app->bus_proxy, "destroy", G_CALLBACK (destroy_cb), app);
	return TRUE;

error:	
	dbus_cleanup (app);
	return FALSE;
}

int
main (int argc, char **argv)
{
	Application *app = g_new0 (Application, 1);
	char *profile;

	g_type_init ();

	profile = get_current_profile_name ();
	app->profile_path = g_strdup_printf (PROFILE_DIR "%s/", profile);
	if (!app->profile_path) {
		g_warning ("Current network profile directory '%s' not found.", profile);
		g_free (profile);
		return 1;
	}
	g_free (profile);

	app->loop = g_main_loop_new (NULL, FALSE);

	if (!dbus_init (app))
		return -1;

	if (!start_dbus_service (app))
		return -1;

	app->settings = nm_sysconfig_settings_new (app->g_connection);
	g_idle_add (parse_files, app);

	g_main_loop_run (app->loop);

	return 0;
}

