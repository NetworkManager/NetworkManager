/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 - 2015 Red Hat, Inc.
 */

/**
 * SECTION:nm-vpn-helpers
 * @short_description: VPN-related utilities
 *
 * Some functions should probably eventually move into libnm.
 */

#include "config.h"

#include <string.h>
#include <glib.h>
#include <gmodule.h>
#include <glib/gi18n-lib.h>

#include <NetworkManager.h>

#include "nm-utils.h"
#include "nm-vpn-helpers.h"


#define VPN_NAME_FILES_DIR NMCONFDIR "/VPN"
#define DEFAULT_DIR_LIB    NMLIBDIR"/VPN"

static gboolean plugins_loaded = FALSE;
static GHashTable *plugins_hash = NULL;
static GSList *plugins_list = NULL;


GQuark nm_vpn_error_quark (void);
G_DEFINE_QUARK (NM_VPN_ERROR, nm_vpn_error)
#define NM_VPN_ERROR nm_vpn_error_quark ()
#define NM_VPN_ERROR_GENERIC 0

NMVpnEditorPlugin *
nm_vpn_get_plugin_by_service (const char *service)
{
	NMVpnEditorPlugin *plugin;
	const char *str;
	char *tmp = NULL;

	g_return_val_if_fail (service != NULL, NULL);

	if (G_UNLIKELY (!plugins_loaded))
		nm_vpn_get_plugins (NULL);

	if (!plugins_hash)
		return NULL;

	if (g_str_has_prefix (service, NM_DBUS_SERVICE))
		str = service;
	else
		str = tmp = g_strdup_printf ("%s.%s", NM_DBUS_SERVICE, service);

	plugin = g_hash_table_lookup (plugins_hash, str);
	g_free (tmp);

	return plugin;
}

GSList *
nm_vpn_get_plugins (GError **error)
{
	GDir *dir;
	const char *f;
	GHashTableIter iter;
	NMVpnEditorPlugin *plugin;

	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	if (G_LIKELY (plugins_loaded))
		return plugins_list;

	plugins_loaded = TRUE;

	dir = g_dir_open (VPN_NAME_FILES_DIR, 0, NULL);
	if (!dir) {
		g_set_error (error, NM_VPN_ERROR, NM_VPN_ERROR_GENERIC, "Couldn't read VPN .name files directory " VPN_NAME_FILES_DIR ".");
		return NULL;
	}

	plugins_hash = g_hash_table_new_full (g_str_hash, g_str_equal,
	                                      (GDestroyNotify) g_free, (GDestroyNotify) g_object_unref);

	while ((f = g_dir_read_name (dir))) {
		char *path = NULL, *service = NULL;
		char *so_path = NULL, *so_name = NULL;
		GKeyFile *keyfile = NULL;
		GModule *module = NULL;
		NMVpnEditorPluginFactory factory = NULL;

		if (!g_str_has_suffix (f, ".name"))
			continue;

		path = g_strdup_printf ("%s/%s", VPN_NAME_FILES_DIR, f);

		keyfile = g_key_file_new ();
		if (!g_key_file_load_from_file (keyfile, path, 0, NULL))
			goto next;

		service = g_key_file_get_string (keyfile, "VPN Connection", "service", NULL);
		if (!service)
			goto next;

		so_path = g_key_file_get_string (keyfile,  "libnm", "plugin", NULL);
		if (!so_path)
			goto next;

		if (g_path_is_absolute (so_path))
			module = g_module_open (so_path, G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);

		if (!module) {
			/* Remove any path and extension components, then reconstruct path
			 * to the SO in LIBDIR
			 */
			so_name = g_path_get_basename (so_path);
			g_free (so_path);
			so_path = g_strdup_printf ("%s/NetworkManager/%s", NMLIBDIR, so_name);
			g_free (so_name);

			module = g_module_open (so_path, G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
			if (!module) {
				g_clear_error (error);
				g_set_error (error, NM_VPN_ERROR, NM_VPN_ERROR_GENERIC, "Cannot load the VPN plugin which provides the "
				             "service '%s'.", service);
				goto next;
			}
		}

		if (g_module_symbol (module, "nm_vpn_editor_plugin_factory", (gpointer) &factory)) {
			GError *factory_error = NULL;
			gboolean success = FALSE;

			plugin = factory (&factory_error);
			if (plugin) {
				char *plug_name = NULL, *plug_service = NULL;

				/* Validate plugin properties */
				g_object_get (G_OBJECT (plugin),
				              NM_VPN_EDITOR_PLUGIN_NAME, &plug_name,
				              NM_VPN_EDITOR_PLUGIN_SERVICE, &plug_service,
				              NULL);
				if (!plug_name || !strlen (plug_name)) {
					g_clear_error (error);
					g_set_error (error, NM_VPN_ERROR, NM_VPN_ERROR_GENERIC, "cannot load VPN plugin in '%s': missing plugin name", 
					             g_module_name (module));
				} else if (!plug_service || strcmp (plug_service, service)) {
					g_clear_error (error);
					g_set_error (error, NM_VPN_ERROR, NM_VPN_ERROR_GENERIC, "cannot load VPN plugin in '%s': invalid service name", 
					             g_module_name (module));
				} else {
					/* Success! */
					g_object_set_data_full (G_OBJECT (plugin), "gmodule", module,
					                        (GDestroyNotify) g_module_close);
					g_hash_table_insert (plugins_hash, g_strdup (service), plugin);
					success = TRUE;
				}
				g_free (plug_name);
				g_free (plug_service);
			} else {
				g_clear_error (error);
				g_set_error (error, NM_VPN_ERROR, NM_VPN_ERROR_GENERIC, "cannot load VPN plugin in '%s': %s", 
				             g_module_name (module), g_module_error ());
			}

			if (!success)
				g_module_close (module);
		} else {
			g_clear_error (error);
			g_set_error (error, NM_VPN_ERROR, NM_VPN_ERROR_GENERIC, "cannot locate nm_vpn_editor_plugin_factory() in '%s': %s", 
			             g_module_name (module), g_module_error ());
			g_module_close (module);
		}

	next:
		g_free (so_path);
		g_free (service);
		g_key_file_free (keyfile);
		g_free (path);
	}
	g_dir_close (dir);

	/* Copy hash to list */
	g_hash_table_iter_init (&iter, plugins_hash);
	while (g_hash_table_iter_next (&iter, NULL, (gpointer *) &plugin))
		plugins_list = g_slist_prepend (plugins_list, plugin);

	return plugins_list;
}

gboolean
nm_vpn_supports_ipv6 (NMConnection *connection)
{
	NMSettingVpn *s_vpn;
	const char *service_type;
	NMVpnEditorPlugin *plugin;
	guint32 capabilities;

	s_vpn = nm_connection_get_setting_vpn (connection);
	g_return_val_if_fail (s_vpn != NULL, FALSE);

	service_type = nm_setting_vpn_get_service_type (s_vpn);
	g_return_val_if_fail (service_type != NULL, FALSE);

	plugin = nm_vpn_get_plugin_by_service (service_type);
	g_return_val_if_fail (plugin != NULL, FALSE);

	capabilities = nm_vpn_editor_plugin_get_capabilities (plugin);
	return (capabilities & NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6) != 0;
}

const VpnPasswordName *
nm_vpn_get_secret_names (const char *vpn_type)
{
	const char *type;
	static VpnPasswordName generic_vpn_secrets[] = { {"password", N_("Password")}, {NULL, NULL} };
	static VpnPasswordName vpnc_secrets[] = { {"Xauth password", N_("Password")},
	                                          {"IPSec secret", N_("Group password")},
	                                          {NULL, NULL} };
	static VpnPasswordName swan_secrets[] = { {"xauthpassword", N_("Password")},
	                                          {"pskvalue", N_("Group password")},
	                                          {NULL, NULL} };
	static VpnPasswordName openconnect_secrets[] = { {"gateway", N_("Gateway")},
	                                                 {"cookie", N_("Cookie")},
	                                                 {"gwcert", N_("Gateway certificate hash")},
	                                                 {NULL, NULL} };

	if (!vpn_type)
		return NULL;

	if (g_str_has_prefix (vpn_type, NM_DBUS_INTERFACE))
		type = vpn_type + strlen (NM_DBUS_INTERFACE) + 1;
	else
		type = vpn_type;

	if (   !g_strcmp0 (type, "openvpn")
	    || !g_strcmp0 (type, "pptp")
	    || !g_strcmp0 (type, "iodine")
	    || !g_strcmp0 (type, "ssh")
	    || !g_strcmp0 (type, "l2tp")
	    || !g_strcmp0 (type, "fortisslvpn"))
		 return generic_vpn_secrets;
	else if (!g_strcmp0 (type, "vpnc"))
		return vpnc_secrets;
	else if (   !g_strcmp0 (type, "openswan")
	         || !g_strcmp0 (type, "libreswan")
	         || !g_strcmp0 (type, "strongswan"))
		return swan_secrets;
	else if (!g_strcmp0 (type, "openconnect"))
		return openconnect_secrets;
	return NULL;
}

static gboolean
_extract_variable_value (char *line, const char *tag, char **value)
{
	char *p1, *p2;

	if (g_str_has_prefix (line, tag)) {
		p1 = line + strlen (tag);
		p2 = line + strlen (line) - 1;
		if ((*p1 == '\'' || *p1 == '"') && (*p1 == *p2)) {
			p1++;
			*p2 = '\0';
		}
		if (value)
			*value = g_strdup (p1);
		return TRUE;
	}
	return FALSE;
}

gboolean
nm_vpn_openconnect_authenticate_helper (const char *host,
                                        char **cookie,
                                        char **gateway,
                                        char **gwcert,
                                        int *status,
                                        GError **error)
{
	char *output = NULL;
	gboolean ret;
	char **strv = NULL, **iter;
	char *argv[4];
	const char *path;
	const char *const DEFAULT_PATHS[] = {
		"/sbin/",
		"/usr/sbin/",
		"/usr/local/sbin/",
		"/bin/",
		"/usr/bin/",
		"/usr/local/bin/",
		NULL,
	};

	path = nm_utils_file_search_in_paths ("openconnect", "/usr/sbin/openconnect", DEFAULT_PATHS,
	                                      G_FILE_TEST_IS_EXECUTABLE, NULL, NULL, error);
	if (!path)
		return FALSE;

	argv[0] = (char *) path;
	argv[1] = "--authenticate";
	argv[2] = (char *) host;
	argv[3] = NULL;

	ret = g_spawn_sync (NULL, argv, NULL,
	                    G_SPAWN_SEARCH_PATH | G_SPAWN_CHILD_INHERITS_STDIN,
	                    NULL, NULL,  &output, NULL,
	                    status, error);

	if (!ret)
		return FALSE;

	/* Parse output and set cookie, gateway and gwcert
	 * output example:
	 * COOKIE='loremipsum'
	 * HOST='1.2.3.4'
	 * FINGERPRINT='sha1:32bac90cf09a722e10ecc1942c67fe2ac8c21e2e'
	 */
	strv = g_strsplit_set (output ? output : "", "\r\n", 0);
	for (iter = strv; iter && *iter; iter++) {
		_extract_variable_value (*iter, "COOKIE=", cookie);
		_extract_variable_value (*iter, "HOST=", gateway);
		_extract_variable_value (*iter, "FINGERPRINT=", gwcert);
	}
	g_strfreev (strv);

	return TRUE;
}

