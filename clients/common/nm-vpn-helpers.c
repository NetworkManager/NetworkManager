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

#include "nm-default.h"

#include "nm-vpn-helpers.h"

#include <string.h>
#include <gmodule.h>

#include "nm-utils.h"

static gboolean plugins_loaded;
static GSList *plugins = NULL;

NMVpnEditorPlugin *
nm_vpn_get_plugin_by_service (const char *service, GError **error)
{
	NMVpnEditorPlugin *plugin = NULL;
	NMVpnPluginInfo *plugin_info;
	char *type = NULL;

	g_return_val_if_fail (service != NULL, NULL);
	g_return_val_if_fail (error == NULL || *error == NULL, NULL);

	if (G_UNLIKELY (!plugins_loaded))
		nm_vpn_get_plugins ();

	if (!g_str_has_prefix (service, NM_DBUS_INTERFACE))
		service = type = g_strdup_printf ("%s.%s", NM_DBUS_INTERFACE, service);

	plugin_info = nm_vpn_plugin_info_list_find_by_service (plugins, service);
	if (plugin_info) {
		plugin = nm_vpn_plugin_info_get_editor_plugin (plugin_info);
		if (!plugin)
			plugin = nm_vpn_plugin_info_load_editor_plugin (plugin_info, error);
	} else
		g_set_error_literal (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED,
		                     _("could not get VPN plugin info"));
	g_free (type);
	return plugin;
}

GSList *
nm_vpn_get_plugins (void)
{
	if (G_LIKELY (plugins_loaded))
		return plugins;
	plugins_loaded = TRUE;
	plugins = nm_vpn_plugin_info_list_load ();
	return plugins;
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

	plugin = nm_vpn_get_plugin_by_service (service_type, NULL);
	g_return_val_if_fail (plugin != NULL, FALSE);

	capabilities = nm_vpn_editor_plugin_get_capabilities (plugin);
	return NM_FLAGS_HAS (capabilities, NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6);
}

const VpnPasswordName *
nm_vpn_get_secret_names (const char *vpn_type)
{
	const char *type;
	static VpnPasswordName generic_vpn_secrets[] = { {"password", N_("Password")}, {NULL, NULL} };
	static VpnPasswordName openvpn_secrets[] = { {"password", N_("Password")},
	                                             {"cert-pass", N_("Certificate password")},
	                                             {"http-proxy-password", N_("HTTP proxy password")},
	                                             {NULL, NULL} };
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

	if (   !g_strcmp0 (type, "pptp")
	    || !g_strcmp0 (type, "iodine")
	    || !g_strcmp0 (type, "ssh")
	    || !g_strcmp0 (type, "l2tp")
	    || !g_strcmp0 (type, "fortisslvpn"))
		 return generic_vpn_secrets;
	else if (!g_strcmp0 (type, "openvpn"))
		return openvpn_secrets;
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

