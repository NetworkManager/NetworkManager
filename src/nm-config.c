/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2011 Red Hat, Inc.
 */

#include <config.h>
#include <string.h>
#include <stdio.h>

#include "nm-config.h"

#define NM_DEFAULT_SYSTEM_CONF_FILE  NMCONFDIR "/NetworkManager.conf"
#define NM_OLD_SYSTEM_CONF_FILE      NMCONFDIR "/nm-system-settings.conf"

struct NMConfig {
	char *path;
	char **plugins;
	char *dhcp_client;
	char **dns_plugins;
	char *log_level;
	char *log_domains;
	char *connectivity_uri;
	guint connectivity_interval;
	char *connectivity_response;
};

/************************************************************************/

GQuark
nm_config_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-config-error");
	return quark;
}

/************************************************************************/

const char *
nm_config_get_path (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return config->path;
}

const char **
nm_config_get_plugins (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return (const char **) config->plugins;
}

const char *
nm_config_get_dhcp_client (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return config->dhcp_client;
}

const char **
nm_config_get_dns_plugins (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return (const char **) config->dns_plugins;
}

const char *
nm_config_get_log_level (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return config->log_level;
}

const char *
nm_config_get_log_domains (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return config->log_domains;
}

const char *
nm_config_get_connectivity_uri (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return config->connectivity_uri;
}

const guint
nm_config_get_connectivity_interval (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, 0);

	return config->connectivity_interval;
}

const char *
nm_config_get_connectivity_response (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return config->connectivity_response;
}


/************************************************************************/

static gboolean
fill_from_file (NMConfig *config,
                const char *path,
                const char *cli_plugins,
                const char *cli_log_level,
                const char *cli_log_domains,
                const char *cli_connectivity_uri,
                const gint cli_connectivity_interval,
                const char *cli_connectivity_response,
                GError **error)
{
	GKeyFile *kf;
	gboolean success = FALSE;

	if (g_file_test (path, G_FILE_TEST_EXISTS) == FALSE) {
		g_set_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND, "file %s not found", path);
		return FALSE;
	}

	kf = g_key_file_new ();
	if (!kf) {
		g_set_error (error, NM_CONFIG_ERROR, NM_CONFIG_ERROR_NO_MEMORY,
		             "Not enough memory to load config file %s", path);
		return FALSE;
	}

	g_key_file_set_list_separator (kf, ',');
	if (g_key_file_load_from_file (kf, path, G_KEY_FILE_NONE, error)) {
		config->path = g_strdup (path);

		/* CLI provided options override config file options */
		if (cli_plugins && strlen (cli_plugins))
			config->plugins = g_strsplit_set (cli_plugins, ",", 0);
		else
			config->plugins = g_key_file_get_string_list (kf, "main", "plugins", NULL, NULL);

		config->dhcp_client = g_key_file_get_value (kf, "main", "dhcp", NULL);
		config->dns_plugins = g_key_file_get_string_list (kf, "main", "dns", NULL, NULL);

		if (cli_log_level && strlen (cli_log_level))
			config->log_level = g_strdup (cli_log_level);
		else
			config->log_level = g_key_file_get_value (kf, "logging", "level", NULL);

		if (cli_log_domains && strlen (cli_log_domains))
			config->log_domains = g_strdup (cli_log_domains);
		else
			config->log_domains = g_key_file_get_value (kf, "logging", "domains", NULL);

		if (cli_connectivity_uri && strlen (cli_connectivity_uri))
			config->connectivity_uri = g_strdup (cli_connectivity_uri);
		else
			config->connectivity_uri = g_key_file_get_value (kf, "connectivity", "uri", NULL);

		if (cli_connectivity_interval >= 0)
			config->connectivity_interval = cli_connectivity_interval;
		else
			config->connectivity_interval = g_key_file_get_integer (kf, "connectivity", "interval", NULL);

		if (cli_connectivity_response && strlen (cli_connectivity_response))
			config->connectivity_response = g_strdup (cli_connectivity_response);
		else
			config->connectivity_response = g_key_file_get_value (kf, "connectivity", "response", NULL);

		success = TRUE;
	}

	g_key_file_free (kf);
	return success;
}

NMConfig *
nm_config_new (const char *cli_config_path,
               const char *cli_plugins,
               const char *cli_log_level,
               const char *cli_log_domains,
               const char *cli_connectivity_uri,
               const gint cli_connectivity_interval,
               const char *cli_connectivity_response,
               GError **error)
{
	NMConfig *config;
	GError *local = NULL;

	config = g_malloc0 (sizeof (*config));

	if (cli_config_path) {
		/* Bad user-specific config file path is a hard error */
		if (!fill_from_file (config, cli_config_path, cli_plugins, cli_log_level, cli_log_domains,
		                     cli_connectivity_uri, cli_connectivity_interval, cli_connectivity_response,
		                     error)) {
			nm_config_free (config);
			return NULL;
		}
		return config;
	}

	/* Even though we prefer NetworkManager.conf, we need to check the
	 * old nm-system-settings.conf first to preserve compat with older
	 * setups.  In package managed systems dropping a NetworkManager.conf
	 * onto the system would make NM use it instead of nm-system-settings.conf,
	 * changing behavior during an upgrade.  We don't want that.
	 */

	/* Try deprecated nm-system-settings.conf first */
	if (fill_from_file (config, NM_OLD_SYSTEM_CONF_FILE, cli_plugins, cli_log_level, cli_log_domains,
	                    cli_connectivity_uri, cli_connectivity_interval, cli_connectivity_response,
	                    &local))
		return config;

	if (g_error_matches (local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND) == FALSE) {
		fprintf (stderr, "Default config file %s invalid: (%d) %s\n",
		         NM_OLD_SYSTEM_CONF_FILE,
		         local ? local->code : -1,
		         (local && local->message) ? local->message : "unknown");
	}
	g_clear_error (&local);

	/* Try the standard config file location next */
	if (fill_from_file (config, NM_DEFAULT_SYSTEM_CONF_FILE, cli_plugins, cli_log_level, cli_log_domains,
	                    cli_connectivity_uri, cli_connectivity_interval, cli_connectivity_response,
	                    &local))
		return config;

	if (g_error_matches (local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND) == FALSE) {
		fprintf (stderr, "Default config file %s invalid: (%d) %s\n",
		         NM_DEFAULT_SYSTEM_CONF_FILE,
		         local ? local->code : -1,
		         (local && local->message) ? local->message : "unknown");
		g_propagate_error (error, local);
		nm_config_free (config);
		return NULL;
	}

	/* If for some reason no config file exists, and NM wasn't given on on
	 * the command line, just use the default config file path.
	 */
	if (config->path == NULL) {
		config->path = g_strdup (NM_DEFAULT_SYSTEM_CONF_FILE);
		fprintf (stderr, "No config file found or given; using %s\n",
		         NM_DEFAULT_SYSTEM_CONF_FILE);
	}

	/* ignore error if config file not found */
	g_clear_error (&local);
	return config;
}

void
nm_config_free (NMConfig *config)
{
	g_return_if_fail (config != NULL);

	g_free (config->path);
	g_strfreev (config->plugins);
	g_free (config->dhcp_client);
	g_strfreev (config->dns_plugins);
	g_free (config->log_level);
	g_free (config->log_domains);
	g_free (config->connectivity_uri);
	g_free (config->connectivity_response);
	memset (config, 0, sizeof (*config));
	g_free (config);
}

