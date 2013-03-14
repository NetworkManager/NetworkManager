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
 * Copyright (C) 2013 Thomas Bechtold <thomasbechtold@jpberlin.de>
 */

#include <config.h>
#include <string.h>
#include <stdio.h>

#include "nm-config.h"
#include "nm-logging.h"

#include <glib/gi18n.h>

#define NM_DEFAULT_SYSTEM_CONF_FILE  NMCONFDIR "/NetworkManager.conf"
#define NM_OLD_SYSTEM_CONF_FILE      NMCONFDIR "/nm-system-settings.conf"

typedef struct {
	char *path;
	char **plugins;
	char *dhcp_client;
	char **dns_plugins;
	char *log_level;
	char *log_domains;
	char *connectivity_uri;
	gint connectivity_interval;
	char *connectivity_response;
} NMConfigPrivate;

static NMConfig *singleton = NULL;

G_DEFINE_TYPE (NMConfig, nm_config, G_TYPE_OBJECT)

#define NM_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONFIG, NMConfigPrivate))

/************************************************************************/

const char *
nm_config_get_path (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->path;
}

const char **
nm_config_get_plugins (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return (const char **) NM_CONFIG_GET_PRIVATE (config)->plugins;
}

const char *
nm_config_get_dhcp_client (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->dhcp_client;
}

const char **
nm_config_get_dns_plugins (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return (const char **) NM_CONFIG_GET_PRIVATE (config)->dns_plugins;
}

const char *
nm_config_get_log_level (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->log_level;
}

const char *
nm_config_get_log_domains (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->log_domains;
}

const char *
nm_config_get_connectivity_uri (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->connectivity_uri;
}

const guint
nm_config_get_connectivity_interval (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, 0);

	/* We store interval as signed internally to track whether it's
	 * set or not, but report as unsigned to callers.
	 */
	return CLAMP (NM_CONFIG_GET_PRIVATE (config)->connectivity_interval, 0, G_MAXINT32);
}

const char *
nm_config_get_connectivity_response (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->connectivity_response;
}

/************************************************************************/

static char *cli_config_path;
static char *cli_plugins;
static char *cli_log_level;
static char *cli_log_domains;
static char *cli_connectivity_uri;
static int cli_connectivity_interval = -1;
static char *cli_connectivity_response;

static GOptionEntry config_options[] = {
	{ "config", 0, 0, G_OPTION_ARG_FILENAME, &cli_config_path, N_("Config file location"), N_("/path/to/config.file") },
	{ "plugins", 0, 0, G_OPTION_ARG_STRING, &cli_plugins, N_("List of plugins separated by ','"), N_("plugin1,plugin2") },
	{ "log-level", 0, 0, G_OPTION_ARG_STRING, &cli_log_level, N_("Log level: one of [%s]"), "INFO" },
	{ "log-domains", 0, 0, G_OPTION_ARG_STRING, &cli_log_domains,
	  N_("Log domains separated by ',': any combination of [%s]"),
	  "PLATFORM,RFKILL,WIFI" },

	/* These three are hidden for now, and should eventually just go away. */
	{ "connectivity-uri", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &cli_connectivity_uri, N_("An http(s) address for checking internet connectivity"), "http://example.com" },
	{ "connectivity-interval", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_INT, &cli_connectivity_interval, N_("The interval between connectivity checks (in seconds)"), "60" },
	{ "connectivity-response", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &cli_connectivity_response, N_("The expected start of the response"), N_("Bingo!") },
	{NULL}
};
static gboolean config_options_inited;

GOptionEntry *
nm_config_get_options (void)
{
	if (!config_options_inited) {
		int i;

		for (i = 0; config_options[i].long_name; i++) {
			if (!strcmp (config_options[i].long_name, "log-level")) {
				config_options[i].description = g_strdup_printf (config_options[i].description,
				                                                 nm_logging_all_levels_to_string ());
			} else if (!strcmp (config_options[i].long_name, "log-domains")) {
				config_options[i].description = g_strdup_printf (config_options[i].description,
				                                                 nm_logging_all_domains_to_string ());
			}
		}
		config_options_inited = TRUE;
	}

	return config_options;
}

/************************************************************************/

static gboolean
read_config (NMConfig *config, const char *path, GError **error)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);
	GKeyFile *kf;
	gboolean success = FALSE;

	if (g_file_test (path, G_FILE_TEST_EXISTS) == FALSE) {
		g_set_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND, "file %s not found", path);
		return FALSE;
	}

	kf = g_key_file_new ();
	g_key_file_set_list_separator (kf, ',');
	if (g_key_file_load_from_file (kf, path, G_KEY_FILE_NONE, error)) {
		priv->path = g_strdup (path);

		/* Only set stuff that's not already set, as CLI options override
		 * config file options.
		 */
		if (!priv->plugins)
			priv->plugins = g_key_file_get_string_list (kf, "main", "plugins", NULL, NULL);

		priv->dhcp_client = g_key_file_get_value (kf, "main", "dhcp", NULL);
		priv->dns_plugins = g_key_file_get_string_list (kf, "main", "dns", NULL, NULL);

		if (!priv->log_level)
			priv->log_level = g_key_file_get_value (kf, "logging", "level", NULL);

		if (!priv->log_domains)
			priv->log_domains = g_key_file_get_value (kf, "logging", "domains", NULL);

		if (!priv->connectivity_uri)
			priv->connectivity_uri = g_key_file_get_value (kf, "connectivity", "uri", NULL);

		if (priv->connectivity_interval < 0)
			priv->connectivity_interval = CLAMP (g_key_file_get_integer (kf, "connectivity", "interval", NULL), 0, G_MAXINT32);

		if (!priv->connectivity_response)
			priv->connectivity_response = g_key_file_get_value (kf, "connectivity", "response", NULL);

		success = TRUE;
	}

	g_key_file_free (kf);
	return success;
}

/************************************************************************/

NMConfig *
nm_config_get (void)
{
	g_assert (singleton);
	return singleton;
}

/* call this function only once! */
NMConfig *
nm_config_new (GError **error)
{
	GError *local = NULL;
	NMConfigPrivate *priv = NULL;

	g_assert (!singleton);
	singleton = NM_CONFIG (g_object_new (NM_TYPE_CONFIG, NULL));
	priv = NM_CONFIG_GET_PRIVATE (singleton);

	/* Fill with command-line defaults */
	if (cli_plugins && cli_plugins[0])
		priv->plugins = g_strsplit_set (cli_plugins, ",", 0);

	if (cli_log_level && cli_log_level[0])
		priv->log_level = g_strdup (cli_log_level);

	if (cli_log_domains && cli_log_domains[0])
		priv->log_domains = g_strdup (cli_log_domains);

	if (cli_connectivity_uri && cli_connectivity_uri[0])
		priv->connectivity_uri = g_strdup (cli_connectivity_uri);

	if (cli_connectivity_interval >= 0)
		priv->connectivity_interval = cli_connectivity_interval;

	if (cli_connectivity_response && cli_connectivity_response[0])
		priv->connectivity_response = g_strdup (cli_connectivity_response);

	/* Try a user-specified config file first */
	if (cli_config_path) {
		/* Bad user-specific config file path is a hard error */
		if (!read_config (singleton, cli_config_path, error)) {
			g_object_unref (singleton);
			singleton = NULL;
		}
		return singleton;
	}

	/* Even though we prefer NetworkManager.conf, we need to check the
	 * old nm-system-settings.conf first to preserve compat with older
	 * setups.  In package managed systems dropping a NetworkManager.conf
	 * onto the system would make NM use it instead of nm-system-settings.conf,
	 * changing behavior during an upgrade.  We don't want that.
	 */

	/* Try deprecated nm-system-settings.conf first */
	if (read_config (singleton, NM_OLD_SYSTEM_CONF_FILE, &local))
		return singleton;

	if (g_error_matches (local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND) == FALSE) {
		fprintf (stderr, "Default config file %s invalid: (%d) %s\n",
		         NM_OLD_SYSTEM_CONF_FILE,
		         local ? local->code : -1,
		         (local && local->message) ? local->message : "unknown");
	}
	g_clear_error (&local);

	/* Try the standard config file location next */
	if (read_config (singleton, NM_DEFAULT_SYSTEM_CONF_FILE, &local))
		return singleton;

	if (g_error_matches (local, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND) == FALSE) {
		fprintf (stderr, "Default config file %s invalid: (%d) %s\n",
		         NM_DEFAULT_SYSTEM_CONF_FILE,
		         local ? local->code : -1,
		         (local && local->message) ? local->message : "unknown");
		g_propagate_error (error, local);
		g_object_unref (singleton);
		return NULL;
	}

	/* If for some reason no config file exists, and NM wasn't given on on
	 * the command line, just use the default config file path.
	 */
	if (priv->path == NULL) {
		priv->path = g_strdup (NM_DEFAULT_SYSTEM_CONF_FILE);
		fprintf (stderr, "No config file found or given; using %s\n",
		         NM_DEFAULT_SYSTEM_CONF_FILE);
	}

	/* ignore error if config file not found */
	g_clear_error (&local);
	return singleton;
}

static void
nm_config_init (NMConfig *config)
{
	NM_CONFIG_GET_PRIVATE (config)->connectivity_interval = -1;
}

static void
finalize (GObject *gobject)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (gobject);

	g_free (priv->path);
	g_strfreev (priv->plugins);
	g_free (priv->dhcp_client);
	g_strfreev (priv->dns_plugins);
	g_free (priv->log_level);
	g_free (priv->log_domains);
	g_free (priv->connectivity_uri);
	g_free (priv->connectivity_response);

	singleton = NULL;

	g_clear_pointer (&cli_config_path, g_free);
	g_clear_pointer (&cli_plugins, g_free);
	g_clear_pointer (&cli_log_level, g_free);
	g_clear_pointer (&cli_log_domains, g_free);
	g_clear_pointer (&cli_connectivity_uri, g_free);
	g_clear_pointer (&cli_connectivity_response, g_free);

	G_OBJECT_CLASS (nm_config_parent_class)->finalize (gobject);
}


static void
nm_config_class_init (NMConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMConfigPrivate));
	object_class->finalize = finalize;
}

