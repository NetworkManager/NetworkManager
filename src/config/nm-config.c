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
#include "nm-utils.h"
#include "nm-glib-compat.h"

#include <gio/gio.h>
#include <glib/gi18n.h>

#define NM_DEFAULT_SYSTEM_CONF_FILE    NMCONFDIR "/NetworkManager.conf"
#define NM_DEFAULT_SYSTEM_CONF_DIR     NMCONFDIR "/conf.d"
#define NM_OLD_SYSTEM_CONF_FILE        NMCONFDIR "/nm-system-settings.conf"
#define NM_NO_AUTO_DEFAULT_STATE_FILE  NMSTATEDIR "/no-auto-default.state"

typedef struct {
	char *nm_conf_path;
	char *config_dir;
	char *config_description;
	char *no_auto_default_file;
	GKeyFile *keyfile;

	char **plugins;
	gboolean monitor_connection_files;
	char *dhcp_client;
	char *dns_mode;

	char *log_level;
	char *log_domains;

	char *debug;

	char *connectivity_uri;
	gint connectivity_interval;
	char *connectivity_response;

	char **no_auto_default;
	char **ignore_carrier;
} NMConfigPrivate;

static NMConfig *singleton = NULL;

G_DEFINE_TYPE (NMConfig, nm_config, G_TYPE_OBJECT)

#define NM_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONFIG, NMConfigPrivate))

/************************************************************************/

const char *
nm_config_get_path (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->nm_conf_path;
}

const char *
nm_config_get_description (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->config_description;
}

const char **
nm_config_get_plugins (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return (const char **) NM_CONFIG_GET_PRIVATE (config)->plugins;
}

gboolean
nm_config_get_monitor_connection_files (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, FALSE);

	return NM_CONFIG_GET_PRIVATE (config)->monitor_connection_files;
}

const char *
nm_config_get_dhcp_client (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->dhcp_client;
}

const char *
nm_config_get_dns_mode (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->dns_mode;
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
nm_config_get_debug (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->debug;
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
	return MAX (NM_CONFIG_GET_PRIVATE (config)->connectivity_interval, 0);
}

const char *
nm_config_get_connectivity_response (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->connectivity_response;
}

char *
nm_config_get_value (NMConfig *config, const char *group, const char *key, GError **error)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);

	return g_key_file_get_string (priv->keyfile, group, key, error);
}

gboolean
nm_config_get_ignore_carrier (NMConfig *config, NMConfigDevice *device)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);

	return nm_config_device_spec_match_list (device, (const char **) priv->ignore_carrier);
}

/************************************************************************/

static void
merge_no_auto_default_state (NMConfig *config)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);
	GPtrArray *updated;
	char **list;
	int i, j;
	char *data;

	/* If the config already matches everything, we don't need to do anything else. */
	if (priv->no_auto_default && !g_strcmp0 (priv->no_auto_default[0], "*"))
		return;

	updated = g_ptr_array_new ();
	if (priv->no_auto_default) {
		for (i = 0; priv->no_auto_default[i]; i++)
			g_ptr_array_add (updated, priv->no_auto_default[i]);
		g_free (priv->no_auto_default);
	}

	if (g_file_get_contents (priv->no_auto_default_file, &data, NULL, NULL)) {
		list = g_strsplit (data, "\n", -1);
		for (i = 0; list[i]; i++) {
			if (!*list[i])
				continue;
			for (j = 0; j < updated->len; j++) {
				if (!strcmp (list[i], updated->pdata[j]))
					break;
			}
			if (j == updated->len)
				g_ptr_array_add (updated, list[i]);
		}
		g_free (list);
		g_free (data);
	}

	g_ptr_array_add (updated, NULL);
	priv->no_auto_default = (char **) g_ptr_array_free (updated, FALSE);
}

gboolean
nm_config_get_ethernet_can_auto_default (NMConfig *config, NMConfigDevice *device)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);

	return !nm_config_device_spec_match_list (device, (const char **) priv->no_auto_default);
}

void
nm_config_set_ethernet_no_auto_default (NMConfig *config, NMConfigDevice *device)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);
	char *current;
	GString *updated;
	GError *error = NULL;

	if (!nm_config_get_ethernet_can_auto_default (config, device))
		return;

	updated = g_string_new (NULL);
	if (g_file_get_contents (priv->no_auto_default_file, &current, NULL, NULL)) {
		g_string_append (updated, current);
		g_free (current);
		if (updated->str[updated->len - 1] != '\n')
			g_string_append_c (updated, '\n');
	}

	g_string_append (updated, nm_config_device_get_hwaddr (device));
	g_string_append_c (updated, '\n');

	if (!g_file_set_contents (priv->no_auto_default_file, updated->str, updated->len, &error)) {
		nm_log_warn (LOGD_SETTINGS, "Could not update no-auto-default.state file: %s",
		             error->message);
		g_error_free (error);
	}

	g_string_free (updated, TRUE);

	merge_no_auto_default_state (config);
}

/************************************************************************/

static char *cli_config_path;
static char *cli_config_dir;
static char *cli_no_auto_default_file;
static char *cli_plugins;
static char *cli_connectivity_uri;
static int cli_connectivity_interval = -1;
static char *cli_connectivity_response;

static GOptionEntry config_options[] = {
	{ "config", 0, 0, G_OPTION_ARG_FILENAME, &cli_config_path, N_("Config file location"), N_("/path/to/config.file") },
	{ "config-dir", 0, 0, G_OPTION_ARG_FILENAME, &cli_config_dir, N_("Config directory location"), N_("/path/to/config/dir") },
	{ "no-auto-default", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_FILENAME, &cli_no_auto_default_file, "no-auto-default.state location", NULL },
	{ "plugins", 0, 0, G_OPTION_ARG_STRING, &cli_plugins, N_("List of plugins separated by ','"), N_("plugin1,plugin2") },

	/* These three are hidden for now, and should eventually just go away. */
	{ "connectivity-uri", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &cli_connectivity_uri, N_("An http(s) address for checking internet connectivity"), "http://example.com" },
	{ "connectivity-interval", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_INT, &cli_connectivity_interval, N_("The interval between connectivity checks (in seconds)"), "60" },
	{ "connectivity-response", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &cli_connectivity_response, N_("The expected start of the response"), N_("Bingo!") },
	{NULL}
};
GOptionEntry *
nm_config_get_options (void)
{
	return config_options;
}

/************************************************************************/

static gboolean
read_config (NMConfig *config, const char *path, GError **error)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);
	GKeyFile *kf;
	char **groups, **keys;
	gsize ngroups, nkeys;
	int g, k;

	if (g_file_test (path, G_FILE_TEST_EXISTS) == FALSE) {
		g_set_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND, "file %s not found", path);
		return FALSE;
	}

	nm_log_dbg (LOGD_SETTINGS, "Reading config file '%s'", path);

	kf = g_key_file_new ();
	g_key_file_set_list_separator (kf, ',');
	if (!g_key_file_load_from_file (kf, path, G_KEY_FILE_NONE, error)) {
		g_key_file_free (kf);
		return FALSE;
	}

	/* Override the current settings with the new ones */
	groups = g_key_file_get_groups (kf, &ngroups);
	for (g = 0; groups[g]; g++) {
		keys = g_key_file_get_keys (kf, groups[g], &nkeys, NULL);
		if (!keys)
			continue;
		for (k = 0; keys[k]; k++) {
			int len = strlen (keys[k]);
			if (keys[k][len - 1] == '+') {
				char *base_key = g_strndup (keys[k], len - 1);
				const char *old_val = g_key_file_get_value (priv->keyfile, groups[g], base_key, NULL);
				const char *new_val = g_key_file_get_value (kf, groups[g], keys[k], NULL);

				if (old_val && *old_val) {
					char *combined = g_strconcat (old_val, ",", new_val, NULL);

					g_key_file_set_value (priv->keyfile, groups[g], base_key, combined);
					g_free (combined);
				} else
					g_key_file_set_value (priv->keyfile, groups[g], base_key, new_val);

				g_free (base_key);
				continue;
			}

			g_key_file_set_value (priv->keyfile, groups[g], keys[k],
			                      g_key_file_get_value (kf, groups[g], keys[k], NULL));
		}
	}
	g_key_file_free (kf);

	return TRUE;
}

static gboolean
find_base_config (NMConfig *config, GError **error)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);
	GError *my_error = NULL;

	/* Try a user-specified config file first */
	if (cli_config_path) {
		/* Bad user-specific config file path is a hard error */
		if (read_config (config, cli_config_path, error)) {
			priv->nm_conf_path = g_strdup (cli_config_path);
			return TRUE;
		} else
			return FALSE;
	}

	/* Even though we prefer NetworkManager.conf, we need to check the
	 * old nm-system-settings.conf first to preserve compat with older
	 * setups.  In package managed systems dropping a NetworkManager.conf
	 * onto the system would make NM use it instead of nm-system-settings.conf,
	 * changing behavior during an upgrade.  We don't want that.
	 */

	/* Try deprecated nm-system-settings.conf first */
	if (read_config (config, NM_OLD_SYSTEM_CONF_FILE, &my_error)) {
		priv->nm_conf_path = g_strdup (NM_OLD_SYSTEM_CONF_FILE);
		return TRUE;
	}

	if (!g_error_matches (my_error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)) {
		g_warning ("Default config file %s invalid: %s\n",
		           NM_OLD_SYSTEM_CONF_FILE,
		           my_error->message);
	}
	g_clear_error (&my_error);

	/* Try the standard config file location next */
	if (read_config (config, NM_DEFAULT_SYSTEM_CONF_FILE, &my_error)) {
		priv->nm_conf_path = g_strdup (NM_DEFAULT_SYSTEM_CONF_FILE);
		return TRUE;
	}

	if (!g_error_matches (my_error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)) {
		g_warning ("Default config file %s invalid: %s\n",
		           NM_DEFAULT_SYSTEM_CONF_FILE,
		           my_error->message);
		g_propagate_error (error, my_error);
		return FALSE;
	}

	/* If for some reason no config file exists, use the default
	 * config file path.
	 */
	priv->nm_conf_path = g_strdup (NM_DEFAULT_SYSTEM_CONF_FILE);
	g_warning ("No config file found or given; using %s\n",
	           NM_DEFAULT_SYSTEM_CONF_FILE);
	return TRUE;
}

/************************************************************************/

NMConfig *
nm_config_get (void)
{
	g_assert (singleton);
	return singleton;
}

static int
sort_asciibetically (gconstpointer a, gconstpointer b)
{
	const char *s1 = *(const char **)a;
	const char *s2 = *(const char **)b;

	return strcmp (s1, s2);
}

/* call this function only once! */
NMConfig *
nm_config_new (GError **error)
{
	NMConfigPrivate *priv = NULL;
	GFile *dir;
	GFileEnumerator *direnum;
	GFileInfo *info;
	GPtrArray *confs;
	const char *name;
	char *value;
	int i;
	GString *config_description;

	g_assert (!singleton);
	singleton = NM_CONFIG (g_object_new (NM_TYPE_CONFIG, NULL));
	priv = NM_CONFIG_GET_PRIVATE (singleton);

	/* First read the base config file */
	if (!find_base_config (singleton, error)) {
		g_object_unref (singleton);
		singleton = NULL;
		return NULL;
	}

	/* Now read the overrides in the config dir */
	if (cli_config_dir)
		priv->config_dir = g_strdup (cli_config_dir);
	else
		priv->config_dir = g_strdup (NM_DEFAULT_SYSTEM_CONF_DIR);

	confs = g_ptr_array_new_with_free_func (g_free);
	config_description = g_string_new (priv->nm_conf_path);
	dir = g_file_new_for_path (priv->config_dir);
	direnum = g_file_enumerate_children (dir, G_FILE_ATTRIBUTE_STANDARD_NAME, 0, NULL, NULL);
	if (direnum) {
		while ((info = g_file_enumerator_next_file (direnum, NULL, NULL))) {
			name = g_file_info_get_name (info);
			if (g_str_has_suffix (name, ".conf")) {
				g_ptr_array_add (confs, g_build_filename (priv->config_dir, name, NULL));
				if (confs->len == 1)
					g_string_append (config_description, " and conf.d: ");
				else
					g_string_append (config_description, ", ");
				g_string_append (config_description, name);
			}
			g_object_unref (info);
		}
		g_object_unref (direnum);
	}
	g_object_unref (dir);

	g_ptr_array_sort (confs, sort_asciibetically);
	priv->config_description = g_string_free (config_description, FALSE);
	for (i = 0; i < confs->len; i++) {
		if (!read_config (singleton, confs->pdata[i], error)) {
			g_object_unref (singleton);
			singleton = NULL;
			break;
		}
	}
	g_ptr_array_unref (confs);
	if (!singleton)
		return FALSE;

	/* Handle no-auto-default key and state file */
	priv->no_auto_default = g_key_file_get_string_list (priv->keyfile, "main", "no-auto-default", NULL, NULL);
	if (cli_no_auto_default_file)
		priv->no_auto_default_file = g_strdup (cli_no_auto_default_file);
	else
		priv->no_auto_default_file = g_strdup (NM_NO_AUTO_DEFAULT_STATE_FILE);
	merge_no_auto_default_state (singleton);

	/* Now let command-line options override the config files, and fill in priv. */
	if (cli_plugins && cli_plugins[0])
		g_key_file_set_value (priv->keyfile, "main", "plugins", cli_plugins);
	priv->plugins = g_key_file_get_string_list (priv->keyfile, "main", "plugins", NULL, NULL);

	value = g_key_file_get_value (priv->keyfile, "main", "monitor-connection-files", NULL);
	if (value) {
		if (!strcmp (value, "true") || !strcmp (value, "yes") || !strcmp (value, "on"))
			priv->monitor_connection_files = TRUE;
		else if (!strcmp (value, "false") || !strcmp (value, "no") || !strcmp (value, "off"))
			priv->monitor_connection_files = FALSE;
		else {
			g_warning ("Unrecognized value for main.monitor-connection-files: %s. Assuming 'false'", value);
			priv->monitor_connection_files = FALSE;
		}
		g_free (value);
	} else
		priv->monitor_connection_files = FALSE;

	priv->dhcp_client = g_key_file_get_value (priv->keyfile, "main", "dhcp", NULL);
	priv->dns_mode = g_key_file_get_value (priv->keyfile, "main", "dns", NULL);

	priv->log_level = g_key_file_get_value (priv->keyfile, "logging", "level", NULL);
	priv->log_domains = g_key_file_get_value (priv->keyfile, "logging", "domains", NULL);

	priv->debug = g_key_file_get_value (priv->keyfile, "main", "debug", NULL);

	if (cli_connectivity_uri && cli_connectivity_uri[0])
		g_key_file_set_value (priv->keyfile, "connectivity", "uri", cli_connectivity_uri);
	priv->connectivity_uri = g_key_file_get_value (priv->keyfile, "connectivity", "uri", NULL);

	if (cli_connectivity_interval >= 0)
		g_key_file_set_integer (priv->keyfile, "connectivity", "interval", cli_connectivity_interval);
	priv->connectivity_interval = g_key_file_get_integer (priv->keyfile, "connectivity", "interval", NULL);

	if (cli_connectivity_response && cli_connectivity_response[0])
		g_key_file_set_value (priv->keyfile, "connectivity", "response", cli_connectivity_response);
	priv->connectivity_response = g_key_file_get_value (priv->keyfile, "connectivity", "response", NULL);

	priv->ignore_carrier = g_key_file_get_string_list (priv->keyfile, "main", "ignore-carrier", NULL, NULL);

	return singleton;
}

static void
nm_config_init (NMConfig *config)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);

	priv->keyfile = g_key_file_new ();
	g_key_file_set_list_separator (priv->keyfile, ',');

	priv->connectivity_interval = -1;
}

static void
finalize (GObject *gobject)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (gobject);

	g_free (priv->nm_conf_path);
	g_free (priv->config_dir);
	g_free (priv->config_description);
	g_free (priv->no_auto_default_file);
	g_clear_pointer (&priv->keyfile, g_key_file_unref);
	g_strfreev (priv->plugins);
	g_free (priv->dhcp_client);
	g_free (priv->dns_mode);
	g_free (priv->log_level);
	g_free (priv->log_domains);
	g_free (priv->debug);
	g_free (priv->connectivity_uri);
	g_free (priv->connectivity_response);
	g_strfreev (priv->no_auto_default);
	g_strfreev (priv->ignore_carrier);

	singleton = NULL;

	g_clear_pointer (&cli_config_path, g_free);
	g_clear_pointer (&cli_config_dir, g_free);
	g_clear_pointer (&cli_no_auto_default_file, g_free);
	g_clear_pointer (&cli_plugins, g_free);
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

