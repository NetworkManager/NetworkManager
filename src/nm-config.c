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

#include "config.h"

#include <string.h>
#include <stdio.h>

#include "nm-config.h"
#include "nm-logging.h"
#include "nm-utils.h"
#include "nm-glib-compat.h"
#include "nm-device.h"
#include "NetworkManagerUtils.h"
#include "gsystem-local-alloc.h"
#include "nm-enum-types.h"
#include "nm-core-internal.h"

#include <gio/gio.h>
#include <glib/gi18n.h>

#define DEFAULT_CONFIG_MAIN_FILE        NMCONFDIR "/NetworkManager.conf"
#define DEFAULT_CONFIG_DIR              NMCONFDIR "/conf.d"
#define DEFAULT_CONFIG_MAIN_FILE_OLD    NMCONFDIR "/nm-system-settings.conf"
#define DEFAULT_NO_AUTO_DEFAULT_FILE    NMSTATEDIR "/no-auto-default.state"

struct NMConfigCmdLineOptions {
	char *config_main_file;
	char *config_dir;
	char *no_auto_default_file;
	char *plugins;
	gboolean configure_and_quit;
	char *connectivity_uri;

	/* We store interval as signed internally to track whether it's
	 * set or not via GOptionEntry
	 */
	int connectivity_interval;
	char *connectivity_response;
};

typedef struct {
	NMConfigCmdLineOptions cli;

	NMConfigData *config_data;
	NMConfigData *config_data_orig;

	char *config_dir;
	char *no_auto_default_file;

	char **plugins;
	gboolean monitor_connection_files;
	gboolean auth_polkit;
	char *dhcp_client;

	char *log_level;
	char *log_domains;

	char *debug;

	gboolean configure_and_quit;
} NMConfigPrivate;

enum {
	PROP_0,
	PROP_CMD_LINE_OPTIONS,
	LAST_PROP,
};

enum {
	SIGNAL_CONFIG_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void nm_config_initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (NMConfig, nm_config, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_config_initable_iface_init);
                         )


#define NM_CONFIG_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CONFIG, NMConfigPrivate))

/************************************************************************/

static void _set_config_data (NMConfig *self, NMConfigData *new_data, int signal);

/************************************************************************/

gint
nm_config_parse_boolean (const char *str,
                         gint default_value)
{
	gsize len;
	char *s = NULL;

	if (!str)
		return default_value;

	while (str[0] && g_ascii_isspace (str[0]))
		str++;

	if (!str[0])
		return default_value;

	len = strlen (str);
	if (g_ascii_isspace (str[len - 1])) {
		s = g_strdup (str);
		g_strchomp (s);
		str = s;
	}

	if (!g_ascii_strcasecmp (str, "true") || !g_ascii_strcasecmp (str, "yes") || !g_ascii_strcasecmp (str, "on") || !g_ascii_strcasecmp (str, "1"))
		default_value = TRUE;
	else if (!g_ascii_strcasecmp (str, "false") || !g_ascii_strcasecmp (str, "no") || !g_ascii_strcasecmp (str, "off") || !g_ascii_strcasecmp (str, "0"))
		default_value = FALSE;
	if (s)
		g_free (s);
	return default_value;
}

gint
nm_config_keyfile_get_boolean (GKeyFile *keyfile,
                               const char *section,
                               const char *key,
                               gint default_value)
{
	gs_free char *str = NULL;

	g_return_val_if_fail (keyfile != NULL, default_value);
	g_return_val_if_fail (section != NULL, default_value);
	g_return_val_if_fail (key != NULL, default_value);

	str = g_key_file_get_value (keyfile, section, key, NULL);
	return nm_config_parse_boolean (str, default_value);
}

void
nm_config_keyfile_set_string_list (GKeyFile *keyfile,
                                   const char *group,
                                   const char *key,
                                   const char *const* strv,
                                   gssize len)
{
	gsize l;
	char *new_value;

	if (len < 0)
		len = strv ? g_strv_length ((char **) strv) : 0;

	g_key_file_set_string_list (keyfile, group, key, strv, len);

	/* g_key_file_set_string_list() appends a trailing separator to the value.
	 * We don't like that, get rid of it. */

	new_value = g_key_file_get_value (keyfile, group, key, NULL);
	if (!new_value)
		return;

	l = strlen (new_value);
	if (l > 0 && new_value[l - 1] == NM_CONFIG_KEYFILE_LIST_SEPARATOR) {
		/* Maybe we should check that value doesn't end with "\\,", i.e.
		 * with an escaped separator. But the way g_key_file_set_string_list()
		 * is implemented (currently), it always adds a trailing separator. */
		new_value[l - 1] = '\0';
		g_key_file_set_value (keyfile, group, key, new_value);
	}
	g_free (new_value);
}

/************************************************************************/

NMConfigData *
nm_config_get_data (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->config_data;
}

/* The NMConfigData instance is reloadable and will be swapped on reload.
 * nm_config_get_data_orig() returns the original configuration, when the NMConfig
 * instance was created. */
NMConfigData *
nm_config_get_data_orig (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->config_data_orig;
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

gboolean
nm_config_get_auth_polkit (NMConfig *config)
{
	g_return_val_if_fail (NM_IS_CONFIG (config), NM_CONFIG_DEFAULT_AUTH_POLKIT);

	return NM_CONFIG_GET_PRIVATE (config)->auth_polkit;
}

const char *
nm_config_get_dhcp_client (NMConfig *config)
{
	g_return_val_if_fail (config != NULL, NULL);

	return NM_CONFIG_GET_PRIVATE (config)->dhcp_client;
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

gboolean
nm_config_get_configure_and_quit (NMConfig *config)
{
	return NM_CONFIG_GET_PRIVATE (config)->configure_and_quit;
}

/************************************************************************/

static char **
no_auto_default_from_file (const char *no_auto_default_file)
{
	GPtrArray *no_auto_default_new;
	char **list;
	guint i;
	char *data;

	no_auto_default_new = g_ptr_array_new ();

	if (   no_auto_default_file
	    && g_file_get_contents (no_auto_default_file, &data, NULL, NULL)) {
		list = g_strsplit (data, "\n", -1);
		for (i = 0; list[i]; i++) {
			if (   *list[i]
			    && nm_utils_hwaddr_valid (list[i], -1)
			    && _nm_utils_strv_find_first (list, i, list[i]) < 0)
				g_ptr_array_add (no_auto_default_new, list[i]);
			else
				g_free (list[i]);
		}
		g_free (list);
		g_free (data);
	}

	g_ptr_array_add (no_auto_default_new, NULL);
	return (char **) g_ptr_array_free (no_auto_default_new, FALSE);
}

static gboolean
no_auto_default_to_file (const char *no_auto_default_file, const char *const*no_auto_default, GError **error)
{
	GString *data;
	gboolean success;
	guint i;

	data = g_string_new ("");
	for (i = 0; no_auto_default && no_auto_default[i]; i++) {
		g_string_append (data, no_auto_default[i]);
		g_string_append_c (data, '\n');
	}
	success = g_file_set_contents (no_auto_default_file, data->str, data->len, error);
	g_string_free (data, TRUE);
	return success;
}

gboolean
nm_config_get_no_auto_default_for_device (NMConfig *self, NMDevice *device)
{
	g_return_val_if_fail (NM_IS_CONFIG (self), FALSE);

	return nm_config_data_get_no_auto_default_for_device (NM_CONFIG_GET_PRIVATE (self)->config_data, device);
}

void
nm_config_set_no_auto_default_for_device (NMConfig *self, NMDevice *device)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (self);
	GError *error = NULL;
	NMConfigData *new_data = NULL;
	const char *hw_address;
	const char *const*no_auto_default_current;
	GPtrArray *no_auto_default_new = NULL;
	guint i;

	g_return_if_fail (NM_IS_CONFIG (self));
	g_return_if_fail (NM_IS_DEVICE (device));

	hw_address = nm_device_get_hw_address (device);

	no_auto_default_current = nm_config_data_get_no_auto_default (priv->config_data);

	if (_nm_utils_strv_find_first ((char **) no_auto_default_current, -1, hw_address) >= 0) {
		/* @hw_address is already blocked. We don't have to update our in-memory representation.
		 * Maybe we should write to no_auto_default_file anew, but let's save that too. */
		return;
	}

	no_auto_default_new = g_ptr_array_new ();
	for (i = 0; no_auto_default_current && no_auto_default_current[i]; i++)
		g_ptr_array_add (no_auto_default_new, (char *) no_auto_default_current[i]);
	g_ptr_array_add (no_auto_default_new, (char *) hw_address);
	g_ptr_array_add (no_auto_default_new, NULL);

	if (!no_auto_default_to_file (priv->no_auto_default_file, (const char *const*) no_auto_default_new->pdata, &error)) {
		nm_log_warn (LOGD_SETTINGS, "Could not update no-auto-default.state file: %s",
		             error->message);
		g_error_free (error);
	}

	new_data = nm_config_data_new_update_no_auto_default (priv->config_data, (const char *const*) no_auto_default_new->pdata);

	/* unref no_auto_default_set here. Note that _set_config_data() probably invalidates the content of the array. */
	g_ptr_array_unref (no_auto_default_new);

	_set_config_data (self, new_data, 0);
}

/************************************************************************/

static void
_nm_config_cmd_line_options_clear (NMConfigCmdLineOptions *cli)
{
	g_clear_pointer (&cli->config_main_file, g_free);
	g_clear_pointer (&cli->config_dir, g_free);
	g_clear_pointer (&cli->no_auto_default_file, g_free);
	g_clear_pointer (&cli->plugins, g_free);
	cli->configure_and_quit = FALSE;
	g_clear_pointer (&cli->connectivity_uri, g_free);
	g_clear_pointer (&cli->connectivity_response, g_free);
	cli->connectivity_interval = -1;
}

static void
_nm_config_cmd_line_options_copy (const NMConfigCmdLineOptions *cli, NMConfigCmdLineOptions *dst)
{
	g_return_if_fail (cli);
	g_return_if_fail (dst);
	g_return_if_fail (cli != dst);

	_nm_config_cmd_line_options_clear (dst);
	dst->config_dir = g_strdup (cli->config_dir);
	dst->config_main_file = g_strdup (cli->config_main_file);
	dst->no_auto_default_file = g_strdup (cli->no_auto_default_file);
	dst->plugins = g_strdup (cli->plugins);
	dst->configure_and_quit = cli->configure_and_quit;
	dst->connectivity_uri = g_strdup (cli->connectivity_uri);
	dst->connectivity_response = g_strdup (cli->connectivity_response);
	dst->connectivity_interval = cli->connectivity_interval;
}

NMConfigCmdLineOptions *
nm_config_cmd_line_options_new ()
{
	NMConfigCmdLineOptions *cli = g_new0 (NMConfigCmdLineOptions, 1);

	_nm_config_cmd_line_options_clear (cli);
	return cli;
}

void
nm_config_cmd_line_options_free (NMConfigCmdLineOptions *cli)
{
	g_return_if_fail (cli);

	_nm_config_cmd_line_options_clear (cli);
	g_free (cli);
}

void
nm_config_cmd_line_options_add_to_entries (NMConfigCmdLineOptions *cli,
                                           GOptionContext *opt_ctx)
{
	g_return_if_fail (opt_ctx);
	g_return_if_fail (cli);

	{
		GOptionEntry config_options[] = {
			{ "config", 0, 0, G_OPTION_ARG_FILENAME, &cli->config_main_file, N_("Config file location"), N_(DEFAULT_CONFIG_MAIN_FILE) },
			{ "config-dir", 0, 0, G_OPTION_ARG_FILENAME, &cli->config_dir, N_("Config directory location"), N_(DEFAULT_CONFIG_DIR) },
			{ "no-auto-default", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_FILENAME, &cli->no_auto_default_file, N_("State file for no-auto-default devices"), N_(DEFAULT_NO_AUTO_DEFAULT_FILE) },
			{ "plugins", 0, 0, G_OPTION_ARG_STRING, &cli->plugins, N_("List of plugins separated by ','"), N_(CONFIG_PLUGINS_DEFAULT) },
			{ "configure-and-quit", 0, 0, G_OPTION_ARG_NONE, &cli->configure_and_quit, N_("Quit after initial configuration"), NULL },

				/* These three are hidden for now, and should eventually just go away. */
			{ "connectivity-uri", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &cli->connectivity_uri, N_("An http(s) address for checking internet connectivity"), "http://example.com" },
			{ "connectivity-interval", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_INT, &cli->connectivity_interval, N_("The interval between connectivity checks (in seconds)"), G_STRINGIFY (NM_CONFIG_DEFAULT_CONNECTIVITY_INTERVAL) },
			{ "connectivity-response", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &cli->connectivity_response, N_("The expected start of the response"), N_(NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE) },
			{ 0 },
		};

		g_option_context_add_main_entries (opt_ctx, config_options, NULL);
	}
}

/************************************************************************/

GKeyFile *
nm_config_create_keyfile ()
{
	GKeyFile *keyfile;

	keyfile = g_key_file_new ();
	g_key_file_set_list_separator (keyfile, NM_CONFIG_KEYFILE_LIST_SEPARATOR);
	return keyfile;
}

static int
_sort_groups_cmp (const char **pa, const char **pb, gpointer dummy)
{
	const char *a, *b;
	gboolean a_is_connection, b_is_connection;

	/* basic NULL checking... */
	if (pa == pb)
		return 0;
	if (!pa)
		return -1;
	if (!pb)
		return 1;

	a = *pa;
	b = *pb;

	a_is_connection = g_str_has_prefix (a, NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION);
	b_is_connection = g_str_has_prefix (b, NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION);

	if (a_is_connection != b_is_connection) {
		/* one is a [connection*] entry, the other not. We sort [connection*] entires
		 * after.  */
		if (a_is_connection)
			return 1;
		return -1;
	}
	if (!a_is_connection) {
		/* both are non-connection entries. Don't reorder. */
		return 0;
	}

	/* both are [connection.\+] entires. Reverse their order.
	 * One of the sections might be literally [connection]. That section
	 * is special and it's order will be fixed later. It doesn't actually
	 * matter here how it compares with [connection.\+] sections. */
	return pa > pb ? -1 : 1;
}

static gboolean
read_config (GKeyFile *keyfile, const char *path, GError **error)
{
	GKeyFile *kf;
	char **groups, **keys;
	gsize ngroups, nkeys;
	int g, k;

	g_return_val_if_fail (keyfile, FALSE);
	g_return_val_if_fail (path, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (g_file_test (path, G_FILE_TEST_EXISTS) == FALSE) {
		g_set_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND, "file %s not found", path);
		return FALSE;
	}

	nm_log_dbg (LOGD_SETTINGS, "Reading config file '%s'", path);

	kf = nm_config_create_keyfile ();
	if (!g_key_file_load_from_file (kf, path, G_KEY_FILE_NONE, error)) {
		g_key_file_free (kf);
		return FALSE;
	}

	/* Override the current settings with the new ones */
	groups = g_key_file_get_groups (kf, &ngroups);
	if (!groups)
		ngroups = 0;

	/* Within one file we reverse the order of the '[connection.\+] sections.
	 * Here we merge the current file (@kf) into @keyfile. As we merge multiple
	 * files, earlier sections (with lower priority) will be added first.
	 * But within one file, we want a top-to-bottom order. This means we
	 * must reverse the order within each file.
	 * At the very end, we will revert the order of all sections again and
	 * get thus the right behavior. This final reversing is done in
	 * NMConfigData:_get_connection_infos().  */
	if (ngroups > 1) {
		g_qsort_with_data (groups,
		                   ngroups,
		                   sizeof (char *),
		                   (GCompareDataFunc) _sort_groups_cmp,
		                   NULL);
	}

	for (g = 0; groups[g]; g++) {
		const char *group = groups[g];

		keys = g_key_file_get_keys (kf, group, &nkeys, NULL);
		if (!keys)
			continue;
		for (k = 0; keys[k]; k++) {
			const char *key;
			char *new_value;
			char last_char;
			gsize key_len;

			key = keys[k];
			g_assert (key && *key);
			key_len = strlen (key);
			last_char = key[key_len - 1];
			if (   key_len > 1
			    && (last_char == '+' || last_char == '-')) {
				gs_free char *base_key = g_strndup (key, key_len - 1);
				gs_strfreev  char **old_val = g_key_file_get_string_list (keyfile, group, base_key, NULL, NULL);
				gs_free char **new_val = g_key_file_get_string_list (kf, group, key, NULL, NULL);
				gs_unref_ptrarray GPtrArray *new = g_ptr_array_new_with_free_func (g_free);
				char **iter_val;

				for (iter_val = old_val; iter_val && *iter_val; iter_val++) {
					if (   last_char != '-'
					    || _nm_utils_strv_find_first (new_val, -1, *iter_val) < 0)
						g_ptr_array_add (new, g_strdup (*iter_val));
				}
				for (iter_val = new_val; iter_val && *iter_val; iter_val++) {
					/* don't add duplicates. That means an "option=a,b"; "option+=a,c" results in "option=a,b,c" */
					if (   last_char == '+'
					    && _nm_utils_strv_find_first (old_val, -1, *iter_val) < 0)
						g_ptr_array_add (new, *iter_val);
					else
						g_free (*iter_val);
				}

				if (new->len > 0)
					nm_config_keyfile_set_string_list (keyfile, group, base_key, (const char *const*) new->pdata, new->len);
				else
					g_key_file_remove_key (keyfile, group, base_key, NULL);
				continue;
			}

			new_value = g_key_file_get_value (kf, group, key, NULL);
			g_key_file_set_value (keyfile, group, key, new_value);
			g_free (new_value);
		}
		g_strfreev (keys);
	}
	g_strfreev (groups);
	g_key_file_free (kf);

	return TRUE;
}

static gboolean
read_base_config (GKeyFile *keyfile,
                  const char *cli_config_main_file,
                  char **out_config_main_file,
                  GError **error)
{
	GError *my_error = NULL;

	g_return_val_if_fail (keyfile, FALSE);
	g_return_val_if_fail (out_config_main_file && !*out_config_main_file, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* Try a user-specified config file first */
	if (cli_config_main_file) {
		/* Bad user-specific config file path is a hard error */
		if (read_config (keyfile, cli_config_main_file, error)) {
			*out_config_main_file = g_strdup (cli_config_main_file);
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
	if (read_config (keyfile, DEFAULT_CONFIG_MAIN_FILE_OLD, &my_error)) {
		*out_config_main_file = g_strdup (DEFAULT_CONFIG_MAIN_FILE_OLD);
		return TRUE;
	}

	if (!g_error_matches (my_error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)) {
		nm_log_warn (LOGD_CORE, "Old default config file %s invalid: %s\n",
		             DEFAULT_CONFIG_MAIN_FILE_OLD,
		             my_error->message);
	}
	g_clear_error (&my_error);

	/* Try the standard config file location next */
	if (read_config (keyfile, DEFAULT_CONFIG_MAIN_FILE, &my_error)) {
		*out_config_main_file = g_strdup (DEFAULT_CONFIG_MAIN_FILE);
		return TRUE;
	}

	if (!g_error_matches (my_error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)) {
		nm_log_warn (LOGD_CORE, "Default config file %s invalid: %s\n",
		             DEFAULT_CONFIG_MAIN_FILE,
		             my_error->message);
		g_propagate_error (error, my_error);
		return FALSE;
	}
	g_clear_error (&my_error);

	/* If for some reason no config file exists, use the default
	 * config file path.
	 */
	*out_config_main_file = g_strdup (DEFAULT_CONFIG_MAIN_FILE);
	nm_log_info (LOGD_CORE, "No config file found or given; using %s\n",
	             DEFAULT_CONFIG_MAIN_FILE);
	return TRUE;
}

static int
sort_asciibetically (gconstpointer a, gconstpointer b)
{
	const char *s1 = *(const char **)a;
	const char *s2 = *(const char **)b;

	return strcmp (s1, s2);
}

static GPtrArray *
_get_config_dir_files (const char *config_main_file,
                       const char *config_dir,
                       char **out_config_description)
{
	GFile *dir;
	GFileEnumerator *direnum;
	GFileInfo *info;
	GPtrArray *confs;
	GString *config_description;
	const char *name;
	guint i;

	g_return_val_if_fail (config_main_file, NULL);
	g_return_val_if_fail (config_dir, NULL);
	g_return_val_if_fail (out_config_description && !*out_config_description, NULL);

	confs = g_ptr_array_new_with_free_func (g_free);
	config_description = g_string_new (config_main_file);
	dir = g_file_new_for_path (config_dir);
	direnum = g_file_enumerate_children (dir, G_FILE_ATTRIBUTE_STANDARD_NAME, 0, NULL, NULL);
	if (direnum) {
		while ((info = g_file_enumerator_next_file (direnum, NULL, NULL))) {
			name = g_file_info_get_name (info);
			if (g_str_has_suffix (name, ".conf"))
				g_ptr_array_add (confs, g_strdup (name));
			g_object_unref (info);
		}
		g_object_unref (direnum);
	}
	g_object_unref (dir);

	if (confs->len > 0) {
		g_ptr_array_sort (confs, sort_asciibetically);
		g_string_append (config_description, " and conf.d: ");
		for (i = 0; i < confs->len; i++) {
			char *n = confs->pdata[i];

			if (i > 0)
				g_string_append (config_description, ", ");
			g_string_append (config_description, n);
			confs->pdata[i] = g_build_filename (config_dir, n, NULL);
			g_free (n);
		}
	}

	*out_config_description = g_string_free (config_description, FALSE);
	return confs;
}

static GKeyFile *
read_entire_config (const NMConfigCmdLineOptions *cli,
                    const char *config_dir,
                    char **out_config_main_file,
                    char **out_config_description,
                    GError **error)
{
	GKeyFile *keyfile = nm_config_create_keyfile ();
	GPtrArray *confs;
	guint i;
	char *o_config_main_file = NULL;
	char *o_config_description = NULL;
	char **plugins_tmp;

	g_return_val_if_fail (config_dir, NULL);
	g_return_val_if_fail (out_config_main_file && !*out_config_main_file, FALSE);
	g_return_val_if_fail (out_config_description && !*out_config_description, NULL);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* First read the base config file */
	if (!read_base_config (keyfile, cli ? cli->config_main_file : NULL, &o_config_main_file, error)) {
		g_key_file_free (keyfile);
		return NULL;
	}

	g_assert (o_config_main_file);

	confs = _get_config_dir_files (o_config_main_file, config_dir, &o_config_description);
	for (i = 0; i < confs->len; i++) {
		if (!read_config (keyfile, confs->pdata[i], error)) {
			g_key_file_free (keyfile);
			g_free (o_config_main_file);
			g_free (o_config_description);
			g_ptr_array_unref (confs);
			return NULL;
		}
	}
	g_ptr_array_unref (confs);

	/* Merge settings from command line. They overwrite everything read from
	 * config files. */

	if (cli && cli->plugins && cli->plugins[0])
		g_key_file_set_value (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "plugins", cli->plugins);
	plugins_tmp = g_key_file_get_string_list (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "plugins", NULL, NULL);
	if (!plugins_tmp) {
		if (STRLEN (CONFIG_PLUGINS_DEFAULT) > 0)
			g_key_file_set_value (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "plugins", CONFIG_PLUGINS_DEFAULT);
	} else
		g_strfreev (plugins_tmp);

	if (cli && cli->configure_and_quit)
		g_key_file_set_boolean (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "configure-and-quit", TRUE);

	if (cli && cli->connectivity_uri && cli->connectivity_uri[0])
		g_key_file_set_string (keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY, "uri", cli->connectivity_uri);
	if (cli && cli->connectivity_interval >= 0)
		g_key_file_set_integer (keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY, "interval", cli->connectivity_interval);
	if (cli && cli->connectivity_response && cli->connectivity_response[0])
		g_key_file_set_string (keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY, "response", cli->connectivity_response);

	*out_config_main_file = o_config_main_file;
	*out_config_description = o_config_description;
	return keyfile;
}

GSList *
nm_config_get_device_match_spec (const GKeyFile *keyfile, const char *group, const char *key, gboolean *out_has_key)
{
	gs_free char *value = NULL;

	/* nm_match_spec_split() already supports full escaping and is basically
	 * a modified version of g_key_file_parse_value_as_string(). So we first read
	 * the raw value (g_key_file_get_value()), and do the parsing ourselves. */
	value = g_key_file_get_value ((GKeyFile *) keyfile, group, key, NULL);
	if (out_has_key)
		*out_has_key = !!value;
	return nm_match_spec_split (value);
}

/************************************************************************/

void
nm_config_reload (NMConfig *self, int signal)
{
	NMConfigPrivate *priv;
	GError *error = NULL;
	GKeyFile *keyfile;
	NMConfigData *new_data = NULL;
	char *config_main_file = NULL;
	char *config_description = NULL;
	gs_strfreev char **no_auto_default = NULL;

	g_return_if_fail (NM_IS_CONFIG (self));

	priv = NM_CONFIG_GET_PRIVATE (self);

	if (signal != SIGHUP) {
		_set_config_data (self, NULL, signal);
		return;
	}

	/* pass on the original command line options. This means, that
	 * options specified at command line cannot ever be reloaded from
	 * file. That seems desirable.
	 */
	keyfile = read_entire_config (&priv->cli,
	                              priv->config_dir,
	                              &config_main_file,
	                              &config_description,
	                              &error);
	if (!keyfile) {
		nm_log_err (LOGD_CORE, "Failed to reload the configuration: %s", error->message);
		g_clear_error (&error);
		_set_config_data (self, NULL, signal);
		return;
	}
	no_auto_default = no_auto_default_from_file (priv->no_auto_default_file);

	new_data = nm_config_data_new (config_main_file, config_description, (const char *const*) no_auto_default, keyfile);
	g_free (config_main_file);
	g_free (config_description);
	g_key_file_unref (keyfile);

	_set_config_data (self, new_data, signal);
}

static const char *
_change_flags_one_to_string (NMConfigChangeFlags flag)
{
	switch (flag) {
	case NM_CONFIG_CHANGE_SIGHUP:
		return "SIGHUP";
	case NM_CONFIG_CHANGE_SIGUSR1:
		return "SIGUSR1";
	case NM_CONFIG_CHANGE_SIGUSR2:
		return "SIGUSR2";
	case NM_CONFIG_CHANGE_CONFIG_FILES:
		return "config-files";
	case NM_CONFIG_CHANGE_VALUES:
		return "values";
	case NM_CONFIG_CHANGE_CONNECTIVITY:
		return "connectivity";
	case NM_CONFIG_CHANGE_NO_AUTO_DEFAULT:
		return "no-auto-default";
	case NM_CONFIG_CHANGE_DNS_MODE:
		return "dns-mode";
	case NM_CONFIG_CHANGE_RC_MANAGER:
		return "rc-manager";
	default:
		g_return_val_if_reached ("unknown");
	}
}

char *
nm_config_change_flags_to_string (NMConfigChangeFlags flags)
{
	GString *str = g_string_new ("");
	NMConfigChangeFlags s = 0x01;

	while (flags) {
		if (NM_FLAGS_HAS (flags, s)) {
			if (str->len)
				g_string_append_c (str, ',');
			g_string_append (str, _change_flags_one_to_string (s));
		}
		flags = flags & ~s;
		s <<= 1;
	}
	return g_string_free (str, FALSE);
}

static void
_set_config_data (NMConfig *self, NMConfigData *new_data, int signal)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (self);
	NMConfigData *old_data = priv->config_data;
	NMConfigChangeFlags changes, changes_diff;
	gs_free char *log_str = NULL;
	gboolean had_new_data = !!new_data;

	switch (signal) {
	case SIGHUP:
		changes = NM_CONFIG_CHANGE_SIGHUP;
		break;
	case SIGUSR1:
		changes = NM_CONFIG_CHANGE_SIGUSR1;
		break;
	case SIGUSR2:
		changes = NM_CONFIG_CHANGE_SIGUSR2;
		break;
	default:
		changes = NM_CONFIG_CHANGE_NONE;
		break;
	}

	if (new_data) {
		changes_diff = nm_config_data_diff (old_data, new_data);
		if (changes_diff == NM_CONFIG_CHANGE_NONE)
			g_clear_object (&new_data);
		else
			changes |= changes_diff;
	}

	if (changes == NM_CONFIG_CHANGE_NONE)
		return;

	if (new_data) {
		nm_log_info (LOGD_CORE, "config: update %s (%s)", nm_config_data_get_config_description (new_data),
		             (log_str = nm_config_change_flags_to_string (changes)));
		nm_config_data_log (new_data, "CONFIG: ");
		priv->config_data = new_data;
	} else if (had_new_data)
		nm_log_info (LOGD_CORE, "config: signal %s (no changes from disk)", (log_str = nm_config_change_flags_to_string (changes)));
	else
		nm_log_info (LOGD_CORE, "config: signal %s", (log_str = nm_config_change_flags_to_string (changes)));
	g_signal_emit (self, signals[SIGNAL_CONFIG_CHANGED], 0,
	               new_data ? new_data : old_data,
	               changes, old_data);
	if (new_data)
		g_object_unref (old_data);
}

NM_DEFINE_SINGLETON_DESTRUCTOR (NMConfig);
NM_DEFINE_SINGLETON_WEAK_REF (NMConfig);

NMConfig *
nm_config_get (void)
{
	g_assert (singleton_instance);
	return singleton_instance;
}

NMConfig *
nm_config_setup (const NMConfigCmdLineOptions *cli, GError **error)
{
	g_assert (!singleton_instance);

	singleton_instance = nm_config_new (cli, error);
	if (singleton_instance)
		nm_singleton_instance_weak_ref_register ();
	return singleton_instance;
}

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMConfig *self = NM_CONFIG (initable);
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (self);
	GKeyFile *keyfile;
	char *config_main_file = NULL;
	char *config_description = NULL;
	gs_strfreev char **no_auto_default = NULL;

	if (priv->config_dir) {
		/* Object is already initialized. */
		if (priv->config_data)
			return TRUE;
		g_set_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND, "unspecified error");
		return FALSE;
	}

	if (priv->cli.config_dir)
		priv->config_dir = g_strdup (priv->cli.config_dir);
	else
		priv->config_dir = g_strdup (DEFAULT_CONFIG_DIR);

	keyfile = read_entire_config (&priv->cli,
	                              priv->config_dir,
	                              &config_main_file,
	                              &config_description,
	                              error);
	if (!keyfile)
		return FALSE;

	/* Initialize read only private members */

	if (priv->cli.no_auto_default_file)
		priv->no_auto_default_file = g_strdup (priv->cli.no_auto_default_file);
	else
		priv->no_auto_default_file = g_strdup (DEFAULT_NO_AUTO_DEFAULT_FILE);

	priv->plugins = _nm_utils_strv_cleanup (g_key_file_get_string_list (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "plugins", NULL, NULL),
	                                        TRUE, TRUE, TRUE);
	if (!priv->plugins)
		priv->plugins = g_new0 (char *, 1);

	priv->monitor_connection_files = nm_config_keyfile_get_boolean (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "monitor-connection-files", FALSE);

	priv->auth_polkit = nm_config_keyfile_get_boolean (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "auth-polkit", NM_CONFIG_DEFAULT_AUTH_POLKIT);

	priv->dhcp_client = nm_strstrip (g_key_file_get_string (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "dhcp", NULL));

	priv->log_level = nm_strstrip (g_key_file_get_string (keyfile, NM_CONFIG_KEYFILE_GROUP_LOGGING, "level", NULL));
	priv->log_domains = nm_strstrip (g_key_file_get_string (keyfile, NM_CONFIG_KEYFILE_GROUP_LOGGING, "domains", NULL));

	priv->debug = g_key_file_get_string (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "debug", NULL);

	priv->configure_and_quit = nm_config_keyfile_get_boolean (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "configure-and-quit", FALSE);

	no_auto_default = no_auto_default_from_file (priv->no_auto_default_file);

	priv->config_data_orig = nm_config_data_new (config_main_file, config_description, (const char *const*) no_auto_default, keyfile);

	priv->config_data = g_object_ref (priv->config_data_orig);

	g_free (config_main_file);
	g_free (config_description);
	g_key_file_unref (keyfile);
	return TRUE;
}

NMConfig *
nm_config_new (const NMConfigCmdLineOptions *cli, GError **error)
{
	return NM_CONFIG (g_initable_new (NM_TYPE_CONFIG,
	                                  NULL,
	                                  error,
	                                  NM_CONFIG_CMD_LINE_OPTIONS, cli,
	                                  NULL));
}

static void
nm_config_init (NMConfig *config)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (config);

	priv->auth_polkit = NM_CONFIG_DEFAULT_AUTH_POLKIT;
}

static void
finalize (GObject *gobject)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (gobject);

	g_free (priv->config_dir);
	g_free (priv->no_auto_default_file);
	g_strfreev (priv->plugins);
	g_free (priv->dhcp_client);
	g_free (priv->log_level);
	g_free (priv->log_domains);
	g_free (priv->debug);

	_nm_config_cmd_line_options_clear (&priv->cli);

	g_clear_object (&priv->config_data);
	g_clear_object (&priv->config_data_orig);

	G_OBJECT_CLASS (nm_config_parent_class)->finalize (gobject);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMConfig *self = NM_CONFIG (object);
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (self);
	NMConfigCmdLineOptions *cli;

	switch (prop_id) {
	case PROP_CMD_LINE_OPTIONS:
		/* construct only */
		cli = g_value_get_pointer (value);
		if (!cli)
			_nm_config_cmd_line_options_clear (&priv->cli);
		else
			_nm_config_cmd_line_options_copy (cli, &priv->cli);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_config_class_init (NMConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	g_type_class_add_private (config_class, sizeof (NMConfigPrivate));
	object_class->finalize = finalize;
	object_class->set_property = set_property;

	g_object_class_install_property
	    (object_class, PROP_CMD_LINE_OPTIONS,
	     g_param_spec_pointer (NM_CONFIG_CMD_LINE_OPTIONS, "", "",
	                           G_PARAM_WRITABLE |
	                           G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS));

	signals[SIGNAL_CONFIG_CHANGED] =
	    g_signal_new (NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  G_STRUCT_OFFSET (NMConfigClass, config_changed),
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 3, NM_TYPE_CONFIG_DATA, NM_TYPE_CONFIG_CHANGE_FLAGS, NM_TYPE_CONFIG_DATA);
}

static void
nm_config_initable_iface_init (GInitableIface *iface)
{
	iface->init = init_sync;
}

