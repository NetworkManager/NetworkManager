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

#include "nm-default.h"

#include "nm-config.h"

#include <stdio.h>

#include "nm-utils.h"
#include "devices/nm-device.h"
#include "NetworkManagerUtils.h"
#include "nm-core-internal.h"
#include "nm-keyfile-internal.h"

#define DEFAULT_CONFIG_MAIN_FILE        NMCONFDIR "/NetworkManager.conf"
#define DEFAULT_CONFIG_DIR              NMCONFDIR "/conf.d"
#define DEFAULT_CONFIG_MAIN_FILE_OLD    NMCONFDIR "/nm-system-settings.conf"
#define DEFAULT_SYSTEM_CONFIG_DIR       NMLIBDIR  "/conf.d"
#define RUN_CONFIG_DIR                  NMRUNDIR  "/conf.d"
#define DEFAULT_NO_AUTO_DEFAULT_FILE    NMSTATEDIR "/no-auto-default.state"
#define DEFAULT_INTERN_CONFIG_FILE      NMSTATEDIR "/NetworkManager-intern.conf"
#define DEFAULT_STATE_FILE              NMSTATEDIR "/NetworkManager.state"

/*****************************************************************************/

struct NMConfigCmdLineOptions {
	char *config_main_file;
	char *intern_config_file;
	char *config_dir;
	char *system_config_dir;
	char *state_file;
	char *no_auto_default_file;
	char *plugins;
	NMConfigConfigureAndQuitType configure_and_quit;

	gboolean is_debug;
	char *connectivity_uri;

	/* We store interval as signed internally to track whether it's
	 * set or not via GOptionEntry
	 */
	int connectivity_interval;
	char *connectivity_response;

	/* @first_start is not provided by command line. It is a convenient hack
	 * to pass in an argument to NMConfig. This makes NMConfigCmdLineOptions a
	 * misnomer.
	 *
	 * It is true, if NM is started the first time -- contrary to a restart
	 * during the same boot up. That is determined by the content of the
	 * /run/NetworManager state directory. */
	bool first_start;
};

typedef struct {
	NMConfigState p;
} State;

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_CMD_LINE_OPTIONS,
	PROP_ATOMIC_SECTION_PREFIXES,
);

enum {
	SIGNAL_CONFIG_CHANGED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct {
	NMConfigCmdLineOptions cli;

	NMConfigData *config_data;
	NMConfigData *config_data_orig;

	char *config_dir;
	char *system_config_dir;
	char *no_auto_default_file;
	char *intern_config_file;

	char *log_level;
	char *log_domains;

	NMConfigConfigureAndQuitType configure_and_quit;

	char **atomic_section_prefixes;

	/* The state. This is actually a mutable data member and it makes sense:
	 * The regular config is immutable (NMConfigData) and can old be swapped
	 * as a whole (via nm_config_set_values() or during reload). Thus, it can
	 * be changed, but it is still immutable and is swapped atomically as a
	 * whole. Also, we emit a config-changed signal on that occasion.
	 *
	 * For state, there are no events. You can query it and set it.
	 * It only gets read *once* at startup, and later is cached and only
	 * written out to disk. Hence, no need for the immutable dance here
	 * because the state changes only on explicit actions from the daemon
	 * itself. */
	State *state;

	/* the hash table of device states. It is only loaded from disk
	 * once and kept immutable afterwards.
	 *
	 * We also read all state file at once. We don't want to support
	 * that they are changed outside of NM (at least not while NM is running).
	 * Hence, we read them once, that's it. */
	GHashTable *device_states;

	char **warnings;
} NMConfigPrivate;

struct _NMConfig {
	GObject parent;
	NMConfigPrivate _priv;
};

struct _NMConfigClass {
	GObjectClass parent;
};

static void nm_config_initable_iface_init (GInitableIface *iface);

G_DEFINE_TYPE_WITH_CODE (NMConfig, nm_config, G_TYPE_OBJECT,
                         G_IMPLEMENT_INTERFACE (G_TYPE_INITABLE, nm_config_initable_iface_init);
                         )

#define NM_CONFIG_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMConfig, NM_IS_CONFIG)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_CORE
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "config", __VA_ARGS__)

/*****************************************************************************/

static void _set_config_data (NMConfig *self, NMConfigData *new_data, NMConfigChangeFlags reload_flags);

/*****************************************************************************/

#define _HAS_PREFIX(str, prefix) \
	({ \
		const char *_str = (str); \
		g_str_has_prefix ( _str, ""prefix"") && _str[NM_STRLEN(prefix)] != '\0'; \
	})

/*****************************************************************************/

int
nm_config_parse_boolean (const char *str,
                         int default_value)
{
	return _nm_utils_ascii_str_to_bool (str, default_value);
}

int
nm_config_keyfile_get_boolean (const GKeyFile *keyfile,
                               const char *section,
                               const char *key,
                               int default_value)
{
	gs_free char *str = NULL;

	g_return_val_if_fail (keyfile != NULL, default_value);
	g_return_val_if_fail (section != NULL, default_value);
	g_return_val_if_fail (key != NULL, default_value);

	str = g_key_file_get_value ((GKeyFile *) keyfile, section, key, NULL);
	return nm_config_parse_boolean (str, default_value);
}

gint64
nm_config_keyfile_get_int64 (const GKeyFile *keyfile,
                             const char *section,
                             const char *key,
                             guint base,
                             gint64 min,
                             gint64 max,
                             gint64 fallback)
{
	gint64 v;
	int errsv;
	char *str;

	g_return_val_if_fail (keyfile, fallback);
	g_return_val_if_fail (section, fallback);
	g_return_val_if_fail (key, fallback);

	str = g_key_file_get_value ((GKeyFile *) keyfile, section, key, NULL);
	v = _nm_utils_ascii_str_to_int64 (str, base, min, max, fallback);
	if (str) {
		errsv = errno;
		g_free (str);
		errno = errsv;
	}
	return v;
}

char *
nm_config_keyfile_get_value (const GKeyFile *keyfile,
                             const char *section,
                             const char *key,
                             NMConfigGetValueFlags flags)
{
	char *value;

	if (NM_FLAGS_HAS (flags, NM_CONFIG_GET_VALUE_RAW))
		value = g_key_file_get_value ((GKeyFile *) keyfile, section, key, NULL);
	else
		value = g_key_file_get_string ((GKeyFile *) keyfile, section, key, NULL);

	if (!value)
		return NULL;

	if (NM_FLAGS_HAS (flags, NM_CONFIG_GET_VALUE_STRIP))
		g_strstrip (value);

	if (   NM_FLAGS_HAS (flags, NM_CONFIG_GET_VALUE_NO_EMPTY)
	    && !*value) {
		g_free (value);
		return NULL;
	}

	return value;
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

/*****************************************************************************/

const char *const*
nm_config_get_warnings (NMConfig *config)
{
	return (const char *const *) NM_CONFIG_GET_PRIVATE (config)->warnings;
}

void
nm_config_clear_warnings (NMConfig *config)
{
	g_clear_pointer (&NM_CONFIG_GET_PRIVATE (config)->warnings, g_strfreev);
}

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

NMConfigConfigureAndQuitType
nm_config_get_configure_and_quit (NMConfig *config)
{
	return NM_CONFIG_GET_PRIVATE (config)->configure_and_quit;
}

gboolean
nm_config_get_is_debug (NMConfig *config)
{
	return NM_CONFIG_GET_PRIVATE (config)->cli.is_debug;
}

gboolean
nm_config_get_first_start (NMConfig *config)
{
	return NM_CONFIG_GET_PRIVATE (config)->cli.first_start;
}

/*****************************************************************************/

static char **
no_auto_default_from_file (const char *no_auto_default_file)
{
	gs_free char *data = NULL;
	const char **list = NULL;
	gsize i;

	if (   no_auto_default_file
	    && g_file_get_contents (no_auto_default_file, &data, NULL, NULL))
		list = nm_utils_strsplit_set (data, "\n");

	if (list) {
		for (i = 0; list[i]; i++)
			list[i] = nm_utils_str_utf8safe_unescape_cp (list[i]);
	}

	/* The returned buffer here is not at all compact. That means, it has additional
	 * memory allocations and is larger than needed. That means, you should not keep
	 * this result around, only process it further and free it. */
	return (char **) list;
}

static gboolean
no_auto_default_to_file (const char *no_auto_default_file, const char *const*no_auto_default, GError **error)
{
	nm_auto_free_gstring GString *data = NULL;
	gsize i;

	data = g_string_new ("");
	for (i = 0; no_auto_default && no_auto_default[i]; i++) {
		gs_free char *s_to_free = NULL;
		const char *s = no_auto_default[i];

		s = nm_utils_str_utf8safe_escape (s,
		                                    NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_CTRL
		                                  | NM_UTILS_STR_UTF8_SAFE_FLAG_ESCAPE_NON_ASCII,
		                                  &s_to_free);
		g_string_append (data, s);
		g_string_append_c (data, '\n');
	}
	return  g_file_set_contents (no_auto_default_file, data->str, data->len, error);
}

gboolean
nm_config_get_no_auto_default_for_device (NMConfig *self, NMDevice *device)
{
	NMConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_CONFIG (self), FALSE);

	priv = NM_CONFIG_GET_PRIVATE (self);

	if (priv->configure_and_quit == NM_CONFIG_CONFIGURE_AND_QUIT_INITRD)
		return TRUE;

	return nm_config_data_get_no_auto_default_for_device (priv->config_data, device);
}

void
nm_config_set_no_auto_default_for_device (NMConfig *self, NMDevice *device)
{
	NMConfigPrivate *priv;
	GError *error = NULL;
	NMConfigData *new_data = NULL;
	gs_free char *spec_to_free = NULL;
	const char *ifname;
	const char *hw_address;
	const char *spec;
	const char *const*no_auto_default_current;
	gs_free const char **no_auto_default_new = NULL;
	gboolean is_fake;
	gsize len;
	gssize idx;

	g_return_if_fail (NM_IS_CONFIG (self));
	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_CONFIG_GET_PRIVATE (self);

	hw_address = nm_device_get_permanent_hw_address_full (device, TRUE, &is_fake);

	if (!hw_address) {
		/* No MAC address, not even a fake one. We don't do anything for this device. */
		return;
	}

	if (is_fake) {
		/* A fake MAC address, no point in storing it to the file.
		 * Also, nm_match_spec_device() would ignore fake MAC addresses.
		 *
		 * Instead, try the interface-name...  */
		ifname = nm_device_get_ip_iface (device);
		if (!nm_utils_is_valid_iface_name (ifname, NULL))
			return;

		spec_to_free = g_strdup_printf (NM_MATCH_SPEC_INTERFACE_NAME_TAG"=%s", ifname);
		spec = spec_to_free;
	} else
		spec = hw_address;

	no_auto_default_current = nm_config_data_get_no_auto_default (priv->config_data);

	len = NM_PTRARRAY_LEN (no_auto_default_current);

	idx = nm_utils_ptrarray_find_binary_search ((gconstpointer *) no_auto_default_current,
	                                            len,
	                                            spec,
	                                            nm_strcmp_with_data,
	                                            NULL,
	                                            NULL,
	                                            NULL);
	if (idx >= 0) {
		/* @spec is already blocked. We don't have to update our in-memory representation.
		 * Maybe we should write to no_auto_default_file anew, but let's save that too. */
		return;
	}

	idx = ~idx;

	no_auto_default_new = g_new (const char *, len + 2);
	if (idx > 0)
		memcpy (no_auto_default_new, no_auto_default_current, sizeof (const char *) * idx);
	no_auto_default_new[idx] = spec;
	if (idx < len)
		memcpy (&no_auto_default_new[idx + 1], &no_auto_default_current[idx], sizeof (const char *) * (len - idx));
	no_auto_default_new[len + 1] = NULL;

	if (!no_auto_default_to_file (priv->no_auto_default_file, no_auto_default_new, &error)) {
		_LOGW ("Could not update no-auto-default.state file: %s",
		       error->message);
		g_error_free (error);
	}

	new_data = nm_config_data_new_update_no_auto_default (priv->config_data, no_auto_default_new);

	_set_config_data (self, new_data, NM_CONFIG_CHANGE_CAUSE_NO_AUTO_DEFAULT);
}

/*****************************************************************************/

static void
_nm_config_cmd_line_options_clear (NMConfigCmdLineOptions *cli)
{
	g_clear_pointer (&cli->config_main_file, g_free);
	g_clear_pointer (&cli->config_dir, g_free);
	g_clear_pointer (&cli->system_config_dir, g_free);
	g_clear_pointer (&cli->no_auto_default_file, g_free);
	g_clear_pointer (&cli->intern_config_file, g_free);
	g_clear_pointer (&cli->state_file, g_free);
	g_clear_pointer (&cli->plugins, g_free);
	cli->configure_and_quit = NM_CONFIG_CONFIGURE_AND_QUIT_DISABLED;
	cli->is_debug = FALSE;
	g_clear_pointer (&cli->connectivity_uri, g_free);
	g_clear_pointer (&cli->connectivity_response, g_free);
	cli->connectivity_interval = -1;
	cli->first_start = FALSE;
}

static void
_nm_config_cmd_line_options_copy (const NMConfigCmdLineOptions *cli, NMConfigCmdLineOptions *dst)
{
	g_return_if_fail (cli);
	g_return_if_fail (dst);
	g_return_if_fail (cli != dst);

	_nm_config_cmd_line_options_clear (dst);
	dst->config_dir = g_strdup (cli->config_dir);
	dst->system_config_dir = g_strdup (cli->system_config_dir);
	dst->config_main_file = g_strdup (cli->config_main_file);
	dst->no_auto_default_file = g_strdup (cli->no_auto_default_file);
	dst->intern_config_file = g_strdup (cli->intern_config_file);
	dst->state_file = g_strdup (cli->state_file);
	dst->plugins = g_strdup (cli->plugins);
	dst->configure_and_quit = cli->configure_and_quit;
	dst->is_debug = cli->is_debug;
	dst->connectivity_uri = g_strdup (cli->connectivity_uri);
	dst->connectivity_response = g_strdup (cli->connectivity_response);
	dst->connectivity_interval = cli->connectivity_interval;
	dst->first_start = cli->first_start;
}

NMConfigCmdLineOptions *
nm_config_cmd_line_options_new (gboolean first_start)
{
	NMConfigCmdLineOptions *cli = g_new0 (NMConfigCmdLineOptions, 1);

	_nm_config_cmd_line_options_clear (cli);

	cli->first_start = first_start;

	return cli;
}

void
nm_config_cmd_line_options_free (NMConfigCmdLineOptions *cli)
{
	g_return_if_fail (cli);

	_nm_config_cmd_line_options_clear (cli);
	g_free (cli);
}

static NMConfigConfigureAndQuitType
string_to_configure_and_quit (const char *value, GError **error)
{
	NMConfigConfigureAndQuitType ret;

	if (value == NULL)
		return NM_CONFIG_CONFIGURE_AND_QUIT_DISABLED;

	if (strcmp (value, "initrd") == 0)
		return NM_CONFIG_CONFIGURE_AND_QUIT_INITRD;

	ret = nm_config_parse_boolean (value, NM_CONFIG_CONFIGURE_AND_QUIT_INVALID);
	if (ret == NM_CONFIG_CONFIGURE_AND_QUIT_INVALID)
		g_set_error (error, 1, 0, N_("'%s' is not valid"), value);

	return ret;
}

static gboolean
parse_configure_and_quit (const char *option_name, const char *value, gpointer user_data, GError **error)
{
	NMConfigCmdLineOptions *cli = user_data;

	if (value == NULL)
		cli->configure_and_quit = NM_CONFIG_CONFIGURE_AND_QUIT_ENABLED;
	else
		cli->configure_and_quit = string_to_configure_and_quit (value, error);

	if (cli->configure_and_quit == NM_CONFIG_CONFIGURE_AND_QUIT_INVALID) {
		g_prefix_error (error, N_("Bad '%s' option: "), option_name);
		return FALSE;
	}

	return TRUE;
}

void
nm_config_cmd_line_options_add_to_entries (NMConfigCmdLineOptions *cli,
                                           GOptionContext *opt_ctx)
{
	GOptionGroup *group;
	GOptionEntry config_options[] = {
		{ "config", 0, 0, G_OPTION_ARG_FILENAME, &cli->config_main_file, N_("Config file location"), DEFAULT_CONFIG_MAIN_FILE },
		{ "config-dir", 0, 0, G_OPTION_ARG_FILENAME, &cli->config_dir, N_("Config directory location"), DEFAULT_CONFIG_DIR },
		{ "system-config-dir", 0, 0, G_OPTION_ARG_FILENAME, &cli->system_config_dir, N_("System config directory location"), DEFAULT_SYSTEM_CONFIG_DIR },
		{ "intern-config", 0, 0, G_OPTION_ARG_FILENAME, &cli->intern_config_file, N_("Internal config file location"), DEFAULT_INTERN_CONFIG_FILE },
		{ "state-file", 0, 0, G_OPTION_ARG_FILENAME, &cli->state_file, N_("State file location"), DEFAULT_STATE_FILE },
		{ "no-auto-default", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_FILENAME, &cli->no_auto_default_file, N_("State file for no-auto-default devices"), DEFAULT_NO_AUTO_DEFAULT_FILE },
		{ "plugins", 0, 0, G_OPTION_ARG_STRING, &cli->plugins, N_("List of plugins separated by ','"), NM_CONFIG_DEFAULT_MAIN_PLUGINS },
		{ "configure-and-quit", 0, G_OPTION_FLAG_OPTIONAL_ARG, G_OPTION_ARG_CALLBACK, parse_configure_and_quit, N_("Quit after initial configuration"), NULL },
		{ "debug", 'd', 0, G_OPTION_ARG_NONE, &cli->is_debug, N_("Don't become a daemon, and log to stderr"), NULL },

			/* These three are hidden for now, and should eventually just go away. */
		{ "connectivity-uri", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &cli->connectivity_uri, N_("An http(s) address for checking internet connectivity"), "http://example.com" },
		{ "connectivity-interval", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_INT, &cli->connectivity_interval, N_("The interval between connectivity checks (in seconds)"), G_STRINGIFY (NM_CONFIG_DEFAULT_CONNECTIVITY_INTERVAL) },
		{ "connectivity-response", 0, G_OPTION_FLAG_HIDDEN, G_OPTION_ARG_STRING, &cli->connectivity_response, N_("The expected start of the response"), NM_CONFIG_DEFAULT_CONNECTIVITY_RESPONSE },
		{ 0 },
	};

	g_return_if_fail (opt_ctx);
	g_return_if_fail (cli);

	group = g_option_group_new ("nm", N_("NetworkManager options" ), N_("Show NetworkManager options"), cli, NULL);

	g_option_group_add_entries (group, config_options);
	g_option_context_add_group (opt_ctx, group);
}

/*****************************************************************************/

GKeyFile *
nm_config_create_keyfile ()
{
	GKeyFile *keyfile;

	keyfile = g_key_file_new ();
	g_key_file_set_list_separator (keyfile, NM_CONFIG_KEYFILE_LIST_SEPARATOR);
	return keyfile;
}

/* this is an external variable, to make loading testable. Other then that,
 * no code is supposed to change this. */
guint _nm_config_match_nm_version = NM_VERSION;
char *_nm_config_match_env = NULL;

static gboolean
ignore_config_snippet (GKeyFile *keyfile, gboolean is_base_config)
{
	GSList *specs;
	gboolean as_bool;
	NMMatchSpecMatchType match_type;

	if (is_base_config)
		return FALSE;

	if (!g_key_file_has_key (keyfile, NM_CONFIG_KEYFILE_GROUP_CONFIG, NM_CONFIG_KEYFILE_KEY_CONFIG_ENABLE, NULL))
		return FALSE;

	/* first, let's try to parse the value as plain boolean. If that is possible, we don't treat
	 * the value as match-spec. */
	as_bool = nm_config_keyfile_get_boolean (keyfile, NM_CONFIG_KEYFILE_GROUP_CONFIG, NM_CONFIG_KEYFILE_KEY_CONFIG_ENABLE, -1);
	if (as_bool != -1)
		return !as_bool;

	if (G_UNLIKELY (!_nm_config_match_env)) {
		const char *e;

		e = g_getenv ("NM_CONFIG_ENABLE_TAG");
		_nm_config_match_env = g_strdup (e ?: "");
	}

	/* second, interpret the value as match-spec. */
	specs = nm_config_get_match_spec (keyfile, NM_CONFIG_KEYFILE_GROUP_CONFIG, NM_CONFIG_KEYFILE_KEY_CONFIG_ENABLE, NULL);
	match_type = nm_match_spec_config (specs,
	                                   _nm_config_match_nm_version,
	                                   _nm_config_match_env);
	g_slist_free_full (specs, g_free);

	return match_type != NM_MATCH_SPEC_MATCH;
}

static int
_sort_groups_cmp (const char **pa, const char **pb, gpointer dummy)
{
	const char *a, *b;
	gboolean a_is_connection, b_is_connection;
	gboolean a_is_device, b_is_device;

	a = *pa;
	b = *pb;

	a_is_connection = g_str_has_prefix (a, NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION);
	b_is_connection = g_str_has_prefix (b, NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION);

	if (a_is_connection != b_is_connection) {
		/* one is a [connection*] entry, the other not. We sort [connection*] entries
		 * after.  */
		if (a_is_connection)
			return 1;
		return -1;
	}
	if (a_is_connection) {
		/* both are [connection.\+] entries. Reverse their order.
		 * One of the sections might be literally [connection]. That section
		 * is special and its order will be fixed later. It doesn't actually
		 * matter here how it compares with [connection.\+] sections. */
		return pa > pb ? -1 : 1;
	}

	a_is_device = g_str_has_prefix (a, NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE);
	b_is_device = g_str_has_prefix (b, NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE);

	if (a_is_device != b_is_device) {
		/* one is a [device*] entry, the other not. We sort [device*] entries
		 * after.  */
		if (a_is_device)
			return 1;
		return -1;
	}
	if (a_is_device) {
		/* both are [device.\+] entries. Reverse their order.
		 * One of the sections might be literally [device]. That section
		 * is special and its order will be fixed later. It doesn't actually
		 * matter here how it compares with [device.\+] sections. */
		return pa > pb ? -1 : 1;
	}

	/* don't reorder the rest. */
	return 0;
}

void
_nm_config_sort_groups (char **groups, gsize ngroups)
{
	if (ngroups > 1) {
		g_qsort_with_data (groups,
		                   ngroups,
		                   sizeof (char *),
		                   (GCompareDataFunc) _sort_groups_cmp,
		                   NULL);
	}
}

static gboolean
_setting_is_device_spec (const char *group, const char *key)
{
#define _IS(group_v, key_v) (strcmp (group, (""group_v)) == 0 && strcmp (key, (""key_v)) == 0)
	return    _IS (NM_CONFIG_KEYFILE_GROUP_MAIN, NM_CONFIG_KEYFILE_KEY_MAIN_NO_AUTO_DEFAULT)
	       || _IS (NM_CONFIG_KEYFILE_GROUP_MAIN, NM_CONFIG_KEYFILE_KEY_MAIN_IGNORE_CARRIER)
	       || _IS (NM_CONFIG_KEYFILE_GROUP_MAIN, NM_CONFIG_KEYFILE_KEY_MAIN_ASSUME_IPV6LL_ONLY)
	       || _IS (NM_CONFIG_KEYFILE_GROUP_KEYFILE, NM_CONFIG_KEYFILE_KEY_KEYFILE_UNMANAGED_DEVICES)
	       || (g_str_has_prefix (group, NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION) && !strcmp (key, NM_CONFIG_KEYFILE_KEY_MATCH_DEVICE))
	       || (g_str_has_prefix (group, NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE    ) && !strcmp (key, NM_CONFIG_KEYFILE_KEY_MATCH_DEVICE));
}

static gboolean
_setting_is_string_list (const char *group, const char *key)
{
	return    _IS (NM_CONFIG_KEYFILE_GROUP_MAIN, NM_CONFIG_KEYFILE_KEY_MAIN_PLUGINS)
	       || _IS (NM_CONFIG_KEYFILE_GROUP_MAIN, NM_CONFIG_KEYFILE_KEY_MAIN_DEBUG)
	       || _IS (NM_CONFIG_KEYFILE_GROUP_LOGGING, NM_CONFIG_KEYFILE_KEY_LOGGING_DOMAINS)
	       || g_str_has_prefix (group, NM_CONFIG_KEYFILE_GROUPPREFIX_TEST_APPEND_STRINGLIST);
#undef _IS
}

typedef struct {
	char *group;
	const char *const *keys;
	bool is_prefix:1;
	bool is_connection:1;
} ConfigGroup;

/* The following comment is used by check-config-options.sh, don't remove it. */
/* START OPTION LIST */

static const ConfigGroup config_groups[] = {
	{
		.group = NM_CONFIG_KEYFILE_GROUP_MAIN,
		.keys = NM_MAKE_STRV (
			NM_CONFIG_KEYFILE_KEY_MAIN_ASSUME_IPV6LL_ONLY,
			NM_CONFIG_KEYFILE_KEY_MAIN_AUTH_POLKIT,
			NM_CONFIG_KEYFILE_KEY_MAIN_AUTOCONNECT_RETRIES_DEFAULT,
			NM_CONFIG_KEYFILE_KEY_MAIN_CONFIGURE_AND_QUIT,
			NM_CONFIG_KEYFILE_KEY_MAIN_DEBUG,
			NM_CONFIG_KEYFILE_KEY_MAIN_DHCP,
			NM_CONFIG_KEYFILE_KEY_MAIN_DNS,
			NM_CONFIG_KEYFILE_KEY_MAIN_HOSTNAME_MODE,
			NM_CONFIG_KEYFILE_KEY_MAIN_IGNORE_CARRIER,
			NM_CONFIG_KEYFILE_KEY_MAIN_MONITOR_CONNECTION_FILES,
			NM_CONFIG_KEYFILE_KEY_MAIN_NO_AUTO_DEFAULT,
			NM_CONFIG_KEYFILE_KEY_MAIN_PLUGINS,
			NM_CONFIG_KEYFILE_KEY_MAIN_RC_MANAGER,
			NM_CONFIG_KEYFILE_KEY_MAIN_SLAVES_ORDER,
			NM_CONFIG_KEYFILE_KEY_MAIN_SYSTEMD_RESOLVED,
		),
	},
	{
		.group = NM_CONFIG_KEYFILE_GROUP_LOGGING,
		.keys = NM_MAKE_STRV (
			NM_CONFIG_KEYFILE_KEY_LOGGING_AUDIT,
			NM_CONFIG_KEYFILE_KEY_LOGGING_BACKEND,
			NM_CONFIG_KEYFILE_KEY_LOGGING_DOMAINS,
			NM_CONFIG_KEYFILE_KEY_LOGGING_LEVEL,
		),
	},
	{
		.group = NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY,
		.keys = NM_MAKE_STRV (
			NM_CONFIG_KEYFILE_KEY_CONNECTIVITY_ENABLED,
			NM_CONFIG_KEYFILE_KEY_CONNECTIVITY_INTERVAL,
			NM_CONFIG_KEYFILE_KEY_CONNECTIVITY_RESPONSE,
			NM_CONFIG_KEYFILE_KEY_CONNECTIVITY_URI,
		),
	},
	{
		.group = NM_CONFIG_KEYFILE_GROUP_KEYFILE,
		.keys = NM_MAKE_STRV (
			NM_CONFIG_KEYFILE_KEY_KEYFILE_HOSTNAME,
			NM_CONFIG_KEYFILE_KEY_KEYFILE_PATH,
			NM_CONFIG_KEYFILE_KEY_KEYFILE_UNMANAGED_DEVICES,
		),
	},
	{
		.group = NM_CONFIG_KEYFILE_GROUP_IFUPDOWN,
		.keys = NM_MAKE_STRV (
			NM_CONFIG_KEYFILE_KEY_IFUPDOWN_MANAGED,
		),
	},
	{
		.group = NM_CONFIG_KEYFILE_GROUPPREFIX_DEVICE,
		.is_prefix = TRUE,
		.keys = NM_MAKE_STRV (
			NM_CONFIG_KEYFILE_KEY_DEVICE_CARRIER_WAIT_TIMEOUT,
			NM_CONFIG_KEYFILE_KEY_DEVICE_IGNORE_CARRIER,
			NM_CONFIG_KEYFILE_KEY_DEVICE_MANAGED,
			NM_CONFIG_KEYFILE_KEY_DEVICE_SRIOV_NUM_VFS,
			NM_CONFIG_KEYFILE_KEY_DEVICE_WIFI_BACKEND,
			NM_CONFIG_KEYFILE_KEY_DEVICE_WIFI_SCAN_RAND_MAC_ADDRESS,
			NM_CONFIG_KEYFILE_KEY_MATCH_DEVICE,
			NM_CONFIG_KEYFILE_KEY_STOP_MATCH,
		),
	},
	{
		.group = NM_CONFIG_KEYFILE_GROUP_GLOBAL_DNS,
		.keys = NM_MAKE_STRV (
			NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_OPTIONS,
			NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_SEARCHES,
		),
	},
	{
		.group = NM_CONFIG_KEYFILE_GROUPPREFIX_GLOBAL_DNS_DOMAIN,
		.is_prefix = TRUE,
		.keys = NM_MAKE_STRV (
			NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_DOMAIN_SERVERS,
			NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_DOMAIN_OPTIONS,
		),
	},
	{
		.group = NM_CONFIG_KEYFILE_GROUPPREFIX_CONNECTION,
		.is_prefix = TRUE,
		.is_connection = TRUE,
		.keys = NM_MAKE_STRV (
			NM_CONFIG_KEYFILE_KEY_MATCH_DEVICE,
			NM_CONFIG_KEYFILE_KEY_STOP_MATCH,
		),
	},
	{ } /* sentinel */
};

/* The following comment is used by check-config-options.sh, don't remove it. */
/* END OPTION LIST */

static gboolean
check_config_key (const char *group, const char *key)
{
	const ConfigGroup *g;
	const char *const *k;
	const char **ptr;

#if NM_MORE_ASSERTS > 10
	{
		static gboolean checked = FALSE;
		const char **ptr1, **ptr2;

		/* check for duplicate elements in the static list */

		if (!checked) {
			for (ptr1 = __start_connection_defaults; ptr1 < __stop_connection_defaults; ptr1++) {
				for (ptr2 = ptr1 + 1; ptr2 < __stop_connection_defaults; ptr2++)
					nm_assert (!nm_streq (*ptr1, *ptr2));
			}
			checked = TRUE;
		}
	}
#endif

	for (g = config_groups; g->group; g++) {
		if (   (!g->is_prefix && nm_streq (group, g->group))
		    || (g->is_prefix && g_str_has_prefix (group, g->group)))
			break;
	}

	if (!g->group)
		return FALSE;

	for (k = g->keys; *k; k++) {
		if (nm_streq (key, *k))
			return TRUE;
	}

	if (g->is_connection) {
		for (ptr = __start_connection_defaults; ptr < __stop_connection_defaults; ptr++) {
			if (nm_streq (key, *ptr))
				return TRUE;
		}
		return FALSE;
	}

	return FALSE;
}

static gboolean
read_config (GKeyFile *keyfile, gboolean is_base_config,
             const char *dirname, const char *path,
             GPtrArray *warnings, GError **error)
{
	GKeyFile *kf;
	char **groups, **keys;
	gsize ngroups, nkeys;
	int g, k;
	gs_free char *path_free = NULL;

	g_return_val_if_fail (keyfile, FALSE);
	g_return_val_if_fail (path, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	if (dirname) {
		path_free = g_build_filename (dirname, path, NULL);
		path = path_free;
	}

	if (g_file_test (path, G_FILE_TEST_EXISTS) == FALSE) {
		g_set_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND, "file %s not found", path);
		return FALSE;
	}

	_LOGD ("Reading config file '%s'", path);

	kf = nm_config_create_keyfile ();
	if (!g_key_file_load_from_file (kf, path, G_KEY_FILE_NONE, error)) {
		g_prefix_error (error, "%s: ", path);
		g_key_file_free (kf);
		return FALSE;
	}

	if (ignore_config_snippet (kf, is_base_config)) {
		g_key_file_free (kf);
		return TRUE;
	}

	/* the config-group is internal to every configuration snippets. It doesn't make sense
	 * to merge it into the global configuration, and it doesn't make sense to preserve the
	 * group beyond this point. */
	g_key_file_remove_group (kf, NM_CONFIG_KEYFILE_GROUP_CONFIG, NULL);

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
	_nm_config_sort_groups (groups, ngroups);

	for (g = 0; groups && groups[g]; g++) {
		const char *group = groups[g];

		if (g_str_has_prefix (group, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN)) {
			/* internal groups cannot be set by user configuration. */
			continue;
		}
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

			if (   _HAS_PREFIX (key, NM_CONFIG_KEYFILE_KEYPREFIX_WAS)
			    || _HAS_PREFIX (key, NM_CONFIG_KEYFILE_KEYPREFIX_SET)) {
				/* these keys are protected. We ignore them if the user sets them. */
				continue;
			}

			if (!strcmp (key, NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS)) {
				/* the "was" key is protected and it cannot be set by user configuration. */
				continue;
			}

			key_len = strlen (key);
			last_char = key[key_len - 1];
			if (   key_len > 1
			    && (last_char == '+' || last_char == '-')) {
				gs_free char *base_key = g_strndup (key, key_len - 1);
				gboolean is_string_list;

				is_string_list = _setting_is_string_list (group, base_key);

				if (   is_string_list
				    || _setting_is_device_spec (group, base_key)) {
					gs_unref_ptrarray GPtrArray *new = g_ptr_array_new_with_free_func (g_free);
					char **iter_val;
					gs_strfreev  char **old_val = NULL;
					gs_free char **new_val = NULL;

					if (is_string_list) {
						old_val = g_key_file_get_string_list (keyfile, group, base_key, NULL, NULL);
						new_val = g_key_file_get_string_list (kf, group, key, NULL, NULL);
						if (!old_val && !g_key_file_has_key (keyfile, group, base_key, NULL)) {
							/* we must fill the unspecified value with the compile-time default. */
							if (nm_streq (group, NM_CONFIG_KEYFILE_GROUP_MAIN) && nm_streq (base_key, "plugins")) {
								g_key_file_set_value (keyfile, group, base_key, NM_CONFIG_DEFAULT_MAIN_PLUGINS);
								old_val = g_key_file_get_string_list (keyfile, group, base_key, NULL, NULL);
							}
						}
					} else {
						gs_free char *old_sval = nm_config_keyfile_get_value (keyfile, group, base_key, NM_CONFIG_GET_VALUE_TYPE_SPEC);
						gs_free char *new_sval = nm_config_keyfile_get_value (kf, group, key, NM_CONFIG_GET_VALUE_TYPE_SPEC);
						gs_free_slist GSList *old_specs = nm_match_spec_split (old_sval);
						gs_free_slist GSList *new_specs = nm_match_spec_split (new_sval);

						/* the key is a device spec. This is a special kind of string-list, that
						 * we must split differently. */
						old_val = _nm_utils_slist_to_strv (old_specs, FALSE);
						new_val = _nm_utils_slist_to_strv (new_specs, FALSE);
					}

					/* merge the string lists, by omitting duplicates. */

					for (iter_val = old_val; iter_val && *iter_val; iter_val++) {
						if (   last_char != '-'
						    || nm_utils_strv_find_first (new_val, -1, *iter_val) < 0)
							g_ptr_array_add (new, g_strdup (*iter_val));
					}
					for (iter_val = new_val; iter_val && *iter_val; iter_val++) {
						/* don't add duplicates. That means an "option=a,b"; "option+=a,c" results in "option=a,b,c" */
						if (   last_char == '+'
						    && nm_utils_strv_find_first (old_val, -1, *iter_val) < 0)
							g_ptr_array_add (new, *iter_val);
						else
							g_free (*iter_val);
					}

					if (new->len > 0) {
						if (is_string_list)
							nm_config_keyfile_set_string_list (keyfile, group, base_key, (const char *const*) new->pdata, new->len);
						else {
							gs_free_slist GSList *specs = NULL;
							gs_free char *specs_joined = NULL;

							g_ptr_array_add (new, NULL);
							specs = _nm_utils_strv_to_slist ((char **) new->pdata, FALSE);

							specs_joined = nm_match_spec_join (specs);

							g_key_file_set_value (keyfile, group, base_key, specs_joined);
						}
					} else {
						if (is_string_list)
							g_key_file_remove_key (keyfile, group, base_key, NULL);
						else
							g_key_file_set_value (keyfile, group, base_key, "");
					}
				} else {
					/* For any other settings we don't support extending the option with +/-.
					 * Just drop the key. */
				}
				continue;
			}

			new_value = g_key_file_get_value (kf, group, key, NULL);
			g_key_file_set_value (keyfile, group, key, new_value);

			if (!check_config_key (group, key)) {
				g_ptr_array_add (warnings,
				                 g_strdup_printf ("unknown key '%s' in section [%s] of file '%s'",
				                                  key, group, path));
			}
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
                  GPtrArray *warnings,
                  GError **error)
{
	GError *my_error = NULL;

	g_return_val_if_fail (keyfile, FALSE);
	g_return_val_if_fail (out_config_main_file && !*out_config_main_file, FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	/* Try a user-specified config file first */
	if (cli_config_main_file) {
		/* Bad user-specific config file path is a hard error */
		if (read_config (keyfile, TRUE, NULL, cli_config_main_file, warnings, error)) {
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
	if (read_config (keyfile, TRUE, NULL, DEFAULT_CONFIG_MAIN_FILE_OLD, warnings, &my_error)) {
		*out_config_main_file = g_strdup (DEFAULT_CONFIG_MAIN_FILE_OLD);
		return TRUE;
	}

	if (!g_error_matches (my_error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)) {
		_LOGW ("Old default config file invalid: %s",
		       my_error->message);
	}
	g_clear_error (&my_error);

	/* Try the standard config file location next */
	if (read_config (keyfile, TRUE, NULL, DEFAULT_CONFIG_MAIN_FILE, warnings, &my_error)) {
		*out_config_main_file = g_strdup (DEFAULT_CONFIG_MAIN_FILE);
		return TRUE;
	}

	if (!g_error_matches (my_error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND)) {
		_LOGW ("Default config file invalid: %s",
		       my_error->message);
		g_propagate_error (error, my_error);
		return FALSE;
	}
	g_clear_error (&my_error);

	/* If for some reason no config file exists, use the default
	 * config file path.
	 */
	*out_config_main_file = g_strdup (DEFAULT_CONFIG_MAIN_FILE);
	_LOGI ("No config file found or given; using %s",
	       DEFAULT_CONFIG_MAIN_FILE);
	return TRUE;
}

static GPtrArray *
_get_config_dir_files (const char *config_dir)
{
	GFile *dir;
	GFileEnumerator *direnum;
	GFileInfo *info;
	GPtrArray *confs;
	const char *name;

	g_return_val_if_fail (config_dir, NULL);

	confs = g_ptr_array_new_with_free_func (g_free);
	if (!*config_dir)
		return confs;

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

	g_ptr_array_sort (confs, nm_strcmp_p);
	return confs;
}

static void
_confs_to_description (GString *str, const GPtrArray *confs, const char *name)
{
	guint i;

	if (!confs->len)
		return;

	for (i = 0; i < confs->len; i++) {
		if (i == 0)
			g_string_append_printf (str, " (%s: ", name);
		else
			g_string_append (str, ", ");
		g_string_append (str, confs->pdata[i]);
	}
	g_string_append (str, ")");
}

static GKeyFile *
read_entire_config (const NMConfigCmdLineOptions *cli,
                    const char *config_dir,
                    const char *system_config_dir,
                    char **out_config_main_file,
                    char **out_config_description,
                    char ***out_warnings,
                    GError **error)
{
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	gs_unref_ptrarray GPtrArray *system_confs = NULL;
	gs_unref_ptrarray GPtrArray *confs = NULL;
	gs_unref_ptrarray GPtrArray *run_confs = NULL;
	guint i;
	gs_free char *o_config_main_file = NULL;
	const char *run_config_dir = "";
	gs_unref_ptrarray GPtrArray *warnings = NULL;

	g_return_val_if_fail (config_dir, NULL);
	g_return_val_if_fail (system_config_dir, NULL);
	g_return_val_if_fail (!out_config_main_file || !*out_config_main_file, FALSE);
	g_return_val_if_fail (!out_config_description || !*out_config_description, NULL);
	g_return_val_if_fail (!error || !*error, FALSE);
	g_return_val_if_fail (out_warnings && !*out_warnings, FALSE);

	if (   (""RUN_CONFIG_DIR)[0] == '/'
	    && !nm_streq (RUN_CONFIG_DIR, system_config_dir)
	    && !nm_streq (RUN_CONFIG_DIR, config_dir))
		run_config_dir = RUN_CONFIG_DIR;

	/* create a default configuration file. */
	keyfile = nm_config_create_keyfile ();
	warnings = g_ptr_array_new_with_free_func (g_free);

	system_confs = _get_config_dir_files (system_config_dir);
	confs = _get_config_dir_files (config_dir);
	run_confs = _get_config_dir_files (run_config_dir);

	for (i = 0; i < system_confs->len; ) {
		const char *filename = system_confs->pdata[i];

		/* if a same named file exists in config_dir or run_config_dir, skip it. */
		if (nm_utils_strv_find_first ((char **) confs->pdata, confs->len, filename) >= 0 ||
		    nm_utils_strv_find_first ((char **) run_confs->pdata, run_confs->len, filename) >= 0) {
			g_ptr_array_remove_index (system_confs, i);
			continue;
		}

		if (!read_config (keyfile, FALSE, system_config_dir, filename, warnings, error))
			return NULL;
		i++;
	}

	for (i = 0; i < run_confs->len; ) {
		const char *filename = run_confs->pdata[i];

		/* if a same named file exists in config_dir, skip it. */
		if (nm_utils_strv_find_first ((char **) confs->pdata, confs->len, filename) >= 0) {
			g_ptr_array_remove_index (run_confs, i);
			continue;
		}

		if (!read_config (keyfile, FALSE, run_config_dir, filename, warnings, error))
			return NULL;
		i++;
	}

	/* First read the base config file */
	if (!read_base_config (keyfile, cli ? cli->config_main_file : NULL, &o_config_main_file, warnings, error))
		return NULL;

	g_assert (o_config_main_file);

	for (i = 0; i < confs->len; i++) {
		if (!read_config (keyfile, FALSE, config_dir, confs->pdata[i], warnings, error))
			return NULL;
	}

	/* Merge settings from command line. They overwrite everything read from
	 * config files. */

	if (cli) {
		if (cli->plugins) {
			/* plugins is a string list. Set the value directly, so the user has to do proper escaping
			 * on the command line. */
			g_key_file_set_value (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "plugins", cli->plugins);
		}

		switch (cli->configure_and_quit) {
		case NM_CONFIG_CONFIGURE_AND_QUIT_INVALID:
			g_assert_not_reached ();
			break;
		case NM_CONFIG_CONFIGURE_AND_QUIT_DISABLED:
			/* do nothing */
			break;
		case NM_CONFIG_CONFIGURE_AND_QUIT_ENABLED:
			g_key_file_set_boolean (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "configure-and-quit", TRUE);
			break;
		case NM_CONFIG_CONFIGURE_AND_QUIT_INITRD:
			g_key_file_set_string (keyfile, NM_CONFIG_KEYFILE_GROUP_MAIN, "configure-and-quit", "initrd");
			break;
		}

		if (cli->connectivity_uri && cli->connectivity_uri[0])
			g_key_file_set_string (keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY, "uri", cli->connectivity_uri);
		if (cli->connectivity_interval >= 0)
			g_key_file_set_integer (keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY, "interval", cli->connectivity_interval);
		if (cli->connectivity_response && cli->connectivity_response[0])
			g_key_file_set_string (keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY, "response", cli->connectivity_response);
	}

	if (out_config_description) {
		GString *str;

		str = g_string_new (o_config_main_file);
		_confs_to_description (str, system_confs, "lib");
		_confs_to_description (str, run_confs, "run");
		_confs_to_description (str, confs, "etc");
		*out_config_description = g_string_free (str, FALSE);
	}
	NM_SET_OUT (out_config_main_file, g_steal_pointer (&o_config_main_file));

	g_ptr_array_add (warnings, NULL);
	*out_warnings = (char **) g_ptr_array_free (warnings, warnings->len == 1);
	g_steal_pointer (&warnings);

	return g_steal_pointer (&keyfile);
}

static gboolean
_is_atomic_section (const char *const*atomic_section_prefixes, const char *group)
{
	if (atomic_section_prefixes) {
		for (; *atomic_section_prefixes; atomic_section_prefixes++) {
			if (   **atomic_section_prefixes
			    && g_str_has_prefix (group, *atomic_section_prefixes))
				return TRUE;
		}
	}
	return FALSE;
}

static void
_string_append_val (GString *str, const char *value)
{
	if (!value)
		return;
	g_string_append_c (str, '+');
	while (TRUE) {
		switch (*value) {
		case '\0':
			return;
		case '\\':
		case '+':
		case '#':
		case ':':
			g_string_append_c (str, '+');
			/* fall through */
		default:
			g_string_append_c (str, *value);
		}
		value++;
	}
}

static char *
_keyfile_serialize_section (GKeyFile *keyfile, const char *group)
{
	gs_strfreev char **keys = NULL;
	GString *str;
	guint k;

	if (keyfile)
		keys = g_key_file_get_keys (keyfile, group, NULL, NULL);
	if (!keys)
		return g_strdup ("0#");

	/* prepend a version. */
	str = g_string_new ("1#");

	for (k = 0; keys[k]; k++) {
		const char *key = keys[k];
		gs_free char *value = NULL;

		_string_append_val (str, key);
		g_string_append_c (str, ':');

		value = g_key_file_get_value (keyfile, group, key, NULL);
		_string_append_val (str, value);
		g_string_append_c (str, '#');
	}
	return g_string_free (str, FALSE);
}

gboolean
nm_config_keyfile_has_global_dns_config (GKeyFile *keyfile, gboolean internal)
{
	gs_strfreev char **groups = NULL;
	guint g;
	const char *prefix;

	if (!keyfile)
		return FALSE;
	if (g_key_file_has_group (keyfile,
	                          internal
	                              ? NM_CONFIG_KEYFILE_GROUP_GLOBAL_DNS
	                              : NM_CONFIG_KEYFILE_GROUP_INTERN_GLOBAL_DNS))
		return TRUE;

	groups = g_key_file_get_groups (keyfile, NULL);
	if (!groups)
		return FALSE;

	prefix = internal ? NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN_GLOBAL_DNS_DOMAIN : NM_CONFIG_KEYFILE_GROUPPREFIX_GLOBAL_DNS_DOMAIN;

	for (g = 0; groups[g]; g++) {
		if (g_str_has_prefix (groups[g], prefix))
			return TRUE;
	}
	return FALSE;
}

/**
 * intern_config_read:
 * @filename: the filename where to store the internal config
 * @keyfile_conf: the merged configuration from user (/etc/NM/NetworkManager.conf).
 * @out_needs_rewrite: (allow-none): whether the read keyfile contains inconsistent
 *   data (compared to @keyfile_conf). If %TRUE, you might want to rewrite
 *   the file.
 *
 * Does the opposite of intern_config_write(). It reads the internal configuration.
 * Note that the actual format of how the configuration is saved in @filename
 * is different then what we return here. NMConfig manages what is written internally
 * by having it inside a keyfile_intern. But we don't write that to disk as is.
 * Especially, we also store parts of @keyfile_conf as ".was" and on read we compare
 * what we have, with what ".was".
 *
 * Returns: a #GKeyFile instance with the internal configuration.
 */
static GKeyFile *
intern_config_read (const char *filename,
                    GKeyFile *keyfile_conf,
                    const char *const*atomic_section_prefixes,
                    gboolean *out_needs_rewrite)
{
	GKeyFile *keyfile_intern;
	GKeyFile *keyfile;
	gboolean needs_rewrite = FALSE;
	gs_strfreev char **groups = NULL;
	guint g, k;
	gboolean has_intern = FALSE;

	g_return_val_if_fail (filename, NULL);

	if (!*filename) {
		if (out_needs_rewrite)
			*out_needs_rewrite = FALSE;
		return NULL;
	}

	keyfile_intern = nm_config_create_keyfile ();

	keyfile = nm_config_create_keyfile ();
	if (!g_key_file_load_from_file (keyfile, filename, G_KEY_FILE_NONE, NULL)) {
		needs_rewrite = TRUE;
		goto out;
	}

	groups = g_key_file_get_groups (keyfile, NULL);
	for (g = 0; groups && groups[g]; g++) {
		gs_strfreev char **keys = NULL;
		const char *group = groups[g];
		gboolean is_intern, is_atomic;

		if (!strcmp (group, NM_CONFIG_KEYFILE_GROUP_CONFIG))
			continue;

		keys = g_key_file_get_keys (keyfile, group, NULL, NULL);
		if (!keys)
			continue;

		is_intern = g_str_has_prefix (group, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN);
		is_atomic = !is_intern && _is_atomic_section (atomic_section_prefixes, group);

		if (is_atomic) {
			gs_free char *conf_section_was = NULL;
			gs_free char *conf_section_is = NULL;

			conf_section_is = _keyfile_serialize_section (keyfile_conf, group);
			conf_section_was = g_key_file_get_string (keyfile, group, NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS, NULL);

			if (g_strcmp0 (conf_section_was, conf_section_is) != 0) {
				/* the section no longer matches. Skip it entirely. */
				needs_rewrite = TRUE;
				continue;
			}
			/* we must set the "was" marker in our keyfile, so that we know that the section
			 * from user config is overwritten. The value doesn't matter, it's just a marker
			 * that this section is present. */
			g_key_file_set_value (keyfile_intern, group, NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS, "");
		}

		for (k = 0; keys[k]; k++) {
			gs_free char *value_set = NULL;
			const char *key = keys[k];

			value_set = g_key_file_get_value (keyfile, group, key, NULL);

			if (is_intern) {
				has_intern = TRUE;
				g_key_file_set_value (keyfile_intern, group, key, value_set);
			} else if (is_atomic) {
				if (strcmp (key, NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS) == 0)
					continue;
				g_key_file_set_value (keyfile_intern, group, key, value_set);
			} else if (_HAS_PREFIX (key, NM_CONFIG_KEYFILE_KEYPREFIX_SET)) {
				const char *key_base = &key[NM_STRLEN (NM_CONFIG_KEYFILE_KEYPREFIX_SET)];
				gs_free char *value_was = NULL;
				gs_free char *value_conf = NULL;
				gs_free char *key_was = g_strdup_printf (NM_CONFIG_KEYFILE_KEYPREFIX_WAS"%s", key_base);

				if (keyfile_conf)
					value_conf = g_key_file_get_value (keyfile_conf, group, key_base, NULL);
				value_was = g_key_file_get_value (keyfile, group, key_was, NULL);

				if (g_strcmp0 (value_conf, value_was) != 0) {
					/* if value_was is no longer the same as @value_conf, it means the user
					 * changed the configuration since the last write. In this case, we
					 * drop the value. It also means our file is out-of-date, and we should
					 * rewrite it. */
					needs_rewrite = TRUE;
					continue;
				}
				has_intern = TRUE;
				g_key_file_set_value (keyfile_intern, group, key_base, value_set);
			} else if (_HAS_PREFIX (key, NM_CONFIG_KEYFILE_KEYPREFIX_WAS)) {
				const char *key_base = &key[NM_STRLEN (NM_CONFIG_KEYFILE_KEYPREFIX_WAS)];
				gs_free char *key_set = g_strdup_printf (NM_CONFIG_KEYFILE_KEYPREFIX_SET"%s", key_base);
				gs_free char *value_was = NULL;
				gs_free char *value_conf = NULL;

				if (g_key_file_has_key (keyfile, group, key_set, NULL)) {
					/* we have a matching "set" key too. Handle the "was" key there. */
					continue;
				}

				if (keyfile_conf)
					value_conf = g_key_file_get_value (keyfile_conf, group, key_base, NULL);
				value_was = g_key_file_get_value (keyfile, group, key, NULL);

				if (g_strcmp0 (value_conf, value_was) != 0) {
					/* if value_was is no longer the same as @value_conf, it means the user
					 * changed the configuration since the last write. In this case, we
					 * don't overwrite the user-provided value. It also means our file is
					 * out-of-date, and we should rewrite it. */
					needs_rewrite = TRUE;
					continue;
				}
				has_intern = TRUE;
				/* signal the absence of the value. That means, we must propagate the
				 * "was" key to NMConfigData, so that it knows to hide the corresponding
				 * user key. */
				g_key_file_set_value (keyfile_intern, group, key, "");
			} else
				needs_rewrite = TRUE;
		}
	}

out:
	/*
	 * If user configuration specifies global DNS options, the DNS
	 * options in internal configuration must be deleted. Otherwise a
	 * deletion of options from user configuration may cause the
	 * internal options to appear again.
	 */
	if (nm_config_keyfile_has_global_dns_config (keyfile_conf, FALSE)) {
		if (g_key_file_remove_group (keyfile_intern, NM_CONFIG_KEYFILE_GROUP_INTERN_GLOBAL_DNS, NULL))
			needs_rewrite = TRUE;
		for (g = 0; groups && groups[g]; g++) {
			if (   g_str_has_prefix (groups[g], NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN_GLOBAL_DNS_DOMAIN)
			    && groups[g][NM_STRLEN (NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN_GLOBAL_DNS_DOMAIN)]) {
				g_key_file_remove_group (keyfile_intern, groups[g], NULL);
				needs_rewrite = TRUE;
			}
		}
	}

	g_key_file_unref (keyfile);

	if (out_needs_rewrite)
		*out_needs_rewrite = needs_rewrite;

	_LOGD ("intern config file \"%s\"", filename);

	if (!has_intern) {
		g_key_file_unref (keyfile_intern);
		return NULL;
	}
	return keyfile_intern;
}

static int
_intern_config_write_sort_fcn (const char **a, const char **b, const char *const*atomic_section_prefixes)
{
	const char *g_a = (a ? *a : NULL);
	const char *g_b = (b ? *b : NULL);
	gboolean a_is, b_is;

	a_is = g_str_has_prefix (g_a, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN);
	b_is = g_str_has_prefix (g_b, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN);

	if (a_is != b_is) {
		if (a_is)
			return 1;
		return -1;
	}
	if (!a_is) {
		a_is = _is_atomic_section (atomic_section_prefixes, g_a);
		b_is = _is_atomic_section (atomic_section_prefixes, g_b);

		if (a_is != b_is) {
			if (a_is)
				return 1;
			return -1;
		}
	}
	return g_strcmp0 (g_a, g_b);
}

static gboolean
intern_config_write (const char *filename,
                     GKeyFile *keyfile_intern,
                     GKeyFile *keyfile_conf,
                     const char *const*atomic_section_prefixes,
                     GError **error)
{
	GKeyFile *keyfile;
	gs_strfreev char **groups = NULL;
	guint g, k;
	gboolean success = FALSE;
	GError *local = NULL;

	g_return_val_if_fail (filename, FALSE);

	if (!*filename) {
		g_set_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND, "no filename to write (use --intern-config?)");
		return FALSE;
	}

	keyfile = nm_config_create_keyfile ();

	if (keyfile_intern) {
		groups = g_key_file_get_groups (keyfile_intern, NULL);
		if (groups && groups[0]) {
			g_qsort_with_data (groups,
			                   g_strv_length (groups),
			                   sizeof (char *),
			                   (GCompareDataFunc) _intern_config_write_sort_fcn,
			                   (gpointer) atomic_section_prefixes);
		}
	}
	for (g = 0; groups && groups[g]; g++) {
		gs_strfreev char **keys = NULL;
		const char *group = groups[g];
		gboolean is_intern, is_atomic;

		keys = g_key_file_get_keys (keyfile_intern, group, NULL, NULL);
		if (!keys)
			continue;

		is_intern = g_str_has_prefix (group, NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN);
		is_atomic = !is_intern && _is_atomic_section (atomic_section_prefixes, group);

		if (is_atomic) {
			if (   (!keys[0] || (!keys[1] && strcmp (keys[0], NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS) == 0))
			    && !g_key_file_has_group (keyfile_conf, group)) {
				/* we are about to save an atomic section. However, we don't have any additional
				 * keys on our own and there is no user-provided (overlapping) section either.
				 * We don't have to write an empty section (i.e. skip the useless ".was=0#"). */
				continue;
			} else {
				gs_free char *conf_section_is = NULL;

				conf_section_is = _keyfile_serialize_section (keyfile_conf, group);
				g_key_file_set_string (keyfile, group, NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS, conf_section_is);
				g_key_file_set_comment (keyfile, group, NULL,
				                        " Overwrites entire section from 'NetworkManager.conf'",
				                        NULL);
			}
		}

		for (k = 0; keys[k]; k++) {
			const char *key = keys[k];
			gs_free char *value_set = NULL;
			gs_free char *key_set = NULL;

			if (   !is_intern
			    && strcmp (key, NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS) == 0) {
				g_warn_if_fail (is_atomic);
				continue;
			}

			value_set = g_key_file_get_value (keyfile_intern, group, key, NULL);

			if (is_intern || is_atomic)
				g_key_file_set_value (keyfile, group, key, value_set);
			else {
				gs_free char *value_was = NULL;

				if (_HAS_PREFIX (key, NM_CONFIG_KEYFILE_KEYPREFIX_SET)) {
					/* Setting a key with .set prefix has no meaning, as these keys
					 * are protected. Just set the value you want to set instead.
					 * Why did this happen?? */
					g_warn_if_reached ();
				} else if (_HAS_PREFIX (key, NM_CONFIG_KEYFILE_KEYPREFIX_WAS)) {
					const char *key_base = &key[NM_STRLEN (NM_CONFIG_KEYFILE_KEYPREFIX_WAS)];

					if (   _HAS_PREFIX (key_base, NM_CONFIG_KEYFILE_KEYPREFIX_SET)
					    || _HAS_PREFIX (key_base, NM_CONFIG_KEYFILE_KEYPREFIX_WAS)) {
						g_warn_if_reached ();
						continue;
					}

					if (g_key_file_has_key (keyfile_intern, group, key_base, NULL)) {
						/* There is also a matching key_base entry. Skip processing
						 * the .was. key ad handle the key_base in the other else branch. */
						continue;
					}

					if (keyfile_conf) {
						value_was = g_key_file_get_value (keyfile_conf, group, key_base, NULL);
						if (value_was)
							g_key_file_set_value (keyfile, group, key, value_was);
					}
				} else {
					if (keyfile_conf) {
						value_was = g_key_file_get_value (keyfile_conf, group, key, NULL);
						if (g_strcmp0 (value_set, value_was) == 0) {
							/* there is no point in storing the identical value as we have via
							 * user configuration. Skip it. */
							continue;
						}
						if (value_was) {
							gs_free char *key_was = NULL;

							key_was = g_strdup_printf (NM_CONFIG_KEYFILE_KEYPREFIX_WAS"%s", key);
							g_key_file_set_value (keyfile, group, key_was, value_was);
						}
					}
					key = key_set = g_strdup_printf (NM_CONFIG_KEYFILE_KEYPREFIX_SET"%s", key);
					g_key_file_set_value (keyfile, group, key, value_set);
				}
			}
		}
		if (   is_intern
		    && g_key_file_has_group (keyfile, group)) {
			g_key_file_set_comment (keyfile, group, NULL,
			                        " Internal section. Not overwritable via user configuration in 'NetworkManager.conf'",
			                        NULL);
		}
	}

	g_key_file_set_comment (keyfile, NULL, NULL,
	                        " Internal configuration file. This file is written and read\n"
	                        " by NetworkManager and its configuration values are merged\n"
	                        " with the configuration from 'NetworkManager.conf'.\n"
	                        "\n"
	                        " Keys with a \""NM_CONFIG_KEYFILE_KEYPREFIX_SET"\" prefix specify the value to set.\n"
	                        " A corresponding key with a \""NM_CONFIG_KEYFILE_KEYPREFIX_WAS"\" prefix records the value\n"
	                        " of the user configuration at the time of storing the file.\n"
	                        " The value from internal configuration is rejected if the corresponding\n"
	                        " \""NM_CONFIG_KEYFILE_KEYPREFIX_WAS"\" key no longer matches the configuration from 'NetworkManager.conf'.\n"
	                        " That means, if you modify a value in 'NetworkManager.conf', the internal\n"
	                        " overwrite no longer matches and is ignored.\n"
	                        "\n"
	                        " Certain sections can only be overwritten whole, not on a per key basis.\n"
	                        " Such sections are marked with a \""NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS"\" key that records the user configuration\n"
	                        " at the time of writing.\n"
	                        "\n"
	                        " Internal sections of the form [" NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN "*] cannot\n"
	                        " be set by user configuration.\n"
	                        "\n"
	                        " CHANGES TO THIS FILE WILL BE OVERWRITTEN",
	                        NULL);

	success = g_key_file_save_to_file (keyfile, filename, &local);

	_LOGD ("write intern config file \"%s\"%s%s", filename, success ? "" : ": ", success ? "" : local->message);
	g_key_file_unref (keyfile);
	if (!success)
		g_propagate_error (error, local);
	return success;
}

/*****************************************************************************/

GSList *
nm_config_get_match_spec (const GKeyFile *keyfile, const char *group, const char *key, gboolean *out_has_key)
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

/*****************************************************************************/

gboolean
nm_config_set_global_dns (NMConfig *self, NMGlobalDnsConfig *global_dns, GError **error)
{
	NMConfigPrivate *priv;
	GKeyFile *keyfile;
	char **groups;
	const NMGlobalDnsConfig *old_global_dns;
	guint i;

	g_return_val_if_fail (NM_IS_CONFIG (self), FALSE);

	priv = NM_CONFIG_GET_PRIVATE (self);
	g_return_val_if_fail (priv->config_data, FALSE);

	old_global_dns = nm_config_data_get_global_dns_config (priv->config_data);
	if (old_global_dns && !nm_global_dns_config_is_internal (old_global_dns)) {
		g_set_error_literal (error, 1, 0,
		                     "Global DNS configuration already set via configuration file");
		return FALSE;
	}

	keyfile = nm_config_data_clone_keyfile_intern (priv->config_data);

	/* Remove existing groups */
	g_key_file_remove_group (keyfile, NM_CONFIG_KEYFILE_GROUP_INTERN_GLOBAL_DNS, NULL);
	groups = g_key_file_get_groups (keyfile, NULL);
	for (i = 0; groups[i]; i++) {
		if (g_str_has_prefix (groups[i], NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN_GLOBAL_DNS_DOMAIN))
			g_key_file_remove_group (keyfile, groups[i], NULL);
	}
	g_strfreev (groups);

	/* An empty configuration removes everything from internal configuration file */
	if (nm_global_dns_config_is_empty (global_dns))
		goto done;

	/* Set new values */
	nm_config_keyfile_set_string_list (keyfile, NM_CONFIG_KEYFILE_GROUP_INTERN_GLOBAL_DNS,
	                                   NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_SEARCHES,
	                                   nm_global_dns_config_get_searches (global_dns),
	                                   -1);

	nm_config_keyfile_set_string_list (keyfile, NM_CONFIG_KEYFILE_GROUP_INTERN_GLOBAL_DNS,
	                                   NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_OPTIONS,
	                                   nm_global_dns_config_get_options (global_dns),
	                                   -1);

	for (i = 0; i < nm_global_dns_config_get_num_domains (global_dns); i++) {
		NMGlobalDnsDomain *domain = nm_global_dns_config_get_domain (global_dns, i);
		gs_free char *group_name = NULL;

		group_name = g_strdup_printf (NM_CONFIG_KEYFILE_GROUPPREFIX_INTERN_GLOBAL_DNS_DOMAIN "%s",
		                              nm_global_dns_domain_get_name (domain));

		nm_config_keyfile_set_string_list (keyfile, group_name, NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_DOMAIN_SERVERS,
		                                   nm_global_dns_domain_get_servers (domain), -1);
		nm_config_keyfile_set_string_list (keyfile, group_name, NM_CONFIG_KEYFILE_KEY_GLOBAL_DNS_DOMAIN_OPTIONS,
		                                   nm_global_dns_domain_get_options (domain), -1);
	}

done:
	nm_config_set_values (self, keyfile, TRUE, FALSE);
	g_key_file_unref (keyfile);

	return TRUE;
}

/*****************************************************************************/

void nm_config_set_connectivity_check_enabled (NMConfig *self,
                                               gboolean enabled)
{
	NMConfigPrivate *priv;
	GKeyFile *keyfile;

	g_return_if_fail (NM_IS_CONFIG (self));

	priv = NM_CONFIG_GET_PRIVATE (self);
	g_return_if_fail (priv->config_data);

	keyfile = nm_config_data_clone_keyfile_intern (priv->config_data);

	/* Remove existing groups */
	g_key_file_remove_group (keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY, NULL);

	g_key_file_set_value (keyfile, NM_CONFIG_KEYFILE_GROUP_CONNECTIVITY,
	                      "enabled", enabled ? "true" : "false");

	nm_config_set_values (self, keyfile, TRUE, FALSE);
	g_key_file_unref (keyfile);
}

/**
 * nm_config_set_values:
 * @self: the NMConfig instance
 * @keyfile_intern_new: (allow-none): the new internal settings to set.
 *   If %NULL, it is equal to an empty keyfile.
 * @allow_write: only if %TRUE, allow writing the changes to file. Otherwise,
 *   do the changes in-memory only.
 * @force_rewrite: if @allow_write is %FALSE, this has no effect. If %FALSE,
 *   only write the configuration to file, if there are any actual changes.
 *   If %TRUE, always write the configuration to file, even if tere are seemingly
 *   no changes.
 *
 *  This is the most flexible function to set values. It all depends on the
 *  keys and values you set in @keyfile_intern_new. You basically reset all
 *  internal configuration values to what is in @keyfile_intern_new.
 *
 *  There are 3 types of settings:
 *    - all groups/sections with a prefix [.intern.*] are taken as is. As these
 *      groups are separate from user configuration, there is no conflict. You set
 *      them, that's it.
 *    - there are atomic sections, i.e. sections whose name start with one of
 *      NM_CONFIG_ATOMIC_SECTION_PREFIXES. If you put values in these sections,
 *      it means you completely replace the section from user configuration.
 *      You can also hide a user provided section by only putting the special
 *      key NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS into that section.
 *    - otherwise you can overwrite individual values from user-configuration.
 *      Just set the value. Keys with a prefix NM_CONFIG_KEYFILE_KEYPREFIX_*
 *      are protected -- as they are not value user keys.
 *      You can also hide a certain user setting by putting only a key
 *      NM_CONFIG_KEYFILE_KEYPREFIX_WAS"keyname" into the keyfile.
 */
void
nm_config_set_values (NMConfig *self,
                      GKeyFile *keyfile_intern_new,
                      gboolean allow_write,
                      gboolean force_rewrite)
{
	NMConfigPrivate *priv;
	GKeyFile *keyfile_intern_current;
	GKeyFile *keyfile_user;
	GKeyFile *keyfile_new;
	GError *local = NULL;
	NMConfigData *new_data = NULL;
	gs_strfreev char **groups = NULL;
	int g;

	g_return_if_fail (NM_IS_CONFIG (self));

	priv = NM_CONFIG_GET_PRIVATE (self);

	keyfile_intern_current = _nm_config_data_get_keyfile_intern (priv->config_data);

	keyfile_new = nm_config_create_keyfile ();
	if (keyfile_intern_new)
		_nm_keyfile_copy (keyfile_new, keyfile_intern_new);

	/* ensure that every atomic section has a .was entry. */
	groups = g_key_file_get_groups (keyfile_new, NULL);
	for (g = 0; groups && groups[g]; g++) {
		if (_is_atomic_section ((const char *const*) priv->atomic_section_prefixes, groups[g]))
			g_key_file_set_value (keyfile_new, groups[g], NM_CONFIG_KEYFILE_KEY_ATOMIC_SECTION_WAS, "");
	}

	if (!_nm_keyfile_equals (keyfile_intern_current, keyfile_new, TRUE))
		new_data = nm_config_data_new_update_keyfile_intern (priv->config_data, keyfile_new);

	_LOGD ("set values(): %s", new_data ? "has changes" : "no changes");

	if (allow_write
	    && (new_data || force_rewrite)) {
		/* We write the internal config file based on the user configuration from
		 * the last load/reload. That is correct, because the intern properties might
		 * be in accordance to what NM thinks is currently configured. Even if the files
		 * on disk changed in the meantime.
		 * But if they changed, on the next reload with might throw away our just
		 * written data. That is correct, because from NM's point of view, those
		 * changes on disk happened in any case *after* now. */
		if (*priv->intern_config_file) {
			keyfile_user = _nm_config_data_get_keyfile_user (priv->config_data);
			if (!intern_config_write (priv->intern_config_file, keyfile_new, keyfile_user,
			                          (const char *const*) priv->atomic_section_prefixes, &local)) {
				_LOGW ("error saving internal configuration \"%s\": %s", priv->intern_config_file, local->message);
				g_clear_error (&local);
			}
		} else
			_LOGD ("don't persist internal configuration (no file set, use --intern-config?)");
	}
	if (new_data)
		_set_config_data (self, new_data, NM_CONFIG_CHANGE_CAUSE_SET_VALUES);

	g_key_file_unref (keyfile_new);
}

/******************************************************************************
 * State
 ******************************************************************************/

static const char *
state_get_filename (const NMConfigCmdLineOptions *cli)
{
	/* For an empty filename, we assume the user wants to disable
	 * state. NMConfig will not try to read it nor write it out. */
	if (!cli->state_file)
		return DEFAULT_STATE_FILE;
	return cli->state_file[0] ? cli->state_file : NULL;
}

static State *
state_new (void)
{
	State *state;

	state = g_slice_new0 (State);
	state->p.net_enabled = TRUE;
	state->p.wifi_enabled = TRUE;
	state->p.wwan_enabled = TRUE;

	return state;
}

static void
state_free (State *state)
{
	if (!state)
		return;
	g_slice_free (State, state);
}

static State *
state_new_from_file (const char *filename)
{
	GKeyFile *keyfile;
	gs_free_error GError *error = NULL;
	State *state;

	state = state_new ();

	if (!filename)
		return state;

	keyfile = g_key_file_new ();
	g_key_file_set_list_separator (keyfile, ',');
	if (!g_key_file_load_from_file (keyfile, filename, G_KEY_FILE_NONE, &error)) {
		if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			_LOGD ("state: missing state file \"%s\": %s", filename, error->message);
		else
			_LOGW ("state: error reading state file \"%s\": %s", filename, error->message);
		goto out;
	}

	_LOGD ("state: successfully read state file \"%s\"", filename);

	state->p.net_enabled  = nm_config_keyfile_get_boolean (keyfile, "main", "NetworkingEnabled", state->p.net_enabled);
	state->p.wifi_enabled = nm_config_keyfile_get_boolean (keyfile, "main", "WirelessEnabled", state->p.wifi_enabled);
	state->p.wwan_enabled = nm_config_keyfile_get_boolean (keyfile, "main", "WWANEnabled", state->p.wwan_enabled);

out:
	g_key_file_unref (keyfile);
	return state;
}

const NMConfigState *
nm_config_state_get (NMConfig *self)
{
	NMConfigPrivate *priv;

	g_return_val_if_fail (NM_IS_CONFIG (self), NULL);

	priv = NM_CONFIG_GET_PRIVATE (self);

	if (G_UNLIKELY (!priv->state)) {
		/* read the state from file lazy on first access. The reason is that
		 * we want to log a failure to read the file via nm-logging.
		 *
		 * So we cannot read the state during construction of NMConfig,
		 * because at that time nm-logging is not yet configured.
		 */
		priv->state = state_new_from_file (state_get_filename (&priv->cli));
	}

	return &priv->state->p;
}

static void
state_write (NMConfig *self)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (self);
	const char *filename;
	GString *str;
	GError *error = NULL;

	if (priv->configure_and_quit != NM_CONFIG_CONFIGURE_AND_QUIT_DISABLED)
		return;

	filename = state_get_filename (&priv->cli);

	if (!filename) {
		priv->state->p.dirty = FALSE;
		return;
	}

	str = g_string_sized_new (256);

	/* Let's construct the keyfile data by hand. */

	g_string_append (str, "[main]\n");
	g_string_append_printf (str, "NetworkingEnabled=%s\n", priv->state->p.net_enabled ? "true" : "false");
	g_string_append_printf (str, "WirelessEnabled=%s\n", priv->state->p.wifi_enabled ? "true" : "false");
	g_string_append_printf (str, "WWANEnabled=%s\n", priv->state->p.wwan_enabled ? "true" : "false");

	if (!g_file_set_contents (filename,
	                          str->str, str->len,
	                          &error)) {
		_LOGD ("state: error writing state file \"%s\": %s", filename, error->message);
		g_clear_error (&error);
		/* we leave the state dirty. That potentially means, that we try to
		 * write the file over and over again, although it isn't possible. */
		priv->state->p.dirty = TRUE;
	} else
		priv->state->p.dirty = FALSE;

	_LOGT ("state: success writing state file \"%s\"", filename);

	g_string_free (str, TRUE);
}

void
_nm_config_state_set (NMConfig *self,
                      gboolean allow_persist,
                      gboolean force_persist,
                      ...)
{
	NMConfigPrivate *priv;
	va_list ap;
	NMConfigRunStatePropertyType property_type;

	g_return_if_fail (NM_IS_CONFIG (self));

	priv = NM_CONFIG_GET_PRIVATE (self);

	va_start (ap, force_persist);

	/* We expect that the NMConfigRunStatePropertyType is an integer type <= sizeof (int).
	 * Smaller would be fine, since the variadic arguments get promoted to int.
	 * Larger would be a problem, also, because we want that "0" is a valid sentinel. */
	G_STATIC_ASSERT_EXPR (sizeof (NMConfigRunStatePropertyType) <= sizeof (int));

	while ((property_type = va_arg (ap, int)) != NM_CONFIG_STATE_PROPERTY_NONE) {
		bool *p_bool, v_bool;

		switch (property_type) {
		case NM_CONFIG_STATE_PROPERTY_NETWORKING_ENABLED:
			p_bool = &priv->state->p.net_enabled;
			break;
		case NM_CONFIG_STATE_PROPERTY_WIFI_ENABLED:
			p_bool = &priv->state->p.wifi_enabled;
			break;
		case NM_CONFIG_STATE_PROPERTY_WWAN_ENABLED:
			p_bool = &priv->state->p.wwan_enabled;
			break;
		default:
			va_end (ap);
			g_return_if_reached ();
		}

		v_bool = va_arg (ap, gboolean);
		if (*p_bool == v_bool)
			continue;
		*p_bool = v_bool;
		priv->state->p.dirty = TRUE;
	}

	va_end (ap);

	if (   allow_persist
	    && (force_persist || priv->state->p.dirty))
		state_write (self);
}

/*****************************************************************************/

#define DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE                   "device"
#define DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_MANAGED             "managed"
#define DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_PERM_HW_ADDR_FAKE   "perm-hw-addr-fake"
#define DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_CONNECTION_UUID     "connection-uuid"
#define DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_NM_OWNED            "nm-owned"
#define DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_ROUTE_METRIC_DEFAULT_ASPIRED   "route-metric-default-aspired"
#define DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_ROUTE_METRIC_DEFAULT_EFFECTIVE "route-metric-default-effective"
#define DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_ROOT_PATH           "root-path"
#define DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_NEXT_SERVER         "next-server"

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (_device_state_managed_type_to_str, NMConfigDeviceStateManagedType,
	NM_UTILS_LOOKUP_DEFAULT_NM_ASSERT ("unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_UNKNOWN,   "unknown"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_UNMANAGED, "unmanaged"),
	NM_UTILS_LOOKUP_STR_ITEM (NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_MANAGED,   "managed"),
);

static NMConfigDeviceStateData *
_config_device_state_data_new (int ifindex, GKeyFile *kf)
{
	NMConfigDeviceStateData *device_state;
	NMConfigDeviceStateManagedType managed_type = NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_UNKNOWN;
	gs_free char *connection_uuid = NULL;
	gs_free char *perm_hw_addr_fake = NULL;
	gsize connection_uuid_len;
	gsize perm_hw_addr_fake_len;
	int nm_owned = -1;
	char *p;
	guint32 route_metric_default_effective;
	guint32 route_metric_default_aspired;

	nm_assert (kf);
	nm_assert (ifindex > 0);

	switch (nm_config_keyfile_get_boolean (kf,
	                                       DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
	                                       DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_MANAGED,
	                                       -1)) {
	case TRUE:
		managed_type = NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_MANAGED;
		connection_uuid = nm_config_keyfile_get_value (kf,
		                                               DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
		                                               DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_CONNECTION_UUID,
		                                               NM_CONFIG_GET_VALUE_STRIP | NM_CONFIG_GET_VALUE_NO_EMPTY);
		break;
	case FALSE:
		managed_type = NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_UNMANAGED;
		break;
	case -1:
		/* missing property in keyfile. */
		break;
	}

	perm_hw_addr_fake = nm_config_keyfile_get_value (kf,
	                                                 DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
	                                                 DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_PERM_HW_ADDR_FAKE,
	                                                 NM_CONFIG_GET_VALUE_STRIP | NM_CONFIG_GET_VALUE_NO_EMPTY);
	if (perm_hw_addr_fake) {
		char *normalized;

		normalized = nm_utils_hwaddr_canonical (perm_hw_addr_fake, -1);
		g_free (perm_hw_addr_fake);
		perm_hw_addr_fake = normalized;
	}

	nm_owned = nm_config_keyfile_get_boolean (kf,
	                                          DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
	                                          DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_NM_OWNED,
	                                          -1);

	/* metric zero is not a valid metric. While zero valid for IPv4, for IPv6 it is an alias
	 * for 1024. Since we handle here IPv4 and IPv6 the same, we cannot allow zero. */
	route_metric_default_effective = nm_config_keyfile_get_int64 (kf,
	                                                              DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
	                                                              DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_ROUTE_METRIC_DEFAULT_EFFECTIVE,
	                                                              10, 1, G_MAXUINT32, 0);
	if (route_metric_default_effective) {
		route_metric_default_aspired = nm_config_keyfile_get_int64 (kf,
		                                                            DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
		                                                            DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_ROUTE_METRIC_DEFAULT_EFFECTIVE,
		                                                            10, 1, route_metric_default_effective,
		                                                            route_metric_default_effective);
	} else
		route_metric_default_aspired = 0;

	connection_uuid_len = connection_uuid ? strlen (connection_uuid) + 1 : 0;
	perm_hw_addr_fake_len = perm_hw_addr_fake ? strlen (perm_hw_addr_fake) + 1 : 0;

	device_state = g_malloc (sizeof (NMConfigDeviceStateData) +
	                         connection_uuid_len +
	                         perm_hw_addr_fake_len);

	device_state->ifindex = ifindex;
	device_state->managed = managed_type;
	device_state->connection_uuid = NULL;
	device_state->perm_hw_addr_fake = NULL;
	device_state->nm_owned = nm_owned;
	device_state->route_metric_default_aspired = route_metric_default_aspired;
	device_state->route_metric_default_effective = route_metric_default_effective;

	p = (char *) (&device_state[1]);
	if (connection_uuid) {
		memcpy (p, connection_uuid, connection_uuid_len);
		device_state->connection_uuid = p;
		p += connection_uuid_len;
	}
	if (perm_hw_addr_fake) {
		memcpy (p, perm_hw_addr_fake, perm_hw_addr_fake_len);
		device_state->perm_hw_addr_fake = p;
		p += perm_hw_addr_fake_len;
	}

	return device_state;
}

/**
 * nm_config_device_state_load:
 * @ifindex: the ifindex for which the state is to load
 *
 * Returns: (transfer full): a run state object.
 *   Must be freed with g_free().
 */
NMConfigDeviceStateData *
nm_config_device_state_load (int ifindex)
{
	NMConfigDeviceStateData *device_state;
	char path[NM_STRLEN (NM_CONFIG_DEVICE_STATE_DIR) + 60];
	gs_unref_keyfile GKeyFile *kf = NULL;
	const char *nm_owned_str;

	g_return_val_if_fail (ifindex > 0, NULL);

	nm_sprintf_buf (path, "%s/%d", NM_CONFIG_DEVICE_STATE_DIR, ifindex);

	kf = nm_config_create_keyfile ();
	if (!g_key_file_load_from_file (kf, path, G_KEY_FILE_NONE, NULL))
		return NULL;

	device_state = _config_device_state_data_new (ifindex, kf);
	nm_owned_str = device_state->nm_owned == TRUE ?
	               ", nm-owned=1" :
	               (device_state->nm_owned == FALSE ? ", nm-owned=0" : "");

	_LOGT ("device-state: %s #%d (%s); managed=%s%s%s%s%s%s%s%s, route-metric-default=%"G_GUINT32_FORMAT"-%"G_GUINT32_FORMAT"",
	       kf ? "read" : "miss",
	       ifindex, path,
	       _device_state_managed_type_to_str (device_state->managed),
	       NM_PRINT_FMT_QUOTED (device_state->connection_uuid, ", connection-uuid=", device_state->connection_uuid, "", ""),
	       NM_PRINT_FMT_QUOTED (device_state->perm_hw_addr_fake, ", perm-hw-addr-fake=", device_state->perm_hw_addr_fake, "", ""),
	       nm_owned_str,
	       device_state->route_metric_default_aspired,
	       device_state->route_metric_default_effective);

	return device_state;
}

static int
_device_state_parse_filename (const char *filename)
{
	if (!filename || !filename[0])
		return 0;
	if (!NM_STRCHAR_ALL (filename, ch, g_ascii_isdigit (ch)))
		return 0;
	return _nm_utils_ascii_str_to_int64 (filename, 10, 1, G_MAXINT, 0);
}

GHashTable *
nm_config_device_state_load_all (void)
{
	GHashTable *states;
	GDir *dir;
	const char *fn;
	int ifindex;

	states = g_hash_table_new_full (nm_direct_hash, NULL, NULL, g_free);

	dir = g_dir_open (NM_CONFIG_DEVICE_STATE_DIR, 0, NULL);
	if (!dir)
		return states;

	while ((fn = g_dir_read_name (dir))) {
		NMConfigDeviceStateData *state;

		ifindex = _device_state_parse_filename (fn);
		if (ifindex <= 0)
			continue;

		state = nm_config_device_state_load (ifindex);
		if (!state)
			continue;

		if (!g_hash_table_insert (states, GINT_TO_POINTER (ifindex), state))
			nm_assert_not_reached ();
	}
	g_dir_close (dir);

	return states;
}

gboolean
nm_config_device_state_write (int ifindex,
                              NMConfigDeviceStateManagedType managed,
                              const char *perm_hw_addr_fake,
                              const char *connection_uuid,
                              int nm_owned,
                              guint32 route_metric_default_aspired,
                              guint32 route_metric_default_effective,
                              const char *next_server,
                              const char *root_path)
{
	char path[NM_STRLEN (NM_CONFIG_DEVICE_STATE_DIR) + 60];
	GError *local = NULL;
	gs_unref_keyfile GKeyFile *kf = NULL;

	g_return_val_if_fail (ifindex > 0, FALSE);
	g_return_val_if_fail (!connection_uuid || *connection_uuid, FALSE);
	g_return_val_if_fail (managed == NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_MANAGED || !connection_uuid, FALSE);

	nm_assert (!perm_hw_addr_fake || nm_utils_hwaddr_valid (perm_hw_addr_fake, -1));

	nm_sprintf_buf (path, "%s/%d", NM_CONFIG_DEVICE_STATE_DIR, ifindex);

	kf = nm_config_create_keyfile ();
	if (NM_IN_SET (managed,
	               NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_MANAGED,
	               NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_UNMANAGED)) {
		g_key_file_set_boolean (kf,
		                        DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
		                        DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_MANAGED,
		                        managed == NM_CONFIG_DEVICE_STATE_MANAGED_TYPE_MANAGED);
	}
	if (perm_hw_addr_fake) {
		g_key_file_set_string (kf,
		                       DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
		                       DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_PERM_HW_ADDR_FAKE,
		                       perm_hw_addr_fake);
	}
	if (connection_uuid) {
		g_key_file_set_string (kf,
		                       DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
		                       DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_CONNECTION_UUID,
		                       connection_uuid);
	}
	if (nm_owned >= 0) {
		g_key_file_set_boolean (kf,
		                        DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
		                        DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_NM_OWNED,
		                        nm_owned);
	}

	if (route_metric_default_effective != 0) {
		g_key_file_set_int64 (kf,
		                      DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
		                      DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_ROUTE_METRIC_DEFAULT_EFFECTIVE,
		                      route_metric_default_effective);
		if (route_metric_default_aspired != route_metric_default_effective) {
			g_key_file_set_int64 (kf,
			                      DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
			                      DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_ROUTE_METRIC_DEFAULT_ASPIRED,
			                      route_metric_default_aspired);
		}
	}
	if (next_server) {
		g_key_file_set_string (kf,
		                       DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
		                       DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_NEXT_SERVER,
		                       next_server);
	}
	if (root_path) {
		g_key_file_set_string (kf,
		                       DEVICE_RUN_STATE_KEYFILE_GROUP_DEVICE,
		                       DEVICE_RUN_STATE_KEYFILE_KEY_DEVICE_ROOT_PATH,
		                       root_path);
	}

	if (!g_key_file_save_to_file (kf, path, &local)) {
		_LOGW ("device-state: write #%d (%s) failed: %s", ifindex, path, local->message);
		g_error_free (local);
		return FALSE;
	}
	_LOGT ("device-state: write #%d (%s); managed=%s%s%s%s%s%s%s, route-metric-default=%"G_GUINT32_FORMAT"-%"G_GUINT32_FORMAT"%s%s%s%s%s%s",
	       ifindex, path,
	       _device_state_managed_type_to_str (managed),
	       NM_PRINT_FMT_QUOTED (connection_uuid, ", connection-uuid=", connection_uuid, "", ""),
	       NM_PRINT_FMT_QUOTED (perm_hw_addr_fake, ", perm-hw-addr-fake=", perm_hw_addr_fake, "", ""),
	       route_metric_default_aspired,
	       route_metric_default_effective,
	       NM_PRINT_FMT_QUOTED (next_server, ", next-server=", next_server, "", ""),
	       NM_PRINT_FMT_QUOTED (root_path, ", root-path=", root_path, "", ""));
	return TRUE;
}

void
nm_config_device_state_prune_unseen (GHashTable *seen_ifindexes)
{
	GDir *dir;
	const char *fn;
	int ifindex;
	gsize fn_len;
	char buf[NM_STRLEN (NM_CONFIG_DEVICE_STATE_DIR"/") + 30 + 3] = NM_CONFIG_DEVICE_STATE_DIR"/";
	char *buf_p = &buf[NM_STRLEN (NM_CONFIG_DEVICE_STATE_DIR"/")];

	g_return_if_fail (seen_ifindexes);

	dir = g_dir_open (NM_CONFIG_DEVICE_STATE_DIR, 0, NULL);
	if (!dir)
		return;

	while ((fn = g_dir_read_name (dir))) {
		ifindex = _device_state_parse_filename (fn);
		if (ifindex <= 0)
			continue;
		if (g_hash_table_contains (seen_ifindexes, GINT_TO_POINTER (ifindex)))
			continue;

		fn_len = strlen (fn) + 1;
		nm_assert (&buf_p[fn_len] < &buf[G_N_ELEMENTS (buf)]);
		memcpy (buf_p, fn, fn_len);
		nm_assert (({
		                char bb[30];
		                nm_sprintf_buf (bb, "%d", ifindex);
		                nm_streq0 (bb, buf_p);
		           }));
		_LOGT ("device-state: prune #%d (%s)", ifindex, buf);
		(void) unlink (buf);
	}

	g_dir_close (dir);
}

/*****************************************************************************/

static GHashTable *
_device_state_get_all (NMConfig *self)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (self);

	if (G_UNLIKELY (!priv->device_states))
		priv->device_states = nm_config_device_state_load_all ();
	return priv->device_states;
}

/**
 * nm_config_device_state_get_all:
 * @self: the #NMConfig
 *
 * This function exists to give convenient access to all
 * device states. Do not ever try to modify the returned
 * hash, it's supposed to be immutable.
 *
 * Returns: the internal #GHashTable object with all device states.
 */
const GHashTable *
nm_config_device_state_get_all (NMConfig *self)
{
	g_return_val_if_fail (NM_IS_CONFIG (self), NULL);

	return _device_state_get_all (self);
}

const NMConfigDeviceStateData *
nm_config_device_state_get (NMConfig *self,
                            int ifindex)
{
	g_return_val_if_fail (NM_IS_CONFIG (self), NULL);
	g_return_val_if_fail (ifindex > 0 , NULL);

	return g_hash_table_lookup (_device_state_get_all (self), GINT_TO_POINTER (ifindex));
}

/*****************************************************************************/

void
nm_config_reload (NMConfig *self, NMConfigChangeFlags reload_flags, gboolean emit_warnings)
{
	NMConfigPrivate *priv;
	GError *error = NULL;
	GKeyFile *keyfile, *keyfile_intern;
	NMConfigData *new_data = NULL;
	char *config_main_file = NULL;
	char *config_description = NULL;
	gs_strfreev char **no_auto_default = NULL;
	gboolean intern_config_needs_rewrite;
	gs_strfreev char **warnings = NULL;
	guint i;

	g_return_if_fail (NM_IS_CONFIG (self));
	g_return_if_fail (   reload_flags
	                  && !NM_FLAGS_ANY (reload_flags, ~NM_CONFIG_CHANGE_CAUSES)
	                  && !NM_FLAGS_ANY (reload_flags,   NM_CONFIG_CHANGE_CAUSE_NO_AUTO_DEFAULT
	                                                  | NM_CONFIG_CHANGE_CAUSE_SET_VALUES));

	priv = NM_CONFIG_GET_PRIVATE (self);

	if (!NM_FLAGS_ANY (reload_flags, NM_CONFIG_CHANGE_CAUSE_SIGHUP | NM_CONFIG_CHANGE_CAUSE_CONF)) {
		/* unless SIGHUP is specified, we don't reload the configuration from disc. */
		_set_config_data (self, NULL, reload_flags);
		return;
	}

	/* pass on the original command line options. This means, that
	 * options specified at command line cannot ever be reloaded from
	 * file. That seems desirable.
	 */
	keyfile = read_entire_config (&priv->cli,
	                              priv->config_dir,
	                              priv->system_config_dir,
	                              &config_main_file,
	                              &config_description,
	                              &warnings,
	                              &error);
	if (!keyfile) {
		_LOGE ("Failed to reload the configuration: %s", error->message);
		g_clear_error (&error);
		_set_config_data (self, NULL, reload_flags);
		return;
	}

	if (emit_warnings && warnings) {
		for (i = 0; warnings[i]; i++)
			_LOGW ("%s", warnings[i]);
	}

	no_auto_default = no_auto_default_from_file (priv->no_auto_default_file);

	keyfile_intern = intern_config_read (priv->intern_config_file,
	                                     keyfile,
	                                     (const char *const*) priv->atomic_section_prefixes,
	                                     &intern_config_needs_rewrite);
	if (intern_config_needs_rewrite) {
		intern_config_write (priv->intern_config_file, keyfile_intern, keyfile,
		                     (const char *const*) priv->atomic_section_prefixes, NULL);
	}

	new_data = nm_config_data_new (config_main_file,
	                               config_description,
	                               (const char *const*) no_auto_default,
	                               keyfile,
	                               keyfile_intern);
	g_free (config_main_file);
	g_free (config_description);
	g_key_file_unref (keyfile);
	if (keyfile_intern)
		g_key_file_unref (keyfile_intern);

	_set_config_data (self, new_data, reload_flags);
}

NM_UTILS_FLAGS2STR_DEFINE (nm_config_change_flags_to_string, NMConfigChangeFlags,

	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_CAUSE_CONF, "CONF"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_CAUSE_DNS_RC, "DNS_RC"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_CAUSE_DNS_FULL, "DNS_FULL"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_CAUSE_SIGHUP, "SIGHUP"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_CAUSE_SIGUSR1, "SIGUSR1"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_CAUSE_SIGUSR2, "SIGUSR2"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_CAUSE_NO_AUTO_DEFAULT, "NO_AUTO_DEFAULT"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_CAUSE_SET_VALUES, "SET_VALUES"),

	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_CONFIG_FILES, "config-files"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_VALUES, "values"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_VALUES_USER, "values-user"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_VALUES_INTERN, "values-intern"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_CONNECTIVITY, "connectivity"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_NO_AUTO_DEFAULT, "no-auto-default"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_DNS_MODE, "dns-mode"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_RC_MANAGER, "rc-manager"),
	NM_UTILS_FLAGS2STR (NM_CONFIG_CHANGE_GLOBAL_DNS_CONFIG, "global-dns-config"),
);

static void
_set_config_data (NMConfig *self, NMConfigData *new_data, NMConfigChangeFlags reload_flags)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (self);
	NMConfigData *old_data = priv->config_data;
	NMConfigChangeFlags changes, changes_diff;
	gboolean had_new_data = !!new_data;

	nm_assert (reload_flags);
	nm_assert (!NM_FLAGS_ANY (reload_flags, ~NM_CONFIG_CHANGE_CAUSES));
	nm_assert (   NM_IN_SET (reload_flags, NM_CONFIG_CHANGE_CAUSE_NO_AUTO_DEFAULT, NM_CONFIG_CHANGE_CAUSE_SET_VALUES)
	           || !NM_FLAGS_ANY (reload_flags, NM_CONFIG_CHANGE_CAUSE_NO_AUTO_DEFAULT | NM_CONFIG_CHANGE_CAUSE_SET_VALUES));

	changes = reload_flags;

	if (new_data) {
		changes_diff = nm_config_data_diff (old_data, new_data);
		if (changes_diff == NM_CONFIG_CHANGE_NONE)
			g_clear_object (&new_data);
		else
			changes |= changes_diff;
	}

	if (   NM_IN_SET (reload_flags,
	                  NM_CONFIG_CHANGE_CAUSE_NO_AUTO_DEFAULT,
	                  NM_CONFIG_CHANGE_CAUSE_SET_VALUES,
	                  NM_CONFIG_CHANGE_CAUSE_CONF)
	    && !new_data) {
		/* no relevant changes that should be propagated. Return silently. */
		return;
	}

	if (new_data) {
		_LOGI ("signal: %s (%s)",
		       nm_config_change_flags_to_string (changes, NULL, 0),
		       nm_config_data_get_config_description (new_data));
		nm_config_data_log (new_data, "CONFIG: ", "  ", NULL);
		priv->config_data = new_data;
	} else if (had_new_data)
		_LOGI ("signal: %s (no changes from disk)", nm_config_change_flags_to_string (changes, NULL, 0));
	else
		_LOGI ("signal: %s", nm_config_change_flags_to_string (changes, NULL, 0));
	g_signal_emit (self, signals[SIGNAL_CONFIG_CHANGED], 0,
	               new_data ?: old_data,
	               changes, old_data);
	if (new_data)
		g_object_unref (old_data);
}

NM_DEFINE_SINGLETON_REGISTER (NMConfig);

NMConfig *
nm_config_get (void)
{
	g_assert (singleton_instance);
	return singleton_instance;
}

NMConfig *
nm_config_setup (const NMConfigCmdLineOptions *cli, char **atomic_section_prefixes, GError **error)
{
	g_assert (!singleton_instance);

	singleton_instance = nm_config_new (cli, atomic_section_prefixes, error);
	if (singleton_instance) {
		nm_singleton_instance_register ();

		/* usually, you would not see this logging line because when creating the
		 * NMConfig instance, the logging is not yet set up to print debug message. */
		nm_log_dbg (LOGD_CORE, "setup %s singleton ("NM_HASH_OBFUSCATE_PTR_FMT")",
		            "NMConfig", NM_HASH_OBFUSCATE_PTR (singleton_instance));
	}
	return singleton_instance;
}

/*****************************************************************************/

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMConfig *self = NM_CONFIG (object);
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (self);
	NMConfigCmdLineOptions *cli;
	char **strv;

	switch (prop_id) {
	case PROP_CMD_LINE_OPTIONS:
		/* construct-only */
		cli = g_value_get_pointer (value);
		if (!cli)
			_nm_config_cmd_line_options_clear (&priv->cli);
		else
			_nm_config_cmd_line_options_copy (cli, &priv->cli);
		break;
	case PROP_ATOMIC_SECTION_PREFIXES:
		/* construct-only */
		strv = g_value_get_boxed (value);
		if (strv && !strv[0])
			strv = NULL;
		priv->atomic_section_prefixes = g_strdupv (strv);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static gboolean
init_sync (GInitable *initable, GCancellable *cancellable, GError **error)
{
	NMConfig *self = NM_CONFIG (initable);
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE (self);
	gs_unref_keyfile GKeyFile *keyfile = NULL;
	gs_unref_keyfile GKeyFile *keyfile_intern = NULL;
	gs_free char *config_main_file = NULL;
	gs_free char *config_description = NULL;
	gs_strfreev char **no_auto_default = NULL;
	gs_strfreev char **warnings = NULL;
	gs_free char *configure_and_quit = NULL;
	gboolean intern_config_needs_rewrite;
	const char *s;

	if (priv->config_dir) {
		/* Object is already initialized. */
		if (priv->config_data)
			return TRUE;
		g_set_error (error, G_KEY_FILE_ERROR, G_KEY_FILE_ERROR_NOT_FOUND, "unspecified error");
		g_return_val_if_reached (FALSE);
	}

	s = priv->cli.config_dir ?: ""DEFAULT_CONFIG_DIR;
	priv->config_dir = g_strdup (s[0] == '/' ? s : "");

	s = priv->cli.system_config_dir ?: ""DEFAULT_SYSTEM_CONFIG_DIR;
	if (   s[0] != '/'
	    || nm_streq (s, priv->config_dir))
		s = "";
	priv->system_config_dir = g_strdup (s);

	if (priv->cli.intern_config_file)
		priv->intern_config_file = g_strdup (priv->cli.intern_config_file);
	else
		priv->intern_config_file = g_strdup (DEFAULT_INTERN_CONFIG_FILE);

	keyfile = read_entire_config (&priv->cli,
	                              priv->config_dir,
	                              priv->system_config_dir,
	                              &config_main_file,
	                              &config_description,
	                              &warnings,
	                              error);
	if (!keyfile)
		return FALSE;

	/* Initialize read-only private members */

	if (priv->cli.no_auto_default_file)
		priv->no_auto_default_file = g_strdup (priv->cli.no_auto_default_file);
	else
		priv->no_auto_default_file = g_strdup (DEFAULT_NO_AUTO_DEFAULT_FILE);

	priv->log_level = nm_strstrip (g_key_file_get_string (keyfile,
	                                                      NM_CONFIG_KEYFILE_GROUP_LOGGING,
	                                                      NM_CONFIG_KEYFILE_KEY_LOGGING_LEVEL,
	                                                      NULL));
	priv->log_domains = nm_strstrip (g_key_file_get_string (keyfile,
	                                                        NM_CONFIG_KEYFILE_GROUP_LOGGING,
	                                                        NM_CONFIG_KEYFILE_KEY_LOGGING_DOMAINS,
	                                                        NULL));
	configure_and_quit = nm_strstrip (g_key_file_get_string (keyfile,
	                                                         NM_CONFIG_KEYFILE_GROUP_MAIN,
	                                                         NM_CONFIG_KEYFILE_KEY_MAIN_CONFIGURE_AND_QUIT,
	                                                         NULL));
	priv->configure_and_quit = string_to_configure_and_quit (configure_and_quit, error);
	if (priv->configure_and_quit == NM_CONFIG_CONFIGURE_AND_QUIT_INVALID)
		return FALSE;

	no_auto_default = no_auto_default_from_file (priv->no_auto_default_file);

	keyfile_intern = intern_config_read (priv->intern_config_file,
	                                     keyfile,
	                                     (const char *const*) priv->atomic_section_prefixes,
	                                     &intern_config_needs_rewrite);
	if (   intern_config_needs_rewrite
	    && priv->configure_and_quit == NM_CONFIG_CONFIGURE_AND_QUIT_DISABLED) {
		intern_config_write (priv->intern_config_file, keyfile_intern, keyfile,
		                     (const char *const*) priv->atomic_section_prefixes, NULL);
	}

	priv->config_data_orig = nm_config_data_new (config_main_file,
	                                             config_description,
	                                             (const char *const*) no_auto_default,
	                                             keyfile,
	                                             keyfile_intern);

	priv->config_data = g_object_ref (priv->config_data_orig);
	priv->warnings = g_steal_pointer (&warnings);
	return TRUE;
}

/*****************************************************************************/

static void
nm_config_init (NMConfig *config)
{
}

NMConfig *
nm_config_new (const NMConfigCmdLineOptions *cli, char **atomic_section_prefixes, GError **error)
{
	return NM_CONFIG (g_initable_new (NM_TYPE_CONFIG,
	                                  NULL,
	                                  error,
	                                  NM_CONFIG_CMD_LINE_OPTIONS, cli,
	                                  NM_CONFIG_ATOMIC_SECTION_PREFIXES, atomic_section_prefixes,
	                                  NULL));
}

static void
finalize (GObject *gobject)
{
	NMConfigPrivate *priv = NM_CONFIG_GET_PRIVATE ((NMConfig *) gobject);

	state_free (priv->state);

	g_free (priv->config_dir);
	g_free (priv->system_config_dir);
	g_free (priv->no_auto_default_file);
	g_free (priv->intern_config_file);
	g_free (priv->log_level);
	g_free (priv->log_domains);
	g_strfreev (priv->atomic_section_prefixes);
	g_strfreev (priv->warnings);

	_nm_config_cmd_line_options_clear (&priv->cli);

	g_clear_object (&priv->config_data);
	g_clear_object (&priv->config_data_orig);

	G_OBJECT_CLASS (nm_config_parent_class)->finalize (gobject);
}

static void
nm_config_class_init (NMConfigClass *config_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (config_class);

	object_class->finalize = finalize;
	object_class->set_property = set_property;

	obj_properties[PROP_CMD_LINE_OPTIONS] =
	     g_param_spec_pointer (NM_CONFIG_CMD_LINE_OPTIONS, "", "",
	                           G_PARAM_WRITABLE |
	                           G_PARAM_CONSTRUCT_ONLY |
	                           G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_ATOMIC_SECTION_PREFIXES] =
	     g_param_spec_boxed (NM_CONFIG_ATOMIC_SECTION_PREFIXES, "", "",
	                         G_TYPE_STRV,
	                         G_PARAM_WRITABLE |
	                         G_PARAM_CONSTRUCT_ONLY |
	                         G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[SIGNAL_CONFIG_CHANGED] =
	    g_signal_new (NM_CONFIG_SIGNAL_CONFIG_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE,
	                  3,
	                  NM_TYPE_CONFIG_DATA,
	                  /* Use plain guint type for changes argument. This avoids
	                   * glib/ffi bug https://bugzilla.redhat.com/show_bug.cgi?id=1260577 */
	                  /* NM_TYPE_CONFIG_CHANGE_FLAGS, */
	                  G_TYPE_UINT,
	                  NM_TYPE_CONFIG_DATA);

	G_STATIC_ASSERT_EXPR (sizeof (guint) == sizeof (NMConfigChangeFlags));
	G_STATIC_ASSERT_EXPR (((gint64) ((NMConfigChangeFlags) -1)) > ((gint64) 0));
}

static void
nm_config_initable_iface_init (GInitableIface *iface)
{
	iface->init = init_sync;
}
