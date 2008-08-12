/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <errno.h>

#include <nm-setting-vpn.h>
#include "nm-vpnc-service.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMVPNCPlugin, nm_vpnc_plugin, NM_TYPE_VPN_PLUGIN)

typedef struct {
	GPid pid;
} NMVPNCPluginPrivate;

#define NM_VPNC_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_VPNC_PLUGIN, NMVPNCPluginPrivate))

static const char *vpnc_binary_paths[] =
{
	"/usr/sbin/vpnc",
	"/sbin/vpnc",
	"/usr/local/sbin/vpnc",
	NULL
};

#define NM_VPNC_HELPER_PATH		LIBEXECDIR"/nm-vpnc-service-vpnc-helper"
#define NM_VPNC_UDP_ENCAPSULATION_PORT	0 /* random port */

typedef struct {
	const char *name;
	GType type;
	gint int_min;
	gint int_max;
} ValidProperty;

#define LEGACY_NAT_KEEPALIVE "NAT-Keepalive packet interval"

static ValidProperty valid_properties[] = {
	{ NM_VPNC_KEY_GATEWAY,               G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_ID,                    G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_SECRET,                G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_XAUTH_USER,            G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_XAUTH_PASSWORD,        G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_DOMAIN,                G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_DHGROUP,               G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_PERFECT_FORWARD,       G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_APP_VERSION,           G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_SINGLE_DES,            G_TYPE_BOOLEAN, 0, 0 },
	{ NM_VPNC_KEY_NO_ENCRYPTION,         G_TYPE_BOOLEAN, 0, 0 },
	{ NM_VPNC_KEY_DPD_IDLE_TIMEOUT,      G_TYPE_INT, 0, 86400 },
	{ NM_VPNC_KEY_NAT_TRAVERSAL_MODE,    G_TYPE_STRING, 0, 0 },
	{ NM_VPNC_KEY_CISCO_UDP_ENCAPS_PORT, G_TYPE_INT, 0, 65535 },
	/* Legacy options that are ignored */
	{ LEGACY_NAT_KEEPALIVE,              G_TYPE_STRING, 0, 0 },
	{ NULL,                              G_TYPE_NONE, 0, 0 }
};

static void
validate_one_property (gpointer key, gpointer value, gpointer user_data)
{
	GError **error = (GError **) user_data;
	int i;

	if (*error)
		return;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp ((char *) key, NM_SETTING_NAME))
		return;

	for (i = 0; valid_properties[i].name; i++) {
		ValidProperty prop = valid_properties[i];
		long int tmp;

		if (strcmp (prop.name, (char *) key))
			continue;

		switch (prop.type) {
		case G_TYPE_STRING:
			return; /* valid */
		case G_TYPE_INT:
			errno = 0;
			tmp = strtol ((char *) value, NULL, 10);
			if (errno == 0 && tmp >= prop.int_min && tmp <= prop.int_max)
				return; /* valid */

			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid integer property '%s' or out of range [%d -> %d]",
			             (const char *) key, prop.int_min, prop.int_max);
			break;
		case G_TYPE_BOOLEAN:
			if (!strcmp ((char *) value, "yes") || !strcmp ((char *) value, "no"))
				return; /* valid */

			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid boolean property '%s' (not yes or no)",
			             (const char *) key);
			break;
		default:
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "unhandled property '%s' type %s",
			             (const char *) key, g_type_name (prop.type));
			break;
		}
	}

	/* Did not find the property from valid_properties or the type did not match */
	if (!valid_properties[i].name) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "property '%s' invalid or not supported",
		             (const char *) key);
	}
}

static gboolean
nm_vpnc_properties_validate (GHashTable *properties, GError **error)
{
	if (g_hash_table_size (properties) < 1) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "No VPN configuration options.");
		return FALSE;
	}

	g_hash_table_foreach (properties, validate_one_property, error);

	return *error ? FALSE : TRUE;
}

static void
vpnc_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMVPNCPlugin *plugin = NM_VPNC_PLUGIN (user_data);
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);
	guint error = 0;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			nm_warning ("vpnc exited with error code %d", error);
	}
	else if (WIFSTOPPED (status))
		nm_warning ("vpnc stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		nm_warning ("vpnc died with signal %d", WTERMSIG (status));
	else
		nm_warning ("vpnc died from an unknown cause");

	/* Reap child if needed. */
	waitpid (priv->pid, NULL, WNOHANG);
	priv->pid = 0;

	/* Must be after data->state is set since signals use data->state */
	switch (error) {
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}

	nm_vpn_plugin_set_state (NM_VPN_PLUGIN (plugin), NM_VPN_SERVICE_STATE_STOPPED);
}

static gint
nm_vpnc_start_vpnc_binary (NMVPNCPlugin *plugin, GError **error)
{
	GPid	pid;
	const char **vpnc_binary = NULL;
	GPtrArray *vpnc_argv;
	GSource *vpnc_watch;
	gint	stdin_fd;

	/* Find vpnc */
	vpnc_binary = vpnc_binary_paths;
	while (*vpnc_binary != NULL) {
		if (g_file_test (*vpnc_binary, G_FILE_TEST_EXISTS))
			break;
		vpnc_binary++;
	}

	if (!*vpnc_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "%s",
		             "Could not find vpnc binary.");
		return -1;
	}

	vpnc_argv = g_ptr_array_new ();
	g_ptr_array_add (vpnc_argv, (gpointer) (*vpnc_binary));
	g_ptr_array_add (vpnc_argv, (gpointer) "--non-inter");
	g_ptr_array_add (vpnc_argv, (gpointer) "--no-detach");
	g_ptr_array_add (vpnc_argv, (gpointer) "-");
	g_ptr_array_add (vpnc_argv, NULL);

	if (!g_spawn_async_with_pipes (NULL, (char **) vpnc_argv->pdata, NULL,
							 G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &stdin_fd,
							 NULL, NULL, error)) {
		g_ptr_array_free (vpnc_argv, TRUE);
		nm_warning ("vpnc failed to start.  error: '%s'", (*error)->message);
		return -1;
	}
	g_ptr_array_free (vpnc_argv, TRUE);

	nm_info ("vpnc started with pid %d", pid);

	NM_VPNC_PLUGIN_GET_PRIVATE (plugin)->pid = pid;
	vpnc_watch = g_child_watch_source_new (pid);
	g_source_set_callback (vpnc_watch, (GSourceFunc) vpnc_watch_cb, plugin, NULL);
	g_source_attach (vpnc_watch, NULL);
	g_source_unref (vpnc_watch);

	return stdin_fd;
}

static inline void
write_config_option (int fd, const char *format, ...)
{
	char * 	string;
	va_list	args;
	int		x;

	va_start (args, format);
	string = g_strdup_vprintf (format, args);
	x = write (fd, string, strlen (string));
	g_free (string);
	va_end (args);
}

typedef struct {
	int fd;
	GError *error;
} WriteConfigInfo;

static void
write_one_property (gpointer key, gpointer value, gpointer user_data)
{
	WriteConfigInfo *info = (WriteConfigInfo *) user_data;
	GType type = G_TYPE_INVALID;
	int i;

	if (info->error)
		return;

	/* Find the value in the table to get its type */
	for (i = 0; valid_properties[i].name; i++) {
		ValidProperty prop = valid_properties[i];

		if (!strcmp (prop.name, (char *) key)) {
			/* Property is ok */
			type = prop.type;
			break;
		}
	}

	if (type == G_TYPE_INVALID) {
		g_set_error (&info->error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Config option '%s' invalid or unknown.",
		             (const char *) key);
	}	

	if (type == G_TYPE_STRING)
		write_config_option (info->fd, "%s %s\n", (char *) key, (char *) value);
	else if (type == G_TYPE_BOOLEAN) {
		if (!strcmp (value, "yes"))
			write_config_option (info->fd, "%s\n", (char *) key);
	} else if (type == G_TYPE_INT) {
		long int tmp_int;
		char *tmp_str;

		/* Convert -> int and back to string for security's sake since
		 * strtol() ignores leading and trailing characters.
		 */
		errno = 0;
		tmp_int = strtol (value, NULL, 10);
		if (errno == 0) {
			tmp_str = g_strdup_printf ("%ld", tmp_int);
			write_config_option (info->fd, "%s %s\n", (char *) key, tmp_str);
			g_free (tmp_str);
		} else {
			g_set_error (&info->error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "Config option '%s' not an integer.",
			             (const char *) key);
		}
	} else {
		/* Just ignore unknown properties */
		nm_warning ("Don't know how to write property '%s' with type %s",
				  (char *) key, g_type_name (type));
	}
}

static gboolean
nm_vpnc_config_write (gint vpnc_fd,
                      const char *default_user_name,
                      GHashTable *properties,
                      GError **error)
{
	WriteConfigInfo *info;
	const char *props_user_name;
	const char *props_natt_mode;

	write_config_option (vpnc_fd, "Script " NM_VPNC_HELPER_PATH "\n");

	write_config_option (vpnc_fd,
	                     NM_VPNC_KEY_CISCO_UDP_ENCAPS_PORT " %d\n",
	                     NM_VPNC_UDP_ENCAPSULATION_PORT);

	/* Fill username if it's not present */
	props_user_name = g_hash_table_lookup (properties, NM_VPNC_KEY_XAUTH_USER);
	if (   default_user_name
	    && strlen (default_user_name)
	    && (!props_user_name || !strlen (props_user_name))) {
		write_config_option (vpnc_fd,
		                     NM_VPNC_KEY_XAUTH_USER " %s\n",
		                     default_user_name);
	}
	
	/* Use NAT-T by default */
	props_natt_mode = g_hash_table_lookup (properties, NM_VPNC_KEY_NAT_TRAVERSAL_MODE);
	if (!props_natt_mode || !strlen (props_natt_mode)) {
		write_config_option (vpnc_fd,
		                     NM_VPNC_KEY_NAT_TRAVERSAL_MODE " %s\n",
		                     NM_VPNC_NATT_MODE_NATT);
	}

	info = g_malloc0 (sizeof (WriteConfigInfo));
	info->fd = vpnc_fd;
	g_hash_table_foreach (properties, write_one_property, info);
	*error = info->error;
	g_free (info);

	return *error ? FALSE : TRUE;
}

static gboolean
real_connect (NMVPNPlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NMSettingVPN *s_vpn;
	gint vpnc_fd = -1;
	gboolean success = FALSE;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	g_assert (s_vpn);
	if (!nm_vpnc_properties_validate (s_vpn->data, error))
		goto out;

	vpnc_fd = nm_vpnc_start_vpnc_binary (NM_VPNC_PLUGIN (plugin), error);
	if (vpnc_fd < 0)
		goto out;

	if (!nm_vpnc_config_write (vpnc_fd, s_vpn->user_name, s_vpn->data, error))
		goto out;

	success = TRUE;

out:
	if (vpnc_fd >= 0)
		close (vpnc_fd);
	return success;
}

static gboolean
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error)
{
	NMSettingVPN *s_vpn;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	if (!s_vpn) {
        g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "Could not process the request because the VPN connection settings were invalid.");
		return FALSE;
	}

	// FIXME: there are some configurations where both passwords are not
	// required.  Make sure they work somehow.
	if (!g_hash_table_lookup (s_vpn->data, NM_VPNC_KEY_SECRET)) {
		*setting_name = NM_SETTING_VPN_SETTING_NAME;
		return TRUE;
	}
	if (!g_hash_table_lookup (s_vpn->data, NM_VPNC_KEY_XAUTH_PASSWORD)) {
		*setting_name = NM_SETTING_VPN_SETTING_NAME;
		return TRUE;
	}

	return FALSE;
}

static gboolean
ensure_killed (gpointer data)
{
	int pid = GPOINTER_TO_INT (data);

	if (kill (pid, 0) == 0)
		kill (pid, SIGKILL);

	return FALSE;
}

static gboolean
real_disconnect (NMVPNPlugin   *plugin,
			  GError       **err)
{
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		nm_info ("Terminated vpnc daemon with PID %d.", priv->pid);
		priv->pid = 0;
	}

	return TRUE;
}

static void
nm_vpnc_plugin_init (NMVPNCPlugin *plugin)
{
}

static void
nm_vpnc_plugin_class_init (NMVPNCPluginClass *vpnc_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (vpnc_class);
	NMVPNPluginClass *parent_class = NM_VPN_PLUGIN_CLASS (vpnc_class);

	g_type_class_add_private (object_class, sizeof (NMVPNCPluginPrivate));

	/* virtual methods */
	parent_class->connect    = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect = real_disconnect;
}

NMVPNCPlugin *
nm_vpnc_plugin_new (void)
{
	return (NMVPNCPlugin *) g_object_new (NM_TYPE_VPNC_PLUGIN,
								   NM_VPN_PLUGIN_DBUS_SERVICE_NAME, NM_DBUS_SERVICE_VPNC,
								   NULL);
}

static void
quit_mainloop (NMVPNCPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NMVPNCPlugin *plugin;
	GMainLoop *main_loop;

	g_type_init ();

	if (system ("/sbin/modprobe tun") == -1)
		exit (EXIT_FAILURE);

	plugin = nm_vpnc_plugin_new ();
	if (!plugin)
		exit (EXIT_FAILURE);

	main_loop = g_main_loop_new (NULL, FALSE);

	g_signal_connect (plugin, "quit",
				   G_CALLBACK (quit_mainloop),
				   main_loop);

	g_main_loop_run (main_loop);

	g_main_loop_unref (main_loop);
	g_object_unref (plugin);

	exit (EXIT_SUCCESS);
}
