/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>

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

#define NM_VPNC_HELPER_PATH		BINDIR"/nm-vpnc-service-vpnc-helper"
#define NM_VPNC_UDP_ENCAPSULATION_PORT	0 /* random port */
#define NM_VPNC_REKEYING_INTERVAL 7200 /* default interval of 2 hours */

typedef struct {
	const char *name;
	GType type;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_VPNC_KEY_GATEWAY,         G_TYPE_STRING },
	{ NM_VPNC_KEY_ID,              G_TYPE_STRING },
	{ NM_VPNC_KEY_SECRET,          G_TYPE_STRING },
	{ NM_VPNC_KEY_XAUTH_USER,      G_TYPE_STRING },
	{ NM_VPNC_KEY_XAUTH_PASSWORD,  G_TYPE_STRING },
	{ NM_VPNC_KEY_UDP_ENCAPS,      G_TYPE_BOOLEAN },
	{ NM_VPNC_KEY_UDP_ENCAPS_PORT, G_TYPE_INT },
	{ NM_VPNC_KEY_DOMAIN,          G_TYPE_STRING },
	{ NM_VPNC_KEY_DHGROUP,         G_TYPE_STRING },
	{ NM_VPNC_KEY_PERFECT_FORWARD, G_TYPE_STRING },
	{ NM_VPNC_KEY_APP_VERSION,     G_TYPE_STRING },
	{ NM_VPNC_KEY_REKEYING,        G_TYPE_INT },
	{ NM_VPNC_KEY_NAT_KEEPALIVE,   G_TYPE_STRING },
	{ NM_VPNC_KEY_DISABLE_NAT,     G_TYPE_BOOLEAN },
	{ NM_VPNC_KEY_SINGLE_DES,      G_TYPE_BOOLEAN },
	{ NULL,                        G_TYPE_NONE }
};

static void
validate_one_property (gpointer key, gpointer val, gpointer user_data)
{
	gboolean *failed = (gboolean *) user_data;
	int i;

	if (*failed)
		return;

	for (i = 0; valid_properties[i].name; i++) {
		ValidProperty prop = valid_properties[i];

		if (!strcmp (prop.name, (char *) key) && prop.type == G_VALUE_TYPE ((GValue *) val))
			/* Property is ok */
			return;
	}

	/* Did not find the property from valid_properties or the type did not match */
	*failed = TRUE;
}

static gboolean
nm_vpnc_properties_validate (GHashTable *properties)
{
	gboolean failed = FALSE;

	if (g_hash_table_size (properties) < 1)
		return failed;

	g_hash_table_foreach (properties, validate_one_property, &failed);

	return !failed;
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
nm_vpnc_start_vpnc_binary (NMVPNCPlugin *plugin)
{
	GPid	pid;
	const char **vpnc_binary = NULL;
	GPtrArray *vpnc_argv;
	GError *err = NULL;
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
		nm_info ("Could not find vpnc binary.");
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
							 NULL, NULL, &err)) {
		g_ptr_array_free (vpnc_argv, TRUE);
		nm_warning ("vpnc failed to start.  error: '%s'", err->message);
		g_error_free (err);
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

static void
write_one_property (gpointer key, gpointer val, gpointer user_data)
{
	gint vpnc_fd = GPOINTER_TO_INT (user_data);
	GValue *value = (GValue *) val;
	GType type;

	type = G_VALUE_TYPE (value);
	if (type == G_TYPE_STRING)
		write_config_option (vpnc_fd, "%s %s\n", (char *) key, g_value_get_string (value));
	else if (type == G_TYPE_BOOLEAN)
		write_config_option (vpnc_fd, "%s\n", (char *) key);
	else if (type == G_TYPE_INT)
		write_config_option (vpnc_fd, "%s %d\n", (char *) key, g_value_get_int (value));
	else if (type == DBUS_TYPE_G_UCHAR_ARRAY) {
		char *tmp;

		tmp = nm_utils_garray_to_string ((GArray *) g_value_get_boxed (value));
		write_config_option (vpnc_fd, "%s %s\n", tmp);
		g_free (tmp);
	}

	else
		nm_warning ("Don't know how to write property '%s' with type %s",
				  (char *) key, g_type_name (type));
}

static void
nm_vpnc_config_write (gint vpnc_fd, GHashTable *properties)
{
	write_config_option (vpnc_fd, "Script " NM_VPNC_HELPER_PATH "\n");

	/* Thankfully vpnc ignores options it does not understand... */

	/* Options for vpnc 0.3.x */
	write_config_option (vpnc_fd, "UDP Encapsulate\n");
	write_config_option (vpnc_fd, "UDP Encapsulation Port %d\n", NM_VPNC_UDP_ENCAPSULATION_PORT);
	if (!g_hash_table_lookup (properties, "Rekeying interval"))
		write_config_option (vpnc_fd, "Rekeying interval %d\n", NM_VPNC_REKEYING_INTERVAL);

	// FIXME: do we need to enable Cisco UDP encapsulation here?
	/* 0.4.x rekeys automatically */

	g_hash_table_foreach (properties, write_one_property, GINT_TO_POINTER (vpnc_fd));
}

static gboolean
real_connect (NMVPNPlugin   *plugin,
		    NMConnection  *connection,
		    GError       **err)
{
	NMSettingVPNProperties *properties;
	gint vpnc_fd;

	properties = (NMSettingVPNProperties *) nm_connection_get_setting (connection, NM_SETTING_VPN_PROPERTIES);
	if (!properties || !nm_vpnc_properties_validate (properties->data)) {
		g_set_error (err,
				   NM_VPN_PLUGIN_ERROR,
				   NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				   "%s",
				   "Invalid arguments.");
		return FALSE;
	}

	if ((vpnc_fd = nm_vpnc_start_vpnc_binary (NM_VPNC_PLUGIN (plugin))) >= 0)
		nm_vpnc_config_write (vpnc_fd, properties->data);
	else {
		g_set_error (err,
				   NM_VPN_PLUGIN_ERROR,
				   NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
				   "%s",
				   "Could not start vpnc binary.");
		close (vpnc_fd);
		return FALSE;
	}

	close (vpnc_fd);
	return TRUE;
}

static gboolean
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error)
{
	NMSettingVPNProperties *s_vpn_props;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn_props = (NMSettingVPNProperties *) nm_connection_get_setting (connection, NM_SETTING_VPN_PROPERTIES);
	if (!s_vpn_props) {
        g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "Could not process the request because the VPN connection settings were invalid.");
		return FALSE;
	}

	// FIXME: there are some configurations where both passwords are not
	// required.  Make sure they work somehow.
	if (!g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_SECRET)) {
		*setting_name = NM_SETTING_VPN_PROPERTIES;
		return TRUE;
	}
	if (!g_hash_table_lookup (s_vpn_props->data, NM_VPNC_KEY_XAUTH_PASSWORD)) {
		*setting_name = NM_SETTING_VPN_PROPERTIES;
		return TRUE;
	}

	return FALSE;
}

static gboolean
real_disconnect (NMVPNPlugin   *plugin,
			  GError       **err)
{
	NMVPNCPluginPrivate *priv = NM_VPNC_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid) {
		kill (priv->pid, SIGTERM);
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
