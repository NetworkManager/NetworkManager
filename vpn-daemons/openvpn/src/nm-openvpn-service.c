/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */
/* nm-openvpn-service - openvpn integration with NetworkManager
 *
 * Tim Niemueller <tim@niemueller.de>
 * Based on work by Dan Williams <dcbw@redhat.com>
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
 * $Id$
 *
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <NetworkManager.h>
#include <NetworkManagerVPN.h>
#include <nm-setting-vpn.h>
#include <nm-setting-vpn-properties.h>

#include "nm-openvpn-service.h"
#include "nm-utils.h"

#define NM_OPENVPN_HELPER_PATH		LIBEXECDIR"/nm-openvpn-service-openvpn-helper"

G_DEFINE_TYPE (NMOpenvpnPlugin, nm_openvpn_plugin, NM_TYPE_VPN_PLUGIN)

#define NM_OPENVPN_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPluginPrivate))

typedef struct {
	char *username;
	char *password;
	char *certpass;
	gint child_stdin_fd;
	gint child_stdout_fd;
	gint child_stderr_fd;
	GIOChannel *socket_channel;
	guint socket_channel_eventid;
} NMOpenvpnPluginIOData;

typedef struct {
	GPid	pid;
	guint connect_timer;
	guint connect_count;
	NMOpenvpnPluginIOData *io_data;
} NMOpenvpnPluginPrivate;

typedef struct {
	const char *name;
	GType type;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_OPENVPN_KEY_CA,                   G_TYPE_STRING },
	{ NM_OPENVPN_KEY_CERT,                 G_TYPE_STRING },
	{ NM_OPENVPN_KEY_CIPHER,               G_TYPE_STRING },
	{ NM_OPENVPN_KEY_COMP_LZO,             G_TYPE_BOOLEAN },
	{ NM_OPENVPN_KEY_CONNECTION_TYPE,      G_TYPE_INT },
	{ NM_OPENVPN_KEY_TAP_DEV,              G_TYPE_BOOLEAN },
	{ NM_OPENVPN_KEY_KEY,                  G_TYPE_STRING },
	{ NM_OPENVPN_KEY_LOCAL_IP,             G_TYPE_STRING },
	{ NM_OPENVPN_KEY_PROTO_TCP,            G_TYPE_BOOLEAN },
	{ NM_OPENVPN_KEY_PORT,                 G_TYPE_INT },
	{ NM_OPENVPN_KEY_REMOTE,               G_TYPE_STRING },
	{ NM_OPENVPN_KEY_REMOTE_IP,            G_TYPE_STRING },
	{ NM_OPENVPN_KEY_SHARED_KEY,           G_TYPE_STRING },
	{ NM_OPENVPN_KEY_SHARED_KEY_DIRECTION, G_TYPE_INT },
	{ NM_OPENVPN_KEY_TA,                   G_TYPE_STRING },
	{ NM_OPENVPN_KEY_TA_DIR,               G_TYPE_STRING },
	{ NM_OPENVPN_KEY_USERNAME,             G_TYPE_STRING },
	{ NM_OPENVPN_KEY_PASSWORD,             G_TYPE_STRING },
	{ NM_OPENVPN_KEY_CERTPASS,             G_TYPE_STRING },
	{ NM_OPENVPN_KEY_NOSECRET,             G_TYPE_STRING },
	{ NULL,                                G_TYPE_NONE }
};

static void
validate_one_property (gpointer key, gpointer val, gpointer user_data)
{
	gboolean *failed = (gboolean *) user_data;
	int i;

	if (*failed)
		return;

	/* 'name' is the setting name; always allowed but unused */
	if (!strcmp ((char *) key, NM_SETTING_NAME))
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
nm_openvpn_properties_validate (GHashTable *properties)
{
	gboolean failed = FALSE;

	if (g_hash_table_size (properties) < 1)
		return failed;

	g_hash_table_foreach (properties, validate_one_property, &failed);

	return !failed;
}

static void
nm_openvpn_disconnect_management_socket (NMOpenvpnPlugin *plugin)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	NMOpenvpnPluginIOData *io_data = priv->io_data;

	/* This should no throw a warning since this can happen in
	   non-password modes */
	if (!io_data)
		return;

	g_source_remove (io_data->socket_channel_eventid);
	g_io_channel_shutdown (io_data->socket_channel, FALSE, NULL);
	g_io_channel_unref (io_data->socket_channel);

	g_free (io_data->username);
	g_free (io_data->password);

	g_free (priv->io_data);
	priv->io_data = NULL;
}

static gboolean
nm_openvpn_socket_data_cb (GIOChannel *source, GIOCondition condition, gpointer user_data)
{
	NMOpenvpnPlugin *plugin = NM_OPENVPN_PLUGIN (user_data);
	NMOpenvpnPluginIOData *io_data = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin)->io_data;
	gboolean again = TRUE;
	char *str = NULL;
	char *auth;
	gsize written;
	char *buf;

	if (!(condition & G_IO_IN))
		return TRUE;

	if (g_io_channel_read_line (source, &str, NULL, NULL, NULL) != G_IO_STATUS_NORMAL)
		goto out;

	if (strlen (str) < 1)
		goto out;

	if (sscanf (str, ">PASSWORD:Need '%a[^']'", &auth) > 0 ) {
		if (strcmp (auth, "Auth") == 0) {
			if (io_data->username != NULL && io_data->password != NULL) {
				buf = g_strdup_printf ("username \"%s\" %s\n"
								   "password \"%s\" %s\n",
								   auth, io_data->username,
								   auth, io_data->password);
				/* Will always write everything in blocking channels (on success) */
				g_io_channel_write_chars (source, buf, strlen (buf), &written, NULL);
				g_io_channel_flush (source, NULL);
				g_free (buf);
			}
		} else if (!strcmp (auth, "Private Key")) {
			if (io_data->certpass) {
				buf = g_strdup_printf ("password \"%s\" %s\n", auth, io_data->certpass);
				/* Will always write everything in blocking channels (on success) */
				g_io_channel_write_chars (source, buf, strlen (buf), &written, NULL);
				g_io_channel_flush (source, NULL);
				g_free (buf);
			} else {
				nm_warning ("Certificate password requested but certpass == NULL");
			}
		} else {
			nm_warning ("No clue what to send for username/password request for '%s'", auth);
			nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
			nm_openvpn_disconnect_management_socket (plugin);
		}

	} else if (strstr (str, ">PASSWORD:Verification Failed: ") == str) {
		nm_warning ("Password verification failed");
		nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		nm_openvpn_disconnect_management_socket (plugin);
		again = FALSE;
	}

 out:
	g_free (str);
	return again;
}

static gboolean
nm_openvpn_connect_timer_cb (gpointer data)
{
	NMOpenvpnPlugin *plugin = NM_OPENVPN_PLUGIN (data);
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	struct sockaddr_in     serv_addr;
	gboolean               connected = FALSE;
	gint                   socket_fd = -1;
	NMOpenvpnPluginIOData *io_data = priv->io_data;

	priv->connect_timer = 0;
	priv->connect_count++;

	/* open socket and start listener */
	socket_fd = socket (PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socket_fd < 0)
		return FALSE;

	serv_addr.sin_family = AF_INET;
	if (inet_pton (AF_INET, "127.0.0.1", &(serv_addr.sin_addr)) <= 0)
		nm_warning ("%s: could not convert 127.0.0.1", __func__);
	serv_addr.sin_port = htons (1194);
 
	connected = (connect (socket_fd, (struct sockaddr *) &serv_addr, sizeof (serv_addr)) == 0);
	if (!connected) {
		close (socket_fd);
		if (priv->connect_count <= 30) {
			return TRUE;
		} else {
			nm_warning ("Could not open management socket");
			nm_vpn_plugin_failure (NM_VPN_PLUGIN (plugin), NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
			nm_vpn_plugin_set_state (NM_VPN_PLUGIN (plugin), NM_VPN_SERVICE_STATE_STOPPED);
			return FALSE;
		}
	} else {
		GIOChannel            *openvpn_socket_channel;
		guint                  openvpn_socket_channel_eventid;

		openvpn_socket_channel = g_io_channel_unix_new (socket_fd);
		openvpn_socket_channel_eventid = g_io_add_watch (openvpn_socket_channel,
											    G_IO_IN,
											    nm_openvpn_socket_data_cb,
											    plugin);

		g_io_channel_set_encoding (openvpn_socket_channel, NULL, NULL);
		io_data->socket_channel = openvpn_socket_channel;
		io_data->socket_channel_eventid = openvpn_socket_channel_eventid;

		return FALSE;
	}
}

static void
nm_openvpn_schedule_connect_timer (NMOpenvpnPlugin *plugin)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);

	if (priv->connect_timer == 0)
		priv->connect_timer = g_timeout_add (200, nm_openvpn_connect_timer_cb, plugin);
}

static void
openvpn_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMVPNPlugin *plugin = NM_VPN_PLUGIN (user_data);
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	guint error = 0;

	if (WIFEXITED (status)) {
		error = WEXITSTATUS (status);
		if (error != 0)
			nm_warning ("openvpn exited with error code %d", error);
    }
	else if (WIFSTOPPED (status))
		nm_warning ("openvpn stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		nm_warning ("openvpn died with signal %d", WTERMSIG (status));
	else
		nm_warning ("openvpn died from an unknown cause");
  
	/* Reap child if needed. */
	waitpid (priv->pid, NULL, WNOHANG);
	priv->pid = 0;

	/* Must be after data->state is set since signals use data->state */
	/* This is still code from vpnc, openvpn does not supply useful exit codes :-/ */
	switch (error) {
	case 2:
		/* Couldn't log in due to bad user/pass */
		nm_vpn_plugin_failure (plugin, NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
		break;
	case 1:
		/* Other error (couldn't bind to address, etc) */
		nm_vpn_plugin_failure (plugin, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		break;
	default:
		break;
	}

	nm_vpn_plugin_set_state (plugin, NM_VPN_SERVICE_STATE_STOPPED);
}

static int
get_connection_type (GHashTable *properties)
{
	int connection_type = NM_OPENVPN_CONTYPE_INVALID;
	gpointer tmp;

	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CONNECTION_TYPE);
	if (tmp)
		connection_type = g_value_get_int ((GValue *) tmp);

	if (connection_type < NM_OPENVPN_CONTYPE_INVALID || connection_type > NM_OPENVPN_CONTYPE_PASSWORD_TLS)
		connection_type = NM_OPENVPN_CONTYPE_INVALID;

	return connection_type;
}

static const char *
nm_find_openvpn (void)
{
	static const char *openvpn_binary_paths[] = {
		"/usr/sbin/openvpn",
		"/sbin/openvpn",
		NULL
	};
	const char  **openvpn_binary = openvpn_binary_paths;

	while (*openvpn_binary != NULL) {
		if (g_file_test (*openvpn_binary, G_FILE_TEST_EXISTS))
			break;
		openvpn_binary++;
	}

	return *openvpn_binary;
}

static gint
nm_openvpn_start_openvpn_binary (NMOpenvpnPlugin *plugin, GHashTable *properties)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	GPid	pid;
	const char *openvpn_binary;
	GPtrArray *openvpn_argv;
	GSource *openvpn_watch;
	gpointer tmp;
	gint	stdin_fd;
	gint stdout_fd;
	gint stderr_fd;
	int connection_type;
	GError *err = NULL;

	/* Find openvpn */
	openvpn_binary = nm_find_openvpn ();
	if (!openvpn_binary) {
		nm_info ("Could not find openvpn binary.");
		return -1;
	}

	connection_type = get_connection_type (properties);
	if (connection_type == NM_OPENVPN_CONTYPE_INVALID)
		return -1;

	openvpn_argv = g_ptr_array_new ();
	g_ptr_array_add (openvpn_argv, (gpointer) (openvpn_binary));

	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_REMOTE);
	if (tmp) {
		g_ptr_array_add (openvpn_argv, (gpointer) "--remote");
		g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
	}

	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_COMP_LZO);
	if (tmp && g_value_get_boolean ((GValue *) tmp))
		g_ptr_array_add (openvpn_argv, (gpointer) "--comp-lzo");

	g_ptr_array_add (openvpn_argv, (gpointer) "--nobind");

	/* Device, either tun or tap */
	g_ptr_array_add (openvpn_argv, (gpointer) "--dev");
	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_TAP_DEV);
	if (tmp && g_value_get_boolean ((GValue *) tmp))
		g_ptr_array_add (openvpn_argv, (gpointer) "tap");
	else
		g_ptr_array_add (openvpn_argv, (gpointer) "tun");

	/* Protocol, either tcp or udp */
	g_ptr_array_add (openvpn_argv, (gpointer) "--proto");
	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_PROTO_TCP);
	if (tmp && g_value_get_boolean ((GValue *) tmp))
		g_ptr_array_add (openvpn_argv, (gpointer) "tcp-client");
	else
		g_ptr_array_add (openvpn_argv, (gpointer) "udp");

	/* Port */
	g_ptr_array_add (openvpn_argv, (gpointer) "--port");
	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_PORT);
	if (tmp)
		/* The string here is leaked, big deal. */
		g_ptr_array_add (openvpn_argv, g_strdup_printf ("%u", g_value_get_int ((GValue *) tmp)));
	else
		/* Default to IANA assigned port 1194 */
		g_ptr_array_add (openvpn_argv, (GValue *) "1194");

	/* Cipher */
	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CIPHER);
	if (tmp) {
		g_ptr_array_add (openvpn_argv, (gpointer) "--cipher");
		g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
	}

	/* TA */
	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_TA);
	if (tmp) {
		g_ptr_array_add (openvpn_argv, (gpointer) "--tls-auth");
		g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_TA_DIR);
		if (tmp && strlen (g_value_get_string (tmp)))
			g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
	}

	/* Syslog */
	g_ptr_array_add (openvpn_argv, (gpointer) "--syslog");
	g_ptr_array_add (openvpn_argv, (gpointer) "nm-openvpn");

	/* Up script, called when connection has been established or has been restarted */
	g_ptr_array_add (openvpn_argv, (gpointer) "--up");
	g_ptr_array_add (openvpn_argv, (gpointer) NM_OPENVPN_HELPER_PATH);
	g_ptr_array_add (openvpn_argv, (gpointer) "--up-restart");

	/* Keep key and tun if restart is needed */
	g_ptr_array_add (openvpn_argv, (gpointer) "--persist-key");
	g_ptr_array_add (openvpn_argv, (gpointer) "--persist-tun");

	/* Management socket for localhost access to supply username and password */
	g_ptr_array_add (openvpn_argv, (gpointer) "--management");
	g_ptr_array_add (openvpn_argv, (gpointer) "127.0.0.1");
	/* with have nobind, thus 1194 should be free, it is the IANA assigned port */
	g_ptr_array_add (openvpn_argv, (gpointer) "1194");
	/* Query on the management socket for user/pass */
	g_ptr_array_add (openvpn_argv, (gpointer) "--management-query-passwords");

	/* do not let openvpn setup routes, NM will handle it */
	g_ptr_array_add (openvpn_argv, (gpointer) "--route-noexec");

	/* Now append configuration options which are dependent on the configuration type */
	switch (connection_type) {
	case NM_OPENVPN_CONTYPE_TLS:
		g_ptr_array_add (openvpn_argv, (gpointer) "--client");

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CA);
		if (tmp) {
			g_ptr_array_add (openvpn_argv, (gpointer) "--ca");
			g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
		}

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CERT);
		if (tmp) {
			g_ptr_array_add (openvpn_argv, (gpointer) "--cert");
			g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
		}

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_KEY);
		if (tmp) {
			g_ptr_array_add (openvpn_argv, (gpointer) "--key");
			g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
		}
		break;

	case NM_OPENVPN_CONTYPE_STATIC_KEY:
		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_SHARED_KEY);
		if (tmp) {
			g_ptr_array_add (openvpn_argv, (gpointer) "--secret");
			g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
		}

		g_ptr_array_add (openvpn_argv, (gpointer) "--ifconfig");

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_LOCAL_IP);
		if (!tmp) {
			/* Insufficient data (FIXME: this should really be detected when validating the properties */
			g_ptr_array_free (openvpn_argv, TRUE);
			return -1;
		}
		g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_REMOTE_IP);
		if (!tmp) {
			/* Insufficient data (FIXME: this should really be detected when validating the properties */
			g_ptr_array_free (openvpn_argv, TRUE);
			return -1;
		}
		g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
		break;

	case NM_OPENVPN_CONTYPE_PASSWORD:
		/* Client mode */
		g_ptr_array_add (openvpn_argv, (gpointer) "--client");
		/* Use user/path authentication */
		g_ptr_array_add (openvpn_argv, (gpointer) "--auth-user-pass");

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CA);
		if (tmp) {
			g_ptr_array_add (openvpn_argv, (gpointer) "--ca");
			g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
		}
		break;

	case NM_OPENVPN_CONTYPE_PASSWORD_TLS:
		g_ptr_array_add (openvpn_argv, (gpointer) "--client");

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CA);
		if (tmp) {
			g_ptr_array_add (openvpn_argv, (gpointer) "--ca");
			g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
		}

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CERT);
		if (tmp) {
			g_ptr_array_add (openvpn_argv, (gpointer) "--cert");
			g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
		}

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_KEY);
		if (tmp) {
			g_ptr_array_add (openvpn_argv, (gpointer) "--key");
			g_ptr_array_add (openvpn_argv, (gpointer) g_value_get_string ((GValue *) tmp));
		}

		/* Use user/path authentication */
		g_ptr_array_add (openvpn_argv, (gpointer) "--auth-user-pass");
		break;
	}

	g_ptr_array_add (openvpn_argv, NULL);

	if (!g_spawn_async_with_pipes (NULL, (char **) openvpn_argv->pdata, NULL,
							 G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, &stdin_fd,
							 &stdout_fd, &stderr_fd, &err)) {
		g_ptr_array_free (openvpn_argv, TRUE);
		nm_warning ("openvpn failed to start.  error: '%s'", err->message);
		g_error_free (err);
		return -1;
	}
	g_ptr_array_free (openvpn_argv, TRUE);

	nm_info ("openvpn started with pid %d", pid);

	priv->pid = pid;
	openvpn_watch = g_child_watch_source_new (pid);
	g_source_set_callback (openvpn_watch, (GSourceFunc) openvpn_watch_cb, plugin, NULL);
	g_source_attach (openvpn_watch, NULL);
	g_source_unref (openvpn_watch);

	/* Listen to the management socket for a few connection types:
	   PASSWORD: Will require username and password
	   X509USERPASS: Will require username and password and maybe certificate password
	   X509: May require certificate password
	*/
	if (connection_type == NM_OPENVPN_CONTYPE_PASSWORD ||
	    connection_type == NM_OPENVPN_CONTYPE_PASSWORD_TLS ||
	    connection_type == NM_OPENVPN_CONTYPE_TLS) {

		NMOpenvpnPluginIOData  *io_data;

		io_data                  = g_new0 (NMOpenvpnPluginIOData, 1);
		io_data->child_stdin_fd  = stdin_fd;
		io_data->child_stdout_fd = stdout_fd;
		io_data->child_stderr_fd = stderr_fd;

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_USERNAME);
		if (tmp)
			io_data->username = g_strdup ((char *) g_value_get_string ((GValue *) tmp));

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_PASSWORD);
		if (tmp)
			io_data->password = g_strdup ((char *) g_value_get_string ((GValue *) tmp));

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CERTPASS);
		if (tmp)
			io_data->certpass = g_strdup ((char *) g_value_get_string ((GValue *) tmp));

		priv->io_data = io_data;

		nm_openvpn_schedule_connect_timer (plugin);
	}

	return stdin_fd;
}

static gboolean
real_connect (NMVPNPlugin   *plugin,
		    NMConnection  *connection,
		    GError       **err)
{
	NMSettingVPNProperties *properties;
	gint fd;
	gboolean success = FALSE;

	properties = NM_SETTING_VPN_PROPERTIES (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN_PROPERTIES));
	if (!properties || !nm_openvpn_properties_validate (properties->data)) {
		g_set_error (err,
				   NM_VPN_PLUGIN_ERROR,
				   NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
				   "%s",
				   "Invalid arguments.");
		goto out;
	}

	if ((fd = nm_openvpn_start_openvpn_binary (NM_OPENVPN_PLUGIN (plugin), properties->data)) < 0) {
		g_set_error (err,
				   NM_VPN_PLUGIN_ERROR,
				   NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
				   "%s",
				   "Could not start openvpn binary.");
		goto out;
	}

	success = TRUE;

 out:
	/* FIXME: It never did that but I guess it should? */
/* 	close (fd); */

	return success;
}

static gboolean
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error)
{
	NMSettingVPNProperties *s_vpn_props;
	int connection_type;
	gboolean need_secrets = FALSE;

	g_return_val_if_fail (NM_IS_VPN_PLUGIN (plugin), FALSE);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), FALSE);

	s_vpn_props = NM_SETTING_VPN_PROPERTIES (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN_PROPERTIES));
	if (!s_vpn_props) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_CONNECTION_INVALID,
		             "%s",
		             "Could not process the request because the VPN connection settings were invalid.");
		return FALSE;
	}

	connection_type = get_connection_type (s_vpn_props->data);
	switch (connection_type) {
	case NM_OPENVPN_CONTYPE_PASSWORD_TLS:
		/* Will require username and password and maybe certificate password */
		if (!g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_CERTPASS))
			need_secrets = TRUE;
		/* Fall through */
	case NM_OPENVPN_CONTYPE_PASSWORD:
		/* Will require username and password */
		if (!g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_USERNAME) ||
		    !g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_PASSWORD))
			need_secrets = TRUE;
		break;
	case NM_OPENVPN_CONTYPE_TLS:
		/* May require certificate password */
		if (!g_hash_table_lookup (s_vpn_props->data, NM_OPENVPN_KEY_CERTPASS))
			need_secrets = TRUE;
		break;
	default:
		break;
	}

	if (need_secrets)
		*setting_name = NM_SETTING_VPN_PROPERTIES_SETTING_NAME;

	return need_secrets;
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
real_disconnect (NMVPNPlugin	 *plugin,
			  GError		**err)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);

	if (priv->pid) {
		if (kill (priv->pid, SIGTERM) == 0)
			g_timeout_add (2000, ensure_killed, GINT_TO_POINTER (priv->pid));
		else
			kill (priv->pid, SIGKILL);

		nm_info ("Terminated openvpn daemon with PID %d.", priv->pid);
		priv->pid = 0;
	}

	return TRUE;
}

static void
nm_openvpn_plugin_init (NMOpenvpnPlugin *plugin)
{
}

static void
nm_openvpn_plugin_class_init (NMOpenvpnPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);
	NMVPNPluginClass *parent_class = NM_VPN_PLUGIN_CLASS (plugin_class);

	g_type_class_add_private (object_class, sizeof (NMOpenvpnPluginPrivate));

	/* virtual methods */
	parent_class->connect      = real_connect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->disconnect   = real_disconnect;
}

NMOpenvpnPlugin *
nm_openvpn_plugin_new (void)
{
	return (NMOpenvpnPlugin *) g_object_new (NM_TYPE_OPENVPN_PLUGIN,
									 NM_VPN_PLUGIN_DBUS_SERVICE_NAME,
									 NM_DBUS_SERVICE_OPENVPN,
									 NULL);
}

static void
quit_mainloop (NMVPNPlugin *plugin, gpointer user_data)
{
	g_main_loop_quit ((GMainLoop *) user_data);
}

int
main (int argc, char *argv[])
{
	NMOpenvpnPlugin *plugin;
	GMainLoop *main_loop;

	g_type_init ();

	if (system ("/sbin/modprobe tun") == -1)
		exit (EXIT_FAILURE);

	plugin = nm_openvpn_plugin_new ();
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
