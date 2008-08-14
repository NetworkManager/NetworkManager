/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-openvpn-service - openvpn integration with NetworkManager
 *
 * Tim Niemueller <tim@niemueller.de>
 * Dan Williams <dcbw@redhat.com>
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
#include <errno.h>

#include <NetworkManager.h>
#include <NetworkManagerVPN.h>
#include <nm-setting-vpn.h>

#include "nm-openvpn-service.h"
#include "nm-utils.h"

#define NM_OPENVPN_HELPER_PATH		LIBEXECDIR"/nm-openvpn-service-openvpn-helper"

G_DEFINE_TYPE (NMOpenvpnPlugin, nm_openvpn_plugin, NM_TYPE_VPN_PLUGIN)

#define NM_OPENVPN_PLUGIN_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_OPENVPN_PLUGIN, NMOpenvpnPluginPrivate))

typedef struct {
	char *username;
	char *password;
	char *certpass;
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
	gint int_min;
	gint int_max;
	gboolean address;
} ValidProperty;

static ValidProperty valid_properties[] = {
	{ NM_OPENVPN_KEY_CA,                   G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CERT,                 G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CIPHER,               G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_COMP_LZO,             G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CONNECTION_TYPE,      G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TAP_DEV,              G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_KEY,                  G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_LOCAL_IP,             G_TYPE_STRING, 0, 0, TRUE },
	{ NM_OPENVPN_KEY_PROTO_TCP,            G_TYPE_BOOLEAN, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PORT,                 G_TYPE_INT, 1, 65535, FALSE },
	{ NM_OPENVPN_KEY_REMOTE,               G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_REMOTE_IP,            G_TYPE_STRING, 0, 0, TRUE },
	{ NM_OPENVPN_KEY_STATIC_KEY,           G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_STATIC_KEY_DIRECTION, G_TYPE_INT, 0, 1, FALSE },
	{ NM_OPENVPN_KEY_TA,                   G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_TA_DIR,               G_TYPE_INT, 0, 1, FALSE },
	{ NM_OPENVPN_KEY_USERNAME,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_PASSWORD,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_CERTPASS,             G_TYPE_STRING, 0, 0, FALSE },
	{ NM_OPENVPN_KEY_NOSECRET,             G_TYPE_STRING, 0, 0, FALSE },
	{ NULL,                                G_TYPE_NONE, FALSE }
};

static gboolean
validate_address (const char *address)
{
	const char *p = address;

	if (!address || !strlen (address))
		return FALSE;

	/* Ensure it's a valid DNS name or IP address */
	while (*p) {
		if (!isalnum (*p) && (*p != '-') && (*p != '.'))
			return FALSE;
		p++;
	}
	return TRUE;
}

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
			if (!prop.address || validate_address ((const char *) value))
				return; /* valid */

			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "invalid address '%s'",
			             (const char *) key);
			break;
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
nm_openvpn_properties_validate (GHashTable *properties, GError **error)
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

static char *
ovpn_quote_string (const char *unquoted)
{
	char *quoted = NULL, *q;
	char *u = (char *) unquoted;

	g_return_val_if_fail (unquoted != NULL, NULL);

	/* FIXME: use unpaged memory */
	quoted = q = g_malloc0 (strlen (unquoted) * 2);
	while (*u) {
		/* Escape certain characters */
		if (*u == ' ' || *u == '\\' || *u == '"')
			*q++ = '\\';
		*q++ = *u++;
	}

	return quoted;
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
				char *quser, *qpass;

				/* Quote strings passed back to openvpn */
				quser = ovpn_quote_string (io_data->username);
				qpass = ovpn_quote_string (io_data->password);
				buf = g_strdup_printf ("username \"%s\" \"%s\"\n"
				                       "password \"%s\" \"%s\"\n",
				                       auth, quser,
				                       auth, qpass);
				memset (qpass, 0, strlen (qpass));
				g_free (qpass);
				g_free (quser);

				/* Will always write everything in blocking channels (on success) */
				g_io_channel_write_chars (source, buf, strlen (buf), &written, NULL);
				g_io_channel_flush (source, NULL);
				g_free (buf);
			}
		} else if (!strcmp (auth, "Private Key")) {
			if (io_data->certpass) {
				char *qpass;

				/* Quote strings passed back to openvpn */
				qpass = ovpn_quote_string (io_data->certpass);
				buf = g_strdup_printf ("password \"%s\" \"%s\"\n", auth, qpass);
				memset (qpass, 0, strlen (qpass));
				g_free (qpass);

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
	} else if (strstr (str, "private key password verification failed")) {
		nm_warning ("Private key verification failed");
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
		GIOChannel *openvpn_socket_channel;
		guint openvpn_socket_channel_eventid;

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

static const char *
get_connection_type (GHashTable *properties)
{
	const char *ctype;

	ctype = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CONNECTION_TYPE);
	if (ctype) {
		if (   !strcmp (ctype, NM_OPENVPN_CONTYPE_TLS)
		    || !strcmp (ctype, NM_OPENVPN_CONTYPE_STATIC_KEY)
		    || !strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD)
		    || !strcmp (ctype, NM_OPENVPN_CONTYPE_PASSWORD_TLS))
			return ctype;
	}

	return NULL;
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

static void
free_openvpn_args (GPtrArray *args)
{
	g_ptr_array_foreach (args, (GFunc) g_free, NULL);
	g_ptr_array_free (args, TRUE);
}

static void
add_openvpn_arg (GPtrArray *args, const char *arg)
{
	g_return_if_fail (args != NULL);
	g_return_if_fail (arg != NULL);

	g_ptr_array_add (args, (gpointer) g_strdup (arg));
}

static gboolean
add_openvpn_arg_int (GPtrArray *args, const char *arg)
{
	long int tmp_int;

	g_return_val_if_fail (args != NULL, FALSE);
	g_return_val_if_fail (arg != NULL, FALSE);

	/* Convert -> int and back to string for security's sake since
	 * strtol() ignores some leading and trailing characters.
	 */
	errno = 0;
	tmp_int = strtol (arg, NULL, 10);
	if (errno != 0)
		return FALSE;
	g_ptr_array_add (args, (gpointer) g_strdup_printf ("%d", (guint32) tmp_int));
	return TRUE;
}

static gboolean
nm_openvpn_start_openvpn_binary (NMOpenvpnPlugin *plugin,
                                 GHashTable *properties,
                                 GError **error)
{
	NMOpenvpnPluginPrivate *priv = NM_OPENVPN_PLUGIN_GET_PRIVATE (plugin);
	const char *openvpn_binary, *connection_type, *tmp;
	GPtrArray *args;
	GSource *openvpn_watch;
	GPid pid;

	/* Find openvpn */
	openvpn_binary = nm_find_openvpn ();
	if (!openvpn_binary) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "Could not find the openvpn binary.");
		return FALSE;
	}

	connection_type = get_connection_type (properties);
	if (!connection_type) {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "%s",
		             "Invalid connection type.");
		return FALSE;
	}

	args = g_ptr_array_new ();
	add_openvpn_arg (args, openvpn_binary);

	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_REMOTE);
	if (tmp && strlen (tmp)) {
		add_openvpn_arg (args, "--remote");
		add_openvpn_arg (args, tmp);
	}

	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_COMP_LZO);
	if (tmp && !strcmp (tmp, "yes"))
		add_openvpn_arg (args, "--comp-lzo");

	add_openvpn_arg (args, "--nobind");

	/* Device, either tun or tap */
	add_openvpn_arg (args, "--dev");
	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_TAP_DEV);
	if (tmp && !strcmp (tmp, "yes"))
		add_openvpn_arg (args, "tap");
	else
		add_openvpn_arg (args, "tun");

	/* Protocol, either tcp or udp */
	add_openvpn_arg (args, "--proto");
	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_PROTO_TCP);
	if (tmp && !strcmp (tmp, "yes"))
		add_openvpn_arg (args, "tcp-client");
	else
		add_openvpn_arg (args, "udp");

	/* Port */
	add_openvpn_arg (args, "--port");
	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_PORT);
	if (tmp && strlen (tmp)) {
		if (!add_openvpn_arg_int (args, tmp)) {
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "Invalid port number '%s'.",
			             tmp);
			free_openvpn_args (args);
			return FALSE;
		}
	} else {
		/* Default to IANA assigned port 1194 */
		add_openvpn_arg (args, "1194");
	}

	/* Cipher */
	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CIPHER);
	if (tmp && strlen (tmp)) {
		add_openvpn_arg (args, "--cipher");
		add_openvpn_arg (args, tmp);
	}

	/* TA */
	tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_TA);
	if (tmp && strlen (tmp)) {
		add_openvpn_arg (args, "--tls-auth");
		add_openvpn_arg (args, tmp);

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_TA_DIR);
		if (tmp && strlen (tmp))
			add_openvpn_arg (args, tmp);
	}

	/* Syslog */
	add_openvpn_arg (args, "--syslog");
	add_openvpn_arg (args, "nm-openvpn");

	/* Up script, called when connection has been established or has been restarted */
	add_openvpn_arg (args, "--up");
	add_openvpn_arg (args, NM_OPENVPN_HELPER_PATH);
	add_openvpn_arg (args, "--up-restart");

	/* Keep key and tun if restart is needed */
	add_openvpn_arg (args, "--persist-key");
	add_openvpn_arg (args, "--persist-tun");

	/* Management socket for localhost access to supply username and password */
	add_openvpn_arg (args, "--management");
	add_openvpn_arg (args, "127.0.0.1");
	/* with have nobind, thus 1194 should be free, it is the IANA assigned port */
	add_openvpn_arg (args, "1194");
	/* Query on the management socket for user/pass */
	add_openvpn_arg (args, "--management-query-passwords");

	/* do not let openvpn setup routes, NM will handle it */
	add_openvpn_arg (args, "--route-noexec");

	/* Now append configuration options which are dependent on the configuration type */
	if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_TLS)) {
		add_openvpn_arg (args, "--client");

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CA);
		if (tmp && strlen (tmp)) {
			add_openvpn_arg (args, "--ca");
			add_openvpn_arg (args, tmp);
		}

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CERT);
		if (tmp && strlen (tmp)) {
			add_openvpn_arg (args, "--cert");
			add_openvpn_arg (args, tmp);
		}

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_KEY);
		if (tmp && strlen (tmp)) {
			add_openvpn_arg (args, "--key");
			add_openvpn_arg (args, tmp);
		}
	} else if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_STATIC_KEY)) {
		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_STATIC_KEY);
		if (tmp && strlen (tmp)) {
			add_openvpn_arg (args, "--secret");
			add_openvpn_arg (args, tmp);

			tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_STATIC_KEY_DIRECTION);
			if (tmp && strlen (tmp))
				add_openvpn_arg (args, tmp);
		}

		add_openvpn_arg (args, "--ifconfig");

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_LOCAL_IP);
		if (!tmp) {
			/* Insufficient data (FIXME: this should really be detected when validating the properties */
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "%s",
			             "Missing required local IP address for static key mode.");
			free_openvpn_args (args);
			return FALSE;
		}
		add_openvpn_arg (args, tmp);

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_REMOTE_IP);
		if (!tmp) {
			/* Insufficient data (FIXME: this should really be detected when validating the properties */
			g_set_error (error,
			             NM_VPN_PLUGIN_ERROR,
			             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "%s",
			             "Missing required remote IP address for static key mode.");
			free_openvpn_args (args);
			return FALSE;
		}
		add_openvpn_arg (args, tmp);
	} else if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD)) {
		/* Client mode */
		add_openvpn_arg (args, "--client");
		/* Use user/path authentication */
		add_openvpn_arg (args, "--auth-user-pass");

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CA);
		if (tmp && strlen (tmp)) {
			add_openvpn_arg (args, "--ca");
			add_openvpn_arg (args, tmp);
		}
	} else if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		add_openvpn_arg (args, "--client");

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CA);
		if (tmp && strlen (tmp)) {
			add_openvpn_arg (args, "--ca");
			add_openvpn_arg (args, tmp);
		}

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CERT);
		if (tmp && strlen (tmp)) {
			add_openvpn_arg (args, "--cert");
			add_openvpn_arg (args, tmp);
		}

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_KEY);
		if (tmp && strlen (tmp)) {
			add_openvpn_arg (args, "--key");
			add_openvpn_arg (args, tmp);
		}

		/* Use user/path authentication */
		add_openvpn_arg (args, "--auth-user-pass");
	} else {
		g_set_error (error,
		             NM_VPN_PLUGIN_ERROR,
		             NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Unknown connection type '%s'.",
		             connection_type);
		free_openvpn_args (args);
		return FALSE;
	}

	g_ptr_array_add (args, NULL);

	if (!g_spawn_async (NULL, (char **) args->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD, NULL, NULL, &pid, error)) {
		free_openvpn_args (args);
		return FALSE;
	}
	free_openvpn_args (args);

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
	if (   !strcmp (connection_type, NM_OPENVPN_CONTYPE_TLS)
	    || !strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD)
	    || !strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		NMOpenvpnPluginIOData *io_data;

		io_data = g_new0 (NMOpenvpnPluginIOData, 1);

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_USERNAME);
		io_data->username = tmp ? g_strdup (tmp) : NULL;

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_PASSWORD);
		io_data->password = tmp ? g_strdup (tmp) : NULL;

		tmp = g_hash_table_lookup (properties, NM_OPENVPN_KEY_CERTPASS);
		io_data->certpass = tmp ? g_strdup (tmp) : NULL;

		priv->io_data = io_data;

		nm_openvpn_schedule_connect_timer (plugin);
	}

	return TRUE;
}

static gboolean
real_connect (NMVPNPlugin   *plugin,
              NMConnection  *connection,
              GError       **error)
{
	NMSettingVPN *s_vpn;

	s_vpn = NM_SETTING_VPN (nm_connection_get_setting (connection, NM_TYPE_SETTING_VPN));
	g_assert (s_vpn);

	if (!nm_openvpn_properties_validate (s_vpn->data, error))
		return FALSE;

	if (!nm_openvpn_start_openvpn_binary (NM_OPENVPN_PLUGIN (plugin), s_vpn->data, error))
		return FALSE;

	return TRUE;
}

static gboolean
real_need_secrets (NMVPNPlugin *plugin,
                   NMConnection *connection,
                   char **setting_name,
                   GError **error)
{
	NMSettingVPN *s_vpn;
	const char *connection_type;
	gboolean need_secrets = FALSE;

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

	connection_type = get_connection_type (s_vpn->data);
	if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD_TLS)) {
		/* Will require username and password and maybe certificate password */
		if (!g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_CERTPASS))
			need_secrets = TRUE;

		if (!g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_USERNAME) ||
		    !g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_PASSWORD))
			need_secrets = TRUE;
	} else if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_PASSWORD)) {
		/* Will require username and password */
		if (!g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_USERNAME) ||
		    !g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_PASSWORD))
			need_secrets = TRUE;
	} else if (!strcmp (connection_type, NM_OPENVPN_CONTYPE_TLS)) {
		/* May require certificate password */
		if (!g_hash_table_lookup (s_vpn->data, NM_OPENVPN_KEY_CERTPASS))
			need_secrets = TRUE;
	}

	if (need_secrets)
		*setting_name = NM_SETTING_VPN_SETTING_NAME;

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
