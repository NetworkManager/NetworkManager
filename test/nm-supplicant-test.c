/* supplicant test utility
 *
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * (C) Copyright 2006 Red Hat, Inc.
 */


#include <glib.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include "../src/wpa_ctrl.h"
#include "../src/wpa_ctrl.c"

#define nm_info(fmt, args...) fprintf(stdout, fmt "\n", ##args)
#define nm_warning(fmt, args...) fprintf(stdout, fmt "\n", ##args)
#define nm_warning_str(fmt_str, args...) fprintf(stdout, "%s\n", fmt_str, ##args)


struct opt {
	char *key;
	char *value;
};

#define STATE_DISCONNECTED 0
#define STATE_DEVICE_CONFIG 1
#define STATE_CONNECTED 2

struct supplicant {
	GMainLoop *			loop;
	GPid				pid;
	GSource *			watch;
	GSource *			status;
	struct wpa_ctrl *	ctrl;
	GSource *			timeout;
	GSource *			stdout;
	GSource *			link_timeout;
	char *				iface;
	guint32				ap_scan;
	GSList *			options;
	guint32				state;
	const char *		ssid;
};


#define SUPPLICANT_DEBUG
#define RESPONSE_SIZE	2048


static char *
kill_newline (char *s, size_t *l)
{
	g_return_val_if_fail (l != NULL, s);

	while ((--(*l) > 0) && (s[*l] != '\n'))
		;
	if (s[*l] == '\n')
		s[*l] = '\0';
	return s;
}

static char *
nm_utils_supplicant_request (struct wpa_ctrl *ctrl,
                             const char *format,
                             ...)
{
	va_list	args;
	size_t	len;
	char *	response = NULL;
	char *	command;

	g_return_val_if_fail (ctrl != NULL, NULL);
	g_return_val_if_fail (format != NULL, NULL);

	va_start (args, format);
	if (!(command = g_strdup_vprintf (format, args)))
		return NULL;
	va_end (args);

	response = g_malloc (RESPONSE_SIZE);
	len = RESPONSE_SIZE;
	nm_info ("SUP: sending command '%s'", command);
	wpa_ctrl_request (ctrl, command, strlen (command), response, &len, NULL);
	g_free (command);
	response[len] = '\0';
	{
		response = kill_newline (response, &len);
		nm_info ("SUP: response was '%s'", response);
	}
	return response;
}

static gboolean
nm_utils_supplicant_request_with_check (struct wpa_ctrl *ctrl,
                                        const char *expected,
                                        const char *func,
								const char *err_msg_cmd,
                                        const char *format,
                                        ...)
{
	va_list	args;
	gboolean	success = FALSE;
	size_t	len;
	char *	response = NULL;
	char *	command;
	char *	temp;

	g_return_val_if_fail (ctrl != NULL, FALSE);
	g_return_val_if_fail (expected != NULL, FALSE);
	g_return_val_if_fail (format != NULL, FALSE);

	va_start (args, format);
	if (!(command = g_strdup_vprintf (format, args)))
		goto out;

	response = g_malloc (RESPONSE_SIZE);
	len = RESPONSE_SIZE;
	nm_info ("SUP: sending command '%s'", err_msg_cmd ? err_msg_cmd : command);
	wpa_ctrl_request (ctrl, command, strlen (command), response, &len, NULL);
	response[len] = '\0';
	{
		response = kill_newline (response, &len);
		nm_info ("SUP: response was '%s'", response);
	}

	if (response)
	{
		if (strncmp (response, expected, strlen (expected)) == 0)
			success = TRUE;
		else
		{
			response = kill_newline (response, &len);
			temp = g_strdup_printf ("%s: supplicant error for '%s'.  Response: '%s'",
						func, err_msg_cmd ? err_msg_cmd : command, response);
			nm_warning_str (temp);
			g_free (temp);
		}
		g_free (response);
	}
	else
	{
		temp = g_strdup_printf ("%s: supplicant error for '%s'.  No response.",
					func, err_msg_cmd ? err_msg_cmd : command);
		nm_warning_str (temp);
		g_free (temp);
	}
	g_free (command);

out:
	va_end (args);
	return success;
}


/****************************************************************************/
/* WPA Supplicant control stuff
 *
 * Originally from:
 *
 *	wpa_supplicant wrapper
 *
 *	Copyright (C) 2005 Kay Sievers <kay.sievers@vrfy.org>
 *
 *	This program is free software; you can redistribute it and/or modify it
 *	under the terms of the GNU General Public License as published by the
 *	Free Software Foundation version 2 of the License.
 */

#define WPA_SUPPLICANT_GLOBAL_SOCKET		"/var/run/wpa_supplicant-global"
#define WPA_SUPPLICANT_CONTROL_SOCKET		"/var/run/wpa_supplicant"
#define WPA_SUPPLICANT_NUM_RETRIES		20
#define WPA_SUPPLICANT_RETRY_TIME_US		100*1000

static void
remove_link_timeout (struct supplicant *sup)
{
	if (sup->link_timeout != NULL)
	{
		g_source_destroy (sup->link_timeout);
		sup->link_timeout = NULL;
	}
}

static void
supplicant_remove_timeout (struct supplicant *sup)
{
	/* Remove any pending timeouts on the request */
	if (sup->timeout != NULL)
	{
		g_source_destroy (sup->timeout);
		sup->timeout = NULL;
	}
}

static char *
supplicant_get_device_socket_path (struct supplicant *sup)
{
	return g_strdup_printf (WPA_SUPPLICANT_CONTROL_SOCKET "/%s", sup->iface);
}

static void
supplicant_cleanup (struct supplicant *sup)
{
	char * sock_path;

	if (sup->pid > 0)
	{
		kill (sup->pid, SIGTERM);
		sup->pid = -1;
	}
	if (sup->watch)
	{
		g_source_destroy (sup->watch);
		sup->watch = NULL;
	}
	if (sup->status)
	{
		g_source_destroy (sup->status);
		sup->status = NULL;
	}
	if (sup->ctrl)
	{
		wpa_ctrl_close (sup->ctrl);
		sup->ctrl = NULL;
	}
	if (sup->stdout)
	{
		g_source_destroy (sup->stdout);
		sup->stdout = NULL;
	}

	supplicant_remove_timeout (sup);
	remove_link_timeout (sup);

	/* HACK: should be fixed in wpa_supplicant.  Will likely
	 * require accomodations for selinux.
	 */
	unlink (WPA_SUPPLICANT_GLOBAL_SOCKET);
	sock_path = supplicant_get_device_socket_path (sup);
	unlink (sock_path);
	g_free (sock_path);
}

static void
supplicant_watch_cb (GPid pid,
                     gint status,
                     gpointer user_data)
{
	struct supplicant *sup = (struct supplicant *) user_data;

	if (WIFEXITED (status))
		nm_warning ("wpa_supplicant exited with error code %d", WEXITSTATUS (status));
	else if (WIFSTOPPED (status)) 
		nm_warning ("wpa_supplicant stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		nm_warning ("wpa_supplicant died with signal %d", WTERMSIG (status));
	else
		nm_warning ("wpa_supplicant died from an unknown cause");

	supplicant_cleanup (sup);
}


/*
 * link_timeout_cb
 *
 * Called when the link to the access point has been down for a specified
 * period of time.
 */
static gboolean
link_timeout_cb (gpointer user_data)
{
	struct supplicant *	sup = (struct supplicant *) user_data;

#if 0
 	/* Disconnect event during initial authentication and credentials
 	 * ARE checked - we are likely to have wrong key.  Ask the user for
 	 * another one.
 	 */
 	if (   (nm_act_request_get_stage (req) == NM_ACT_STAGE_DEVICE_CONFIG)
 	    && (ap_is_auth_required (ap, &has_key) && has_key))
 	{
 		/* Association/authentication failed, we must have bad encryption key */
 		nm_info ("Activation (%s/wireless): disconnected during association,"
 		         " asking for new key.", nm_device_get_iface (dev));
 		supplicant_remove_timeout(self);
 		nm_dbus_get_user_key_for_network (data->dbus_connection, req, TRUE);
 	}
 	else
#endif
 	{
 		nm_info ("%s: link timed out.", sup->iface);
		sup->state = STATE_DISCONNECTED;
 	}

	return FALSE;
}


#define MESSAGE_LEN	2048

static gboolean
supplicant_status_cb (GIOChannel *source,
                      GIOCondition condition,
                      gpointer user_data)
{
	struct supplicant * sup = (struct supplicant *) user_data;
	char *				message;
	size_t				len;

	message = g_malloc (MESSAGE_LEN);
	len = MESSAGE_LEN;
	wpa_ctrl_recv (sup->ctrl, message, &len);
	message[len] = '\0';

	if (strstr (message, WPA_EVENT_CONNECTED) != NULL)
	{
		remove_link_timeout (sup);

		/* If this is the initial association during device activation,
		 * schedule the next activation stage.
		 */
		if (sup->state == STATE_DEVICE_CONFIG)
		{
			nm_info ("Activation (%s/wireless) Stage 2 of 5 (Device Configure) "
					"successful.  Connected to access point '%s'.",
					sup->iface, sup->ssid);
			supplicant_remove_timeout (sup);
			sup->state = STATE_CONNECTED;
		}
	}
	else if (strstr (message, WPA_EVENT_DISCONNECTED) != NULL)
	{
		if (sup->state == STATE_CONNECTED || sup->state == STATE_DEVICE_CONFIG)
		{
			/* Start the link timeout so we allow some time for reauthentication */
			if (sup->link_timeout == NULL)
			{
				sup->link_timeout = g_timeout_source_new (8000);
				g_source_set_callback (sup->link_timeout, link_timeout_cb, sup, NULL);
				g_source_attach (sup->link_timeout, NULL);
			}
		}
	}

	g_free (message);

	return TRUE;
}


#define NM_SUPPLICANT_TIMEOUT	20	/* how long we wait for wpa_supplicant to associate (in seconds) */

static unsigned int
get_supplicant_timeout (struct supplicant *sup)
{
#if 0
	if (self->priv->num_freqs > 14)
		return NM_SUPPLICANT_TIMEOUT * 2;
#endif
	return NM_SUPPLICANT_TIMEOUT;
}


/*
 * supplicant_timeout_cb
 *
 * Called when the supplicant has been unable to connect to an access point
 * within a specified period of time.
 */
static gboolean
supplicant_timeout_cb (gpointer user_data)
{
	struct supplicant * sup = (struct supplicant *) user_data;

#if 0
	/* Timed out waiting for authentication success; if the security method
	 * in use does not require access point side authentication (Open System
	 * WEP, for example) then we are likely using the wrong authentication
	 * algorithm or key.  Request new one from the user.
	 */
	if (!ap_is_auth_required (ap, &has_key) && has_key)
	{
		/* Activation failed, we must have bad encryption key */
		nm_info ("Activation (%s/wireless): association took too long (>%us), asking for new key.",
				nm_device_get_iface (dev), get_supplicant_timeout (self));
		nm_dbus_get_user_key_for_network (data->dbus_connection, req, TRUE);
	}
	else
#endif
	{
		nm_info ("Activation (%s/wireless): association took too long (>%us), failing activation.",
				sup->iface, get_supplicant_timeout (sup));
		if (sup->state == STATE_DEVICE_CONFIG)
			sup->state = STATE_DISCONNECTED;
		g_main_loop_quit (sup->loop);
	}

	return FALSE;
}

/*
 * supplicant_log_stdout
 *
 * Read text from a GIOChannel that's hooked up to the stdout of
 * wpa_supplicant, then write that text to NM's syslog service.
 * Adapted from Gnome's bug-buddy.
 *
 */
static gboolean
supplicant_log_stdout (GIOChannel *ioc, GIOCondition condition, gpointer data)
{
	struct supplicant *sup = (struct supplicant *) data;
	gboolean retval = FALSE;
	char *buf;
	gsize len;
	GIOStatus io_status;
	GTimeVal start_time, cur_time;

	#define LINE_SIZE 1024
	buf = g_malloc0 (LINE_SIZE);
	g_get_current_time (&start_time);
 try_read:
	io_status = g_io_channel_read_chars (ioc, buf, LINE_SIZE-1, &len, NULL);
	switch (io_status)
	{
		case G_IO_STATUS_AGAIN:
			g_usleep (G_USEC_PER_SEC / 60);
			/* Only wait for data for 1/2 a second */
			g_get_current_time (&cur_time);
			/* Subtract 1/2 second from current time so we don't have
			 * to modify start_time.
			 */
			g_time_val_add (&cur_time, -1 * (G_USEC_PER_SEC / 2));
			/* Compare times.  If cur_time is less, keep trying to read */
			if ((cur_time.tv_sec < start_time.tv_sec)
				|| ((cur_time.tv_sec == start_time.tv_sec)
					&& (cur_time.tv_usec < start_time.tv_usec)))
				goto try_read;
			nm_warning ("Waited too long for wpa_supplicant output, some may be lost.");
			break;
		case G_IO_STATUS_ERROR:
			nm_warning ("Error reading wpa_supplicant output.");
			break;
		case G_IO_STATUS_NORMAL:
			retval = TRUE;
			break;
		default:
			break;
	}

	if (len > 0)
	{
		char *end;
		char *start;

		/* Log each line separately; sometimes we get a couple lines at a time */
		buf[LINE_SIZE-1] = '\0';
		start = end = &buf[0];
		while (*end != '\0')
		{
			if (*end == '\n')
			{
				*end = '\0';
				nm_info ("wpa_supplicant(%d): %s", sup->pid, start);
				start = end + 1;
			}
			end++;
		}
	}
	g_free (buf);

	return retval;
}


static gboolean
supplicant_exec (struct supplicant *sup)
{
	gboolean success = FALSE;
	char *	argv[5];
	GError *	error = NULL;
	GPid		pid = -1;
	int		sup_stdout;

	argv[0] = WPA_SUPPLICANT_BIN;
	argv[1] = "-g";
	argv[2] = WPA_SUPPLICANT_GLOBAL_SOCKET;
	argv[3] = "-dd";
	argv[4] = NULL;

	success = g_spawn_async_with_pipes ("/", argv, NULL, 0, NULL, NULL,
	                    &pid, NULL, &sup_stdout, NULL, &error);
	if (!success)
	{
		nm_warning ("Couldn't start wpa_supplicant.  Error: (%d) %s", error->code, error->message);
		g_error_free (error);
	}
	else
	{
		GIOChannel *	channel;
		const char *	charset = NULL;

		/* Monitor output from supplicant and redirect to syslog */
		channel = g_io_channel_unix_new (sup_stdout);
		g_io_channel_set_flags (channel, G_IO_FLAG_NONBLOCK, NULL);
		g_get_charset (&charset);
		g_io_channel_set_encoding (channel, charset, NULL);
		sup->stdout = g_io_create_watch (channel, G_IO_IN | G_IO_ERR);
		g_source_set_priority (sup->stdout, G_PRIORITY_LOW);
		g_source_set_callback (sup->stdout, (GSourceFunc) supplicant_log_stdout, sup, NULL);
		g_source_attach (sup->stdout, NULL);
		g_io_channel_unref (channel);

		/* Monitor the child process so we know when it stops */
		sup->pid = pid;
		if (sup->watch)
			g_source_destroy (sup->watch);
		sup->watch = g_child_watch_source_new (pid);
		g_source_set_callback (sup->watch, (GSourceFunc) supplicant_watch_cb, sup, NULL);
		g_source_attach (sup->watch, NULL);
	}

	return success;
}

static gboolean
supplicant_interface_init (struct supplicant *sup)
{
	struct wpa_ctrl *	ctrl = NULL;
	char *			socket_path;
	gboolean			success = FALSE;
	int				tries = 0;

	/* Try to open wpa_supplicant's global control socket */
	for (tries = 0; tries < WPA_SUPPLICANT_NUM_RETRIES && !ctrl; tries++)
	{
		ctrl = wpa_ctrl_open (WPA_SUPPLICANT_GLOBAL_SOCKET, NM_RUN_DIR);
		g_usleep (WPA_SUPPLICANT_RETRY_TIME_US);
	}

	if (!ctrl)
	{
		nm_info ("Error opening supplicant global control interface.");
		goto exit;
	}

	/* wpa_cli -g/var/run/wpa_supplicant-global interface_add eth1 "" wext /var/run/wpa_supplicant */
	if (!nm_utils_supplicant_request_with_check (ctrl, "OK", __func__, NULL,
			"INTERFACE_ADD %s\t\twext\t" WPA_SUPPLICANT_CONTROL_SOCKET "\t", sup->iface))
		goto exit;
	wpa_ctrl_close (ctrl);

	/* Get a control socket to wpa_supplicant for this interface.
	 * Try a couple times to work around naive socket naming
	 * in wpa_ctrl that sometimes collides with stale ones.
	 */
	socket_path = supplicant_get_device_socket_path (sup);
	while (!sup->ctrl && (tries++ < 10))
		sup->ctrl = wpa_ctrl_open (socket_path, NM_RUN_DIR);
	g_free (socket_path);
	if (!sup->ctrl)
	{
		nm_info ("Error opening control interface to supplicant.");
		goto exit;
	}
	success = TRUE;

exit:
	return success;
}

static gboolean
supplicant_send_network_config (struct supplicant *sup)
{
	gboolean			success = FALSE;
	char *			response = NULL;
	int				nwid;
	GSList *			elt;

	g_assert (sup->ctrl);

	/* Tell wpa_supplicant that we'll do the scanning */
	if (!nm_utils_supplicant_request_with_check (sup->ctrl, "OK", __func__, NULL, "AP_SCAN %d",
			sup->ap_scan))
		goto out;

	/* Standard network setup info */
	if (!(response = nm_utils_supplicant_request (sup->ctrl, "ADD_NETWORK"))) {
		nm_warning ("Supplicant error for ADD_NETWORK.\n");
		goto out;
	}
	if (sscanf (response, "%i\n", &nwid) != 1) {
		nm_warning ("Supplicant error for ADD_NETWORK.  Response: '%s'\n", response);
		g_free (response);
		goto out;
	}
	g_free (response);

	for (elt = sup->options; elt; elt = g_slist_next (elt)) {
		struct opt * item = (struct opt *)(elt->data);

		if (!nm_utils_supplicant_request_with_check (sup->ctrl, "OK", __func__, NULL,
				"SET_NETWORK %i %s %s", nwid, item->key, item->value))
			goto out;
	}

	if (!nm_utils_supplicant_request_with_check (sup->ctrl, "OK", __func__, NULL,
			"ENABLE_NETWORK %i", nwid))
		goto out;

	success = TRUE;
out:
	return success;
}


static gboolean
supplicant_monitor_start (struct supplicant *sup)
{
	gboolean		success = FALSE;
	int			fd = -1;
	GIOChannel *	channel;

	/* register network event monitor */
	if (wpa_ctrl_attach (sup->ctrl) != 0)
		goto out;

	if ((fd = wpa_ctrl_get_fd (sup->ctrl)) < 0)
		goto out;

	channel = g_io_channel_unix_new (fd);
	sup->status = g_io_create_watch (channel, G_IO_IN);
	g_source_set_callback (sup->status, (GSourceFunc) supplicant_status_cb, sup, NULL);
	g_source_attach (sup->status, NULL);

	/* Set up a timeout on the association to kill it after get_supplicant_time() seconds */
	sup->timeout = g_timeout_source_new (get_supplicant_timeout (sup) * 1000);
	g_source_set_callback (sup->timeout, supplicant_timeout_cb, sup, NULL);
	g_source_attach (sup->timeout, NULL);

	success = TRUE;

out:
	return success;
}


static gboolean
handle_connect (gpointer user_data)
{
	struct supplicant *sup = (struct supplicant *) user_data;

	sup->state = STATE_DEVICE_CONFIG;
	if (!supplicant_exec (sup))
	{
		nm_warning ("Activation (%s/wireless): couldn't start the supplicant.",
			sup->iface);
		g_main_loop_quit (sup->loop);
		goto out;
	}
	if (!supplicant_interface_init (sup))
	{
		nm_warning ("Activation (%s/wireless): couldn't connect to the supplicant.",
			sup->iface);
		g_main_loop_quit (sup->loop);
		goto out;
	}
	if (!supplicant_send_network_config (sup))
	{
		nm_warning ("Activation (%s/wireless): couldn't send wireless configuration"
			" to the supplicant.", sup->iface);
		g_main_loop_quit (sup->loop);
		goto out;
	}
	if (!supplicant_monitor_start (sup))
	{
		nm_warning ("Activation (%s/wireless): couldn't monitor the supplicant.",
			sup->iface);
		g_main_loop_quit (sup->loop);
		goto out;
	}

out:
	return FALSE;
}


static void
parse_config(struct supplicant *sup, const char *file)
{
	gboolean success;
	GError *err = NULL;
	gsize len;
	gchar *contents;
	gchar **config_lines;
	gchar **line;
	gboolean in_network = FALSE;

	success = g_file_get_contents (file, &contents, &len, &err);
	if (!success) {
		nm_warning ("Error opening config %s: %s\n", file, err->message);
		g_error_free (err);
		exit (1);
	}

	config_lines = g_strsplit (contents, "\n", -1);
	g_free (contents);
	if (!config_lines) {
		nm_warning ("Error reading file contents.\n");
		exit (1);
	}

	for (line = config_lines; *line; line++) {
		struct opt * item;
		char **vals;

		if (!strlen (*line))
			continue;

		g_strstrip (*line);

		/* Ignore comments */
		if (*line[0] == '#')
			continue;

		/* End of first network block; we're done */
		if (*line[0] == '}')
			break;

		vals = g_strsplit (*line, "=", 2);
		/* Only accept two values */
		if (!vals || !vals[0] || !vals[1] || vals[2]) {
			nm_warning ("Bad config line %s.\n", *line);
			exit (1);
		}
		vals[0] = g_strstrip (vals[0]);
		vals[1] = g_strstrip (vals[1]);
		if ((strcmp (vals[0], "network") == 0) && (strcmp (vals[1], "{") == 0)) {
			in_network = TRUE;
		} else if (!in_network) {
			if (strcmp (vals[0], "ap_scan") == 0) {
				sup->ap_scan = atoi (vals[1]);
				if (sup->ap_scan < 0 || sup->ap_scan > 2) {
					nm_warning ("Bad ap_scan value (not between 0 and 2 inclusive)\n");
					exit (1);
				}
			}
		} else {
			item = g_malloc0 (sizeof (struct opt));
			item->key = g_strdup (vals[0]);
			item->value = g_strdup (vals[1]);
			if (strcmp (item->key, "ssid") == 0)
				sup->ssid = item->value;
			sup->options = g_slist_append (sup->options, item);
		}
		g_strfreev (vals);
	}

	g_strfreev (config_lines);

	{
		GSList *elt;
		fprintf (stderr, "ap_scan: %d\n", sup->ap_scan);
		for (elt = sup->options; elt; elt = g_slist_next (elt)) {
			struct opt *item = (struct opt *)(elt->data);
			fprintf (stdout, "Key: %s, Value: %s\n", item->key, item->value);
		}
	}
}


static void
print_usage(const char *prog)
{
	gchar *base = g_filename_display_basename (prog);
	fprintf (stdout, "Usage:  %s <iface> <configfile>\n\n", base);
	g_free (base);
}

int
main (int argc, char **argv)
{
	struct supplicant *sup;
	
	if (argc != 3) {
		print_usage(argv[0]);
		exit(1);
	}

	sup = g_malloc0 (sizeof (struct supplicant));
	sup->ap_scan = 2;
	sup->loop = g_main_loop_new (NULL, FALSE);
	sup->iface = g_strdup (argv[1]);
	sup->state = STATE_DISCONNECTED;

	parse_config (sup, argv[2]);

	g_idle_add (handle_connect, sup);
	g_main_loop_run (sup->loop);

	
	supplicant_cleanup (sup);
	g_free (sup->iface);
	g_free (sup);
	return 0;
}
