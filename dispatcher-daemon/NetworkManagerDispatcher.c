/* NetworkManagerDispatcher -- Dispatches messages from NetworkManager
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
 * (C) Copyright 2004 Red Hat, Inc.
 */

#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib-lowlevel.h>
#include <dbus/dbus-glib.h>
#include <getopt.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <string.h>

#include "NetworkManager.h"
#include "nm-utils.h"
#include "nm-client.h"


#define NM_SCRIPT_DIR		SYSCONFDIR"/NetworkManager/dispatcher.d"

#define NMD_DEFAULT_PID_FILE	LOCALSTATEDIR"/run/NetworkManagerDispatcher.pid"

GHashTable *device_signals_hash;

/*
 * nmd_permission_check
 *
 * Verify that the given script has the permissions we want.  Specifically,
 * ensure that the file is
 *	- A regular file.
 *	- Owned by root.
 *	- Not writable by the group or by other.
 *	- Not setuid.
 *	- Executable by the owner.
 *
 */
static inline gboolean
nmd_permission_check (struct stat *s)
{
	if (!S_ISREG (s->st_mode))
		return FALSE;
	if (s->st_uid != 0)
		return FALSE;
	if (s->st_mode & (S_IWGRP|S_IWOTH|S_ISUID))
		return FALSE;
	if (!(s->st_mode & S_IXUSR))
		return FALSE;
	return TRUE;
}


/*
 * nmd_is_valid_filename
 *
 * Verify that the given script is a valid file name. Specifically,
 * ensure that the file:
 *	- is not a editor backup file
 *	- is not a package management file
 *	- does not start with '.'
 */
static inline gboolean
nmd_is_valid_filename (const char *file_name)
{
	char *bad_suffixes[] = { "~", ".rpmsave", ".rpmorig", ".rpmnew", NULL };
	char *tmp;
	int i;

	if (file_name[0] == '.')
		return FALSE;
	for (i = 0; bad_suffixes[i]; i++) {
		if (g_str_has_suffix(file_name, bad_suffixes[i]))
			return FALSE;
	}
	tmp = g_strrstr(file_name, ".dpkg-");
	if (tmp && (tmp == strrchr(file_name,'.')))
		return FALSE;
	return TRUE;
}


/*
 * nmd_execute_scripts
 *
 * Call scripts in /etc/NetworkManager.d when devices go down or up
 *
 */
static void
nmd_execute_scripts (NMDeviceState state, const char *iface_name)
{
	GDir *		dir;
	const char *	file_name;
	const char *	char_act;

	if (state == NM_DEVICE_STATE_ACTIVATED)
		char_act = "up";
	else if (state == NM_DEVICE_STATE_DISCONNECTED)
		char_act = "down";
	else
		return;

	nm_info ("Device %s is now %s.", iface_name, char_act);

	if (!(dir = g_dir_open (NM_SCRIPT_DIR, 0, NULL)))
	{
		nm_warning ("nmd_execute_scripts(): opendir() could not open '" NM_SCRIPT_DIR "'.  errno = %d", errno);
		return;
	}

	while ((file_name = g_dir_read_name (dir)))
	{
		char *file_path = g_build_filename (NM_SCRIPT_DIR, file_name, NULL);
		struct stat	s;

		if (nmd_is_valid_filename(file_name) && (stat (file_path, &s) == 0))
		{
			if (nmd_permission_check (&s))
			{
				char *cmd;
				int ret;

				cmd = g_strdup_printf ("%s %s %s", file_path, iface_name, char_act);
				ret = system (cmd);
				if (ret == -1)
					nm_warning ("nmd_execute_scripts(): system() failed with errno = %d", errno);
				g_free (cmd);
			}
		}

		g_free (file_path);
	}

	g_dir_close (dir);
}

static void
device_state_changed (NMDevice *device, GParamSpec *pspec, gpointer user_data)
{
	NMDeviceState state;

	state = nm_device_get_state (device);
	if (state == NM_DEVICE_STATE_ACTIVATED || state == NM_DEVICE_STATE_DISCONNECTED)
		nmd_execute_scripts (state, nm_device_get_iface (device));
}

static void
device_add_listener (NMClient *client, NMDevice *device, gpointer user_data)
{
	guint id;

	if (!g_hash_table_lookup (device_signals_hash, device)) {
		id = g_signal_connect (device, "notify::state",
							   G_CALLBACK (device_state_changed),
							   NULL);

		g_hash_table_insert (device_signals_hash, g_object_ref (device), GUINT_TO_POINTER (id));
	}
}

static void
device_remove_listener (NMClient *client, NMDevice *device, gpointer user_data)
{
	guint id;

	id = GPOINTER_TO_UINT (g_hash_table_lookup (device_signals_hash, device));
	if (id) {
		g_signal_handler_disconnect (device, id);
		g_hash_table_remove (device_signals_hash, device);
	}
}

static void
add_existing_device_listeners (NMClient *client)
{
	const GPtrArray *devices;
	int i;

	devices = nm_client_get_devices (client);
	for (i = 0; devices && (i < devices->len); i++)
		device_add_listener (client, g_ptr_array_index (devices, i), NULL);
}

static void
write_pidfile (const char *pidfile)
{
 	char pid[16];
	int fd;
 
	if ((fd = open (pidfile, O_CREAT|O_WRONLY|O_TRUNC, 00644)) < 0)
	{
		nm_warning ("Opening %s failed: %s", pidfile, strerror (errno));
		return;
	}
 	snprintf (pid, sizeof (pid), "%d", getpid ());
	if (write (fd, pid, strlen (pid)) < 0)
		nm_warning ("Writing to %s failed: %s", pidfile, strerror (errno));
	if (close (fd))
		nm_warning ("Closing %s failed: %s", pidfile, strerror (errno));
}


/*
 * main
 *
 */
int
main (int argc, char *argv[])
{
	GError *err = NULL;
	GOptionContext *opt_ctx;
	GMainLoop *loop;
	int ret = EXIT_FAILURE;
	NMClient *client;
	gboolean no_daemon = FALSE;
	char *pidfile = NMD_DEFAULT_PID_FILE;

	GOptionEntry entries[] = {
		{ "no-daemon", 0, 0, G_OPTION_ARG_NONE, &no_daemon, "Do not daemonize", NULL },
		{ "pid-file", 0, 0, G_OPTION_ARG_FILENAME, &pidfile, "Specify the location of a PID file", "filename" },
		{ NULL }
	};

	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_summary (opt_ctx,
								  "NetworkManagerDispatcher listens for device messages from NetworkManager\n"
								  "and runs scripts in " NM_SCRIPT_DIR);
	g_option_context_add_main_entries (opt_ctx, entries, NULL);

	if (!g_option_context_parse (opt_ctx, &argc, &argv, &err)) {
		g_print ("%s\n", err->message);
		g_error_free (err);
		goto out;
	}

	openlog ("NetworkManagerDispatcher",
			 (no_daemon) ? LOG_CONS | LOG_PERROR : LOG_CONS,
			 (no_daemon) ? LOG_USER : LOG_DAEMON);

	if (!no_daemon) {
		if (daemon (FALSE, FALSE) < 0) {
			nm_warning ("NetworkManagerDispatcher could not daemonize: %s", strerror (errno));
			goto out;
		}

		write_pidfile (pidfile);
	}

	g_type_init ();

	client = nm_client_new ();
	if (!client)
		goto out;

	device_signals_hash = g_hash_table_new_full (NULL, NULL, (GDestroyNotify) g_object_unref, NULL);

	g_signal_connect (client, "device-added",
					  G_CALLBACK (device_add_listener), NULL);
	g_signal_connect (client, "device-removed",
					  G_CALLBACK (device_remove_listener), NULL);

	add_existing_device_listeners (client);

	loop = g_main_loop_new (NULL, FALSE);
	g_main_loop_run (loop);
	g_main_loop_unref (loop);
	g_object_unref (client);
	g_hash_table_destroy (device_signals_hash);

	ret = EXIT_SUCCESS;

 out:
	g_option_context_free (opt_ctx);
	closelog ();
	unlink (pidfile);

	return ret;
}
