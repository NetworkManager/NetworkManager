/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-dhcp-dhcpcd.c - dhcpcd specific hooks for NetworkManager
 *
 * Copyright (C) 2008 Roy Marples
 * Copyright (C) 2010 Dan Williams <dcbw@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
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
 */


#include <config.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <dbus/dbus.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nm-dhcp-dhcpcd.h"
#include "nm-dhcp-manager.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-posix-signals.h"

G_DEFINE_TYPE (NMDHCPDhcpcd, nm_dhcp_dhcpcd, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_DHCPCD_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_DHCPCD, NMDHCPDhcpcdPrivate))

typedef struct {
	const char *path;
	char *pid_file;
} NMDHCPDhcpcdPrivate;

const char *
nm_dhcp_dhcpcd_get_path (const char *try_first)
{
	static const char *dhcpcd_paths[] = {
		"/sbin/dhcpcd",
		"/usr/sbin/dhcpcd",
		"/usr/pkg/sbin/dhcpcd",
		"/usr/local/sbin/dhcpcd",
		NULL
	};
	const char **path = dhcpcd_paths;

	if (strlen (try_first) && g_file_test (try_first, G_FILE_TEST_EXISTS))
		return try_first;

	while (*path != NULL) {
		if (g_file_test (*path, G_FILE_TEST_EXISTS))
			break;
		path++;
	}

	return *path;
}

static void
dhcpcd_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);

	/*
	 * We blocked signals in main(). We need to restore original signal
	 * mask for dhcpcd here so that it can receive signals.
	 */
	nm_unblock_posix_signals (NULL);
}

static GPid
ip4_start (NMDHCPClient *client,
           const char *dhcp_client_id,
           GByteArray *dhcp_anycast_addr,
           const char *hostname)
{
	NMDHCPDhcpcdPrivate *priv = NM_DHCP_DHCPCD_GET_PRIVATE (client);
	GPtrArray *argv = NULL;
	GPid pid = -1;
	GError *error = NULL;
	char *pid_contents = NULL, *binary_name, *cmd_str;
	const char *iface;

	g_return_val_if_fail (priv->pid_file == NULL, -1);

	iface = nm_dhcp_client_get_iface (client);

	/* dhcpcd does not allow custom pidfiles; the pidfile is always
	 * RUNDIR "dhcpcd-<ifname>.pid".
	 */
	priv->pid_file = g_strdup_printf (RUNDIR "/dhcpcd-%s.pid", iface);

	if (!g_file_test (priv->path, G_FILE_TEST_EXISTS)) {
		nm_log_warn (LOGD_DHCP4, "%s does not exist.", priv->path);
		return -1;
	}

	/* Kill any existing dhcpcd from the pidfile */
	binary_name = g_path_get_basename (priv->path);
	nm_dhcp_client_stop_existing (priv->pid_file, binary_name);
	g_free (binary_name);

	argv = g_ptr_array_new ();
	g_ptr_array_add (argv, (gpointer) priv->path);

	g_ptr_array_add (argv, (gpointer) "-B");	/* Don't background on lease (disable fork()) */

	g_ptr_array_add (argv, (gpointer) "-K");	/* Disable built-in carrier detection */

	g_ptr_array_add (argv, (gpointer) "-L");	/* Disable built-in IPv4LL since we use avahi-autoipd */

	g_ptr_array_add (argv, (gpointer) "-G");	/* Let NM handle routing */

	g_ptr_array_add (argv, (gpointer) "-c");	/* Set script file */
	g_ptr_array_add (argv, (gpointer) nm_dhcp_helper_path);

#ifdef DHCPCD_SUPPORTS_IPV6
	/* IPv4-only for now.  NetworkManager knows better than dhcpcd when to
	 * run IPv6, and dhcpcd's automatic Router Solicitations cause problems
	 * with devices that don't expect them.
	 */
	g_ptr_array_add (argv, (gpointer) "-4");
#endif

	if (hostname && strlen (hostname)) {
		g_ptr_array_add (argv, (gpointer) "-h");	/* Send hostname to DHCP server */
		g_ptr_array_add (argv, (gpointer) hostname );
	}

	g_ptr_array_add (argv, (gpointer) iface);
	g_ptr_array_add (argv, NULL);

	cmd_str = g_strjoinv (" ", (gchar **) argv->pdata);
	nm_log_dbg (LOGD_DHCP4, "running: %s", cmd_str);
	g_free (cmd_str);

	if (!g_spawn_async (NULL, (char **) argv->pdata, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
	                    &dhcpcd_child_setup, NULL, &pid, &error)) {
		nm_log_warn (LOGD_DHCP4, "dhcpcd failed to start.  error: '%s'", error->message);
		g_error_free (error);
		pid = -1;
	} else
		nm_log_info (LOGD_DHCP4, "dhcpcd started with pid %d", pid);

	g_free (pid_contents);
	g_ptr_array_free (argv, TRUE);
	return pid;
}

static GPid
ip6_start (NMDHCPClient *client,
           GByteArray *dhcp_anycast_addr,
           const char *hostname,
           gboolean info_only,
           const GByteArray *duid)
{
	nm_log_warn (LOGD_DHCP6, "the dhcpcd backend does not support IPv6.");
	return -1;
}

static void
stop (NMDHCPClient *client, gboolean release, const GByteArray *duid)
{
	NMDHCPDhcpcdPrivate *priv = NM_DHCP_DHCPCD_GET_PRIVATE (client);

	/* Chain up to parent */
	NM_DHCP_CLIENT_CLASS (nm_dhcp_dhcpcd_parent_class)->stop (client, release, duid);

	if (priv->pid_file) {
		if (remove (priv->pid_file) == -1)
			nm_log_dbg (LOGD_DHCP, "Could not remove dhcp pid file \"%s\": %d (%s)", priv->pid_file, errno, g_strerror (errno));
	}

	/* FIXME: implement release... */
}

/***************************************************/

static void
nm_dhcp_dhcpcd_init (NMDHCPDhcpcd *self)
{
	NMDHCPDhcpcdPrivate *priv = NM_DHCP_DHCPCD_GET_PRIVATE (self);

	priv->path = nm_dhcp_dhcpcd_get_path (DHCPCD_PATH);
}

static void
dispose (GObject *object)
{
	NMDHCPDhcpcdPrivate *priv = NM_DHCP_DHCPCD_GET_PRIVATE (object);

	g_free (priv->pid_file);

	G_OBJECT_CLASS (nm_dhcp_dhcpcd_parent_class)->dispose (object);
}

static void
nm_dhcp_dhcpcd_class_init (NMDHCPDhcpcdClass *dhcpcd_class)
{
	NMDHCPClientClass *client_class = NM_DHCP_CLIENT_CLASS (dhcpcd_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dhcpcd_class);

	g_type_class_add_private (dhcpcd_class, sizeof (NMDHCPDhcpcdPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	client_class->ip4_start = ip4_start;
	client_class->ip6_start = ip6_start;
	client_class->stop = stop;
}

