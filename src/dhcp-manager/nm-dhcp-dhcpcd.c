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


#include "nm-default.h"

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
#include "NetworkManagerUtils.h"
#include "nm-dhcp-listener.h"
#include "nm-dhcp-client-logging.h"

G_DEFINE_TYPE (NMDhcpDhcpcd, nm_dhcp_dhcpcd, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_DHCPCD_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_DHCPCD, NMDhcpDhcpcdPrivate))

typedef struct {
	char *pid_file;
} NMDhcpDhcpcdPrivate;

static const char *
nm_dhcp_dhcpcd_get_path (void)
{
	const char *path = NULL;

	if (WITH_DHCPCD)
		path = nm_utils_find_helper ("dhcpcd", DHCPCD_PATH, NULL);
	return path;
}

static gboolean
ip4_start (NMDhcpClient *client, const char *dhcp_anycast_addr, const char *last_ip4_address)
{
	NMDhcpDhcpcd *self = NM_DHCP_DHCPCD (client);
	NMDhcpDhcpcdPrivate *priv = NM_DHCP_DHCPCD_GET_PRIVATE (self);
	GPtrArray *argv = NULL;
	pid_t pid = -1;
	GError *error = NULL;
	char *pid_contents = NULL, *binary_name, *cmd_str, *dot;
	const char *iface, *dhcpcd_path, *hostname, *fqdn;
	gs_free char *prefix = NULL;

	g_return_val_if_fail (priv->pid_file == NULL, FALSE);

	iface = nm_dhcp_client_get_iface (client);

	/* dhcpcd does not allow custom pidfiles; the pidfile is always
	 * RUNDIR "dhcpcd-<ifname>.pid".
	 */
	priv->pid_file = g_strdup_printf (RUNDIR "/dhcpcd-%s.pid", iface);

	dhcpcd_path = nm_dhcp_dhcpcd_get_path ();
	if (!dhcpcd_path) {
		_LOGW ("dhcpcd could not be found");
		return FALSE;
	}

	/* Kill any existing dhcpcd from the pidfile */
	binary_name = g_path_get_basename (dhcpcd_path);
	nm_dhcp_client_stop_existing (priv->pid_file, binary_name);
	g_free (binary_name);

	argv = g_ptr_array_new ();
	g_ptr_array_add (argv, (gpointer) dhcpcd_path);

	g_ptr_array_add (argv, (gpointer) "-B");	/* Don't background on lease (disable fork()) */

	g_ptr_array_add (argv, (gpointer) "-K");	/* Disable built-in carrier detection */

	g_ptr_array_add (argv, (gpointer) "-L");	/* Disable built-in IPv4LL */

	/* --noarp. Don't request or claim the address by ARP; this also disables IPv4LL. */
	g_ptr_array_add (argv, (gpointer) "-A");

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

	hostname = nm_dhcp_client_get_hostname (client);
	fqdn = nm_dhcp_client_get_fqdn (client);

	if (fqdn) {
		g_ptr_array_add (argv, (gpointer) "-h");
		g_ptr_array_add (argv, (gpointer) fqdn);
		g_ptr_array_add (argv, (gpointer) "-F");
		g_ptr_array_add (argv, (gpointer) "both");
	} else if (hostname) {
		prefix = strdup (hostname);
		dot = strchr (prefix, '.');
		/* get rid of the domain */
		if (dot)
			*dot = '\0';

		g_ptr_array_add (argv, (gpointer) "-h");	/* Send hostname to DHCP server */
		g_ptr_array_add (argv, (gpointer) prefix);
	}

	g_ptr_array_add (argv, (gpointer) iface);
	g_ptr_array_add (argv, NULL);

	cmd_str = g_strjoinv (" ", (gchar **) argv->pdata);
	_LOGD ("running: %s", cmd_str);
	g_free (cmd_str);

	if (g_spawn_async (NULL, (char **) argv->pdata, NULL,
	                   G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
	                   nm_utils_setpgid, NULL, &pid, &error)) {
		g_assert (pid > 0);
		_LOGI ("dhcpcd started with pid %d", pid);
		nm_dhcp_client_watch_child (client, pid);
	} else {
		_LOGW ("dhcpcd failed to start, error: '%s'", error->message);
		g_error_free (error);
	}

	g_free (pid_contents);
	g_ptr_array_free (argv, TRUE);
	return pid > 0 ? TRUE : FALSE;
}

static gboolean
ip6_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           const struct in6_addr *ll_addr,
           gboolean info_only,
           NMSettingIP6ConfigPrivacy privacy,
           const GByteArray *duid)
{
	NMDhcpDhcpcd *self = NM_DHCP_DHCPCD (client);

	_LOGW ("the dhcpcd backend does not support IPv6");
	return FALSE;
}

static void
stop (NMDhcpClient *client, gboolean release, const GByteArray *duid)
{
	NMDhcpDhcpcd *self = NM_DHCP_DHCPCD (client);
	NMDhcpDhcpcdPrivate *priv = NM_DHCP_DHCPCD_GET_PRIVATE (self);

	/* Chain up to parent */
	NM_DHCP_CLIENT_CLASS (nm_dhcp_dhcpcd_parent_class)->stop (client, release, duid);

	if (priv->pid_file) {
		if (remove (priv->pid_file) == -1)
			_LOGD ("could not remove dhcp pid file \"%s\": %d (%s)", priv->pid_file, errno, g_strerror (errno));
	}

	/* FIXME: implement release... */
}

/***************************************************/

static void
nm_dhcp_dhcpcd_init (NMDhcpDhcpcd *self)
{
	g_signal_connect (nm_dhcp_listener_get (),
	                  NM_DHCP_LISTENER_EVENT,
	                  G_CALLBACK (nm_dhcp_client_handle_event),
	                  self);
}

static void
dispose (GObject *object)
{
	NMDhcpDhcpcdPrivate *priv = NM_DHCP_DHCPCD_GET_PRIVATE (object);

	g_signal_handlers_disconnect_by_func (nm_dhcp_listener_get (),
	                                      G_CALLBACK (nm_dhcp_client_handle_event),
	                                      NM_DHCP_DHCPCD (object));

	g_free (priv->pid_file);

	G_OBJECT_CLASS (nm_dhcp_dhcpcd_parent_class)->dispose (object);
}

static void
nm_dhcp_dhcpcd_class_init (NMDhcpDhcpcdClass *dhcpcd_class)
{
	NMDhcpClientClass *client_class = NM_DHCP_CLIENT_CLASS (dhcpcd_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dhcpcd_class);

	g_type_class_add_private (dhcpcd_class, sizeof (NMDhcpDhcpcdPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	client_class->ip4_start = ip4_start;
	client_class->ip6_start = ip6_start;
	client_class->stop = stop;
}

static void __attribute__((constructor))
register_dhcp_dhclient (void)
{
	nm_g_type_init ();
	_nm_dhcp_client_register (NM_TYPE_DHCP_DHCPCD,
	                          "dhcpcd",
	                          nm_dhcp_dhcpcd_get_path,
	                          NULL);
}

