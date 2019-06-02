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

#if WITH_DHCPCD

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "nm-dhcp-manager.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-dhcp-listener.h"
#include "nm-dhcp-client-logging.h"

/*****************************************************************************/

#define NM_TYPE_DHCP_DHCPCD            (nm_dhcp_dhcpcd_get_type ())
#define NM_DHCP_DHCPCD(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_DHCPCD, NMDhcpDhcpcd))
#define NM_DHCP_DHCPCD_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_DHCPCD, NMDhcpDhcpcdClass))
#define NM_IS_DHCP_DHCPCD(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_DHCPCD))
#define NM_IS_DHCP_DHCPCD_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_DHCPCD))
#define NM_DHCP_DHCPCD_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_DHCPCD, NMDhcpDhcpcdClass))

typedef struct _NMDhcpDhcpcd NMDhcpDhcpcd;
typedef struct _NMDhcpDhcpcdClass NMDhcpDhcpcdClass;

static GType nm_dhcp_dhcpcd_get_type (void);

/*****************************************************************************/

typedef struct {
	char *pid_file;
	NMDhcpListener *dhcp_listener;
} NMDhcpDhcpcdPrivate;

struct _NMDhcpDhcpcd {
	NMDhcpClient parent;
	NMDhcpDhcpcdPrivate _priv;
};

struct _NMDhcpDhcpcdClass {
	NMDhcpClientClass parent;
};

G_DEFINE_TYPE (NMDhcpDhcpcd, nm_dhcp_dhcpcd, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_DHCPCD_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDhcpDhcpcd, NM_IS_DHCP_DHCPCD)

/*****************************************************************************/

static const char *
nm_dhcp_dhcpcd_get_path (void)
{
	return nm_utils_find_helper ("dhcpcd", DHCPCD_PATH, NULL);
}

static gboolean
ip4_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           const char *last_ip4_address,
           GError **error)
{
	NMDhcpDhcpcd *self = NM_DHCP_DHCPCD (client);
	NMDhcpDhcpcdPrivate *priv = NM_DHCP_DHCPCD_GET_PRIVATE (self);
	gs_unref_ptrarray GPtrArray *argv = NULL;
	pid_t pid = -1;
	GError *local = NULL;
	gs_free char *cmd_str = NULL;
	gs_free char *binary_name = NULL;
	const char *iface;
	const char *dhcpcd_path;
	const char *hostname;

	g_return_val_if_fail (priv->pid_file == NULL, FALSE);

	iface = nm_dhcp_client_get_iface (client);

	/* dhcpcd does not allow custom pidfiles; the pidfile is always
	 * RUNSTATEDIR "dhcpcd-<ifname>.pid".
	 */
	priv->pid_file = g_strdup_printf (RUNSTATEDIR "/dhcpcd-%s.pid", iface);

	dhcpcd_path = nm_dhcp_dhcpcd_get_path ();
	if (!dhcpcd_path) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "dhcpcd binary not found");
		return FALSE;
	}

	/* Kill any existing dhcpcd from the pidfile */
	binary_name = g_path_get_basename (dhcpcd_path);
	nm_dhcp_client_stop_existing (priv->pid_file, binary_name);

	argv = g_ptr_array_new ();
	g_ptr_array_add (argv, (gpointer) dhcpcd_path);

	g_ptr_array_add (argv, (gpointer) "-B");    /* Don't background on lease (disable fork()) */

	g_ptr_array_add (argv, (gpointer) "-K");    /* Disable built-in carrier detection */

	g_ptr_array_add (argv, (gpointer) "-L");    /* Disable built-in IPv4LL */

	/* --noarp. Don't request or claim the address by ARP; this also disables IPv4LL. */
	g_ptr_array_add (argv, (gpointer) "-A");

	g_ptr_array_add (argv, (gpointer) "-G");    /* Let NM handle routing */

	g_ptr_array_add (argv, (gpointer) "-c");    /* Set script file */
	g_ptr_array_add (argv, (gpointer) nm_dhcp_helper_path);

	/* IPv4-only for now.  NetworkManager knows better than dhcpcd when to
	 * run IPv6, and dhcpcd's automatic Router Solicitations cause problems
	 * with devices that don't expect them.
	 */
	g_ptr_array_add (argv, (gpointer) "-4");

	hostname = nm_dhcp_client_get_hostname (client);

	if (hostname) {
		if (nm_dhcp_client_get_use_fqdn (client)) {
			g_ptr_array_add (argv, (gpointer) "-h");
			g_ptr_array_add (argv, (gpointer) hostname);
			g_ptr_array_add (argv, (gpointer) "-F");
			g_ptr_array_add (argv, (gpointer) "both");
		} else {
			g_ptr_array_add (argv, (gpointer) "-h");
			g_ptr_array_add (argv, (gpointer) hostname);
		}
	}

	g_ptr_array_add (argv, (gpointer) iface);
	g_ptr_array_add (argv, NULL);

	_LOGD ("running: %s",
	       (cmd_str = g_strjoinv (" ", (char **) argv->pdata)));

	if (!g_spawn_async (NULL,
	                    (char **) argv->pdata, NULL,
	                      G_SPAWN_DO_NOT_REAP_CHILD
	                    | G_SPAWN_STDOUT_TO_DEV_NULL
	                    | G_SPAWN_STDERR_TO_DEV_NULL,
	                    nm_utils_setpgid,
	                    NULL,
	                    &pid,
	                    &local)) {
		nm_utils_error_set (error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "dhcpcd failed to start: %s",
		                    local->message);
		g_error_free (local);
		return FALSE;
	}

	nm_assert (pid > 0);
	_LOGI ("dhcpcd started with pid %d", pid);
	nm_dhcp_client_watch_child (client, pid);
	return TRUE;
}

static void
stop (NMDhcpClient *client, gboolean release)
{
	NMDhcpDhcpcd *self = NM_DHCP_DHCPCD (client);
	NMDhcpDhcpcdPrivate *priv = NM_DHCP_DHCPCD_GET_PRIVATE (self);
	int errsv;

	NM_DHCP_CLIENT_CLASS (nm_dhcp_dhcpcd_parent_class)->stop (client, release);

	if (priv->pid_file) {
		if (remove (priv->pid_file) == -1) {
			errsv = errno;
			_LOGD ("could not remove dhcp pid file \"%s\": %d (%s)", priv->pid_file, errsv, nm_strerror_native (errsv));
		}
	}

	/* FIXME: implement release... */
}

/*****************************************************************************/

static void
nm_dhcp_dhcpcd_init (NMDhcpDhcpcd *self)
{
	NMDhcpDhcpcdPrivate *priv = NM_DHCP_DHCPCD_GET_PRIVATE (self);

	priv->dhcp_listener = g_object_ref (nm_dhcp_listener_get ());
	g_signal_connect (priv->dhcp_listener,
	                  NM_DHCP_LISTENER_EVENT,
	                  G_CALLBACK (nm_dhcp_client_handle_event),
	                  self);
}

static void
dispose (GObject *object)
{
	NMDhcpDhcpcdPrivate *priv = NM_DHCP_DHCPCD_GET_PRIVATE ((NMDhcpDhcpcd *) object);

	if (priv->dhcp_listener) {
		g_signal_handlers_disconnect_by_func (priv->dhcp_listener,
		                                      G_CALLBACK (nm_dhcp_client_handle_event),
		                                      NM_DHCP_DHCPCD (object));
		g_clear_object (&priv->dhcp_listener);
	}

	nm_clear_g_free (&priv->pid_file);

	G_OBJECT_CLASS (nm_dhcp_dhcpcd_parent_class)->dispose (object);
}

static void
nm_dhcp_dhcpcd_class_init (NMDhcpDhcpcdClass *dhcpcd_class)
{
	NMDhcpClientClass *client_class = NM_DHCP_CLIENT_CLASS (dhcpcd_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dhcpcd_class);

	object_class->dispose = dispose;

	client_class->ip4_start = ip4_start;
	client_class->stop = stop;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_dhcpcd = {
	.name = "dhcpcd",
	.get_type = nm_dhcp_dhcpcd_get_type,
	.get_path = nm_dhcp_dhcpcd_get_path,
};

#endif /* WITH_DHCPCD */
