/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-dhcp-dhcpcanon.c - dhcpcanon specific hooks for NetworkManager
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
 * Copyright (C) 2017 juga <juga at riseup dot net>
 */

#include "nm-default.h"

#if WITH_DHCPCANON

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>

#include "nm-utils.h"
#include "nm-dhcp-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-dhcp-listener.h"
#include "nm-dhcp-client-logging.h"

#define NM_TYPE_DHCP_DHCPCANON            (nm_dhcp_dhcpcanon_get_type ())
#define NM_DHCP_DHCPCANON(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_DHCPCANON, NMDhcpDhcpcanon))
#define NM_DHCP_DHCPCANON_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_DHCPCANON, NMDhcpDhcpcanonClass))
#define NM_IS_DHCP_DHCPCANON(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_DHCPCANON))
#define NM_IS_DHCP_DHCPCANON_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_DHCPCANON))
#define NM_DHCP_DHCPCANON_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_DHCPCANON, NMDhcpDhcpcanonClass))

typedef struct _NMDhcpDhcpcanon NMDhcpDhcpcanon;
typedef struct _NMDhcpDhcpcanonClass NMDhcpDhcpcanonClass;

static GType nm_dhcp_dhcpcanon_get_type (void);

/*****************************************************************************/

typedef struct {
	char *conf_file;
	const char *def_leasefile;
	char *lease_file;
	char *pid_file;
	NMDhcpListener *dhcp_listener;
} NMDhcpDhcpcanonPrivate;

struct _NMDhcpDhcpcanon {
	NMDhcpClient parent;
	NMDhcpDhcpcanonPrivate _priv;
};

struct _NMDhcpDhcpcanonClass {
	NMDhcpClientClass parent;
};

G_DEFINE_TYPE (NMDhcpDhcpcanon, nm_dhcp_dhcpcanon, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_DHCPCANON_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDhcpDhcpcanon, NM_IS_DHCP_DHCPCANON)

/*****************************************************************************/

static const char *
nm_dhcp_dhcpcanon_get_path (void)
{
	return nm_utils_find_helper ("dhcpcanon", DHCPCANON_PATH, NULL);
}

static gboolean
dhcpcanon_start (NMDhcpClient *client,
                const char *mode_opt,
                GBytes *duid,
                gboolean release,
                pid_t *out_pid,
                int prefixes)
{
	NMDhcpDhcpcanon *self = NM_DHCP_DHCPCANON (client);
	NMDhcpDhcpcanonPrivate *priv = NM_DHCP_DHCPCANON_GET_PRIVATE (self);
	GPtrArray *argv = NULL;
	pid_t pid;
	GError *error = NULL;
	const char *iface, *system_bus_address, *dhcpcanon_path = NULL;
	char *binary_name, *cmd_str, *pid_file = NULL, *system_bus_address_env = NULL;
	int addr_family;

	g_return_val_if_fail (priv->pid_file == NULL, FALSE);

	iface = nm_dhcp_client_get_iface (client);
	addr_family = nm_dhcp_client_get_addr_family (client);
	dhcpcanon_path = nm_dhcp_dhcpcanon_get_path ();
	_LOGD ("dhcpcanon_path: %s", dhcpcanon_path);
	if (!dhcpcanon_path) {
		_LOGW ("dhcpcanon could not be found");
		return FALSE;
	}

	pid_file = g_strdup_printf (RUNSTATEDIR "/dhcpcanon%c-%s.pid",
	                            nm_utils_addr_family_to_char (addr_family),
	                            iface);
	_LOGD ("pid_file: %s", pid_file);

	/* Kill any existing dhcpcanon from the pidfile */
	binary_name = g_path_get_basename (dhcpcanon_path);
	nm_dhcp_client_stop_existing (pid_file, binary_name);
	g_free (binary_name);

	argv = g_ptr_array_new ();
	g_ptr_array_add (argv, (gpointer) dhcpcanon_path);

	g_ptr_array_add (argv, (gpointer) "-sf"); /* Set script file */
	g_ptr_array_add (argv, (gpointer) nm_dhcp_helper_path);

	if (pid_file) {
		g_ptr_array_add (argv, (gpointer) "-pf"); /* Set pid file */
		g_ptr_array_add (argv, (gpointer) pid_file);
	}

	if (priv->conf_file) {
		g_ptr_array_add (argv, (gpointer) "-cf"); /* Set interface config file */
		g_ptr_array_add (argv, (gpointer) priv->conf_file);
	}

	/* Usually the system bus address is well-known; but if it's supposed
	 * to be something else, we need to push it to dhcpcanon, since dhcpcanon
	 * sanitizes the environment it gives the action scripts.
	 */
	system_bus_address = getenv ("DBUS_SYSTEM_BUS_ADDRESS");
	if (system_bus_address) {
		system_bus_address_env = g_strdup_printf ("DBUS_SYSTEM_BUS_ADDRESS=%s", system_bus_address);
		g_ptr_array_add (argv, (gpointer) "-e");
		g_ptr_array_add (argv, (gpointer) system_bus_address_env);
	}

	g_ptr_array_add (argv, (gpointer) iface);
	g_ptr_array_add (argv, NULL);

	cmd_str = g_strjoinv (" ", (gchar **) argv->pdata);
	g_free (cmd_str);

	if (g_spawn_async (NULL, (char **) argv->pdata, NULL,
	                   G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
	                   nm_utils_setpgid, NULL, &pid, &error)) {
		 g_assert (pid > 0);
		_LOGI ("dhcpcanon started with pid %d", pid);
		nm_dhcp_client_watch_child (client, pid);
		priv->pid_file = pid_file;
	} else {
		_LOGW ("dhcpcanon failed to start: '%s'", error->message);
		g_error_free (error);
		g_free (pid_file);
	}

	g_ptr_array_free (argv, TRUE);
	g_free (system_bus_address_env);
	return pid > 0 ? TRUE : FALSE;
}

static gboolean
ip4_start (NMDhcpClient *client, const char *dhcp_anycast_addr, const char *last_ip4_address)
{
	gboolean success = FALSE;
	success = dhcpcanon_start (client, NULL, NULL, FALSE, NULL, 0);
	return success;
}

static gboolean
ip6_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           const struct in6_addr *ll_addr,
           NMSettingIP6ConfigPrivacy privacy,
           GBytes *duid,
           guint needed_prefixes)
{
	NMDhcpDhcpcanon *self = NM_DHCP_DHCPCANON (client);

	_LOGW ("the dhcpcd backend does not support IPv6");
	return FALSE;
}
static void
stop (NMDhcpClient *client, gboolean release, GBytes *duid)
{
	NMDhcpDhcpcanon *self = NM_DHCP_DHCPCANON (client);
	NMDhcpDhcpcanonPrivate *priv = NM_DHCP_DHCPCANON_GET_PRIVATE (self);

	NM_DHCP_CLIENT_CLASS (nm_dhcp_dhcpcanon_parent_class)->stop (client, release, duid);

	if (priv->pid_file) {
		if (remove (priv->pid_file) == -1)
			_LOGD ("could not remove dhcp pid file \"%s\": %d (%s)", priv->pid_file, errno, g_strerror (errno));
		g_free (priv->pid_file);
		priv->pid_file = NULL;
	}
}

static void
state_changed (NMDhcpClient *client,
               NMDhcpState state,
               GObject *ip_config,
               GHashTable *options)
{
	if (nm_dhcp_client_get_client_id (client))
		return;
	if (state != NM_DHCP_STATE_BOUND)
		return;
}

/*****************************************************************************/

static void
nm_dhcp_dhcpcanon_init (NMDhcpDhcpcanon *self)
{
	NMDhcpDhcpcanonPrivate *priv = NM_DHCP_DHCPCANON_GET_PRIVATE (self);

	priv->dhcp_listener = g_object_ref (nm_dhcp_listener_get ());
	g_signal_connect (priv->dhcp_listener,
	                  NM_DHCP_LISTENER_EVENT,
	                  G_CALLBACK (nm_dhcp_client_handle_event),
	                  self);
}

static void
dispose (GObject *object)
{
	NMDhcpDhcpcanonPrivate *priv = NM_DHCP_DHCPCANON_GET_PRIVATE ((NMDhcpDhcpcanon *) object);

	if (priv->dhcp_listener) {
		g_signal_handlers_disconnect_by_func (priv->dhcp_listener,
		                                      G_CALLBACK (nm_dhcp_client_handle_event),
		                                      NM_DHCP_DHCPCANON (object));
		g_clear_object (&priv->dhcp_listener);
	}

	nm_clear_g_free (&priv->pid_file);

	G_OBJECT_CLASS (nm_dhcp_dhcpcanon_parent_class)->dispose (object);
}

static void
nm_dhcp_dhcpcanon_class_init (NMDhcpDhcpcanonClass *dhcpcanon_class)
{
	NMDhcpClientClass *client_class = NM_DHCP_CLIENT_CLASS (dhcpcanon_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dhcpcanon_class);

	object_class->dispose = dispose;

	client_class->ip4_start = ip4_start;
	client_class->ip6_start = ip6_start;
	client_class->stop = stop;
	client_class->state_changed = state_changed;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_dhcpcanon = {
	.name = "dhcpcanon",
	.get_type = nm_dhcp_dhcpcanon_get_type,
	.get_path = nm_dhcp_dhcpcanon_get_path,
};

#endif /* WITH_DHCPCANON */
