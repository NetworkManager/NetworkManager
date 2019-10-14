// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 juga <juga at riseup dot net>
 */

#include "nm-default.h"

#if WITH_DHCPCANON

#include <stdlib.h>
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
                guint needed_prefixes,
                GError **error)
{
	NMDhcpDhcpcanon *self = NM_DHCP_DHCPCANON (client);
	NMDhcpDhcpcanonPrivate *priv = NM_DHCP_DHCPCANON_GET_PRIVATE (self);
	gs_unref_ptrarray GPtrArray *argv = NULL;
	pid_t pid;
	gs_free_error GError *local = NULL;
	const char *iface;
	const char *system_bus_address;
	const char *dhcpcanon_path;
	gs_free char *binary_name = NULL;
	gs_free char *pid_file = NULL;
	gs_free char *system_bus_address_env = NULL;
	int addr_family;

	g_return_val_if_fail (!priv->pid_file, FALSE);

	iface = nm_dhcp_client_get_iface (client);

	addr_family = nm_dhcp_client_get_addr_family (client);

	dhcpcanon_path = nm_dhcp_dhcpcanon_get_path ();
	if (!dhcpcanon_path) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "dhcpcanon binary not found");
		return FALSE;
	}

	_LOGD ("dhcpcanon_path: %s", dhcpcanon_path);

	pid_file = g_strdup_printf (RUNSTATEDIR "/dhcpcanon%c-%s.pid",
	                            nm_utils_addr_family_to_char (addr_family),
	                            iface);
	_LOGD ("pid_file: %s", pid_file);

	/* Kill any existing dhcpcanon from the pidfile */
	binary_name = g_path_get_basename (dhcpcanon_path);
	nm_dhcp_client_stop_existing (pid_file, binary_name);

	argv = g_ptr_array_new ();
	g_ptr_array_add (argv, (gpointer) dhcpcanon_path);

	g_ptr_array_add (argv, (gpointer) "-sf"); /* Set script file */
	g_ptr_array_add (argv, (gpointer) nm_dhcp_helper_path);

	g_ptr_array_add (argv, (gpointer) "-pf"); /* Set pid file */
	g_ptr_array_add (argv, (gpointer) pid_file);

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

	if (!g_spawn_async (NULL,
	                   (char **) argv->pdata,
	                   NULL,
	                     G_SPAWN_DO_NOT_REAP_CHILD
	                   | G_SPAWN_STDOUT_TO_DEV_NULL
	                   | G_SPAWN_STDERR_TO_DEV_NULL,
	                   nm_utils_setpgid,
	                   NULL,
	                   &pid,
	                   &local)) {
		nm_utils_error_set (error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "dhcpcanon failed to start: %s",
		                    local->message);
		return FALSE;
	}

	nm_assert (pid > 0);
	_LOGI ("dhcpcanon started with pid %d", pid);
	nm_dhcp_client_watch_child (client, pid);
	priv->pid_file = g_steal_pointer (&pid_file);
	return TRUE;
}

static gboolean
ip4_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           const char *last_ip4_address,
           GError **error)
{
	return dhcpcanon_start (client,
	                        NULL,
	                        NULL,
	                        FALSE,
	                        NULL,
	                        0,
	                        error);
}

static void
stop (NMDhcpClient *client, gboolean release)
{
	NMDhcpDhcpcanon *self = NM_DHCP_DHCPCANON (client);
	NMDhcpDhcpcanonPrivate *priv = NM_DHCP_DHCPCANON_GET_PRIVATE (self);
	int errsv;

	NM_DHCP_CLIENT_CLASS (nm_dhcp_dhcpcanon_parent_class)->stop (client, release);

	if (priv->pid_file) {
		if (remove (priv->pid_file) == -1) {
			errsv = errno;
			_LOGD ("could not remove dhcp pid file \"%s\": %d (%s)", priv->pid_file, errsv, nm_strerror_native (errsv));
		}
		g_free (priv->pid_file);
		priv->pid_file = NULL;
	}
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
	client_class->stop = stop;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_dhcpcanon = {
	.name     = "dhcpcanon",
	.get_type = nm_dhcp_dhcpcanon_get_type,
	.get_path = nm_dhcp_dhcpcanon_get_path,
};

#endif /* WITH_DHCPCANON */
