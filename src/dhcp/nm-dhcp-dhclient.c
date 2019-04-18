/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-dhcp-dhclient.c - dhclient specific hooks for NetworkManager
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
 * Copyright (C) 2005 - 2012 Red Hat, Inc.
 */

#include <config.h>
#define __CONFIG_H__

#define _XOPEN_SOURCE
#include <time.h>
#undef _XOPEN_SOURCE

#include "nm-default.h"

#if WITH_DHCLIENT

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "nm-glib-aux/nm-dedup-multi.h"

#include "nm-utils.h"
#include "nm-config.h"
#include "nm-dhcp-dhclient-utils.h"
#include "nm-dhcp-manager.h"
#include "NetworkManagerUtils.h"
#include "nm-dhcp-listener.h"
#include "nm-dhcp-client-logging.h"

/*****************************************************************************/

static const char *
_addr_family_to_path_part (int addr_family)
{
	nm_assert (NM_IN_SET (addr_family, AF_INET, AF_INET6));
	return (addr_family == AF_INET6) ? "6" : "";
}

/*****************************************************************************/

#define NM_TYPE_DHCP_DHCLIENT            (nm_dhcp_dhclient_get_type ())
#define NM_DHCP_DHCLIENT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DHCP_DHCLIENT, NMDhcpDhclient))
#define NM_DHCP_DHCLIENT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_DHCP_DHCLIENT, NMDhcpDhclientClass))
#define NM_IS_DHCP_DHCLIENT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DHCP_DHCLIENT))
#define NM_IS_DHCP_DHCLIENT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_DHCP_DHCLIENT))
#define NM_DHCP_DHCLIENT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_DHCP_DHCLIENT, NMDhcpDhclientClass))

typedef struct _NMDhcpDhclient NMDhcpDhclient;
typedef struct _NMDhcpDhclientClass NMDhcpDhclientClass;

static GType nm_dhcp_dhclient_get_type (void);

/*****************************************************************************/

typedef struct {
	char *conf_file;
	const char *def_leasefile;
	char *lease_file;
	char *pid_file;
	NMDhcpListener *dhcp_listener;
} NMDhcpDhclientPrivate;

struct _NMDhcpDhclient {
	NMDhcpClient parent;
	NMDhcpDhclientPrivate _priv;
};

struct _NMDhcpDhclientClass {
	NMDhcpClientClass parent;
};

G_DEFINE_TYPE (NMDhcpDhclient, nm_dhcp_dhclient, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_DHCLIENT_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDhcpDhclient, NM_IS_DHCP_DHCLIENT)

/*****************************************************************************/

static const char *
nm_dhcp_dhclient_get_path (void)
{
	return nm_utils_find_helper ("dhclient", DHCLIENT_PATH, NULL);
}

/**
 * get_dhclient_leasefile():
 * @addr_family: AF_INET or AF_INET6
 * @iface: the interface name of the device on which DHCP will be done
 * @uuid: the connection UUID to which the returned lease should belong
 * @out_preferred_path: on return, the "most preferred" leasefile path
 *
 * Returns the path of an existing leasefile (if any) for this interface and
 * connection UUID.  Also returns the "most preferred" leasefile path, which
 * may be different than any found leasefile.
 *
 * Returns: an existing leasefile, or %NULL if no matching leasefile could be found
 */
static char *
get_dhclient_leasefile (int addr_family,
                        const char *iface,
                        const char *uuid,
                        char **out_preferred_path)
{
	gs_free char *rundir_path = NULL;
	gs_free char *path = NULL;

	/* First, see if the lease file is in /run */
	rundir_path = g_strdup_printf (NMRUNDIR "/dhclient%s-%s-%s.lease",
	                               _addr_family_to_path_part (addr_family),
	                               uuid,
	                               iface);

	if (g_file_test (rundir_path, G_FILE_TEST_EXISTS)) {
		NM_SET_OUT (out_preferred_path, g_strdup (rundir_path));
		return g_steal_pointer (&rundir_path);
	}

	/* /var/lib/NetworkManager is the preferred leasefile path */
	path = g_strdup_printf (NMSTATEDIR "/dhclient%s-%s-%s.lease",
	                        _addr_family_to_path_part (addr_family),
	                        uuid,
	                        iface);

	if (g_file_test (path, G_FILE_TEST_EXISTS)) {
		NM_SET_OUT (out_preferred_path, g_strdup (path));
		return g_steal_pointer (&path);
	}

	if (nm_config_get_configure_and_quit (nm_config_get ()) == NM_CONFIG_CONFIGURE_AND_QUIT_INITRD)
		NM_SET_OUT (out_preferred_path, g_steal_pointer (&rundir_path));
	else
		NM_SET_OUT (out_preferred_path, g_steal_pointer (&path));

	/* If the leasefile we're looking for doesn't exist yet in the new location
	 * (eg, /var/lib/NetworkManager) then look in old locations to maintain
	 * backwards compatibility with external tools (like dracut) that put
	 * leasefiles there.
	 */

	/* Old Debian, SUSE, and Mandriva location */
	g_free (path);
	path = g_strdup_printf (LOCALSTATEDIR "/lib/dhcp/dhclient%s-%s-%s.lease",
	                        _addr_family_to_path_part (addr_family), uuid, iface);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return g_steal_pointer (&path);

	/* Old Red Hat and Fedora location */
	g_free (path);
	path = g_strdup_printf (LOCALSTATEDIR "/lib/dhclient/dhclient%s-%s-%s.lease",
	                        _addr_family_to_path_part (addr_family), uuid, iface);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return g_steal_pointer (&path);

	/* Fail */
	return NULL;
}

static gboolean
merge_dhclient_config (NMDhcpDhclient *self,
                       int addr_family,
                       const char *iface,
                       const char *conf_file,
                       GBytes *client_id,
                       const char *anycast_addr,
                       const char *hostname,
                       guint32 timeout,
                       gboolean use_fqdn,
                       const char *orig_path,
                       GBytes **out_new_client_id,
                       GError **error)
{
	gs_free char *orig = NULL;
	gs_free char *new = NULL;

	g_return_val_if_fail (iface, FALSE);
	g_return_val_if_fail (conf_file, FALSE);

	if (   orig_path
	    && g_file_test (orig_path, G_FILE_TEST_EXISTS)) {
		GError *read_error = NULL;

		if (!g_file_get_contents (orig_path, &orig, NULL, &read_error)) {
			_LOGW ("error reading dhclient configuration %s: %s",
			       orig_path, read_error->message);
			g_error_free (read_error);
		}
	}

	new = nm_dhcp_dhclient_create_config (iface,
	                                      addr_family,
	                                      client_id,
	                                      anycast_addr,
	                                      hostname,
	                                      timeout,
	                                      use_fqdn,
	                                      orig_path,
	                                      orig,
	                                      out_new_client_id);
	g_assert (new);

	return g_file_set_contents (conf_file,
	                            new,
	                            -1,
	                            error);
}

static char *
find_existing_config (NMDhcpDhclient *self, int addr_family, const char *iface, const char *uuid)
{
	char *path;

	/* NetworkManager-overridden configuration can be used to ship DHCP config
	 * with NetworkManager itself. It can be uuid-specific, device-specific
	 * or generic.
	 */
	if (uuid) {
		path = g_strdup_printf (NMCONFDIR "/dhclient%s-%s.conf", _addr_family_to_path_part (addr_family), uuid);
		_LOGD ("looking for existing config %s", path);
		if (g_file_test (path, G_FILE_TEST_EXISTS))
			return path;
		g_free (path);
	}

	path = g_strdup_printf (NMCONFDIR "/dhclient%s-%s.conf", _addr_family_to_path_part (addr_family), iface);
	_LOGD ("looking for existing config %s", path);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;
	g_free (path);

	path = g_strdup_printf (NMCONFDIR "/dhclient%s.conf", _addr_family_to_path_part (addr_family));
	_LOGD ("looking for existing config %s", path);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;
	g_free (path);

	/* Distribution's dhclient configuration is used so that we can use
	 * configuration shipped with dhclient (if any).
	 *
	 * This replaces conditional compilation based on distribution name. Fedora
	 * and Debian store the configs in /etc/dhcp while upstream defaults to /etc
	 * which is then used by many other distributions. Some distributions
	 * (including Fedora) don't even provide a default configuration file.
	 */
	path = g_strdup_printf (SYSCONFDIR "/dhcp/dhclient%s-%s.conf", _addr_family_to_path_part (addr_family), iface);
	_LOGD ("looking for existing config %s", path);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;
	g_free (path);

	path = g_strdup_printf (SYSCONFDIR "/dhclient%s-%s.conf", _addr_family_to_path_part (addr_family), iface);
	_LOGD ("looking for existing config %s", path);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;
	g_free (path);

	path = g_strdup_printf (SYSCONFDIR "/dhcp/dhclient%s.conf", _addr_family_to_path_part (addr_family));
	_LOGD ("looking for existing config %s", path);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;
	g_free (path);

	path = g_strdup_printf (SYSCONFDIR "/dhclient%s.conf", _addr_family_to_path_part (addr_family));
	_LOGD ("looking for existing config %s", path);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;
	g_free (path);

	return NULL;
}

/* NM provides interface-specific options; thus the same dhclient config
 * file cannot be used since DHCP transactions can happen in parallel.
 * Since some distros don't have default per-interface dhclient config files,
 * read their single config file and merge that into a custom per-interface
 * config file along with the NM options.
 */
static char *
create_dhclient_config (NMDhcpDhclient *self,
                        int addr_family,
                        const char *iface,
                        const char *uuid,
                        GBytes *client_id,
                        const char *dhcp_anycast_addr,
                        const char *hostname,
                        guint32 timeout,
                        gboolean use_fqdn,
                        GBytes **out_new_client_id)
{
	gs_free char *orig = NULL;
	char *new = NULL;
	GError *error = NULL;

	g_return_val_if_fail (iface != NULL, NULL);

	new = g_strdup_printf (NMSTATEDIR "/dhclient%s-%s.conf", _addr_family_to_path_part (addr_family), iface);

	_LOGD ("creating composite dhclient config %s", new);

	orig = find_existing_config (self, addr_family, iface, uuid);
	if (orig)
		_LOGD ("merging existing dhclient config %s", orig);
	else
		_LOGD ("no existing dhclient configuration to merge");

	if (!merge_dhclient_config (self,
	                            addr_family,
	                            iface,
	                            new,
	                            client_id,
	                            dhcp_anycast_addr,
	                            hostname,
	                            timeout,
	                            use_fqdn,
	                            orig,
	                            out_new_client_id,
	                            &error)) {
		_LOGW ("error creating dhclient configuration: %s", error->message);
		g_clear_error (&error);
	}

	return new;
}

static gboolean
dhclient_start (NMDhcpClient *client,
                const char *mode_opt,
                gboolean release,
                pid_t *out_pid,
                int prefixes,
                GError **error)
{
	NMDhcpDhclient *self = NM_DHCP_DHCLIENT (client);
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);
	gs_unref_ptrarray GPtrArray *argv = NULL;
	pid_t pid;
	gs_free_error GError *local = NULL;
	const char *iface;
	const char *uuid;
	const char *system_bus_address;
	const char *dhclient_path;
	char *binary_name;
	gs_free char *cmd_str = NULL;
	gs_free char *pid_file = NULL;
	gs_free char *system_bus_address_env = NULL;
	gs_free char *preferred_leasefile_path = NULL;
	const int addr_family = nm_dhcp_client_get_addr_family (client);

	g_return_val_if_fail (!priv->pid_file, FALSE);

	NM_SET_OUT (out_pid, 0);

	dhclient_path = nm_dhcp_dhclient_get_path ();
	if (!dhclient_path) {
		nm_utils_error_set_literal (error, NM_UTILS_ERROR_UNKNOWN, "dhclient binary not found");
		return FALSE;
	}

	iface = nm_dhcp_client_get_iface (client);
	uuid = nm_dhcp_client_get_uuid (client);

	pid_file = g_strdup_printf (RUNSTATEDIR "/dhclient%s-%s.pid",
	                            _addr_family_to_path_part (addr_family),
	                            iface);

	/* Kill any existing dhclient from the pidfile */
	binary_name = g_path_get_basename (dhclient_path);
	nm_dhcp_client_stop_existing (pid_file, binary_name);
	g_free (binary_name);

	if (release) {
		/* release doesn't use the pidfile after killing an old client */
		nm_clear_g_free (&pid_file);
	}

	g_free (priv->lease_file);
	priv->lease_file = get_dhclient_leasefile (addr_family, iface, uuid, &preferred_leasefile_path);
	nm_assert (preferred_leasefile_path);
	if (!priv->lease_file) {
		/* No existing leasefile, dhclient will create one at the preferred path */
		priv->lease_file = g_steal_pointer (&preferred_leasefile_path);
	} else if (!nm_streq0 (priv->lease_file, preferred_leasefile_path)) {
		gs_unref_object GFile *src = g_file_new_for_path (priv->lease_file);
		gs_unref_object GFile *dst = g_file_new_for_path (preferred_leasefile_path);

		/* Try to copy the existing leasefile to the preferred location */
		if (!g_file_copy (src, dst, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL, &local)) {
			gs_free char *s_path = NULL;
			gs_free char *d_path = NULL;

			/* Failure; just use the existing leasefile */
			_LOGW ("failed to copy leasefile %s to %s: %s",
			       (s_path = g_file_get_path (src)),
			       (d_path = g_file_get_path (dst)),
			       local->message);
			g_clear_error (&local);
		} else {
			/* Success; use the preferred leasefile path */
			g_free (priv->lease_file);
			priv->lease_file = g_file_get_path (dst);
		}
	}

	/* Save the DUID to the leasefile dhclient will actually use */
	if (addr_family == AF_INET6) {
		if (!nm_dhcp_dhclient_save_duid (priv->lease_file,
		                                 nm_dhcp_client_get_client_id (client),
		                                 &local)) {
			nm_utils_error_set (error,
			                    NM_UTILS_ERROR_UNKNOWN,
			                    "failed to save DUID to '%s': %s",
			                    priv->lease_file,
			                    local->message);
			return FALSE;
		}
	}

	argv = g_ptr_array_new ();
	g_ptr_array_add (argv, (gpointer) dhclient_path);

	g_ptr_array_add (argv, (gpointer) "-d");

	/* Be quiet. dhclient logs to syslog anyway. And we duplicate the syslog
	 * to stderr in case of NM running with --debug.
	 */
	g_ptr_array_add (argv, (gpointer) "-q");

	if (release)
		g_ptr_array_add (argv, (gpointer) "-r");

	if (addr_family == AF_INET6) {
		g_ptr_array_add (argv, (gpointer) "-6");
		if (mode_opt)
			g_ptr_array_add (argv, (gpointer) mode_opt);
		while (prefixes--)
			g_ptr_array_add (argv, (gpointer) "-P");
	}
	g_ptr_array_add (argv, (gpointer) "-sf"); /* Set script file */
	g_ptr_array_add (argv, (gpointer) nm_dhcp_helper_path);

	if (pid_file) {
		g_ptr_array_add (argv, (gpointer) "-pf"); /* Set pid file */
		g_ptr_array_add (argv, (gpointer) pid_file);
	}

	g_ptr_array_add (argv, (gpointer) "-lf"); /* Set lease file */
	g_ptr_array_add (argv, (gpointer) priv->lease_file);

	if (priv->conf_file) {
		g_ptr_array_add (argv, (gpointer) "-cf"); /* Set interface config file */
		g_ptr_array_add (argv, (gpointer) priv->conf_file);
	}

	/* Usually the system bus address is well-known; but if it's supposed
	 * to be something else, we need to push it to dhclient, since dhclient
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

	_LOGD ("running: %s",
	       (cmd_str = g_strjoinv (" ", (char **) argv->pdata)));

	if (!g_spawn_async (NULL, (char **) argv->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
	                    nm_utils_setpgid, NULL, &pid, &local)) {
		nm_utils_error_set (error,
		                    NM_UTILS_ERROR_UNKNOWN,
		                    "dhclient failed to start: %s",
		                    local->message);
		return FALSE;
	}

	_LOGI ("dhclient started with pid %lld", (long long int) pid);

	if (!release)
		nm_dhcp_client_watch_child (client, pid);

	priv->pid_file = g_steal_pointer (&pid_file);

	NM_SET_OUT (out_pid, pid);
	return TRUE;
}

static gboolean
ip4_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           const char *last_ip4_address,
           GError **error)
{
	NMDhcpDhclient *self = NM_DHCP_DHCLIENT (client);
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);
	GBytes *client_id;
	gs_unref_bytes GBytes *new_client_id = NULL;

	client_id = nm_dhcp_client_get_client_id (client);

	priv->conf_file = create_dhclient_config (self,
	                                          AF_INET,
	                                          nm_dhcp_client_get_iface (client),
	                                          nm_dhcp_client_get_uuid (client),
	                                          client_id,
	                                          dhcp_anycast_addr,
	                                          nm_dhcp_client_get_hostname (client),
	                                          nm_dhcp_client_get_timeout (client),
	                                          nm_dhcp_client_get_use_fqdn (client),
	                                          &new_client_id);
	if (!priv->conf_file) {
		nm_utils_error_set_literal (error,
		                            NM_UTILS_ERROR_UNKNOWN,
		                            "error creating dhclient configuration file");
		return FALSE;
	}

	if (new_client_id) {
		nm_assert (!client_id);
		nm_dhcp_client_set_client_id (client, new_client_id);
	}
	return dhclient_start (client,
	                       NULL,
	                       FALSE,
	                       NULL,
	                       0,
	                       error);
}

static gboolean
ip6_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           const struct in6_addr *ll_addr,
           NMSettingIP6ConfigPrivacy privacy,
           guint needed_prefixes,
           GError **error)
{
	NMDhcpDhclient *self = NM_DHCP_DHCLIENT (client);
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);

	priv->conf_file = create_dhclient_config (self,
	                                          AF_INET6,
	                                          nm_dhcp_client_get_iface (client),
	                                          nm_dhcp_client_get_uuid (client),
	                                          NULL,
	                                          dhcp_anycast_addr,
	                                          nm_dhcp_client_get_hostname (client),
	                                          nm_dhcp_client_get_timeout (client),
	                                          TRUE,
	                                          NULL);
	if (!priv->conf_file) {
		nm_utils_error_set_literal (error,
		                            NM_UTILS_ERROR_UNKNOWN,
		                            "error creating dhclient configuration file");
		return FALSE;
	}

	return dhclient_start (client,
	                       nm_dhcp_client_get_info_only (NM_DHCP_CLIENT (self))
	                         ? "-S"
	                         : "-N",
	                       FALSE,
	                       NULL,
	                       needed_prefixes,
	                       error);
}

static void
stop (NMDhcpClient *client, gboolean release)
{
	NMDhcpDhclient *self = NM_DHCP_DHCLIENT (client);
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);
	int errsv;

	NM_DHCP_CLIENT_CLASS (nm_dhcp_dhclient_parent_class)->stop (client, release);

	if (priv->conf_file)
		if (remove (priv->conf_file) == -1) {
			errsv = errno;
			_LOGD ("could not remove dhcp config file \"%s\": %d (%s)", priv->conf_file, errsv, nm_strerror_native (errsv));
		}
	if (priv->pid_file) {
		if (remove (priv->pid_file) == -1) {
			errsv = errno;
			_LOGD ("could not remove dhcp pid file \"%s\": %s (%d)", priv->pid_file, nm_strerror_native (errsv), errsv);
		}
		nm_clear_g_free (&priv->pid_file);
	}

	if (release) {
		pid_t rpid = -1;

		if (dhclient_start (client,
		                    NULL,
		                    TRUE,
		                    &rpid,
		                    0,
		                    NULL)) {
			/* Wait a few seconds for the release to happen */
			nm_dhcp_client_stop_pid (rpid, nm_dhcp_client_get_iface (client));
		}
	}
}

static GBytes *
get_duid (NMDhcpClient *client)
{
	NMDhcpDhclient *self = NM_DHCP_DHCLIENT (client);
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);
	GBytes *duid = NULL;
	gs_free char *leasefile = NULL;
	GError *error = NULL;

	/* Look in interface-specific leasefile first for backwards compat */
	leasefile = get_dhclient_leasefile (AF_INET6,
	                                    nm_dhcp_client_get_iface (client),
	                                    nm_dhcp_client_get_uuid (client),
	                                    NULL);
	if (leasefile) {
		_LOGD ("looking for DUID in '%s'", leasefile);
		duid = nm_dhcp_dhclient_read_duid (leasefile, &error);
		if (error) {
			_LOGW ("failed to read leasefile '%s': %s",
			       leasefile, error->message);
			g_clear_error (&error);
		}
		if (duid)
			return duid;
	}

	/* Otherwise read the default machine-wide DUID */
	_LOGD ("looking for default DUID in '%s'", priv->def_leasefile);
	duid = nm_dhcp_dhclient_read_duid (priv->def_leasefile, &error);
	if (error) {
		_LOGW ("failed to read leasefile '%s': %s",
		        priv->def_leasefile,
		        error->message);
		g_clear_error (&error);
	}

	return duid;
}

/*****************************************************************************/

static void
nm_dhcp_dhclient_init (NMDhcpDhclient *self)
{
	static const char *const FILES[] = {
		SYSCONFDIR "/dhclient6.leases", /* default */
		LOCALSTATEDIR "/lib/dhcp/dhclient6.leases",
		LOCALSTATEDIR "/lib/dhclient/dhclient6.leases",
	};
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);
	int i;

	priv->def_leasefile = FILES[0];
	for (i = 0; i < G_N_ELEMENTS (FILES); i++) {
		if (g_file_test (FILES[i], G_FILE_TEST_EXISTS)) {
			priv->def_leasefile = FILES[i];
			break;
		}
	}

	priv->dhcp_listener = g_object_ref (nm_dhcp_listener_get ());
	g_signal_connect (priv->dhcp_listener,
	                  NM_DHCP_LISTENER_EVENT,
	                  G_CALLBACK (nm_dhcp_client_handle_event),
	                  self);
}

static void
dispose (GObject *object)
{
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE ((NMDhcpDhclient *) object);

	if (priv->dhcp_listener) {
		g_signal_handlers_disconnect_by_func (priv->dhcp_listener,
		                                      G_CALLBACK (nm_dhcp_client_handle_event),
		                                      NM_DHCP_DHCLIENT (object));
		g_clear_object (&priv->dhcp_listener);
	}

	nm_clear_g_free (&priv->pid_file);
	nm_clear_g_free (&priv->conf_file);
	nm_clear_g_free (&priv->lease_file);

	G_OBJECT_CLASS (nm_dhcp_dhclient_parent_class)->dispose (object);
}

static void
nm_dhcp_dhclient_class_init (NMDhcpDhclientClass *dhclient_class)
{
	NMDhcpClientClass *client_class = NM_DHCP_CLIENT_CLASS (dhclient_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dhclient_class);

	object_class->dispose = dispose;

	client_class->ip4_start = ip4_start;
	client_class->ip6_start = ip6_start;
	client_class->stop = stop;
	client_class->get_duid = get_duid;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_dhclient = {
	.name = "dhclient",
	.get_type = nm_dhcp_dhclient_get_type,
	.get_path = nm_dhcp_dhclient_get_path,
};

#endif /* WITH_DHCLIENT */
