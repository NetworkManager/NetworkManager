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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "nm-utils/nm-dedup-multi.h"

#include "nm-utils.h"
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
	char *path;

	/* /var/lib/NetworkManager is the preferred leasefile path */
	path = g_strdup_printf (NMSTATEDIR "/dhclient%s-%s-%s.lease",
	                        _addr_family_to_path_part (addr_family),
	                        uuid,
	                        iface);
	if (out_preferred_path)
		*out_preferred_path = g_strdup (path);

	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;

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
		return path;

	/* Old Red Hat and Fedora location */
	g_free (path);
	path = g_strdup_printf (LOCALSTATEDIR "/lib/dhclient/dhclient%s-%s-%s.lease",
	                        _addr_family_to_path_part (addr_family), uuid, iface);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;

	/* Fail */
	g_free (path);
	return NULL;
}

static GSList *
nm_dhcp_dhclient_get_lease_ip_configs (NMDedupMultiIndex *multi_idx,
                                       int addr_family,
                                       const char *iface,
                                       int ifindex,
                                       const char *uuid,
                                       guint32 route_table,
                                       guint32 route_metric)
{
	gs_free char *contents = NULL;
	gs_free char *leasefile = NULL;

	leasefile = get_dhclient_leasefile (addr_family, iface, uuid, NULL);
	if (!leasefile)
		return NULL;

	if (   g_file_test (leasefile, G_FILE_TEST_EXISTS)
	    && g_file_get_contents (leasefile, &contents, NULL, NULL)
	    && contents
	    && contents[0]) {
		return nm_dhcp_dhclient_read_lease_ip_configs (multi_idx, addr_family, iface, ifindex,
		                                               route_table, route_metric, contents, NULL);
	}
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
	char *orig = NULL, *new;
	gboolean success = FALSE;

	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (conf_file != NULL, FALSE);

	if (orig_path && g_file_test (orig_path, G_FILE_TEST_EXISTS)) {
		GError *read_error = NULL;

		if (!g_file_get_contents (orig_path, &orig, NULL, &read_error)) {
			_LOGW ("error reading dhclient configuration %s: %s",
			       orig_path, read_error->message);
			g_error_free (read_error);
		}
	}

	new = nm_dhcp_dhclient_create_config (iface, addr_family, client_id, anycast_addr, hostname, timeout,
	                                      use_fqdn, orig_path, orig, out_new_client_id);
	g_assert (new);
	success = g_file_set_contents (conf_file, new, -1, error);
	g_free (new);
	g_free (orig);

	return success;
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
	char *orig = NULL, *new = NULL;
	GError *error = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (iface != NULL, NULL);

	new = g_strdup_printf (NMSTATEDIR "/dhclient%s-%s.conf", _addr_family_to_path_part (addr_family), iface);
	_LOGD ("creating composite dhclient config %s", new);

	orig = find_existing_config (self, addr_family, iface, uuid);
	if (orig)
		_LOGD ("merging existing dhclient config %s", orig);
	else
		_LOGD ("no existing dhclient configuration to merge");

	error = NULL;
	success = merge_dhclient_config (self, addr_family, iface, new, client_id, dhcp_anycast_addr,
	                                 hostname, timeout, use_fqdn, orig, out_new_client_id, &error);
	if (!success) {
		_LOGW ("error creating dhclient configuration: %s", error->message);
		g_error_free (error);
	}

	g_free (orig);
	return new;
}


static gboolean
dhclient_start (NMDhcpClient *client,
                const char *mode_opt,
                const GByteArray *duid,
                gboolean release,
                pid_t *out_pid,
                int prefixes)
{
	NMDhcpDhclient *self = NM_DHCP_DHCLIENT (client);
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);
	GPtrArray *argv = NULL;
	pid_t pid;
	GError *error = NULL;
	const char *iface, *uuid, *system_bus_address, *dhclient_path = NULL;
	char *binary_name, *cmd_str, *pid_file = NULL, *system_bus_address_env = NULL;
	int addr_family;
	gboolean success;
	char *escaped, *preferred_leasefile_path = NULL;

	g_return_val_if_fail (priv->pid_file == NULL, FALSE);

	iface = nm_dhcp_client_get_iface (client);
	uuid = nm_dhcp_client_get_uuid (client);
	addr_family = nm_dhcp_client_get_addr_family (client);

	dhclient_path = nm_dhcp_dhclient_get_path ();
	if (!dhclient_path) {
		_LOGW ("dhclient could not be found");
		return FALSE;
	}

	pid_file = g_strdup_printf (RUNSTATEDIR "/dhclient%s-%s.pid",
	                            _addr_family_to_path_part (addr_family),
	                            iface);

	/* Kill any existing dhclient from the pidfile */
	binary_name = g_path_get_basename (dhclient_path);
	nm_dhcp_client_stop_existing (pid_file, binary_name);
	g_free (binary_name);

	if (release) {
		/* release doesn't use the pidfile after killing an old client */
		g_free (pid_file);
		pid_file = NULL;
	}

	g_free (priv->lease_file);
	priv->lease_file = get_dhclient_leasefile (addr_family, iface, uuid, &preferred_leasefile_path);
	if (!priv->lease_file) {
		/* No existing leasefile, dhclient will create one at the preferred path */
		priv->lease_file = g_strdup (preferred_leasefile_path);
	} else if (g_strcmp0 (priv->lease_file, preferred_leasefile_path) != 0) {
		GFile *src = g_file_new_for_path (priv->lease_file);
		GFile *dst = g_file_new_for_path (preferred_leasefile_path);

		/* Try to copy the existing leasefile to the preferred location */
		if (g_file_copy (src, dst, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL, &error)) {
			/* Success; use the preferred leasefile path */
			g_free (priv->lease_file);
			priv->lease_file = g_strdup (g_file_get_path (dst));
		} else {
			/* Failure; just use the existing leasefile */
			_LOGW ("failed to copy leasefile %s to %s: %s",
			       g_file_get_path (src), g_file_get_path (dst),
			       error->message);
			g_clear_error (&error);
		}
		g_object_unref (src);
		g_object_unref (dst);
	}
	g_free (preferred_leasefile_path);

	/* Save the DUID to the leasefile dhclient will actually use */
	if (addr_family == AF_INET6) {
		escaped = nm_dhcp_dhclient_escape_duid (duid);
		success = nm_dhcp_dhclient_save_duid (priv->lease_file, escaped, &error);
		g_free (escaped);
		if (!success) {
			_LOGW ("failed to save DUID to %s: %s", priv->lease_file, error->message);
			g_free (pid_file);
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
	g_ptr_array_add (argv, (gpointer) "-sf");	/* Set script file */
	g_ptr_array_add (argv, (gpointer) nm_dhcp_helper_path);

	if (pid_file) {
		g_ptr_array_add (argv, (gpointer) "-pf");	/* Set pid file */
		g_ptr_array_add (argv, (gpointer) pid_file);
	}

	g_ptr_array_add (argv, (gpointer) "-lf");	/* Set lease file */
	g_ptr_array_add (argv, (gpointer) priv->lease_file);

	if (priv->conf_file) {
		g_ptr_array_add (argv, (gpointer) "-cf");	/* Set interface config file */
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

	cmd_str = g_strjoinv (" ", (gchar **) argv->pdata);
	_LOGD ("running: %s", cmd_str);
	g_free (cmd_str);

	if (g_spawn_async (NULL, (char **) argv->pdata, NULL,
	                   G_SPAWN_DO_NOT_REAP_CHILD | G_SPAWN_STDOUT_TO_DEV_NULL | G_SPAWN_STDERR_TO_DEV_NULL,
	                   nm_utils_setpgid, NULL, &pid, &error)) {
		g_assert (pid > 0);
		_LOGI ("dhclient started with pid %d", pid);
		if (release == FALSE)
			nm_dhcp_client_watch_child (client, pid);
		priv->pid_file = pid_file;
	} else {
		_LOGW ("dhclient failed to start: '%s'", error->message);
		g_error_free (error);
		g_free (pid_file);
	}

	if (out_pid)
		*out_pid = pid;

	g_ptr_array_free (argv, TRUE);
	g_free (system_bus_address_env);
	return pid > 0 ? TRUE : FALSE;
}

static gboolean
ip4_start (NMDhcpClient *client, const char *dhcp_anycast_addr, const char *last_ip4_address)
{
	NMDhcpDhclient *self = NM_DHCP_DHCLIENT (client);
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);
	GBytes *client_id;
	gs_unref_bytes GBytes *new_client_id = NULL;
	const char *iface, *uuid, *hostname;
	guint32 timeout;
	gboolean success = FALSE;
	gboolean use_fqdn;

	iface = nm_dhcp_client_get_iface (client);
	uuid = nm_dhcp_client_get_uuid (client);
	client_id = nm_dhcp_client_get_client_id (client);
	hostname = nm_dhcp_client_get_hostname (client);
	timeout = nm_dhcp_client_get_timeout (client);
	use_fqdn = nm_dhcp_client_get_use_fqdn (client);

	priv->conf_file = create_dhclient_config (self, AF_INET, iface, uuid, client_id, dhcp_anycast_addr,
	                                          hostname, timeout, use_fqdn, &new_client_id);
	if (priv->conf_file) {
		if (new_client_id)
			nm_dhcp_client_set_client_id (client, new_client_id);
		success = dhclient_start (client, NULL, NULL, FALSE, NULL, 0);
	} else
		_LOGW ("error creating dhclient configuration file");

	return success;
}

static gboolean
ip6_start (NMDhcpClient *client,
           const char *dhcp_anycast_addr,
           const struct in6_addr *ll_addr,
           gboolean info_only,
           NMSettingIP6ConfigPrivacy privacy,
           const GByteArray *duid,
           guint needed_prefixes)
{
	NMDhcpDhclient *self = NM_DHCP_DHCLIENT (client);
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);
	const char *iface, *uuid, *hostname;
	guint32 timeout;

	iface = nm_dhcp_client_get_iface (client);
	uuid = nm_dhcp_client_get_uuid (client);
	hostname = nm_dhcp_client_get_hostname (client);
	timeout = nm_dhcp_client_get_timeout (client);

	priv->conf_file = create_dhclient_config (self, AF_INET6, iface, uuid, NULL, dhcp_anycast_addr,
	                                          hostname, timeout, TRUE, NULL);
	if (!priv->conf_file) {
		_LOGW ("error creating dhclient configuration file");
		return FALSE;
	}

	return dhclient_start (client, info_only ? "-S" : "-N", duid, FALSE, NULL, needed_prefixes);
}

static void
stop (NMDhcpClient *client, gboolean release, const GByteArray *duid)
{
	NMDhcpDhclient *self = NM_DHCP_DHCLIENT (client);
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);

	/* Chain up to parent */
	NM_DHCP_CLIENT_CLASS (nm_dhcp_dhclient_parent_class)->stop (client, release, duid);

	if (priv->conf_file)
		if (remove (priv->conf_file) == -1)
			_LOGD ("could not remove dhcp config file \"%s\": %d (%s)", priv->conf_file, errno, g_strerror (errno));
	if (priv->pid_file) {
		if (remove (priv->pid_file) == -1)
			_LOGD ("could not remove dhcp pid file \"%s\": %d (%s)", priv->pid_file, errno, g_strerror (errno));
		g_free (priv->pid_file);
		priv->pid_file = NULL;
	}

	if (release) {
		pid_t rpid = -1;

		if (dhclient_start (client, NULL, duid, TRUE, &rpid, 0)) {
			/* Wait a few seconds for the release to happen */
			nm_dhcp_client_stop_pid (rpid, nm_dhcp_client_get_iface (client));
		}
	}
}

static void
state_changed (NMDhcpClient *client,
               NMDhcpState state,
               GObject *ip_config,
               GHashTable *options)
{
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE ((NMDhcpDhclient *) client);
	gs_unref_bytes GBytes *client_id = NULL;

	if (nm_dhcp_client_get_client_id (client))
		return;
	if (state != NM_DHCP_STATE_BOUND)
		return;

	client_id = nm_dhcp_dhclient_get_client_id_from_config_file (priv->conf_file);
	nm_dhcp_client_set_client_id (client, client_id);
}

static GByteArray *
get_duid (NMDhcpClient *client)
{
	NMDhcpDhclient *self = NM_DHCP_DHCLIENT (client);
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);
	GByteArray *duid = NULL;
	char *leasefile;
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
		g_free (leasefile);
	}

	if (!duid && priv->def_leasefile) {
		/* Otherwise read the default machine-wide DUID */
		_LOGD ("looking for default DUID in '%s'", priv->def_leasefile);
		duid = nm_dhcp_dhclient_read_duid (priv->def_leasefile, &error);
		if (error) {
			_LOGW ("failed to read leasefile '%s': %s",
			        priv->def_leasefile,
			        error->message);
			g_clear_error (&error);
		}
	}

	/* return our DUID, otherwise let the parent class make a default DUID */
	return duid ? duid : NM_DHCP_CLIENT_CLASS (nm_dhcp_dhclient_parent_class)->get_duid (client);
}

/*****************************************************************************/

static const char *def_leasefiles[] = {
	SYSCONFDIR "/dhclient6.leases",
	LOCALSTATEDIR "/lib/dhcp/dhclient6.leases",
	LOCALSTATEDIR "/lib/dhclient/dhclient6.leases",
	NULL
};

static void
nm_dhcp_dhclient_init (NMDhcpDhclient *self)
{
	NMDhcpDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);
	const char **iter = &def_leasefiles[0];

	while (iter && *iter) {
		if (g_file_test (*iter, G_FILE_TEST_EXISTS)) {
			priv->def_leasefile = *iter;
			break;
		}
		iter++;
	}

	/* Fallback option */
	if (!priv->def_leasefile)
		priv->def_leasefile = SYSCONFDIR "/dhclient6.leases";

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
	client_class->state_changed = state_changed;
}

const NMDhcpClientFactory _nm_dhcp_client_factory_dhclient = {
	.name = "dhclient",
	.get_type = nm_dhcp_dhclient_get_type,
	.get_path = nm_dhcp_dhclient_get_path,
	.get_lease_ip_configs = nm_dhcp_dhclient_get_lease_ip_configs,
};

#endif /* WITH_DHCLIENT */
