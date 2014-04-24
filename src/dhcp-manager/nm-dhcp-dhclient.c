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

#define _XOPEN_SOURCE
#include <time.h>
#undef _XOPEN_SOURCE

#include <glib.h>
#include <glib/gi18n.h>
#include <gio/gio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include <config.h>

#include "nm-dhcp-dhclient.h"
#include "nm-utils.h"
#include "nm-logging.h"
#include "nm-dhcp-dhclient-utils.h"
#include "nm-dhcp-manager.h"
#include "nm-posix-signals.h"

G_DEFINE_TYPE (NMDHCPDhclient, nm_dhcp_dhclient, NM_TYPE_DHCP_CLIENT)

#define NM_DHCP_DHCLIENT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DHCP_DHCLIENT, NMDHCPDhclientPrivate))

typedef struct {
	const char *path;
	char *conf_file;
	const char *def_leasefile;
	char *lease_file;
	char *pid_file;
} NMDHCPDhclientPrivate;

const char *
nm_dhcp_dhclient_get_path (const char *try_first)
{
	static const char *dhclient_paths[] = {
		"/sbin/dhclient",
		"/usr/sbin/dhclient",
		"/usr/pkg/sbin/dhclient",
		"/usr/local/sbin/dhclient",
		NULL
	};
	const char **path = dhclient_paths;

	if (strlen (try_first) && g_file_test (try_first, G_FILE_TEST_EXISTS))
		return try_first;

	while (*path != NULL) {
		if (g_file_test (*path, G_FILE_TEST_EXISTS))
			break;
		path++;
	}

	return *path;
}

/**
 * get_dhclient_leasefile():
 * @iface: the interface name of the device on which DHCP will be done
 * @uuid: the connection UUID to which the returned lease should belong
 * @ipv6: %TRUE for IPv6, %FALSE for IPv4
 * @out_preferred_path: on return, the "most preferred" leasefile path
 *
 * Returns the path of an existing leasefile (if any) for this interface and
 * connection UUID.  Also returns the "most preferred" leasefile path, which
 * may be different than any found leasefile.
 *
 * Returns: an existing leasefile, or %NULL if no matching leasefile could be found
 */
static char *
get_dhclient_leasefile (const char *iface,
                        const char *uuid,
                        gboolean ipv6,
                        char **out_preferred_path)
{
	char *path;

	/* /var/lib/NetworkManager is the preferred leasefile path */
	path = g_strdup_printf (NMSTATEDIR "/dhclient%s-%s-%s.lease",
	                        ipv6 ? "6" : "",
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
	                        ipv6 ? "6" : "", uuid, iface);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;

	/* Old Red Hat and Fedora location */
	g_free (path);
	path = g_strdup_printf (LOCALSTATEDIR "/lib/dhclient/dhclient%s-%s-%s.lease",
	                        ipv6 ? "6" : "", uuid, iface);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;

	/* Fail */
	g_free (path);
	return NULL;
}

GSList *
nm_dhcp_dhclient_get_lease_ip_configs (const char *iface,
                                       const char *uuid,
                                       gboolean ipv6)
{
	char *contents = NULL;
	char *leasefile;
	GSList *leases = NULL;

	leasefile = get_dhclient_leasefile (iface, uuid, FALSE, NULL);
	if (!leasefile)
		return NULL;

	if (   g_file_test (leasefile, G_FILE_TEST_EXISTS)
	    && g_file_get_contents (leasefile, &contents, NULL, NULL)
	    && contents
	    && contents[0])
		leases = nm_dhcp_dhclient_read_lease_ip_configs (iface, contents, ipv6, NULL);

	g_free (leasefile);
	g_free (contents);

	return leases;
}

static gboolean
merge_dhclient_config (const char *iface,
                       const char *conf_file,
                       gboolean is_ip6,
                       const char *dhcp_client_id,
                       GByteArray *anycast_addr,
                       const char *hostname,
                       const char *orig_path,
                       GError **error)
{
	char *orig = NULL, *new;
	gboolean success = FALSE;

	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (conf_file != NULL, FALSE);

	if (orig_path && g_file_test (orig_path, G_FILE_TEST_EXISTS)) {
		GError *read_error = NULL;

		if (!g_file_get_contents (orig_path, &orig, NULL, &read_error)) {
			nm_log_warn (LOGD_DHCP, "(%s): error reading dhclient%s configuration %s: %s",
			             iface, is_ip6 ? "6" : "", orig_path, read_error->message);
			g_error_free (read_error);
		}
	}

	new = nm_dhcp_dhclient_create_config (iface, is_ip6, dhcp_client_id, anycast_addr, hostname, orig_path, orig);
	g_assert (new);
	success = g_file_set_contents (conf_file, new, -1, error);
	g_free (new);
	g_free (orig);

	return success;
}

static char *
find_existing_config (const char *iface, const char *uuid, gboolean ipv6)
{
	char *path;

	/* NetworkManager-overridden configuration can be used to ship DHCP config
	 * with NetworkManager itself. It can be uuid-specific, device-specific
	 * or generic.
	 */
	if (uuid) {
		path = g_strdup_printf (NMCONFDIR "/dhclient%s-%s.conf", ipv6 ? "6" : "", uuid);
		nm_log_dbg (ipv6 ? LOGD_DHCP6 : LOGD_DHCP4, "(%s) looking for existing config %s", iface, path);
		if (g_file_test (path, G_FILE_TEST_EXISTS))
			return path;
		g_free (path);
	}

	path = g_strdup_printf (NMCONFDIR "/dhclient%s-%s.conf", ipv6 ? "6" : "", iface);
	nm_log_dbg (ipv6 ? LOGD_DHCP6 : LOGD_DHCP4, "(%s) looking for existing config %s", iface, path);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;
	g_free (path);

	path = g_strdup_printf (NMCONFDIR "/dhclient%s.conf", ipv6 ? "6" : "");
	nm_log_dbg (ipv6 ? LOGD_DHCP6 : LOGD_DHCP4, "(%s) looking for existing config %s", iface, path);
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
	path = g_strdup_printf (SYSCONFDIR "/dhcp/dhclient%s-%s.conf", ipv6 ? "6" : "", iface);
	nm_log_dbg (ipv6 ? LOGD_DHCP6 : LOGD_DHCP4, "(%s) looking for existing config %s", iface, path);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;
	g_free (path);

	path = g_strdup_printf (SYSCONFDIR "/dhclient%s-%s.conf", ipv6 ? "6" : "", iface);
	nm_log_dbg (ipv6 ? LOGD_DHCP6 : LOGD_DHCP4, "(%s) looking for existing config %s", iface, path);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;
	g_free (path);

	path = g_strdup_printf (SYSCONFDIR "/dhcp/dhclient%s.conf", ipv6 ? "6" : "");
	nm_log_dbg (ipv6 ? LOGD_DHCP6 : LOGD_DHCP4, "(%s) looking for existing config %s", iface, path);
	if (g_file_test (path, G_FILE_TEST_EXISTS))
		return path;
	g_free (path);

	path = g_strdup_printf (SYSCONFDIR "/dhclient%s.conf", ipv6 ? "6" : "");
	nm_log_dbg (ipv6 ? LOGD_DHCP6 : LOGD_DHCP4, "(%s) looking for existing config %s", iface, path);
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
create_dhclient_config (const char *iface,
                        gboolean is_ip6,
                        const char *uuid,
                        const char *dhcp_client_id,
                        GByteArray *dhcp_anycast_addr,
                        const char *hostname)
{
	char *orig = NULL, *new = NULL;
	GError *error = NULL;
	gboolean success = FALSE;

	g_return_val_if_fail (iface != NULL, NULL);

	new = g_strdup_printf (NMSTATEDIR "/dhclient%s-%s.conf", is_ip6 ? "6" : "", iface);
	nm_log_dbg (is_ip6 ? LOGD_DHCP6 : LOGD_DHCP4,
	            "(%s): creating composite dhclient config %s",
	            iface, new);

	orig = find_existing_config (iface, uuid, is_ip6);
	if (orig) {
		nm_log_dbg (is_ip6 ? LOGD_DHCP6 : LOGD_DHCP4,
		            "(%s): merging existing dhclient config %s",
		            iface, orig);
	} else {
		nm_log_dbg (is_ip6 ? LOGD_DHCP6 : LOGD_DHCP4,
		            "(%s): no existing dhclient configuration to merge",
		            iface);
	}

	error = NULL;
	success = merge_dhclient_config (iface, new, is_ip6, dhcp_client_id, dhcp_anycast_addr, hostname, orig, &error);
	if (!success) {
		nm_log_warn (LOGD_DHCP, "(%s): error creating dhclient%s configuration: %s",
		             iface, is_ip6 ? "6" : "", error->message);
		g_error_free (error);
	}

	g_free (orig);
	return new;
}


static void
dhclient_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	/* We are in the child process at this point */
	pid_t pid = getpid ();
	setpgid (pid, pid);

	/*
	 * We blocked signals in main(). We need to restore original signal
	 * mask for dhclient here so that it can receive signals.
	 */
	nm_unblock_posix_signals (NULL);
}

static GPid
dhclient_start (NMDHCPClient *client,
                const char *mode_opt,
                const GByteArray *duid,
                gboolean release)
{
	NMDHCPDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (client);
	GPtrArray *argv = NULL;
	GPid pid = -1;
	GError *error = NULL;
	const char *iface, *uuid, *system_bus_address;
	char *binary_name, *cmd_str, *pid_file = NULL, *system_bus_address_env = NULL;
	gboolean ipv6, success;
	guint log_domain;
	char *escaped, *preferred_leasefile_path = NULL;

	g_return_val_if_fail (priv->pid_file == NULL, -1);

	iface = nm_dhcp_client_get_iface (client);
	uuid = nm_dhcp_client_get_uuid (client);
	ipv6 = nm_dhcp_client_get_ipv6 (client);

	log_domain = ipv6 ? LOGD_DHCP6 : LOGD_DHCP4;

	if (!g_file_test (priv->path, G_FILE_TEST_EXISTS)) {
		nm_log_warn (log_domain, "%s does not exist.", priv->path);
		return -1;
	}

	pid_file = g_strdup_printf (LOCALSTATEDIR "/run/dhclient%s-%s.pid",
		                        ipv6 ? "6" : "",
		                        iface);

	/* Kill any existing dhclient from the pidfile */
	binary_name = g_path_get_basename (priv->path);
	nm_dhcp_client_stop_existing (pid_file, binary_name);
	g_free (binary_name);

	if (release) {
		/* release doesn't use the pidfile after killing an old client */
		g_free (pid_file);
		pid_file = NULL;
	}

	g_free (priv->lease_file);
	priv->lease_file = get_dhclient_leasefile (iface, uuid, ipv6, &preferred_leasefile_path);
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
			nm_log_warn (log_domain, "Failed to copy leasefile %s to %s: (%d) %s",
			             g_file_get_path (src), g_file_get_path (dst),
			             error->code, error->message);
			g_clear_error (&error);
		}
		g_object_unref (src);
		g_object_unref (dst);
	}
	g_free (preferred_leasefile_path);

	/* Save the DUID to the leasefile dhclient will actually use */
	if (ipv6) {
		escaped = nm_dhcp_dhclient_escape_duid (duid);
		success = nm_dhcp_dhclient_save_duid (priv->lease_file, escaped, &error);
		g_free (escaped);
		if (!success) {
			nm_log_warn (log_domain, "(%s): failed to save DUID to %s: (%d) %s.",
			             iface, priv->lease_file,
			             error ? error->code : -1,
			             error && error->message ? error->message : "(unknown)");
			return -1;
		}
	}

	argv = g_ptr_array_new ();
	g_ptr_array_add (argv, (gpointer) priv->path);

	g_ptr_array_add (argv, (gpointer) "-d");

	if (release)
		g_ptr_array_add (argv, (gpointer) "-r");

	if (ipv6) {
		g_ptr_array_add (argv, (gpointer) "-6");
		if (mode_opt)
			g_ptr_array_add (argv, (gpointer) mode_opt);
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
	nm_log_dbg (log_domain, "running: %s", cmd_str);
	g_free (cmd_str);

	if (!g_spawn_async (NULL, (char **) argv->pdata, NULL, G_SPAWN_DO_NOT_REAP_CHILD,
	                    &dhclient_child_setup, NULL, &pid, &error)) {
		nm_log_warn (log_domain, "dhclient failed to start: '%s'", error->message);
		g_error_free (error);
		pid = -1;
	} else {
		nm_log_info (log_domain, "dhclient started with pid %d", pid);
		priv->pid_file = pid_file;
	}

	g_ptr_array_free (argv, TRUE);
	g_free (system_bus_address_env);
	return pid;
}

static GPid
ip4_start (NMDHCPClient *client,
           const char *dhcp_client_id,
           GByteArray *dhcp_anycast_addr,
           const char *hostname)
{
	NMDHCPDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (client);
	const char *iface, *uuid;

	iface = nm_dhcp_client_get_iface (client);
	uuid = nm_dhcp_client_get_uuid (client);

	priv->conf_file = create_dhclient_config (iface, FALSE, uuid, dhcp_client_id, dhcp_anycast_addr, hostname);
	if (!priv->conf_file) {
		nm_log_warn (LOGD_DHCP4, "(%s): error creating dhclient configuration file.", iface);
		return -1;
	}

	return dhclient_start (client, NULL, NULL, FALSE);
}

static GPid
ip6_start (NMDHCPClient *client,
           GByteArray *dhcp_anycast_addr,
           const char *hostname,
           gboolean info_only,
           const GByteArray *duid)
{
	NMDHCPDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (client);
	const char *iface, *uuid;

	iface = nm_dhcp_client_get_iface (client);
	uuid = nm_dhcp_client_get_uuid (client);

	priv->conf_file = create_dhclient_config (iface, TRUE, uuid, NULL, dhcp_anycast_addr, hostname);
	if (!priv->conf_file) {
		nm_log_warn (LOGD_DHCP6, "(%s): error creating dhclient6 configuration file.", iface);
		return -1;
	}

	return dhclient_start (client, info_only ? "-S" : "-N", duid, FALSE);
}

static void
stop (NMDHCPClient *client, gboolean release, const GByteArray *duid)
{
	NMDHCPDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (client);

	/* Chain up to parent */
	NM_DHCP_CLIENT_CLASS (nm_dhcp_dhclient_parent_class)->stop (client, release, duid);

	if (priv->conf_file)
		if (remove (priv->conf_file) == -1)
			nm_log_dbg (LOGD_DHCP, "Could not remove dhcp config file \"%s\": %d (%s)", priv->conf_file, errno, g_strerror (errno));
	if (priv->pid_file) {
		if (remove (priv->pid_file) == -1)
			nm_log_dbg (LOGD_DHCP, "Could not remove dhcp pid file \"%s\": %d (%s)", priv->pid_file, errno, g_strerror (errno));
		g_free (priv->pid_file);
		priv->pid_file = NULL;
	}

	if (release) {
		GPid rpid;

		rpid = dhclient_start (client, NULL, duid, TRUE);
		if (rpid > 0) {
			/* Wait a few seconds for the release to happen */
			nm_dhcp_client_stop_pid (rpid, nm_dhcp_client_get_iface (client));
		}
	}
}

static GByteArray *
get_duid (NMDHCPClient *client)
{
	NMDHCPDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (client);
	GByteArray *duid = NULL;
	char *leasefile;
	GError *error = NULL;

	/* Look in interface-specific leasefile first for backwards compat */
	leasefile = get_dhclient_leasefile (nm_dhcp_client_get_iface (client),
	                                    nm_dhcp_client_get_uuid (client),
	                                    TRUE,
	                                    NULL);
	if (leasefile) {
		nm_log_dbg (LOGD_DHCP, "Looking for DHCPv6 DUID in '%s'.", leasefile);
		duid = nm_dhcp_dhclient_read_duid (leasefile, &error);

		if (error) {
			nm_log_warn (LOGD_DHCP, "Failed to read leasefile '%s': (%d) %s",
			             leasefile, error->code, error->message);
			g_clear_error (&error);
		}
		g_free (leasefile);
	}

	if (!duid && priv->def_leasefile) {
		/* Otherwise read the default machine-wide DUID */
		nm_log_dbg (LOGD_DHCP, "Looking for default DHCPv6 DUID in '%s'.", priv->def_leasefile);
		duid = nm_dhcp_dhclient_read_duid (priv->def_leasefile, &error);
		if (error) {
			nm_log_warn (LOGD_DHCP, "Failed to read leasefile '%s': (%d) %s",
			             priv->def_leasefile,
			             error ? error->code : -1,
			             error ? error->message : "(unknown)");
			g_clear_error (&error);
		}
	}

	/* return our DUID, otherwise let the parent class make a default DUID */
	return duid ? duid : NM_DHCP_CLIENT_CLASS (nm_dhcp_dhclient_parent_class)->get_duid (client);
}

/***************************************************/

static const char *def_leasefiles[] = {
	SYSCONFDIR "/dhclient6.leases",
	LOCALSTATEDIR "/lib/dhcp/dhclient6.leases",
	LOCALSTATEDIR "/lib/dhclient/dhclient6.leases",
	NULL
};

static void
nm_dhcp_dhclient_init (NMDHCPDhclient *self)
{
	NMDHCPDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (self);
	const char **iter = &def_leasefiles[0];

	priv->path = nm_dhcp_dhclient_get_path (DHCLIENT_PATH);

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
}

static void
dispose (GObject *object)
{
	NMDHCPDhclientPrivate *priv = NM_DHCP_DHCLIENT_GET_PRIVATE (object);

	g_free (priv->pid_file);
	g_free (priv->conf_file);
	g_free (priv->lease_file);

	G_OBJECT_CLASS (nm_dhcp_dhclient_parent_class)->dispose (object);
}

static void
nm_dhcp_dhclient_class_init (NMDHCPDhclientClass *dhclient_class)
{
	NMDHCPClientClass *client_class = NM_DHCP_CLIENT_CLASS (dhclient_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dhclient_class);

	g_type_class_add_private (dhclient_class, sizeof (NMDHCPDhclientPrivate));

	/* virtual methods */
	object_class->dispose = dispose;

	client_class->ip4_start = ip4_start;
	client_class->ip6_start = ip6_start;
	client_class->stop = stop;
	client_class->get_duid = get_duid;
}

