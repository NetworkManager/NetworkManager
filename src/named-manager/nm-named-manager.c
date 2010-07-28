/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2004 - 2005 Colin Walters <walters@redhat.com>
 * Copyright (C) 2004 - 2010 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 *   and others
 */

#include "config.h"

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/wait.h> 
#include <unistd.h>
#include <glib.h>

#include <glib/gi18n.h>

#include "nm-named-manager.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-logging.h"
#include "nm-system.h"
#include "NetworkManagerUtils.h"

#ifdef HAVE_SELINUX
#include <selinux/selinux.h>
#endif

#ifndef RESOLV_CONF
#define RESOLV_CONF "/etc/resolv.conf"
#endif

#define ADDR_BUF_LEN 50

G_DEFINE_TYPE(NMNamedManager, nm_named_manager, G_TYPE_OBJECT)

#define NM_NAMED_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                         NM_TYPE_NAMED_MANAGER, \
                                         NMNamedManagerPrivate))


struct NMNamedManagerPrivate {
	NMIP4Config *ip4_vpn_config;
	NMIP4Config *ip4_device_config;
	NMIP6Config *ip6_vpn_config;
	NMIP6Config *ip6_device_config;
	GSList *configs;
	char *hostname;

	/* This is a hack because SUSE's netconfig always wants changes
	 * associated with a network interface, but sometimes a change isn't
	 * associated with a network interface (like hostnames).
	 */
	char *last_iface;
};


NMNamedManager *
nm_named_manager_get (void)
{
	static NMNamedManager * singleton = NULL;

	if (!singleton)
		singleton = NM_NAMED_MANAGER (g_object_new (NM_TYPE_NAMED_MANAGER, NULL));
	else
		g_object_ref (singleton);

	g_assert (singleton);
	return singleton;
}


GQuark
nm_named_manager_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm_named_manager_error");

	return quark;
}

typedef struct {
	GPtrArray *nameservers;
	const char *domain;
	GPtrArray *searches;
	const char *nis_domain;
	GPtrArray *nis_servers;
} NMResolvConfData;

static void
add_string_item (GPtrArray *array, const char *str)
{
	int i;

	g_return_if_fail (array != NULL);
	g_return_if_fail (str != NULL);

	/* Check for dupes before adding */
	for (i = 0; i < array->len; i++) {
		const char *candidate = g_ptr_array_index (array, i);

		if (candidate && !strcmp (candidate, str))
			return;
	}

	/* No dupes, add the new item */
	g_ptr_array_add (array, g_strdup (str));
}

static void
merge_one_ip4_config (NMResolvConfData *rc, NMIP4Config *src)
{
	guint32 num, i;

	num = nm_ip4_config_get_num_nameservers (src);
	for (i = 0; i < num; i++) {
		struct in_addr addr;
		char buf[INET_ADDRSTRLEN];

		addr.s_addr = nm_ip4_config_get_nameserver (src, i);
		if (inet_ntop (AF_INET, &addr, buf, INET_ADDRSTRLEN) > 0)
			add_string_item (rc->nameservers, buf);
	}

	num = nm_ip4_config_get_num_domains (src);
	for (i = 0; i < num; i++) {
		const char *domain;

		domain = nm_ip4_config_get_domain (src, i);
		if (!rc->domain)
			rc->domain = domain;
		add_string_item (rc->searches, domain);
	}

	num = nm_ip4_config_get_num_searches (src);
	for (i = 0; i < num; i++)
		add_string_item (rc->searches, nm_ip4_config_get_search (src, i));

	/* NIS stuff */
	num = nm_ip4_config_get_num_nis_servers (src);
	for (i = 0; i < num; i++) {
		struct in_addr addr;
		char buf[INET_ADDRSTRLEN];

		addr.s_addr = nm_ip4_config_get_nis_server (src, i);
		if (inet_ntop (AF_INET, &addr, buf, INET_ADDRSTRLEN) > 0)
			add_string_item (rc->nis_servers, buf);
	}

	if (nm_ip4_config_get_nis_domain (src)) {
		/* FIXME: handle multiple domains */
		if (!rc->nis_domain)
			rc->nis_domain = nm_ip4_config_get_nis_domain (src);
	}
}

static void
merge_one_ip6_config (NMResolvConfData *rc, NMIP6Config *src)
{
	guint32 num, i;

	num = nm_ip6_config_get_num_nameservers (src);
	for (i = 0; i < num; i++) {
		const struct in6_addr *addr;
		char buf[INET6_ADDRSTRLEN];

		addr = nm_ip6_config_get_nameserver (src, i);

		/* inet_ntop is probably supposed to do this for us, but it doesn't */
		if (IN6_IS_ADDR_V4MAPPED (addr)) {
			if (inet_ntop (AF_INET, &(addr->s6_addr32[3]), buf, INET_ADDRSTRLEN) > 0)
				add_string_item (rc->nameservers, buf);
		} else {
			if (inet_ntop (AF_INET6, addr, buf, INET6_ADDRSTRLEN) > 0)
				add_string_item (rc->nameservers, buf);
		}
	}

	num = nm_ip6_config_get_num_domains (src);
	for (i = 0; i < num; i++) {
		const char *domain;

		domain = nm_ip6_config_get_domain (src, i);
		if (!rc->domain)
			rc->domain = domain;
		add_string_item (rc->searches, domain);
	}

	num = nm_ip6_config_get_num_searches (src);
	for (i = 0; i < num; i++)
		add_string_item (rc->searches, nm_ip6_config_get_search (src, i));
}


#if defined(TARGET_SUSE)
/**********************************/
/* SUSE */

static void
netconfig_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	pid_t pid = getpid ();
	setpgid (pid, pid);
}

static GPid
run_netconfig (GError **error, gint *stdin_fd)
{
	char *argv[5];
	char *tmp;
	GPid pid = -1;

	argv[0] = "/sbin/netconfig";
	argv[1] = "modify";
	argv[2] = "--service";
	argv[3] = "NetworkManager";
	argv[4] = NULL;

	tmp = g_strjoinv (" ", argv);
	nm_log_dbg (LOGD_DNS, "spawning '%s'", tmp);
	g_free (tmp);

	if (!g_spawn_async_with_pipes (NULL, argv, NULL, 0, netconfig_child_setup,
	                               NULL, &pid, stdin_fd, NULL, NULL, error))
		return -1;

	return pid;
}

static void
write_to_netconfig (gint fd, const char *key, const char *value)
{
	char *str;
	int x;

	str = g_strdup_printf ("%s='%s'\n", key, value);
	nm_log_dbg (LOGD_DNS, "writing to netconfig: %s", str);
	x = write (fd, str, strlen (str));
	g_free (str);
}

static gboolean
dispatch_netconfig (const char *domain,
                    char **searches,
                    char **nameservers,
                    const char *nis_domain,
                    char **nis_servers,
                    const char *iface,
                    GError **error)
{
	char *str;
	GPid pid;
	gint fd;
	int ret;

	pid = run_netconfig (error, &fd);
	if (pid < 0)
		return FALSE;

	// FIXME: this is wrong. We are not writing out the iface-specific
	// resolv.conf data, we are writing out an already-fully-merged
	// resolv.conf. Assuming netconfig works in the obvious way, then
	// there are various failure modes, such as, eg, bringing up a VPN on
	// eth0, then bringing up wlan0, then bringing down the VPN. Because
	// NMNamedManager would have claimed that the VPN DNS server was also
	// part of the wlan0 config, it will remain in resolv.conf after the
	// VPN goes down, even though it is presumably no longer reachable
	// at that point.
	write_to_netconfig (fd, "INTERFACE", iface);

	if (searches) {
		str = g_strjoinv (" ", searches);

		if (domain) {
			char *tmp;

			tmp = g_strconcat (domain, " ", str, NULL);
			g_free (str);
			str = tmp;
		}

		write_to_netconfig (fd, "DNSSEARCH", str);
		g_free (str);
	}

	if (nameservers) {
		str = g_strjoinv (" ", nameservers);
		write_to_netconfig (fd, "DNSSERVERS", str);
		g_free (str);
	}

	if (nis_domain)
		write_to_netconfig (fd, "NISDOMAIN", nis_domain);

	if (nis_servers) {
		str = g_strjoinv (" ", nis_servers);
		write_to_netconfig (fd, "NISSERVERS", str);
		g_free (str);
	}

	close (fd);

	/* Wait until the process exits */

 again:

	ret = waitpid (pid, NULL, 0);
	if (ret < 0 && errno == EINTR)
		goto again;
	else if (ret < 0 && errno == ECHILD) {
		/* When the netconfig exist, the errno is ECHILD, it should return TRUE */
		return TRUE;
	}

	return ret > 0;
}
#endif


static gboolean
write_resolv_conf (FILE *f, const char *domain,
                   char **searches,
                   char **nameservers,
                   GError **error)
{
	char *domain_str = NULL;
	char *searches_str = NULL;
	char *nameservers_str = NULL;
	int i;
	gboolean retval = FALSE;

	if (fprintf (f, "%s","# Generated by NetworkManager\n") < 0) {
		g_set_error (error,
				   NM_NAMED_MANAGER_ERROR,
				   NM_NAMED_MANAGER_ERROR_SYSTEM,
				   "Could not write " RESOLV_CONF ": %s\n",
				   g_strerror (errno));
		return FALSE;
	}

	if (domain)
		domain_str = g_strconcat ("domain ", domain, "\n", NULL);

	if (searches) {
		char *tmp_str;

		tmp_str = g_strjoinv (" ", searches);
		searches_str = g_strconcat ("search ", tmp_str, "\n", NULL);
		g_free (tmp_str);
	}

	if (nameservers) {
		GString *str;
		int num;

		str = g_string_new ("");
		num = g_strv_length (nameservers);

		for (i = 0; i < num; i++) {
			if (i == 3) {
				g_string_append (str, "# ");
				g_string_append (str, _("NOTE: the libc resolver may not support more than 3 nameservers."));
				g_string_append (str, "\n# ");
				g_string_append (str, _("The nameservers listed below may not be recognized."));
				g_string_append_c (str, '\n');
			}

			g_string_append (str, "nameserver ");
			g_string_append (str, nameservers[i]);
			g_string_append_c (str, '\n');
		}

		nameservers_str = g_string_free (str, FALSE);
	}

	if (fprintf (f, "%s%s%s",
	             domain_str ? domain_str : "",
	             searches_str ? searches_str : "",
	             nameservers_str ? nameservers_str : "") != -1)
		retval = TRUE;

	g_free (domain_str);
	g_free (searches_str);
	g_free (nameservers_str);

	return retval;
}

#ifdef RESOLVCONF_PATH
static gboolean
dispatch_resolvconf (const char *domain,
                     char **searches,
                     char **nameservers,
                     const char *iface,
                     GError **error)
{
	char *cmd;
	FILE *f;
	gboolean retval = FALSE;

	if (! g_file_test (RESOLVCONF_PATH, G_FILE_TEST_IS_EXECUTABLE))
		return FALSE;

	if (domain || searches || nameservers) {
		cmd = g_strconcat (RESOLVCONF_PATH, " -a ", "NetworkManager", NULL);
		nm_log_info (LOGD_DNS, "(%s): writing resolv.conf to %s", iface, RESOLVCONF_PATH);
		if ((f = popen (cmd, "w")) == NULL)
			g_set_error (error,
				     NM_NAMED_MANAGER_ERROR,
				     NM_NAMED_MANAGER_ERROR_SYSTEM,
				     "Could not write to %s: %s\n",
				     RESOLVCONF_PATH,
				     g_strerror (errno));
		else {
			retval = write_resolv_conf (f, domain, searches, nameservers, error);
			retval &= (pclose (f) == 0);
		}
	} else {
		cmd = g_strconcat (RESOLVCONF_PATH, " -d ", "NetworkManager", NULL);
		nm_log_info (LOGD_DNS, "(%s): removing resolv.conf from %s", iface, RESOLVCONF_PATH);
		if (nm_spawn_process (cmd) == 0)
			retval = TRUE;
	}

	g_free (cmd);

	return retval;
}
#endif

static gboolean
update_resolv_conf (const char *domain,
                    char **searches,
                    char **nameservers,
                    const char *iface,
                    GError **error)
{
	char *tmp_resolv_conf;
	char *tmp_resolv_conf_realpath;
	char *resolv_conf_realpath;
	FILE *f;
	int do_rename = 1;
	int old_errno = 0;

	g_return_val_if_fail (error != NULL, FALSE);

	/* Find the real path of resolv.conf; it could be a symlink to something */
	resolv_conf_realpath = realpath (RESOLV_CONF, NULL);
	if (!resolv_conf_realpath)
		resolv_conf_realpath = strdup (RESOLV_CONF);

	/* Build up the real path for the temp resolv.conf that we're about to
	 * write out.
	 */
	tmp_resolv_conf = g_strdup_printf ("%s.tmp", resolv_conf_realpath);
	tmp_resolv_conf_realpath = realpath (tmp_resolv_conf, NULL);
	if (!tmp_resolv_conf_realpath)
		tmp_resolv_conf_realpath = strdup (tmp_resolv_conf);
	g_free (tmp_resolv_conf);
	tmp_resolv_conf = NULL;

	if ((f = fopen (tmp_resolv_conf_realpath, "w")) == NULL) {
		do_rename = 0;
		old_errno = errno;
		if ((f = fopen (RESOLV_CONF, "w")) == NULL) {
			g_set_error (error,
			             NM_NAMED_MANAGER_ERROR,
			             NM_NAMED_MANAGER_ERROR_SYSTEM,
			             "Could not open %s: %s\nCould not open %s: %s\n",
			             tmp_resolv_conf_realpath,
			             g_strerror (old_errno),
			             RESOLV_CONF,
			             g_strerror (errno));
			goto out;
		}
		/* Update tmp_resolv_conf_realpath so the error message on fclose()
		 * failure will be correct.
		 */
		strcpy (tmp_resolv_conf_realpath, RESOLV_CONF);
	}

	write_resolv_conf (f, domain, searches, nameservers, error);

	if (fclose (f) < 0) {
		if (*error == NULL) {
			/* only set an error here if write_resolv_conf() was successful,
			 * since its error is more important.
			 */
			g_set_error (error,
			             NM_NAMED_MANAGER_ERROR,
			             NM_NAMED_MANAGER_ERROR_SYSTEM,
			             "Could not close %s: %s\n",
			             tmp_resolv_conf_realpath,
			             g_strerror (errno));
		}
	}

	/* Don't rename the tempfile over top of the existing resolv.conf if there
	 * was an error writing it out.
	 */
	if (*error == NULL && do_rename) {
		if (rename (tmp_resolv_conf_realpath, resolv_conf_realpath) < 0) {
			g_set_error (error,
			             NM_NAMED_MANAGER_ERROR,
			             NM_NAMED_MANAGER_ERROR_SYSTEM,
			             "Could not replace " RESOLV_CONF ": %s\n",
			             g_strerror (errno));
		}
	}

out:
	free (tmp_resolv_conf_realpath);
	free (resolv_conf_realpath);
	return *error ? FALSE : TRUE;
}

static gboolean
rewrite_resolv_conf (NMNamedManager *mgr, const char *iface, GError **error)
{
	NMNamedManagerPrivate *priv;
	NMResolvConfData rc;
	GSList *iter;
	const char *domain = NULL;
	const char *nis_domain = NULL;
	char **searches = NULL;
	char **nameservers = NULL;
	char **nis_servers = NULL;
	int num, i, len;
	gboolean success = FALSE;

	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	priv = NM_NAMED_MANAGER_GET_PRIVATE (mgr);

	if (iface) {
		g_free (priv->last_iface);
		priv->last_iface = g_strdup (iface);
	}

	rc.nameservers = g_ptr_array_new ();
	rc.domain = NULL;
	rc.searches = g_ptr_array_new ();
	rc.nis_servers = g_ptr_array_new ();

	if (priv->ip4_vpn_config)
		merge_one_ip4_config (&rc, priv->ip4_vpn_config);
	if (priv->ip4_device_config)
		merge_one_ip4_config (&rc, priv->ip4_device_config);

	if (priv->ip6_vpn_config)
		merge_one_ip6_config (&rc, priv->ip6_vpn_config);
	if (priv->ip6_device_config)
		merge_one_ip6_config (&rc, priv->ip6_device_config);

	for (iter = priv->configs; iter; iter = g_slist_next (iter)) {
		if (   (iter->data == priv->ip4_vpn_config)
		    || (iter->data == priv->ip4_device_config)
		    || (iter->data == priv->ip6_vpn_config)
		    || (iter->data == priv->ip6_device_config))
			continue;

		if (NM_IS_IP4_CONFIG (iter->data)) {
			NMIP4Config *config = NM_IP4_CONFIG (iter->data);

			merge_one_ip4_config (&rc, config);
		} else if (NM_IS_IP6_CONFIG (iter->data)) {
			NMIP6Config *config = NM_IP6_CONFIG (iter->data);

			merge_one_ip6_config (&rc, config);
		} else
			g_assert_not_reached ();
	}

	/* Add the current domain name (from the hostname) to the searches list;
	 * see rh #600407.  The bug report is that when the hostname is set to
	 * something like 'dcbw.foobar.com' (ie an FQDN) that pinging 'dcbw' doesn't
	 * work because the resolver doesn't have anything to append to 'dcbw' when
	 * looking it up.
	 */
	if (priv->hostname) {
		const char *hostsearch = strchr (priv->hostname, '.');

		/* +1 to get rid of the dot */
		if (hostsearch && strlen (hostsearch + 1))
			add_string_item (rc.searches, hostsearch + 1);
	}

	domain = rc.domain;

	/* Per 'man resolv.conf', the search list is limited to 6 domains
	 * totalling 256 characters.
	 */
	num = MIN (rc.searches->len, 6);
	for (i = 0, len = 0; i < num; i++) {
		len += strlen (rc.searches->pdata[i]) + 1; /* +1 for spaces */
		if (len > 256)
			break;
	}
	g_ptr_array_set_size (rc.searches, i);
	if (rc.searches->len) {
		g_ptr_array_add (rc.searches, NULL);
		searches = (char **) g_ptr_array_free (rc.searches, FALSE);
	} else
		g_ptr_array_free (rc.searches, TRUE);

	if (rc.nameservers->len) {
		g_ptr_array_add (rc.nameservers, NULL);
		nameservers = (char **) g_ptr_array_free (rc.nameservers, FALSE);
	} else
		g_ptr_array_free (rc.nameservers, TRUE);

	if (rc.nis_servers->len) {
		g_ptr_array_add (rc.nis_servers, NULL);
		nis_servers = (char **) g_ptr_array_free (rc.nis_servers, FALSE);
	} else
		g_ptr_array_free (rc.nis_servers, TRUE);

	nis_domain = rc.nis_domain;

#ifdef RESOLVCONF_PATH
	success = dispatch_resolvconf (domain, searches, nameservers, iface, error);
#endif

#ifdef TARGET_SUSE
	if (success == FALSE) {
		success = dispatch_netconfig (domain, searches, nameservers,
		                              nis_domain, nis_servers,
		                              iface, error);
	}
#endif

	if (success == FALSE)
		success = update_resolv_conf (domain, searches, nameservers, iface, error);

	if (success)
		nm_system_update_dns ();

	if (searches)
		g_strfreev (searches);
	if (nameservers)
		g_strfreev (nameservers);
	if (nis_servers)
		g_strfreev (nis_servers);

	return success;
}

gboolean
nm_named_manager_add_ip4_config (NMNamedManager *mgr,
								 const char *iface,
								 NMIP4Config *config,
								 NMNamedIPConfigType cfg_type)
{
	NMNamedManagerPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	priv = NM_NAMED_MANAGER_GET_PRIVATE (mgr);

	switch (cfg_type) {
	case NM_NAMED_IP_CONFIG_TYPE_VPN:
		priv->ip4_vpn_config = config;
		break;
	case NM_NAMED_IP_CONFIG_TYPE_BEST_DEVICE:
		priv->ip4_device_config = config;
		break;
	default:
		break;
	}

	/* Don't allow the same zone added twice */
	if (!g_slist_find (priv->configs, config))
		priv->configs = g_slist_append (priv->configs, g_object_ref (config));

	if (!rewrite_resolv_conf (mgr, iface, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: '%s'", error ? error->message : "(none)");
		g_error_free (error);
	}

	return TRUE;
}

gboolean
nm_named_manager_remove_ip4_config (NMNamedManager *mgr,
									const char *iface,
									NMIP4Config *config)
{
	NMNamedManagerPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	priv = NM_NAMED_MANAGER_GET_PRIVATE (mgr);

	/* Can't remove it if it wasn't in the list to begin with */
	if (!g_slist_find (priv->configs, config))
		return FALSE;

	priv->configs = g_slist_remove (priv->configs, config);

	if (config == priv->ip4_vpn_config)
		priv->ip4_vpn_config = NULL;
	if (config == priv->ip4_device_config)
		priv->ip4_device_config = NULL;

	g_object_unref (config);

	if (!rewrite_resolv_conf (mgr, iface, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: '%s'", error ? error->message : "(none)");
		if (error)
			g_error_free (error);
	}

	return TRUE;
}

gboolean
nm_named_manager_add_ip6_config (NMNamedManager *mgr,
								 const char *iface,
								 NMIP6Config *config,
								 NMNamedIPConfigType cfg_type)
{
	NMNamedManagerPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	priv = NM_NAMED_MANAGER_GET_PRIVATE (mgr);

	switch (cfg_type) {
	case NM_NAMED_IP_CONFIG_TYPE_VPN:
		/* FIXME: not quite yet... */
		g_return_val_if_fail (cfg_type != NM_NAMED_IP_CONFIG_TYPE_VPN, FALSE);
		priv->ip6_vpn_config = config;
		break;
	case NM_NAMED_IP_CONFIG_TYPE_BEST_DEVICE:
		priv->ip6_device_config = config;
		break;
	default:
		break;
	}

	/* Don't allow the same zone added twice */
	if (!g_slist_find (priv->configs, config))
		priv->configs = g_slist_append (priv->configs, g_object_ref (config));

	if (!rewrite_resolv_conf (mgr, iface, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: '%s'", error ? error->message : "(none)");
		g_error_free (error);
	}

	return TRUE;
}

gboolean
nm_named_manager_remove_ip6_config (NMNamedManager *mgr,
									const char *iface,
									NMIP6Config *config)
{
	NMNamedManagerPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (iface != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	priv = NM_NAMED_MANAGER_GET_PRIVATE (mgr);

	/* Can't remove it if it wasn't in the list to begin with */
	if (!g_slist_find (priv->configs, config))
		return FALSE;

	priv->configs = g_slist_remove (priv->configs, config);

	if (config == priv->ip6_vpn_config)
		priv->ip6_vpn_config = NULL;
	if (config == priv->ip6_device_config)
		priv->ip6_device_config = NULL;

	g_object_unref (config);	

	if (!rewrite_resolv_conf (mgr, iface, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: '%s'", error ? error->message : "(none)");
		if (error)
			g_error_free (error);
	}

	return TRUE;
}

void
nm_named_manager_set_hostname (NMNamedManager *mgr,
                               const char *hostname)
{
	NMNamedManagerPrivate *priv = NM_NAMED_MANAGER_GET_PRIVATE (mgr);
	GError *error = NULL;
	const char *filtered = NULL;

	/* Certain hostnames we don't want to include in resolv.conf 'searches' */
	if (   hostname
	    && strcmp (hostname, "localhost.localdomain")
	    && strcmp (hostname, "localhost6.localdomain6")
	    && !strstr (hostname, ".in-addr.arpa")
	    && strchr (hostname, '.')) {
		filtered = hostname;
	}

	if (   (!priv->hostname && !filtered)
	    || (priv->hostname && filtered && !strcmp (priv->hostname, filtered)))
		return;

	g_free (priv->hostname);
	priv->hostname = g_strdup (filtered);

	/* Passing the last interface here is completely bogus, but SUSE's netconfig
	 * wants one.  But hostname changes are system-wide and *not* tied to a
	 * specific interface, so netconfig can't really handle this.  Fake it.
	 */
	if (!rewrite_resolv_conf (mgr, priv->last_iface, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: '%s'", error ? error->message : "(none)");
		g_clear_error (&error);
	}
}


static void
nm_named_manager_init (NMNamedManager *mgr)
{
}

static void
nm_named_manager_finalize (GObject *object)
{
	NMNamedManagerPrivate *priv = NM_NAMED_MANAGER_GET_PRIVATE (object);

	g_slist_foreach (priv->configs, (GFunc) g_object_unref, NULL);
	g_slist_free (priv->configs);
	g_free (priv->hostname);
	g_free (priv->last_iface);

	G_OBJECT_CLASS (nm_named_manager_parent_class)->finalize (object);
}

static void
nm_named_manager_class_init (NMNamedManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->finalize = nm_named_manager_finalize;

	g_type_class_add_private (object_class, sizeof (NMNamedManagerPrivate));
}

