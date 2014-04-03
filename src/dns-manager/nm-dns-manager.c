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
 * Copyright (C) 2004 - 2013 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 *   and others
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <resolv.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <linux/fs.h>

#include <glib.h>
#include <glib/gi18n.h>

#include "nm-dns-manager.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-logging.h"
#include "NetworkManagerUtils.h"
#include "nm-posix-signals.h"
#include "nm-config.h"

#include "nm-dns-plugin.h"
#include "nm-dns-dnsmasq.h"
#include "nm-dns-unbound.h"

#if HAVE_LIBSOUP
#include <libsoup/soup.h>

#ifdef SOUP_CHECK_VERSION
#if SOUP_CHECK_VERSION (2, 40, 0)
#define DOMAIN_IS_VALID(domain) (*(domain) && !soup_tld_domain_is_public_suffix (domain))
#endif
#endif
#endif

#ifndef DOMAIN_IS_VALID
#define DOMAIN_IS_VALID(domain) (*(domain))
#endif

G_DEFINE_TYPE (NMDnsManager, nm_dns_manager, G_TYPE_OBJECT)

#define NM_DNS_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), \
                                       NM_TYPE_DNS_MANAGER, \
                                       NMDnsManagerPrivate))

#define HASH_LEN 20

typedef struct {
	NMIP4Config *ip4_vpn_config;
	NMIP4Config *ip4_device_config;
	NMIP6Config *ip6_vpn_config;
	NMIP6Config *ip6_device_config;
	GSList *configs;
	char *hostname;
	guint updates_queue;

	guint8 hash[HASH_LEN];  /* SHA1 hash of current DNS config */
	guint8 prev_hash[HASH_LEN];  /* Hash when begin_updates() was called */

	NMDnsManagerResolvConfMode resolv_conf_mode;
	NMDnsPlugin *plugin;

	gboolean dns_touched;
} NMDnsManagerPrivate;

enum {
	CONFIG_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


typedef struct {
	GPtrArray *nameservers;
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
		guint32 addr;
		char buf[INET_ADDRSTRLEN];

		addr = nm_ip4_config_get_nameserver (src, i);
		if (inet_ntop (AF_INET, &addr, buf, INET_ADDRSTRLEN) > 0)
			add_string_item (rc->nameservers, buf);
	}

	num = nm_ip4_config_get_num_domains (src);
	for (i = 0; i < num; i++) {
		const char *domain;

		domain = nm_ip4_config_get_domain (src, i);
		if (!DOMAIN_IS_VALID (domain))
			continue;
		add_string_item (rc->searches, domain);
	}

	num = nm_ip4_config_get_num_searches (src);
	for (i = 0; i < num; i++) {
		const char *search;

		search = nm_ip4_config_get_search (src, i);
		if (!DOMAIN_IS_VALID (search))
			continue;
		add_string_item (rc->searches, search);
	}

	/* NIS stuff */
	num = nm_ip4_config_get_num_nis_servers (src);
	for (i = 0; i < num; i++) {
		guint32 addr;
		char buf[INET_ADDRSTRLEN];

		addr = nm_ip4_config_get_nis_server (src, i);
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
	const char *iface;

	iface = g_object_get_data (G_OBJECT (src), IP_CONFIG_IFACE_TAG);

	num = nm_ip6_config_get_num_nameservers (src);
	for (i = 0; i < num; i++) {
		const struct in6_addr *addr;
		char buf[INET6_ADDRSTRLEN];
		char *tmp;

		addr = nm_ip6_config_get_nameserver (src, i);

		/* inet_ntop is probably supposed to do this for us, but it doesn't */
		if (IN6_IS_ADDR_V4MAPPED (addr)) {
			if (inet_ntop (AF_INET, &(addr->s6_addr32[3]), buf, INET_ADDRSTRLEN) > 0)
				add_string_item (rc->nameservers, buf);
		} else {
			if (inet_ntop (AF_INET6, addr, buf, INET6_ADDRSTRLEN) > 0) {
				if (iface && IN6_IS_ADDR_LINKLOCAL (addr)) {
					tmp = g_strdup_printf ("%s%%%s", buf, iface);
					add_string_item (rc->nameservers, tmp);
					g_free (tmp);
				} else
					add_string_item (rc->nameservers, buf);
			}
		}
	}

	num = nm_ip6_config_get_num_domains (src);
	for (i = 0; i < num; i++) {
		const char *domain;

		domain = nm_ip6_config_get_domain (src, i);
		if (!DOMAIN_IS_VALID (domain))
			continue;
		add_string_item (rc->searches, domain);
	}

	num = nm_ip6_config_get_num_searches (src);
	for (i = 0; i < num; i++) {
		const char *search;

		search = nm_ip6_config_get_search (src, i);
		if (!DOMAIN_IS_VALID (search))
			continue;
		add_string_item (rc->searches, search);
	}
}


#if defined(NETCONFIG_PATH)
/**********************************/
/* SUSE */

static void
netconfig_child_setup (gpointer user_data G_GNUC_UNUSED)
{
	pid_t pid = getpid ();
	setpgid (pid, pid);

	/*
	 * We blocked signals in main(). We need to restore original signal
	 * mask for netconfig here so that it can receive signals.
	 */
	nm_unblock_posix_signals (NULL);
}

static GPid
run_netconfig (GError **error, gint *stdin_fd)
{
	char *argv[5];
	char *tmp;
	GPid pid = -1;

	argv[0] = NETCONFIG_PATH;
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
dispatch_netconfig (char **searches,
                    char **nameservers,
                    const char *nis_domain,
                    char **nis_servers,
                    GError **error)
{
	char *str, *tmp;
	GPid pid;
	gint fd;
	int ret;

	pid = run_netconfig (error, &fd);
	if (pid < 0)
		return FALSE;

	/* NM is writing already-merged DNS information to netconfig, so it
	 * does not apply to a specific network interface.
	 */
	write_to_netconfig (fd, "INTERFACE", "NetworkManager");

	if (searches) {
		str = g_strjoinv (" ", searches);

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
write_resolv_conf (FILE *f,
                   char **searches,
                   char **nameservers,
                   GError **error)
{
	char *searches_str = NULL;
	char *nameservers_str = NULL;
	int i;
	gboolean retval = FALSE;
	GString *str;

	if (fprintf (f, "%s","# Generated by NetworkManager\n") < 0) {
		g_set_error (error,
		             NM_DNS_MANAGER_ERROR,
		             NM_DNS_MANAGER_ERROR_SYSTEM,
		             "Could not write " _PATH_RESCONF ": %s\n",
		             g_strerror (errno));
		return FALSE;
	}

	if (searches) {
		char *tmp_str;

		tmp_str = g_strjoinv (" ", searches);
		searches_str = g_strconcat ("search ", tmp_str, "\n", NULL);
		g_free (tmp_str);
	}

	str = g_string_new ("");

	if (nameservers) {
		int num = g_strv_length (nameservers);

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
	}

	nameservers_str = g_string_free (str, FALSE);

	if (fprintf (f, "%s%s",
	             searches_str ? searches_str : "",
	             strlen (nameservers_str) ? nameservers_str : "") != -1)
		retval = TRUE;

	g_free (searches_str);
	g_free (nameservers_str);

	return retval;
}

#ifdef RESOLVCONF_PATH
static gboolean
dispatch_resolvconf (char **searches,
                     char **nameservers,
                     GError **error)
{
	char *cmd;
	FILE *f;
	gboolean retval = FALSE;

	if (! g_file_test (RESOLVCONF_PATH, G_FILE_TEST_IS_EXECUTABLE))
		return FALSE;

	if (searches || nameservers) {
		cmd = g_strconcat (RESOLVCONF_PATH, " -a ", "NetworkManager", NULL);
		nm_log_info (LOGD_DNS, "Writing DNS information to %s", RESOLVCONF_PATH);
		if ((f = popen (cmd, "w")) == NULL)
			g_set_error (error,
			             NM_DNS_MANAGER_ERROR,
			             NM_DNS_MANAGER_ERROR_SYSTEM,
			             "Could not write to %s: %s\n",
			             RESOLVCONF_PATH,
			             g_strerror (errno));
		else {
			retval = write_resolv_conf (f, searches, nameservers, error);
			retval &= (pclose (f) == 0);
		}
	} else {
		cmd = g_strconcat (RESOLVCONF_PATH, " -d ", "NetworkManager", NULL);
		nm_log_info (LOGD_DNS, "Removing DNS information from %s", RESOLVCONF_PATH);
		if (nm_spawn_process (cmd) == 0)
			retval = TRUE;
	}

	g_free (cmd);

	return retval;
}
#endif

static gboolean
update_resolv_conf (char **searches,
                    char **nameservers,
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
	resolv_conf_realpath = realpath (_PATH_RESCONF, NULL);
	if (!resolv_conf_realpath)
		resolv_conf_realpath = strdup (_PATH_RESCONF);

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
		if ((f = fopen (_PATH_RESCONF, "w")) == NULL) {
			g_set_error (error,
			             NM_DNS_MANAGER_ERROR,
			             NM_DNS_MANAGER_ERROR_SYSTEM,
			             "Could not open %s: %s\nCould not open %s: %s\n",
			             tmp_resolv_conf_realpath,
			             g_strerror (old_errno),
			             _PATH_RESCONF,
			             g_strerror (errno));
			goto out;
		}
		/* Update tmp_resolv_conf_realpath so the error message on fclose()
		 * failure will be correct.
		 */
		strcpy (tmp_resolv_conf_realpath, _PATH_RESCONF);
	}

	write_resolv_conf (f, searches, nameservers, error);

	if (fclose (f) < 0) {
		if (*error == NULL) {
			/* only set an error here if write_resolv_conf() was successful,
			 * since its error is more important.
			 */
			g_set_error (error,
			             NM_DNS_MANAGER_ERROR,
			             NM_DNS_MANAGER_ERROR_SYSTEM,
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
			             NM_DNS_MANAGER_ERROR,
			             NM_DNS_MANAGER_ERROR_SYSTEM,
			             "Could not replace " _PATH_RESCONF ": %s\n",
			             g_strerror (errno));
		}
	}

out:
	free (tmp_resolv_conf_realpath);
	free (resolv_conf_realpath);
	return *error ? FALSE : TRUE;
}

static void
compute_hash (NMDnsManager *self, guint8 buffer[HASH_LEN])
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);
	GChecksum *sum;
	GSList *iter;
	gsize len = HASH_LEN;

	sum = g_checksum_new (G_CHECKSUM_SHA1);
	g_assert (len == g_checksum_type_get_length (G_CHECKSUM_SHA1));

	if (priv->ip4_vpn_config)
		nm_ip4_config_hash (priv->ip4_vpn_config, sum, TRUE);
	if (priv->ip4_device_config)
		nm_ip4_config_hash (priv->ip4_device_config, sum, TRUE);

	if (priv->ip6_vpn_config)
		nm_ip6_config_hash (priv->ip6_vpn_config, sum, TRUE);
	if (priv->ip6_device_config)
		nm_ip6_config_hash (priv->ip6_device_config, sum, TRUE);

	/* add any other configs we know about */
	for (iter = priv->configs; iter; iter = g_slist_next (iter)) {
		if (   (iter->data == priv->ip4_vpn_config)
		    && (iter->data == priv->ip4_device_config)
		    && (iter->data == priv->ip6_vpn_config)
		    && (iter->data == priv->ip6_device_config))
			continue;

		if (NM_IS_IP4_CONFIG (iter->data))
			nm_ip4_config_hash (NM_IP4_CONFIG (iter->data), sum, TRUE);
		else if (NM_IS_IP6_CONFIG (iter->data))
			nm_ip6_config_hash (NM_IP6_CONFIG (iter->data), sum, TRUE);
	}

	g_checksum_get_digest (sum, buffer, &len);
	g_checksum_free (sum);
}

static gboolean
update_dns (NMDnsManager *self,
            gboolean no_caching,
            GError **error)
{
	NMDnsManagerPrivate *priv;
	NMResolvConfData rc;
	GSList *iter, *vpn_configs = NULL, *dev_configs = NULL, *other_configs = NULL;
	const char *nis_domain = NULL;
	char **searches = NULL;
	char **nameservers = NULL;
	char **nis_servers = NULL;
	int num, i, len;
	gboolean success = FALSE, caching = FALSE;

	g_return_val_if_fail (error != NULL, FALSE);
	g_return_val_if_fail (*error == NULL, FALSE);

	priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	if (priv->resolv_conf_mode == NM_DNS_MANAGER_RESOLV_CONF_UNMANAGED)
		return TRUE;

	priv->dns_touched = TRUE;

	nm_log_dbg (LOGD_DNS, "updating resolv.conf");

	/* Update hash with config we're applying */
	compute_hash (self, priv->hash);

	rc.nameservers = g_ptr_array_new ();
	rc.searches = g_ptr_array_new ();
	rc.nis_domain = NULL;
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

	/* If the hostname is a FQDN ("dcbw.example.com"), then add the domain part of it
	 * ("example.com") to the searches list, to ensure that we can still resolve its
	 * non-FQ form ("dcbw") too. (Also, if there are no other search domains specified,
	 * this makes a good default.) However, if the hostname is the top level of a domain
	 * (eg, "example.com"), then use the hostname itself as the search (since the user is
	 * unlikely to want "com" as a search domain).
	 */
	if (priv->hostname) {
		const char *hostdomain = strchr (priv->hostname, '.');

		if (hostdomain) {
			hostdomain++;
			if (DOMAIN_IS_VALID (hostdomain))
				add_string_item (rc.searches, hostdomain);
			else if (DOMAIN_IS_VALID (priv->hostname))
				add_string_item (rc.searches, priv->hostname);
		}
	}

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

	/* Build up config lists for plugins; we use the raw configs here, not the
	 * merged information that we write to resolv.conf so that the plugins can
	 * still use the domain information in each config to provide split DNS if
	 * they want to.
	 */
	if (priv->ip4_vpn_config)
		vpn_configs = g_slist_append (vpn_configs, priv->ip4_vpn_config);
	if (priv->ip6_vpn_config)
		vpn_configs = g_slist_append (vpn_configs, priv->ip6_vpn_config);
	if (priv->ip4_device_config)
		dev_configs = g_slist_append (dev_configs, priv->ip4_device_config);
	if (priv->ip6_device_config)
		dev_configs = g_slist_append (dev_configs, priv->ip6_device_config);

	for (iter = priv->configs; iter; iter = g_slist_next (iter)) {
		if (   (iter->data != priv->ip4_vpn_config)
		    && (iter->data != priv->ip4_device_config)
		    && (iter->data != priv->ip6_vpn_config)
		    && (iter->data != priv->ip6_device_config))
			other_configs = g_slist_append (other_configs, iter->data);
	}

	/* Let any plugins do their thing first */
	if (priv->plugin) {
		NMDnsPlugin *plugin = priv->plugin;
		const char *plugin_name = nm_dns_plugin_get_name (plugin);

		if (nm_dns_plugin_is_caching (plugin)) {
			if (no_caching) {
				nm_log_dbg (LOGD_DNS, "DNS: plugin %s ignored (caching disabled)",
				            plugin_name);
				goto skip;
			}
			caching = TRUE;
		}

		nm_log_dbg (LOGD_DNS, "DNS: updating plugin %s", plugin_name);
		if (!nm_dns_plugin_update (plugin,
		                           vpn_configs,
		                           dev_configs,
		                           other_configs,
		                           priv->hostname)) {
			nm_log_warn (LOGD_DNS, "DNS: plugin %s update failed", plugin_name);

			/* If the plugin failed to update, we shouldn't write out a local
			 * caching DNS configuration to resolv.conf.
			 */
			caching = FALSE;
		}

	skip:
		;
	}

	g_slist_free (vpn_configs);
	g_slist_free (dev_configs);
	g_slist_free (other_configs);

	/* If caching was successful, we only send 127.0.0.1 to /etc/resolv.conf
	 * to ensure that the glibc resolver doesn't try to round-robin nameservers,
	 * but only uses the local caching nameserver.
	 */
	if (caching) {
		if (nameservers)
			g_strfreev (nameservers);
		nameservers = g_new0 (char*, 2);
		nameservers[0] = g_strdup ("127.0.0.1");
	}

#ifdef RESOLVCONF_PATH
	success = dispatch_resolvconf (searches, nameservers, error);
#endif

#ifdef NETCONFIG_PATH
	if (success == FALSE) {
		success = dispatch_netconfig (searches, nameservers,
		                              nis_domain, nis_servers, error);
	}
#endif

	if (success == FALSE)
		success = update_resolv_conf (searches, nameservers, error);

	/* signal that resolv.conf was changed */
	if (success)
		g_signal_emit (self, signals[CONFIG_CHANGED], 0);

	if (searches)
		g_strfreev (searches);
	if (nameservers)
		g_strfreev (nameservers);
	if (nis_servers)
		g_strfreev (nis_servers);

	return success;
}

static void
plugin_failed (NMDnsPlugin *plugin, gpointer user_data)
{
	NMDnsManager *self = NM_DNS_MANAGER (user_data);
	GError *error = NULL;

	/* Errors with non-caching plugins aren't fatal */
	if (!nm_dns_plugin_is_caching (plugin))
		return;

	/* Disable caching until the next DNS update */
	if (!update_dns (self, TRUE, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}
}

gboolean
nm_dns_manager_add_ip4_config (NMDnsManager *mgr,
                               const char *iface,
                               NMIP4Config *config,
                               NMDnsIPConfigType cfg_type)
{
	NMDnsManagerPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	priv = NM_DNS_MANAGER_GET_PRIVATE (mgr);

	g_object_set_data_full (G_OBJECT (config), IP_CONFIG_IFACE_TAG, g_strdup (iface), g_free);

	switch (cfg_type) {
	case NM_DNS_IP_CONFIG_TYPE_VPN:
		priv->ip4_vpn_config = config;
		break;
	case NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE:
		priv->ip4_device_config = config;
		break;
	default:
		break;
	}

	/* Don't allow the same zone added twice */
	if (!g_slist_find (priv->configs, config))
		priv->configs = g_slist_append (priv->configs, g_object_ref (config));

	if (!priv->updates_queue && !update_dns (mgr, FALSE, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	return TRUE;
}

gboolean
nm_dns_manager_remove_ip4_config (NMDnsManager *mgr, NMIP4Config *config)
{
	NMDnsManagerPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	priv = NM_DNS_MANAGER_GET_PRIVATE (mgr);

	/* Can't remove it if it wasn't in the list to begin with */
	if (!g_slist_find (priv->configs, config))
		return FALSE;

	priv->configs = g_slist_remove (priv->configs, config);

	if (config == priv->ip4_vpn_config)
		priv->ip4_vpn_config = NULL;
	if (config == priv->ip4_device_config)
		priv->ip4_device_config = NULL;

	g_object_unref (config);

	if (!priv->updates_queue && !update_dns (mgr, FALSE, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	g_object_set_data (G_OBJECT (config), IP_CONFIG_IFACE_TAG, NULL);

	return TRUE;
}

gboolean
nm_dns_manager_add_ip6_config (NMDnsManager *mgr,
                               const char *iface,
                               NMIP6Config *config,
                               NMDnsIPConfigType cfg_type)
{
	NMDnsManagerPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	priv = NM_DNS_MANAGER_GET_PRIVATE (mgr);

	g_object_set_data_full (G_OBJECT (config), IP_CONFIG_IFACE_TAG, g_strdup (iface), g_free);

	switch (cfg_type) {
	case NM_DNS_IP_CONFIG_TYPE_VPN:
		priv->ip6_vpn_config = config;
		break;
	case NM_DNS_IP_CONFIG_TYPE_BEST_DEVICE:
		priv->ip6_device_config = config;
		break;
	default:
		break;
	}

	/* Don't allow the same zone added twice */
	if (!g_slist_find (priv->configs, config))
		priv->configs = g_slist_append (priv->configs, g_object_ref (config));

	if (!priv->updates_queue && !update_dns (mgr, FALSE, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	return TRUE;
}

gboolean
nm_dns_manager_remove_ip6_config (NMDnsManager *mgr, NMIP6Config *config)
{
	NMDnsManagerPrivate *priv;
	GError *error = NULL;

	g_return_val_if_fail (mgr != NULL, FALSE);
	g_return_val_if_fail (config != NULL, FALSE);

	priv = NM_DNS_MANAGER_GET_PRIVATE (mgr);

	/* Can't remove it if it wasn't in the list to begin with */
	if (!g_slist_find (priv->configs, config))
		return FALSE;

	priv->configs = g_slist_remove (priv->configs, config);

	if (config == priv->ip6_vpn_config)
		priv->ip6_vpn_config = NULL;
	if (config == priv->ip6_device_config)
		priv->ip6_device_config = NULL;

	g_object_unref (config);	

	if (!priv->updates_queue && !update_dns (mgr, FALSE, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	g_object_set_data (G_OBJECT (config), IP_CONFIG_IFACE_TAG, NULL);

	return TRUE;
}

void
nm_dns_manager_set_initial_hostname (NMDnsManager *mgr,
                                     const char *hostname)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (mgr);

	priv->hostname = g_strdup (hostname);
}

void
nm_dns_manager_set_hostname (NMDnsManager *mgr,
                             const char *hostname)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (mgr);
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

	if (!priv->updates_queue && !update_dns (mgr, FALSE, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}
}

NMDnsManagerResolvConfMode
nm_dns_manager_get_resolv_conf_mode (NMDnsManager *mgr)
{
	return NM_DNS_MANAGER_GET_PRIVATE (mgr)->resolv_conf_mode;
}

void
nm_dns_manager_begin_updates (NMDnsManager *mgr, const char *func)
{
	NMDnsManagerPrivate *priv;

	g_return_if_fail (mgr != NULL);
	priv = NM_DNS_MANAGER_GET_PRIVATE (mgr);

	/* Save current hash when starting a new batch */
	if (priv->updates_queue == 0)
		memcpy (priv->prev_hash, priv->hash, sizeof (priv->hash));

	priv->updates_queue++;

	nm_log_dbg (LOGD_DNS, "(%s): queueing DNS updates (%d)", func, priv->updates_queue);
}

void
nm_dns_manager_end_updates (NMDnsManager *mgr, const char *func)
{
	NMDnsManagerPrivate *priv;
	GError *error = NULL;
	gboolean changed;
	guint8 new[HASH_LEN];

	g_return_if_fail (mgr != NULL);

	priv = NM_DNS_MANAGER_GET_PRIVATE (mgr);
	g_return_if_fail (priv->updates_queue > 0);

	compute_hash (mgr, new);
	changed = (memcmp (new, priv->prev_hash, sizeof (new)) != 0) ? TRUE : FALSE;
	nm_log_dbg (LOGD_DNS, "(%s): DNS configuration %s", __func__, changed ? "changed" : "did not change");

	priv->updates_queue--;
	if ((priv->updates_queue > 0) || (changed == FALSE)) {
		nm_log_dbg (LOGD_DNS, "(%s): no DNS changes to commit (%d)", func, priv->updates_queue);
		return;
	}

	/* Commit all the outstanding changes */
	nm_log_dbg (LOGD_DNS, "(%s): committing DNS changes (%d)", func, priv->updates_queue);
	if (!update_dns (mgr, FALSE, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes: (%d) %s",
			         error ? error->code : -1,
			         error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
	}

	memset (priv->prev_hash, 0, sizeof (priv->prev_hash));
}

/******************************************************************/

NMDnsManager *
nm_dns_manager_get (void)
{
	static NMDnsManager * singleton = NULL;

	if (!singleton) {
		singleton = NM_DNS_MANAGER (g_object_new (NM_TYPE_DNS_MANAGER, NULL));
		g_assert (singleton);
	}

	return singleton;
}

GQuark
nm_dns_manager_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm_dns_manager_error");

	return quark;
}

static void
init_resolv_conf_mode (NMDnsManager *self)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);
	const char *mode;
	int fd, flags;

	fd = open (_PATH_RESCONF, O_RDONLY);
	if (fd != -1) {
		if (ioctl (fd, FS_IOC_GETFLAGS, &flags) == -1)
			flags = 0;
		close (fd);

		if (flags & FS_IMMUTABLE_FL) {
			nm_log_info (LOGD_DNS, "DNS: " _PATH_RESCONF " is immutable; not managing");
			priv->resolv_conf_mode = NM_DNS_MANAGER_RESOLV_CONF_UNMANAGED;
			return;
		}
	}

	mode = nm_config_get_dns_mode (nm_config_get ());
	if (!g_strcmp0 (mode, "none")) {
		priv->resolv_conf_mode = NM_DNS_MANAGER_RESOLV_CONF_UNMANAGED;
		nm_log_info (LOGD_DNS, "DNS: not managing " _PATH_RESCONF);
	} else if (!g_strcmp0 (mode, "dnsmasq")) {
		priv->resolv_conf_mode = NM_DNS_MANAGER_RESOLV_CONF_PROXY;
		priv->plugin = nm_dns_dnsmasq_new ();
	} else if (!g_strcmp0 (mode, "unbound")) {
		priv->resolv_conf_mode = NM_DNS_MANAGER_RESOLV_CONF_PROXY;
		priv->plugin = nm_dns_unbound_new ();
	} else {
		priv->resolv_conf_mode = NM_DNS_MANAGER_RESOLV_CONF_EXPLICIT;
		if (mode && g_strcmp0 (mode, "default") != 0)
			nm_log_warn (LOGD_DNS, "Unknown DNS mode '%s'", mode);
	}
}

static void
nm_dns_manager_init (NMDnsManager *self)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);

	/* Set the initial hash */
	compute_hash (self, NM_DNS_MANAGER_GET_PRIVATE (self)->hash);

	init_resolv_conf_mode (self);

	if (priv->plugin) {
		nm_log_info (LOGD_DNS, "DNS: loaded plugin %s", nm_dns_plugin_get_name (priv->plugin));
		g_signal_connect (priv->plugin, NM_DNS_PLUGIN_FAILED, G_CALLBACK (plugin_failed), self);
	}
}

static void
dispose (GObject *object)
{
	NMDnsManager *self = NM_DNS_MANAGER (object);
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (self);
	GError *error = NULL;

	g_clear_object (&priv->plugin);

	/* If we're quitting, leave a valid resolv.conf in place, not one
	 * pointing to 127.0.0.1 if any plugins were active.  Thus update
	 * DNS after disposing of all plugins.  But if we haven't done any
	 * DNS updates yet, there's no reason to touch resolv.conf on shutdown.
	 */
	if (priv->dns_touched && !update_dns (self, TRUE, &error)) {
		nm_log_warn (LOGD_DNS, "could not commit DNS changes on shutdown: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		priv->dns_touched = FALSE;
	}

	g_slist_free_full (priv->configs, g_object_unref);
	priv->configs = NULL;

	G_OBJECT_CLASS (nm_dns_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMDnsManagerPrivate *priv = NM_DNS_MANAGER_GET_PRIVATE (object);

	g_free (priv->hostname);

	G_OBJECT_CLASS (nm_dns_manager_parent_class)->finalize (object);
}

static void
nm_dns_manager_class_init (NMDnsManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDnsManagerPrivate));

	/* virtual methods */
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	/* signals */
	signals[CONFIG_CHANGED] =
		g_signal_new ("config-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDnsManagerClass, config_changed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);
}

