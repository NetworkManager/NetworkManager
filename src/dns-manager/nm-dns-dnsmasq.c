/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
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

#include "config.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include "nm-default.h"
#include "nm-dns-dnsmasq.h"
#include "nm-utils.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-dns-utils.h"
#include "NetworkManagerUtils.h"

G_DEFINE_TYPE (NMDnsDnsmasq, nm_dns_dnsmasq, NM_TYPE_DNS_PLUGIN)

#define NM_DNS_DNSMASQ_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DNS_DNSMASQ, NMDnsDnsmasqPrivate))

#define PIDFILE NMRUNDIR "/dnsmasq.pid"
#define CONFFILE NMRUNDIR "/dnsmasq.conf"
#define CONFDIR NMCONFDIR "/dnsmasq.d"

typedef struct {
	guint32 foo;
} NMDnsDnsmasqPrivate;

/*******************************************/

static gboolean
add_ip4_config (GString *str, NMIP4Config *ip4, gboolean split)
{
	char buf[INET_ADDRSTRLEN];
	in_addr_t addr;
	int nnameservers, i_nameserver, n, i;
	gboolean added = FALSE;

	nnameservers = nm_ip4_config_get_num_nameservers (ip4);

	if (split) {
		char **domains, **iter;

		if (nnameservers == 0)
			return FALSE;

		for (i_nameserver = 0; i_nameserver < nnameservers; i_nameserver++) {
			addr = nm_ip4_config_get_nameserver (ip4, i_nameserver);
			nm_utils_inet4_ntop (addr, buf);

			/* searches are preferred over domains */
			n = nm_ip4_config_get_num_searches (ip4);
			for (i = 0; i < n; i++) {
				g_string_append_printf (str, "server=/%s/%s\n",
				                        nm_ip4_config_get_search (ip4, i),
				                        buf);
				added = TRUE;
			}

			if (n == 0) {
				/* If not searches, use any domains */
				n = nm_ip4_config_get_num_domains (ip4);
				for (i = 0; i < n; i++) {
					g_string_append_printf (str, "server=/%s/%s\n",
					                        nm_ip4_config_get_domain (ip4, i),
					                        buf);
					added = TRUE;
				}
			}

			/* Ensure reverse-DNS works by directing queries for in-addr.arpa
			 * domains to the split domain's nameserver.
			 */
			domains = nm_dns_utils_get_ip4_rdns_domains (ip4);
			if (domains) {
				for (iter = domains; iter && *iter; iter++)
					g_string_append_printf (str, "server=/%s/%s\n", *iter, buf);
				g_strfreev (domains);
				added = TRUE;
			}
		}
	}

	/* If no searches or domains, just add the namservers */
	if (!added) {
		for (i = 0; i < nnameservers; i++) {
			addr = nm_ip4_config_get_nameserver (ip4, i);
			g_string_append_printf (str, "server=%s\n", nm_utils_inet4_ntop (addr, NULL));
		}
	}

	return TRUE;
}

static char *
ip6_addr_to_string (const struct in6_addr *addr, const char *iface)
{
	char *buf;

	if (IN6_IS_ADDR_V4MAPPED (addr)) {
		/* inet_ntop is probably supposed to do this for us, but it doesn't */
		buf = g_malloc (INET_ADDRSTRLEN);
		nm_utils_inet4_ntop (addr->s6_addr32[3], buf);
	} else if (!iface || !iface[0] || !IN6_IS_ADDR_LINKLOCAL (addr)) {
		buf = g_malloc (INET6_ADDRSTRLEN);
		nm_utils_inet6_ntop (addr, buf);
	} else {
		/* If we got a scope identifier, we need use '%' instead of
		 * '@', since dnsmasq supports '%' in server= addresses
		 * only since version 2.58 and up
		 */
		buf = g_strconcat (nm_utils_inet6_ntop (addr, NULL), "@", iface, NULL);
	}
	return buf;
}

static void
add_global_config (GString *str, const NMGlobalDnsConfig *config)
{
	guint i, j;

	g_return_if_fail (config);

	for (i = 0; i < nm_global_dns_config_get_num_domains (config); i++) {
		NMGlobalDnsDomain *domain = nm_global_dns_config_get_domain (config, i);
		const char *const *servers = nm_global_dns_domain_get_servers (domain);

		for (j = 0; servers && servers[j]; j++) {
			if (!strcmp (servers[j], "*"))
				g_string_append_printf (str, "server=%s\n", servers[j]);
			else {
				g_string_append_printf (str, "server=/%s/%s\n",
				                        nm_global_dns_domain_get_name (domain),
				                        servers[j]);
			}
		}

	}
}

static gboolean
add_ip6_config (GString *str, NMIP6Config *ip6, gboolean split)
{
	const struct in6_addr *addr;
	char *buf = NULL;
	int nnameservers, i_nameserver, n, i;
	gboolean added = FALSE;
	const char *iface;

	nnameservers = nm_ip6_config_get_num_nameservers (ip6);

	iface = g_object_get_data (G_OBJECT (ip6), IP_CONFIG_IFACE_TAG);
	g_assert (iface);

	if (split) {
		if (nnameservers == 0)
			return FALSE;

		for (i_nameserver = 0; i_nameserver < nnameservers; i_nameserver++) {
			addr = nm_ip6_config_get_nameserver (ip6, i_nameserver);
			buf = ip6_addr_to_string (addr, iface);

			/* searches are preferred over domains */
			n = nm_ip6_config_get_num_searches (ip6);
			for (i = 0; i < n; i++) {
				g_string_append_printf (str, "server=/%s/%s\n",
				                        nm_ip6_config_get_search (ip6, i),
				                        buf);
				added = TRUE;
			}

			if (n == 0) {
				/* If not searches, use any domains */
				n = nm_ip6_config_get_num_domains (ip6);
				for (i = 0; i < n; i++) {
					g_string_append_printf (str, "server=/%s/%s\n",
					                        nm_ip6_config_get_domain (ip6, i),
					                        buf);
					added = TRUE;
				}
			}

			g_free (buf);
		}
	}

	/* If no searches or domains, just add the namservers */
	if (!added) {
		for (i = 0; i < nnameservers; i++) {
			addr = nm_ip6_config_get_nameserver (ip6, i);
			buf = ip6_addr_to_string (addr, iface);
			if (buf) {
				g_string_append_printf (str, "server=%s\n", buf);
				g_free (buf);
			}
		}
	}

	return TRUE;
}

static gboolean
update (NMDnsPlugin *plugin,
        const GSList *vpn_configs,
        const GSList *dev_configs,
        const GSList *other_configs,
        const NMGlobalDnsConfig *global_config,
        const char *hostname)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);
	const char *dm_binary;
	GString *conf;
	GSList *iter;
	const char *argv[15];
	GError *error = NULL;
	int ignored;
	GPid pid = 0;
	guint idx = 0;

	/* Kill the old dnsmasq; there doesn't appear to be a way to get dnsmasq
	 * to reread the config file using SIGHUP or similar.  This is a small race
	 * here when restarting dnsmasq when DNS requests could go to the upstream
	 * servers instead of to dnsmasq.
	 */
	nm_dns_plugin_child_kill (plugin);

	dm_binary = nm_utils_find_helper ("dnsmasq", DNSMASQ_PATH, NULL);
	if (!dm_binary) {
		nm_log_warn (LOGD_DNS, "Could not find dnsmasq binary");
		return FALSE;
	}

	/* Build up the new dnsmasq config file */
	conf = g_string_sized_new (150);

	if (global_config)
		add_global_config (conf, global_config);
	else {
		/* Use split DNS for VPN configs */
		for (iter = (GSList *) vpn_configs; iter; iter = g_slist_next (iter)) {
			if (NM_IS_IP4_CONFIG (iter->data))
				add_ip4_config (conf, NM_IP4_CONFIG (iter->data), TRUE);
			else if (NM_IS_IP6_CONFIG (iter->data))
				add_ip6_config (conf, NM_IP6_CONFIG (iter->data), TRUE);
		}

		/* Now add interface configs without split DNS */
		for (iter = (GSList *) dev_configs; iter; iter = g_slist_next (iter)) {
			if (NM_IS_IP4_CONFIG (iter->data))
				add_ip4_config (conf, NM_IP4_CONFIG (iter->data), FALSE);
			else if (NM_IS_IP6_CONFIG (iter->data))
				add_ip6_config (conf, NM_IP6_CONFIG (iter->data), FALSE);
		}

		/* And any other random configs */
		for (iter = (GSList *) other_configs; iter; iter = g_slist_next (iter)) {
			if (NM_IS_IP4_CONFIG (iter->data))
				add_ip4_config (conf, NM_IP4_CONFIG (iter->data), FALSE);
			else if (NM_IS_IP6_CONFIG (iter->data))
				add_ip6_config (conf, NM_IP6_CONFIG (iter->data), FALSE);
		}
	}

	/* Write out the config file */
	if (!g_file_set_contents (CONFFILE, conf->str, -1, &error)) {
		nm_log_warn (LOGD_DNS, "Failed to write dnsmasq config file %s: (%d) %s",
		             CONFFILE,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		goto out;
	}
	ignored = chmod (CONFFILE, 0644);

	nm_log_dbg (LOGD_DNS, "dnsmasq local caching DNS configuration:");
	nm_log_dbg (LOGD_DNS, "%s", conf->str);

	argv[idx++] = dm_binary;
	argv[idx++] = "--no-resolv";  /* Use only commandline */
	argv[idx++] = "--keep-in-foreground";
	argv[idx++] = "--no-hosts"; /* don't use /etc/hosts to resolve */
	argv[idx++] = "--bind-interfaces";
	argv[idx++] = "--pid-file=" PIDFILE;
	argv[idx++] = "--listen-address=127.0.0.1"; /* Should work for both 4 and 6 */
	argv[idx++] = "--conf-file=" CONFFILE;
	argv[idx++] = "--cache-size=400";
	argv[idx++] = "--proxy-dnssec"; /* Allow DNSSEC to pass through */

	/* dnsmasq exits if the conf dir is not present */
	if (g_file_test (CONFDIR, G_FILE_TEST_IS_DIR))
		argv[idx++] = "--conf-dir=" CONFDIR;

	argv[idx++] = NULL;
	g_warn_if_fail (idx <= G_N_ELEMENTS (argv));

	/* And finally spawn dnsmasq */
	pid = nm_dns_plugin_child_spawn (NM_DNS_PLUGIN (self), argv, PIDFILE, "bin/dnsmasq");

out:
	g_string_free (conf, TRUE);
	return pid ? TRUE : FALSE;
}

/****************************************************************/

static const char *
dm_exit_code_to_msg (int status)
{
	if (status == 1)
		return "Configuration problem";
	else if (status == 2)
		return "Network access problem (address in use; permissions; etc)";
	else if (status == 3)
		return "Filesystem problem (missing file/directory; permissions; etc)";
	else if (status == 4)
		return "Memory allocation failure";
	else if (status == 5)
		return "Other problem";
	else if (status >= 11)
		return "Lease-script 'init' process failure";
	return "Unknown error";
}

static void
child_quit (NMDnsPlugin *plugin, gint status)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);
	gboolean failed = TRUE;
	int err;

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err) {
			nm_log_warn (LOGD_DNS, "dnsmasq exited with error: %s (%d)",
			             dm_exit_code_to_msg (err),
			             err);
		} else
			failed = FALSE;
	} else if (WIFSTOPPED (status)) {
		nm_log_warn (LOGD_DNS, "dnsmasq stopped unexpectedly with signal %d", WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		nm_log_warn (LOGD_DNS, "dnsmasq died with signal %d", WTERMSIG (status));
	} else {
		nm_log_warn (LOGD_DNS, "dnsmasq died from an unknown cause");
	}
	unlink (CONFFILE);

	if (failed)
		g_signal_emit_by_name (self, NM_DNS_PLUGIN_FAILED);
}

/****************************************************************/

static gboolean
is_caching (NMDnsPlugin *plugin)
{
	return TRUE;
}

static const char *
get_name (NMDnsPlugin *plugin)
{
	return "dnsmasq";
}

/****************************************************************/

NMDnsPlugin *
nm_dns_dnsmasq_new (void)
{
	return g_object_new (NM_TYPE_DNS_DNSMASQ, NULL);
}

static void
nm_dns_dnsmasq_init (NMDnsDnsmasq *self)
{
}

static void
dispose (GObject *object)
{
	unlink (CONFFILE);

	G_OBJECT_CLASS (nm_dns_dnsmasq_parent_class)->dispose (object);
}

static void
nm_dns_dnsmasq_class_init (NMDnsDnsmasqClass *dns_class)
{
	NMDnsPluginClass *plugin_class = NM_DNS_PLUGIN_CLASS (dns_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dns_class);

	g_type_class_add_private (dns_class, sizeof (NMDnsDnsmasqPrivate));

	object_class->dispose = dispose;

	plugin_class->child_quit = child_quit;
	plugin_class->is_caching = is_caching;
	plugin_class->update = update;
	plugin_class->get_name = get_name;
}

