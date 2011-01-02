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

#include <config.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <glib.h>
#include <glib/gi18n.h>

#include "nm-dns-dnsmasq.h"
#include "nm-logging.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-dns-utils.h"

G_DEFINE_TYPE (NMDnsDnsmasq, nm_dns_dnsmasq, NM_TYPE_DNS_PLUGIN)

#define NM_DNS_DNSMASQ_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DNS_DNSMASQ, NMDnsDnsmasqPrivate))

#define PIDFILE LOCALSTATEDIR "/run/nm-dns-dnsmasq.pid"
#define CONFFILE LOCALSTATEDIR "/run/nm-dns-dnsmasq.conf"

typedef struct {
	guint32 foo;
} NMDnsDnsmasqPrivate;

/*******************************************/

static inline const char *
find_dnsmasq (void)
{
	static const char *paths[] = {
		"/usr/local/sbin/dnsmasq",
		"/usr/sbin/dnsmasq",
		"/sbin/dnsmasq",
		NULL
	};
	const char **binary = paths;

	while (*binary != NULL) {
		if (g_file_test (*binary, G_FILE_TEST_EXISTS))
			return *binary;
		binary++;
	}
	return NULL;
}

static gboolean
add_ip4_config (GString *str, NMIP4Config *ip4, gboolean split)
{
	char buf[INET_ADDRSTRLEN + 1];
	struct in_addr addr;
	int n, i;
	gboolean added = FALSE;

	if (split) {
		char **domains, **iter;

		/* FIXME: it appears that dnsmasq can only handle one nameserver
		 * per domain (and the manpage says this too) so only use the first
		 * nameserver here.
		 */
		addr.s_addr = nm_ip4_config_get_nameserver (ip4, 0);
		memset (&buf[0], 0, sizeof (buf));
		if (!inet_ntop (AF_INET, &addr, buf, sizeof (buf)))
			return FALSE;

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

	/* If no searches or domains, just add the namservers */
	if (!added) {
		n = nm_ip4_config_get_num_nameservers (ip4);
		for (i = 0; i < n; i++) {
			memset (&buf[0], 0, sizeof (buf));
			addr.s_addr = nm_ip4_config_get_nameserver (ip4, i);
			if (inet_ntop (AF_INET, &addr, buf, sizeof (buf)))
				g_string_append_printf (str, "server=%s\n", buf);
		}
	}

	return TRUE;
}

static gboolean
ip6_addr_to_string (const struct in6_addr *addr, char *buf, size_t buflen)
{
	memset (buf, 0, buflen);

	/* inet_ntop is probably supposed to do this for us, but it doesn't */
	if (IN6_IS_ADDR_V4MAPPED (addr))
		return !!inet_ntop (AF_INET, &(addr->s6_addr32[3]), buf, buflen);

	return !!inet_ntop (AF_INET6, addr, buf, buflen);
}

static gboolean
add_ip6_config (GString *str, NMIP6Config *ip6, gboolean split)
{
	char buf[INET6_ADDRSTRLEN + 1];
	const struct in6_addr *addr;
	int n, i;
	gboolean added = FALSE;

	if (split) {
		/* FIXME: it appears that dnsmasq can only handle one nameserver
		 * per domain (at the manpage seems to indicate that) so only use
		 * the first nameserver here.
		 */
		addr = nm_ip6_config_get_nameserver (ip6, 0);
		if (!ip6_addr_to_string (addr, &buf[0], sizeof (buf)))
			return FALSE;

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
	}

	/* If no searches or domains, just add the namservers */
	if (!added) {
		n = nm_ip6_config_get_num_nameservers (ip6);
		for (i = 0; i < n; i++) {
			addr = nm_ip6_config_get_nameserver (ip6, i);
			if (ip6_addr_to_string (addr, &buf[0], sizeof (buf)))
				g_string_append_printf (str, "server=%s\n", buf);
		}
	}

	return TRUE;
}

static gboolean
update (NMDnsPlugin *plugin,
        const GSList *vpn_configs,
        const GSList *dev_configs,
        const GSList *other_configs,
        const char *hostname)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);
	GString *conf;
	GSList *iter;
	const char *argv[10];
	GError *error = NULL;
	int ignored;
	GPid pid = 0;

	/* Kill the old dnsmasq; there doesn't appear to be a way to get dnsmasq
	 * to reread the config file using SIGHUP or similar.  This is a small race
	 * here when restarting dnsmasq when DNS requests could go to the upstream
	 * servers instead of to dnsmasq.
	 */
	nm_dns_plugin_child_kill (plugin);

	/* Build up the new dnsmasq config file */
	conf = g_string_sized_new (150);

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

	/* Write out the config file */
	if (!g_file_set_contents (CONFFILE, conf->str, -1, &error)) {
		nm_log_warn (LOGD_DNS, "Failed to write dnsmasq config file %s: (%d) %s",
		             CONFFILE,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		goto out;
	}
	ignored = chmod (CONFFILE, 0600);

	nm_log_dbg (LOGD_DNS, "dnsmasq local caching DNS configuration:");
	nm_log_dbg (LOGD_DNS, "%s", conf->str);

	argv[0] = find_dnsmasq ();
	argv[1] = "--no-resolv";  /* Use only commandline */
	argv[2] = "--keep-in-foreground";
	argv[3] = "--strict-order";
	argv[4] = "--bind-interfaces";
	argv[5] = "--pid-file=" PIDFILE;
	argv[6] = "--listen-address=127.0.0.1"; /* Should work for both 4 and 6 */
	argv[7] = "--conf-file=" CONFFILE;
	argv[8] = NULL;

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
init (NMDnsPlugin *plugin)
{
	return TRUE;
}

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

NMDnsDnsmasq *
nm_dns_dnsmasq_new (void)
{
	return (NMDnsDnsmasq *) g_object_new (NM_TYPE_DNS_DNSMASQ, NULL);
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

	plugin_class->init = init;
	plugin_class->child_quit = child_quit;
	plugin_class->is_caching = is_caching;
	plugin_class->update = update;
	plugin_class->get_name = get_name;
}

