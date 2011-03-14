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

#include "nm-dns-bind.h"
#include "nm-logging.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"

G_DEFINE_TYPE (NMDnsBind, nm_dns_bind, NM_TYPE_DNS_PLUGIN)

#define NM_DNS_BIND_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DNS_BIND, NMDnsBindPrivate))

#define PIDFILE LOCALSTATEDIR "/run/nm-dns-named.pid"
#define CONFFILE LOCALSTATEDIR "/run/nm-dns-named.conf"

typedef struct {
	GPid pid;
} NMDnsBindPrivate;

/*******************************************/

static inline const char *
find_bind (void)
{
	static const char *paths[] = {
		"/usr/local/sbin/named",
		"/usr/sbin/named",
		"/sbin/named",
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
start_bind (NMDnsBind *self)
{
	const char *argv[10];

	argv[0] = find_bind ();
	argv[1] = "-f";  /* don't daemonize; stay in foreground */
	argv[2] = "-c";
	argv[3] = CONFFILE;
	argv[4] = NULL;

	/* And finally spawn bind */
	return nm_dns_plugin_child_spawn (NM_DNS_PLUGIN (self), argv, PIDFILE, "bin/named");
}

/*******************************************/

static gboolean
find_address (GPtrArray *array, const char *addr)
{
	int n;

	for (n = 0; n < array->len; n++) {
		if (g_strcmp0 ((const char*) g_ptr_array_index (array, n), addr) == 0)
			return TRUE;
	}
	return FALSE;
}

static void
add_ip4_nameservers (NMIP4Config *ip4, GPtrArray *array)
{
	int i;

	for (i = 0; i < nm_ip4_config_get_num_nameservers (ip4); i++) {
		char buf[INET_ADDRSTRLEN + 1];
		struct in_addr addr;

		memset (&buf[0], 0, sizeof (buf));
		addr.s_addr = nm_ip4_config_get_nameserver (ip4, i);
		if (inet_ntop (AF_INET, &addr, buf, sizeof (buf))) {
			if (!find_address (array, buf))
				g_ptr_array_add (array, g_strdup (buf));
		}
	}
}

static gboolean
ip6_addr_to_string (const struct in6_addr *addr, char *buf, size_t buflen)
{
	/* inet_ntop is probably supposed to do this for us, but it doesn't */
	if (IN6_IS_ADDR_V4MAPPED (addr))
		return !!inet_ntop (AF_INET, &(addr->s6_addr32[3]), buf, buflen);

	return !!inet_ntop (AF_INET6, addr, buf, buflen);
}

static void
add_ip6_nameservers (NMIP6Config *ip6, GPtrArray *array)
{
	char buf[INET6_ADDRSTRLEN + 1];
	int i;

	for (i = 0; i < nm_ip6_config_get_num_nameservers (ip6); i++) {
		memset (buf, 0, sizeof (buf));
		if (ip6_addr_to_string (nm_ip6_config_get_nameserver (ip6, i), buf, sizeof (buf))) {
			if (!find_address (array, buf))
				g_ptr_array_add (array, g_strdup (buf));
		}
	}
}

typedef struct {
	guint32 dhash;
	char *domain;
	GPtrArray *servers;
} ZoneInfo;

static ZoneInfo *
zone_new (const char *domain)
{
	ZoneInfo *info;

	g_return_val_if_fail (domain != NULL, NULL);

	info = g_malloc0 (sizeof (ZoneInfo));
	info->domain = g_strdup (domain);
	info->dhash = g_str_hash (domain);
	info->servers = g_ptr_array_sized_new (4);
	return info;
}

static void
zone_add_nameserver (ZoneInfo *info, const char *server)
{
	guint32 i;

	g_return_if_fail (info != NULL);
	g_return_if_fail (server != NULL);

	for (i = 0; i < info->servers->len; i++) {
		if (g_strcmp0 ((char *) g_ptr_array_index (info->servers, i), server) == 0)
			return;
	}
	g_ptr_array_add (info->servers, g_strdup (server));
}

static void
zone_free (ZoneInfo *info)
{
	g_return_if_fail (info != NULL);

	g_free (info->domain);
	g_ptr_array_foreach (info->servers, (GFunc) g_free, NULL);
	g_ptr_array_free (info->servers, TRUE);
	memset (info, 0, sizeof (ZoneInfo));
	g_free (info);
}

static ZoneInfo *
find_zone (GPtrArray *zones, const char *domain)
{
	guint32 dhash, i;

	g_return_val_if_fail (domain != NULL, NULL);

	dhash = g_str_hash (domain);
	for (i = 0; i < zones->len; i++) {
		ZoneInfo *zone = g_ptr_array_index (zones, i);

		if (zone->dhash == dhash)
			return zone;
	}
	return NULL;
}

static void
add_zone (GObject *ip, GPtrArray *zones)
{
	guint32 i, j, ns, nd, nn;
	GPtrArray *to_add;
	ZoneInfo *z;

	if (NM_IS_IP4_CONFIG (ip)) {
		ns = nm_ip4_config_get_num_searches (NM_IP4_CONFIG (ip));
		nd = nm_ip4_config_get_num_domains (NM_IP4_CONFIG (ip));
		nn = nm_ip4_config_get_num_nameservers (NM_IP4_CONFIG (ip));
	} else if (NM_IS_IP6_CONFIG (ip)) {
		ns = nm_ip6_config_get_num_searches (NM_IP6_CONFIG (ip));
		nd = nm_ip6_config_get_num_domains (NM_IP6_CONFIG (ip));
		nn = nm_ip6_config_get_num_nameservers (NM_IP6_CONFIG (ip));
	} else
		g_assert_not_reached ();

	/* If we don't have any domains or searches, or we don't have any
	 * nameservers, we can't do split DNS for this config.
	 */
	if ((!nd && !ns) || !nn)
		return;

	to_add = g_ptr_array_sized_new (MAX (ns, nd));

	/* searches are preferred over domains */
	for (i = 0; i < ns; i++) {
		const char *domain = NULL;

		if (NM_IS_IP4_CONFIG (ip))
			domain = nm_ip4_config_get_search (NM_IP4_CONFIG (ip), i);
		else if (NM_IS_IP6_CONFIG (ip))
			domain = nm_ip6_config_get_search (NM_IP6_CONFIG (ip), i);

		z = find_zone (zones, domain);
		if (!z) {
			z = zone_new (domain);
			g_ptr_array_add (zones, z);
		}
		g_ptr_array_add (to_add, z);
	}

	if (ns == 0) {
		/* If no searches, add any domains */
		for (i = 0; i < nd; i++) {
			const char *domain = NULL;

			if (NM_IS_IP4_CONFIG (ip))
				domain = nm_ip4_config_get_domain (NM_IP4_CONFIG (ip), i);
			else if (NM_IS_IP6_CONFIG (ip))
				domain = nm_ip6_config_get_domain (NM_IP6_CONFIG (ip), i);

			z = find_zone (zones, domain);
			if (!z) {
				z = zone_new (domain);
				g_ptr_array_add (zones, z);
			}
			g_ptr_array_add (to_add, z);
		}
	}

	/* Now add the nameservers to every zone for this config */
	for (i = 0; i < nn; i++) {
		char buf[INET6_ADDRSTRLEN + 1];
		struct in_addr addr4;
		const struct in6_addr *addr6;

		memset (&buf[0], 0, sizeof (buf));

		if (NM_IS_IP4_CONFIG (ip)) {
			addr4.s_addr = nm_ip4_config_get_nameserver (NM_IP4_CONFIG (ip), i);
			if (!inet_ntop (AF_INET, &addr4, buf, sizeof (buf)))
				continue;
		} else if (NM_IS_IP6_CONFIG (ip)) {
			addr6 = nm_ip6_config_get_nameserver (NM_IP6_CONFIG (ip), i);
			if (!ip6_addr_to_string (addr6, buf, sizeof (buf)))
				continue;
		}

		/* Add this nameserver to every zone from this IP config */
		for (j = 0; j < to_add->len; j++) {
			z = g_ptr_array_index (to_add, j);
			zone_add_nameserver (z, buf);
		}
	}

	g_ptr_array_free (to_add, TRUE);
}

static gboolean
update (NMDnsPlugin *plugin,
        const GSList *vpn_configs,
        const GSList *dev_configs,
        const GSList *other_configs,
        const char *hostname)
{
	NMDnsBind *self = NM_DNS_BIND (plugin);
	NMDnsBindPrivate *priv = NM_DNS_BIND_GET_PRIVATE (self);
	GString *conf;
	GPtrArray *globals, *zones;
	GSList *iter;
	GError *error = NULL;
	int ignored, i, j;
	gboolean success = FALSE;

	/* Build up the new bind config file */
	conf = g_string_sized_new (200);
	globals = g_ptr_array_sized_new (6);

	/* If any of the VPN configs *don't* have domains or searches, then we
	 * dont' have any split DNS configuration for them, and we add them
	 * first in the global nameserver lists.  Otherwise we add them later as
	 * split DNS zones.
	 */
	for (iter = (GSList *) vpn_configs; iter;iter = g_slist_next (iter)) {
		if (NM_IS_IP4_CONFIG (iter->data)) {
			NMIP4Config *ip4 = NM_IP4_CONFIG (iter->data);

			if (!nm_ip4_config_get_num_domains (ip4) && !nm_ip4_config_get_num_searches (ip4))
				add_ip4_nameservers (ip4, globals);
		} else if (NM_IS_IP6_CONFIG (iter->data)) {
			NMIP6Config *ip6 = NM_IP6_CONFIG (iter->data);

			if (!nm_ip6_config_get_num_domains (ip6) && !nm_ip6_config_get_num_searches (ip6))
				add_ip6_nameservers (ip6, globals);
		}
	}

	/* Get a list of global upstream servers with dupe checking */
	for (iter = (GSList *) dev_configs; iter;iter = g_slist_next (iter)) {
		if (NM_IS_IP4_CONFIG (iter->data))
			add_ip4_nameservers (NM_IP4_CONFIG (iter->data), globals);
		else if (NM_IS_IP6_CONFIG (iter->data))
			add_ip6_nameservers (NM_IP6_CONFIG (iter->data), globals);
	}

	/* And any other random configs with dupe checking */
	for (iter = (GSList *) other_configs; iter;iter = g_slist_next (iter)) {
		if (NM_IS_IP4_CONFIG (iter->data))
			add_ip4_nameservers (NM_IP4_CONFIG (iter->data), globals);
		else if (NM_IS_IP6_CONFIG (iter->data))
			add_ip6_nameservers (NM_IP6_CONFIG (iter->data), globals);
	}

	g_string_append (conf,
		"options {\n"
		"    directory \"" LOCALSTATEDIR "/named\";\n"
		"    forward only;\n"
		"    recursion yes;\n"
		"    listen-on-v6 { ::1; };\n"
		"    listen-on { 127.0.0.1; };\n"
		"    forwarders {\n");

	for (i = 0; i < globals->len; i++) {
		char *ns = g_ptr_array_index (globals, i);

		g_string_append_printf (conf, "        %s;\n", ns);
		g_free (ns);
	}
	g_ptr_array_free (globals, TRUE);

	g_string_append (conf,
		"    };\n"
		"};\n\n");

	/* Build up the list of any split DNS zones, avoiding duplicates */
	zones = g_ptr_array_sized_new (4);
	for (iter = (GSList *) vpn_configs; iter;iter = g_slist_next (iter)) {
		if (NM_IS_IP4_CONFIG (iter->data))
			add_zone (G_OBJECT (iter->data), zones);
		else if (NM_IS_IP6_CONFIG (iter->data))
			add_zone (G_OBJECT (iter->data), zones);
	}

	/* Add all the zones to the config */
	for (i = 0; i < zones->len; i++) {
		ZoneInfo *z = g_ptr_array_index (zones, i);

		g_string_append_printf (conf,
			"zone \"%s\" IN {\n"
			"    type forward;\n"
			"    forward only;\n"
			"    forwarders {\n",
			z->domain);

		/* Add each nameserver for this zone */
		for (j = 0; j < z->servers->len; j++) {
			g_string_append_printf (conf,
				"        %s;\n",
				(const char *) g_ptr_array_index (z->servers, j));
		}

		g_string_append (conf,
			"    };\n"
			"};\n\n");

		zone_free (z);
	}
	g_ptr_array_free (zones, TRUE);

	/* Write out the config file */
	if (!g_file_set_contents (CONFFILE, conf->str, -1, &error)) {
		nm_log_warn (LOGD_DNS, "Failed to write named config file %s: (%d) %s",
		             CONFFILE,
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);
		goto out;
	}
	ignored = chmod (CONFFILE, 0600);

	nm_log_dbg (LOGD_DNS, "BIND local caching DNS configuration:");
	nm_log_dbg (LOGD_DNS, "%s", conf->str);

	if (priv->pid) {
		/* Send it SIGHUP to reload the new configuration */
		if (kill (priv->pid, SIGHUP) == 0)
			success = TRUE;
		else {
			/* Sigh... some error.  Kill it and restart */
			 nm_dns_plugin_child_kill (NM_DNS_PLUGIN (self));
			 priv->pid = 0;
		}
	}

	if (!success) {
		/* Spawn it */
		priv->pid = start_bind (self);
		if (priv->pid)
			success = TRUE;
	}

out:
	g_string_free (conf, TRUE);
	return success;
}

/****************************************************************/

static void
child_quit (NMDnsPlugin *plugin, gint status)
{
	NMDnsBind *self = NM_DNS_BIND (plugin);
	gboolean failed = TRUE;
	int err;

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err) {
			nm_log_warn (LOGD_DNS, "named exited with error %d", err);
		} else
			failed = FALSE;
	} else if (WIFSTOPPED (status)) {
		nm_log_warn (LOGD_DNS, "named stopped unexpectedly with signal %d", WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		nm_log_warn (LOGD_DNS, "named died with signal %d", WTERMSIG (status));
	} else {
		nm_log_warn (LOGD_DNS, "named died from an unknown cause");
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
	return "bind";
}

/****************************************************************/

NMDnsBind *
nm_dns_bind_new (void)
{
	return (NMDnsBind *) g_object_new (NM_TYPE_DNS_BIND, NULL);
}

static void
nm_dns_bind_init (NMDnsBind *self)
{
}

static void
dispose (GObject *object)
{
	unlink (CONFFILE);

	G_OBJECT_CLASS (nm_dns_bind_parent_class)->dispose (object);
}

static void
nm_dns_bind_class_init (NMDnsBindClass *dns_class)
{
	NMDnsPluginClass *plugin_class = NM_DNS_PLUGIN_CLASS (dns_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dns_class);

	g_type_class_add_private (dns_class, sizeof (NMDnsBindPrivate));

	object_class->dispose = dispose;

	plugin_class->init = init;
	plugin_class->child_quit = child_quit;
	plugin_class->is_caching = is_caching;
	plugin_class->update = update;
	plugin_class->get_name = get_name;
}

