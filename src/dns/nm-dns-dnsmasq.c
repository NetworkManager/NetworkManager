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

#include "nm-default.h"

#include "nm-dns-dnsmasq.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <linux/if.h>

#include "nm-core-internal.h"
#include "platform/nm-platform.h"
#include "nm-utils.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-dbus-manager.h"
#include "NetworkManagerUtils.h"

#define PIDFILE NMRUNDIR "/dnsmasq.pid"
#define CONFDIR NMCONFDIR "/dnsmasq.d"

#define DNSMASQ_DBUS_SERVICE "org.freedesktop.NetworkManager.dnsmasq"
#define DNSMASQ_DBUS_PATH "/uk/org/thekelleys/dnsmasq"

/*****************************************************************************/

typedef struct {
	GDBusProxy *dnsmasq;
	GCancellable *dnsmasq_cancellable;
	GCancellable *update_cancellable;
	gboolean running;

	GVariant *set_server_ex_args;
} NMDnsDnsmasqPrivate;

struct _NMDnsDnsmasq {
	NMDnsPlugin parent;
	NMDnsDnsmasqPrivate _priv;
};

struct _NMDnsDnsmasqClass {
	NMDnsPluginClass parent;
};

G_DEFINE_TYPE (NMDnsDnsmasq, nm_dns_dnsmasq, NM_TYPE_DNS_PLUGIN)

#define NM_DNS_DNSMASQ_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDnsDnsmasq, NM_IS_DNS_DNSMASQ)

/*****************************************************************************/

#define _NMLOG_DOMAIN         LOGD_DNS
#define _NMLOG(level, ...) __NMLOG_DEFAULT_WITH_ADDR (level, _NMLOG_DOMAIN, "dnsmasq", __VA_ARGS__)

/*****************************************************************************/

static void
add_dnsmasq_nameserver (NMDnsDnsmasq *self,
                        GVariantBuilder *servers,
                        const char *ip,
                        const char *domain)
{
	g_return_if_fail (ip);

	_LOGD ("adding nameserver '%s'%s%s%s", ip,
	       NM_PRINT_FMT_QUOTED (domain, " for domain \"", domain, "\"", ""));

	g_variant_builder_open (servers, G_VARIANT_TYPE ("as"));

	g_variant_builder_add (servers, "s", ip);
	if (domain)
		g_variant_builder_add (servers, "s", domain);

	g_variant_builder_close (servers);
}

#define IP_ADDR_TO_STRING_BUFLEN (NM_UTILS_INET_ADDRSTRLEN + 1 + IFNAMSIZ)

static const char *
ip_addr_to_string (int addr_family, gconstpointer addr, const char *iface, char *out_buf)
{
	int n_written;
	char buf2[NM_UTILS_INET_ADDRSTRLEN];
	const char *separator;

	nm_assert_addr_family (addr_family);
	nm_assert (addr);
	nm_assert (out_buf);

	if (addr_family == AF_INET) {
		nm_utils_inet_ntop (addr_family, addr, buf2);
		separator = "@";
	} else {
		if (IN6_IS_ADDR_V4MAPPED (addr))
			nm_utils_inet4_ntop (((const struct in6_addr *) addr)->s6_addr32[3], buf2);
		else
			nm_utils_inet6_ntop (addr, buf2);
		/* Need to scope link-local addresses with %<zone-id>. Before dnsmasq 2.58,
		 * only '@' was supported as delimiter. Since 2.58, '@' and '%' are
		 * supported. Due to a bug, since 2.73 only '%' works properly as "server"
		 * address.
		 */
		separator = IN6_IS_ADDR_LINKLOCAL (addr) ? "%" : "@";
	}

	n_written = g_snprintf (out_buf,
	                        IP_ADDR_TO_STRING_BUFLEN,
	                        "%s%s%s",
	                        buf2,
	                        iface ? separator : "",
	                        iface ?: "");
	nm_assert (n_written < IP_ADDR_TO_STRING_BUFLEN);
	return out_buf;
}

static void
add_global_config (NMDnsDnsmasq *self, GVariantBuilder *dnsmasq_servers, const NMGlobalDnsConfig *config)
{
	guint i, j;

	g_return_if_fail (config);

	for (i = 0; i < nm_global_dns_config_get_num_domains (config); i++) {
		NMGlobalDnsDomain *domain = nm_global_dns_config_get_domain (config, i);
		const char *const *servers = nm_global_dns_domain_get_servers (domain);
		const char *name = nm_global_dns_domain_get_name (domain);

		g_return_if_fail (name);

		for (j = 0; servers && servers[j]; j++) {
			if (!strcmp (name, "*"))
				add_dnsmasq_nameserver (self, dnsmasq_servers, servers[j], NULL);
			else
				add_dnsmasq_nameserver (self, dnsmasq_servers, servers[j], name);
		}

	}
}

static void
add_ip_config (NMDnsDnsmasq *self, GVariantBuilder *servers, const NMDnsIPConfigData *ip_data)
{
	NMIPConfig *ip_config = ip_data->ip_config;
	gconstpointer addr;
	const char *iface, *domain;
	char ip_addr_to_string_buf[IP_ADDR_TO_STRING_BUFLEN];
	int addr_family;
	guint i, j, num;

	iface = nm_platform_link_get_name (NM_PLATFORM_GET, ip_data->data->ifindex);
	addr_family = nm_ip_config_get_addr_family (ip_config);

	num = nm_ip_config_get_num_nameservers (ip_config);
	for (i = 0; i < num; i++) {
		addr = nm_ip_config_get_nameserver (ip_config, i);
		ip_addr_to_string (addr_family, addr, iface, ip_addr_to_string_buf);
		for (j = 0; ip_data->domains.search[j]; j++) {
			domain = nm_utils_parse_dns_domain (ip_data->domains.search[j], NULL);
			add_dnsmasq_nameserver (self,
			                        servers,
			                        ip_addr_to_string_buf,
			                        domain[0] ? domain : NULL);
		}

		for (j = 0; ip_data->domains.reverse[j]; j++) {
			add_dnsmasq_nameserver (self, servers,
			                        ip_addr_to_string_buf,
			                        ip_data->domains.reverse[j]);
		}
	}
}

static void
dnsmasq_update_done (GDBusProxy *proxy, GAsyncResult *res, gpointer user_data)
{
	NMDnsDnsmasq *self;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *response = NULL;

	response = g_dbus_proxy_call_finish (proxy, res, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_DNS_DNSMASQ (user_data);

	if (!response)
		_LOGW ("dnsmasq update failed: %s", error->message);
	else
		_LOGD ("dnsmasq update successful");
}

static void
send_dnsmasq_update (NMDnsDnsmasq *self)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	if (!priv->set_server_ex_args)
		return;

	if (priv->running) {
		_LOGD ("trying to update dnsmasq nameservers");

		nm_clear_g_cancellable (&priv->update_cancellable);
		priv->update_cancellable = g_cancellable_new ();

		g_dbus_proxy_call (priv->dnsmasq,
		                   "SetServersEx",
		                   priv->set_server_ex_args,
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->update_cancellable,
		                   (GAsyncReadyCallback) dnsmasq_update_done,
		                   self);
		g_clear_pointer (&priv->set_server_ex_args, g_variant_unref);
	} else
		_LOGD ("dnsmasq not found on the bus. The nameserver update will be sent when dnsmasq appears");
}

static void
name_owner_changed (GObject    *object,
                    GParamSpec *pspec,
                    gpointer    user_data)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (user_data);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	gs_free char *owner = NULL;

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (object));
	if (owner) {
		_LOGI ("dnsmasq appeared as %s", owner);
		priv->running = TRUE;
		send_dnsmasq_update (self);
	} else {
		_LOGI ("dnsmasq disappeared");
		priv->running = FALSE;
		g_signal_emit_by_name (self, NM_DNS_PLUGIN_FAILED);
	}
}

static void
dnsmasq_proxy_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMDnsDnsmasq *self;
	NMDnsDnsmasqPrivate *priv;
	gs_free_error GError *error = NULL;
	gs_free char *owner = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_finish (res, &error);
	if (   !proxy
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	self = NM_DNS_DNSMASQ (user_data);

	if (!proxy) {
		_LOGW ("failed to connect to dnsmasq via DBus: %s", error->message);
		g_signal_emit_by_name (self, NM_DNS_PLUGIN_FAILED);
		return;
	}

	priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	priv->dnsmasq = proxy;
	nm_clear_g_cancellable (&priv->dnsmasq_cancellable);

	_LOGD ("dnsmasq proxy creation successful");

	g_signal_connect (priv->dnsmasq, "notify::g-name-owner",
	                  G_CALLBACK (name_owner_changed), self);
	owner = g_dbus_proxy_get_name_owner (priv->dnsmasq);
	priv->running = (owner != NULL);

	if (priv->running)
		send_dnsmasq_update (self);
}

static void
start_dnsmasq (NMDnsDnsmasq *self)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	const char *dm_binary;
	const char *argv[15];
	GPid pid = 0;
	guint idx = 0;
	NMDBusManager *dbus_mgr;
	GDBusConnection *connection;

	if (priv->running) {
		/* the dnsmasq process is running. Nothing to do. */
		return;
	}

	if (nm_dns_plugin_child_pid ((NMDnsPlugin *) self) > 0) {
		/* if we already have a child process spawned, don't do
		 * it again. */
		return;
	}

	dm_binary = nm_utils_find_helper ("dnsmasq", DNSMASQ_PATH, NULL);
	if (!dm_binary) {
		_LOGW ("could not find dnsmasq binary");
		return;
	}

	argv[idx++] = dm_binary;
	argv[idx++] = "--no-resolv";  /* Use only commandline */
	argv[idx++] = "--keep-in-foreground";
	argv[idx++] = "--no-hosts"; /* don't use /etc/hosts to resolve */
	argv[idx++] = "--bind-interfaces";
	argv[idx++] = "--pid-file=" PIDFILE;
	argv[idx++] = "--listen-address=127.0.0.1"; /* Should work for both 4 and 6 */
	argv[idx++] = "--cache-size=400";
	argv[idx++] = "--clear-on-reload"; /* clear cache when dns server changes */
	argv[idx++] = "--conf-file=/dev/null"; /* avoid loading /etc/dnsmasq.conf */
	argv[idx++] = "--proxy-dnssec"; /* Allow DNSSEC to pass through */
	argv[idx++] = "--enable-dbus=" DNSMASQ_DBUS_SERVICE;

	/* dnsmasq exits if the conf dir is not present */
	if (g_file_test (CONFDIR, G_FILE_TEST_IS_DIR))
		argv[idx++] = "--conf-dir=" CONFDIR;

	argv[idx++] = NULL;
	nm_assert (idx <= G_N_ELEMENTS (argv));

	/* And finally spawn dnsmasq */
	pid = nm_dns_plugin_child_spawn (NM_DNS_PLUGIN (self), argv, PIDFILE, "bin/dnsmasq");
	if (!pid)
		return;

	if (   priv->dnsmasq
	    || priv->dnsmasq_cancellable) {
		/* we already have a proxy or are about to create it.
		 * We are done. */
		return;
	}

	dbus_mgr = nm_dbus_manager_get ();
	g_return_if_fail (dbus_mgr);

	connection = nm_dbus_manager_get_connection (dbus_mgr);
	g_return_if_fail (connection);

	priv->dnsmasq_cancellable = g_cancellable_new ();
	g_dbus_proxy_new (connection,
	                  G_DBUS_PROXY_FLAGS_DO_NOT_AUTO_START,
	                  NULL,
	                  DNSMASQ_DBUS_SERVICE,
	                  DNSMASQ_DBUS_PATH,
	                  DNSMASQ_DBUS_SERVICE,
	                  priv->dnsmasq_cancellable,
	                  dnsmasq_proxy_cb,
	                  self);
}

static gboolean
update (NMDnsPlugin *plugin,
        const NMGlobalDnsConfig *global_config,
        const CList *ip_config_lst_head,
        const char *hostname)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	GVariantBuilder servers;
	const NMDnsIPConfigData *ip_data;

	start_dnsmasq (self);

	g_variant_builder_init (&servers, G_VARIANT_TYPE ("aas"));

	if (global_config)
		add_global_config (self, &servers, global_config);
	else {
		c_list_for_each_entry (ip_data, ip_config_lst_head, ip_config_lst)
			add_ip_config (self, &servers, ip_data);
	}

	g_clear_pointer (&priv->set_server_ex_args, g_variant_unref);
	priv->set_server_ex_args = g_variant_ref_sink (g_variant_new ("(aas)", &servers));

	send_dnsmasq_update (self);

	return TRUE;
}

/*****************************************************************************/

static void
child_quit (NMDnsPlugin *plugin, gint status)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	gboolean failed = TRUE;
	int err;

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err) {
			_LOGW ("dnsmasq exited with error: %s",
			       nm_utils_dnsmasq_status_to_string (err, NULL, 0));
		} else {
			_LOGD ("dnsmasq exited normally");
			failed = FALSE;
		}
	} else if (WIFSTOPPED (status))
		_LOGW ("dnsmasq stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		_LOGW ("dnsmasq died with signal %d", WTERMSIG (status));
	else
		_LOGW ("dnsmasq died from an unknown cause");

	priv->running = FALSE;

	if (failed)
		g_signal_emit_by_name (self, NM_DNS_PLUGIN_FAILED);
}

/*****************************************************************************/

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

/*****************************************************************************/

static void
nm_dns_dnsmasq_init (NMDnsDnsmasq *self)
{
}

NMDnsPlugin *
nm_dns_dnsmasq_new (void)
{
	return g_object_new (NM_TYPE_DNS_DNSMASQ, NULL);
}

static void
dispose (GObject *object)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE ((NMDnsDnsmasq *) object);

	nm_clear_g_cancellable (&priv->dnsmasq_cancellable);
	nm_clear_g_cancellable (&priv->update_cancellable);

	g_clear_object (&priv->dnsmasq);

	g_clear_pointer (&priv->set_server_ex_args, g_variant_unref);

	G_OBJECT_CLASS (nm_dns_dnsmasq_parent_class)->dispose (object);
}

static void
nm_dns_dnsmasq_class_init (NMDnsDnsmasqClass *dns_class)
{
	NMDnsPluginClass *plugin_class = NM_DNS_PLUGIN_CLASS (dns_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dns_class);

	object_class->dispose = dispose;

	plugin_class->child_quit = child_quit;
	plugin_class->is_caching = is_caching;
	plugin_class->update = update;
	plugin_class->get_name = get_name;
}
