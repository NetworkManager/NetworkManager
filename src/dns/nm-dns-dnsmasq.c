// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2010 Dan Williams <dcbw@redhat.com>
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

	GPid pid;
	guint watch_id;
	char *progname;
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
kill_existing (const char *progname, const char *pidfile, const char *kill_match)
{
	long pid;
	gs_free char *contents = NULL;
	gs_free char *cmdline_contents = NULL;
	guint64 start_time;
	char proc_path[256];
	gs_free_error GError *error = NULL;

	if (!pidfile)
		return;

	if (!kill_match)
		g_return_if_reached ();

	if (!g_file_get_contents (pidfile, &contents, NULL, &error)) {
		if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT))
			return;
		goto out;
	}

	pid = _nm_utils_ascii_str_to_int64 (contents, 10, 2, INT_MAX, -1);
	if (pid == -1)
		goto out;

	start_time = nm_utils_get_start_time_for_pid (pid, NULL, NULL);
	if (start_time == 0)
		goto out;

	nm_sprintf_buf (proc_path, "/proc/%ld/cmdline", pid);
	if (!g_file_get_contents (proc_path, &cmdline_contents, NULL, NULL))
		goto out;

	if (!strstr (cmdline_contents, kill_match))
		goto out;

	nm_utils_kill_process_sync (pid, start_time, SIGKILL, _NMLOG_DOMAIN,
	                            progname ?: "<dns-process>",
	                            0, 0, 1000);

out:
	unlink (pidfile);
}

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

		if (ip_data->domains.reverse) {
			for (j = 0; ip_data->domains.reverse[j]; j++) {
				add_dnsmasq_nameserver (self, servers,
				                        ip_addr_to_string_buf,
				                        ip_data->domains.reverse[j]);
			}
		}
	}
}

static GVariant *
create_update_args (NMDnsDnsmasq *self,
                    const NMGlobalDnsConfig *global_config,
                    const CList *ip_config_lst_head,
                    const char *hostname)
{
	GVariantBuilder servers;
	const NMDnsIPConfigData *ip_data;

	g_variant_builder_init (&servers, G_VARIANT_TYPE ("aas"));

	if (global_config)
		add_global_config (self, &servers, global_config);
	else {
		c_list_for_each_entry (ip_data, ip_config_lst_head, ip_config_lst)
			add_ip_config (self, &servers, ip_data);
	}

	return g_variant_new ("(aas)", &servers);
}

/*****************************************************************************/

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
		if (priv->running) {
			_LOGI ("dnsmasq disappeared");
			priv->running = FALSE;
			_nm_dns_plugin_emit_failed (self, FALSE);
		} else {
			/* The only reason for which (!priv->running) here
			 * is that the dnsmasq process quit. We don't care
			 * of that here, the manager handles child restarts
			 * by itself. */
		}
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
		_nm_dns_plugin_emit_failed (self, FALSE);
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
watch_cb (GPid pid, int status, gpointer user_data)
{
	NMDnsDnsmasq *self = user_data;
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	int err;

	priv->pid = 0;
	priv->watch_id = 0;
	g_clear_pointer (&priv->progname, g_free);
	(void) unlink (PIDFILE);

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err) {
			_LOGW ("dnsmasq exited with error: %s",
			       nm_utils_dnsmasq_status_to_string (err, NULL, 0));
		} else
			_LOGD ("dnsmasq exited normally");
	} else if (WIFSTOPPED (status))
		_LOGW ("dnsmasq stopped unexpectedly with signal %d", WSTOPSIG (status));
	else if (WIFSIGNALED (status))
		_LOGW ("dnsmasq died with signal %d", WTERMSIG (status));
	else
		_LOGW ("dnsmasq died from an unknown cause");

	priv->running = FALSE;

	_nm_dns_plugin_emit_failed (self, TRUE);
}

static void
start_dnsmasq (NMDnsDnsmasq *self)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);
	gs_free_error GError *local = NULL;
	const char *dm_binary;
	const char *argv[15];
	GPid pid = 0;
	guint idx = 0;
	gs_free char *cmdline = NULL;
	gs_free char *progname = NULL;

	if (priv->running) {
		/* the dnsmasq process is running. Nothing to do. */
		return;
	}

	if (priv->pid > 0) {
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

	nm_assert (priv->pid == 0);
	nm_assert (!priv->progname);
	nm_assert (!priv->watch_id);

	progname = g_path_get_basename (argv[0]);
	kill_existing (progname, PIDFILE, "bin/dnsmasq");

	_LOGI ("starting %s...", progname);
	_LOGD ("command line: %s",
	       (cmdline = g_strjoinv (" ", (char **) argv)));

	if (!g_spawn_async (NULL,
	                    (char **) argv,
	                    NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD,
	                    nm_utils_setpgid,
	                    NULL,
	                    &pid,
	                    &local)) {
		_LOGW ("failed to spawn dnsmasq: %s", local->message);
		return;
	}

	_LOGD ("%s started with pid %d", progname, pid);
	priv->watch_id = g_child_watch_add (pid, (GChildWatchFunc) watch_cb, self);
	priv->pid = pid;
	priv->progname = g_steal_pointer (&progname);

	if (   priv->dnsmasq
	    || priv->dnsmasq_cancellable) {
		/* we already have a proxy or are about to create it.
		 * We are done. */
		return;
	}

	priv->dnsmasq_cancellable = g_cancellable_new ();
	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
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
        const char *hostname,
        GError **error)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	start_dnsmasq (self);

	nm_clear_pointer (&priv->set_server_ex_args, g_variant_unref);
	priv->set_server_ex_args = g_variant_ref_sink (create_update_args (self,
	                                                                   global_config,
	                                                                   ip_config_lst_head,
	                                                                   hostname));

	send_dnsmasq_update (self);
	return TRUE;
}

/*****************************************************************************/

static void
kill_child (NMDnsDnsmasq *self)
{
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	nm_clear_g_source (&priv->watch_id);
	if (priv->pid) {
		nm_utils_kill_child_sync (priv->pid, SIGTERM, _NMLOG_DOMAIN,
		                          priv->progname ?: "<dns-process>", NULL, 1000, 0);
		priv->pid = 0;
		g_clear_pointer (&priv->progname, g_free);
	}
	(void) unlink (PIDFILE);
}

static void
stop (NMDnsPlugin *plugin)
{
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (plugin);

	kill_child (self);
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
	NMDnsDnsmasq *self = NM_DNS_DNSMASQ (object);
	NMDnsDnsmasqPrivate *priv = NM_DNS_DNSMASQ_GET_PRIVATE (self);

	kill_child (self);

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

	plugin_class->plugin_name = "dnsmasq";
	plugin_class->is_caching  = TRUE;
	plugin_class->stop        = stop;
	plugin_class->update      = update;
}
