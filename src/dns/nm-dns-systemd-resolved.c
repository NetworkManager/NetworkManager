/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * Copyright (C) 2010 Dan Williams <dcbw@redhat.com>
 * Copyright (C) 2016 Sjoerd Simons <sjoerd@luon.net>
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

#include "nm-dns-systemd-resolved.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <linux/if.h>

#include "nm-utils/nm-c-list.h"
#include "nm-core-internal.h"
#include "platform/nm-platform.h"
#include "nm-utils.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-bus-manager.h"
#include "nm-manager.h"
#include "nm-setting-connection.h"
#include "devices/nm-device.h"
#include "NetworkManagerUtils.h"

#define SYSTEMD_RESOLVED_DBUS_SERVICE "org.freedesktop.resolve1"
#define SYSTEMD_RESOLVED_DBUS_PATH "/org/freedesktop/resolve1"

/*****************************************************************************/

typedef struct {
	int ifindex;
	CList configs_lst_head;
} InterfaceConfig;

/*****************************************************************************/

typedef struct {
	GDBusProxy *resolve;
	GCancellable *init_cancellable;
	GCancellable *update_cancellable;
	GCancellable *mdns_cancellable;
	GQueue dns_updates;
	GQueue domain_updates;
} NMDnsSystemdResolvedPrivate;

struct _NMDnsSystemdResolved {
	NMDnsPlugin parent;
	NMDnsSystemdResolvedPrivate _priv;
};

struct _NMDnsSystemdResolvedClass {
	NMDnsPluginClass parent;
};

G_DEFINE_TYPE (NMDnsSystemdResolved, nm_dns_systemd_resolved, NM_TYPE_DNS_PLUGIN)

#define NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMDnsSystemdResolved, NM_IS_DNS_SYSTEMD_RESOLVED)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_DNS
#define _NMLOG(level, ...) __NMLOG_DEFAULT_WITH_ADDR (level, _NMLOG_DOMAIN, "dns-sd-resolved", __VA_ARGS__)

/*****************************************************************************/

static void
_interface_config_free (InterfaceConfig *config)
{
	nm_c_list_elem_free_all (&config->configs_lst_head, NULL);
	g_slice_free (InterfaceConfig, config);
}

static void
call_done (GObject *source, GAsyncResult *r, gpointer user_data)
{
	GVariant *v;
	GError *error = NULL;
	NMDnsSystemdResolved *self = (NMDnsSystemdResolved *) user_data;

	v = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), r, &error);
	if (!v) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			return;
		_LOGW ("Failed: %s\n", error->message);
		g_error_free (error);
	}
}

static void
update_add_ip_config (NMDnsSystemdResolved *self,
                      GVariantBuilder *dns,
                      GVariantBuilder *domains,
                      gpointer config)
{
	int addr_family;
	gsize addr_size;
	guint i, n;
	gboolean route_only;

	if (NM_IS_IP4_CONFIG (config))
		addr_family = AF_INET;
	else if (NM_IS_IP6_CONFIG (config))
		addr_family = AF_INET6;
	else
		g_return_if_reached ();

	addr_size = nm_utils_addr_family_to_size (addr_family);

	n =   addr_family == AF_INET
	    ? nm_ip4_config_get_num_nameservers (config)
	    : nm_ip6_config_get_num_nameservers (config);
	for (i = 0 ; i < n; i++) {
		in_addr_t ns4;
		gconstpointer ns;

		if (addr_family == AF_INET) {
			ns4 = nm_ip4_config_get_nameserver (config, i);
			ns = &ns4;
		} else
			ns = nm_ip6_config_get_nameserver (config, i);

		g_variant_builder_open (dns, G_VARIANT_TYPE ("(iay)"));
		g_variant_builder_add (dns, "i", addr_family);
		g_variant_builder_add_value (dns,
		                             g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                                        ns,
		                                                        addr_size,
		                                                        1));
		g_variant_builder_close (dns);
	}

	/* If this link is never the default (e.g. only used for resources on this
	 * network) add a routing domain. */
	route_only =   addr_family == AF_INET
	             ? !nm_ip4_config_best_default_route_get (config)
	             : !nm_ip6_config_best_default_route_get (config);

	n =   addr_family == AF_INET
	    ? nm_ip4_config_get_num_searches (config)
	    : nm_ip6_config_get_num_searches (config);
	if (n  > 0) {
		for (i = 0; i < n; i++) {
			g_variant_builder_add (domains, "(sb)",
			                       addr_family == AF_INET
			                         ? nm_ip4_config_get_search (config, i)
			                         : nm_ip6_config_get_search (config, i),
			                       route_only);
		}
	} else {
		n =   addr_family == AF_INET
		    ? nm_ip4_config_get_num_domains (config)
		    : nm_ip6_config_get_num_domains (config);
		for (i = 0; i < n; i++) {
			g_variant_builder_add (domains, "(sb)",
			                       addr_family == AF_INET
			                         ? nm_ip4_config_get_domain (config, i)
			                         : nm_ip6_config_get_domain (config, i),
			                       route_only);
		}
	}
}

static void
free_pending_updates (NMDnsSystemdResolved *self)
{
	NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE (self);
	GVariant *v;

	while ((v = g_queue_pop_head (&priv->dns_updates)) != NULL)
		g_variant_unref (v);

	while ((v = g_queue_pop_head (&priv->domain_updates)) != NULL)
		g_variant_unref (v);
}

static void
prepare_one_interface (NMDnsSystemdResolved *self, InterfaceConfig *ic)
{
	NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE (self);
	GVariantBuilder dns, domains;
	NMCListElem *elem;

	g_variant_builder_init (&dns, G_VARIANT_TYPE ("(ia(iay))"));
	g_variant_builder_add (&dns, "i", ic->ifindex);
	g_variant_builder_open (&dns, G_VARIANT_TYPE ("a(iay)"));

	g_variant_builder_init (&domains, G_VARIANT_TYPE ("(ia(sb))"));
	g_variant_builder_add (&domains, "i", ic->ifindex);
	g_variant_builder_open (&domains, G_VARIANT_TYPE ("a(sb)"));

	c_list_for_each_entry (elem, &ic->configs_lst_head, lst)
		update_add_ip_config (self, &dns, &domains, elem->data);

	g_variant_builder_close (&dns);
	g_variant_builder_close (&domains);

	g_queue_push_tail (&priv->dns_updates,
	                   g_variant_ref_sink (g_variant_builder_end (&dns)));
	g_queue_push_tail (&priv->domain_updates,
	                   g_variant_ref_sink (g_variant_builder_end (&domains)));
}

static void
send_updates (NMDnsSystemdResolved *self)
{
	NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE (self);
	GVariant *v;

	nm_clear_g_cancellable (&priv->update_cancellable);

	if (!priv->resolve)
		return;

	priv->update_cancellable = g_cancellable_new ();

	while ((v = g_queue_pop_head (&priv->dns_updates)) != NULL) {
		g_dbus_proxy_call (priv->resolve, "SetLinkDNS", v,
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1, priv->update_cancellable, call_done, self);
		g_variant_unref (v);
	}

	while ((v = g_queue_pop_head (&priv->domain_updates)) != NULL) {
		g_dbus_proxy_call (priv->resolve, "SetLinkDomains", v,
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1, priv->update_cancellable, call_done, self);
		g_variant_unref (v);
	}
}

static gboolean
update (NMDnsPlugin *plugin,
        const GPtrArray *configs,
        const NMGlobalDnsConfig *global_config,
        const char *hostname)
{
	NMDnsSystemdResolved *self = NM_DNS_SYSTEMD_RESOLVED (plugin);
	gs_unref_hashtable GHashTable *interfaces = NULL;
	gs_free gpointer *interfaces_keys = NULL;
	guint interfaces_len;
	guint i;
	int prio, first_prio = 0;

	interfaces = g_hash_table_new_full (nm_direct_hash, NULL,
	                                    NULL, (GDestroyNotify) _interface_config_free);

	for (i = 0; i < configs->len; i++) {
		const NMDnsIPConfigData *data = configs->pdata[i];
		gboolean skip = FALSE;
		InterfaceConfig *ic = NULL;
		int ifindex;

		prio = nm_ip_config_get_dns_priority (data->config);
		if (i == 0)
			first_prio = prio;
		else if (first_prio < 0 && first_prio != prio)
			skip = TRUE;

		ifindex = nm_ip_config_get_ifindex (data->config);

		ic = g_hash_table_lookup (interfaces, GINT_TO_POINTER (ifindex));
		if (!ic) {
			ic = g_slice_new (InterfaceConfig);
			ic->ifindex = ifindex;
			c_list_init (&ic->configs_lst_head);
			g_hash_table_insert (interfaces, GINT_TO_POINTER (ifindex), ic);
		}

		if (!skip) {
			c_list_link_tail (&ic->configs_lst_head,
			                  &nm_c_list_elem_new_stale (data->config)->lst);
		}
	}

	free_pending_updates (self);

	interfaces_keys = g_hash_table_get_keys_as_array (interfaces, &interfaces_len);
	if (interfaces_len > 1) {
		g_qsort_with_data (interfaces_keys,
		                   interfaces_len,
		                   sizeof (gpointer),
		                   nm_cmp_int2ptr_p_with_data,
		                   NULL);
	}
	for (i = 0; i < interfaces_len; i++) {
		InterfaceConfig *ic = g_hash_table_lookup (interfaces, GINT_TO_POINTER (interfaces_keys[i]));

		prepare_one_interface (self, ic);
	}

	send_updates (self);

	return TRUE;
}

static gboolean
update_mdns (NMDnsPlugin *plugin, int ifindex, NMSettingConnectionMdns mdns)
{
	NMDnsSystemdResolved *self = NM_DNS_SYSTEMD_RESOLVED (plugin);
	NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE (self);
	char *value;

	_LOGI ("update_mdns: %i/%d", ifindex, mdns);

	nm_clear_g_cancellable (&priv->mdns_cancellable);

	if (!priv->resolve)
		return FALSE;

	priv->mdns_cancellable = g_cancellable_new ();

	switch (mdns) {
		case NM_SETTING_CONNECTION_MDNS_YES:
			value = "yes";
			break;
		case NM_SETTING_CONNECTION_MDNS_NO:
			value = "no";
			break;
		case NM_SETTING_CONNECTION_MDNS_RESOLVE:
			value = "resolve";
			break;
		default:
			/* reset to system default */
			value = "";
	}

	g_dbus_proxy_call (priv->resolve, "SetLinkMulticastDNS",
                           g_variant_new ("(is)", ifindex, value),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   -1, priv->mdns_cancellable, call_done, self);

	return TRUE;
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
	return "systemd-resolved";
}

/*****************************************************************************/

static void
resolved_proxy_created (GObject *source, GAsyncResult *r, gpointer user_data)
{
	NMDnsSystemdResolved *self = (NMDnsSystemdResolved *) user_data;
	NMDnsSystemdResolvedPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *resolve;

	resolve = g_dbus_proxy_new_finish (r, &error);
	if (   !resolve
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE (self);
	g_clear_object (&priv->init_cancellable);
	if (!resolve) {
		_LOGW ("failed to connect to resolved via DBus: %s", error->message);
		g_signal_emit_by_name (self, NM_DNS_PLUGIN_FAILED);
		return;
	}

	priv->resolve = resolve;
	send_updates (self);
}

/*****************************************************************************/

static void
nm_dns_systemd_resolved_init (NMDnsSystemdResolved *self)
{
	NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE (self);
	NMBusManager *dbus_mgr;
	GDBusConnection *connection;

	g_queue_init (&priv->dns_updates);
	g_queue_init (&priv->domain_updates);

	dbus_mgr = nm_bus_manager_get ();
	g_return_if_fail (dbus_mgr);

	connection = nm_bus_manager_get_connection (dbus_mgr);
	g_return_if_fail (connection);

	priv->init_cancellable = g_cancellable_new ();
	g_dbus_proxy_new (connection,
	                  G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                  G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                  NULL,
	                  SYSTEMD_RESOLVED_DBUS_SERVICE,
	                  SYSTEMD_RESOLVED_DBUS_PATH,
	                  SYSTEMD_RESOLVED_DBUS_SERVICE ".Manager",
	                  priv->init_cancellable,
	                  resolved_proxy_created,
	                  self);
}

NMDnsPlugin *
nm_dns_systemd_resolved_new (void)
{
	return g_object_new (NM_TYPE_DNS_SYSTEMD_RESOLVED, NULL);
}

static void
dispose (GObject *object)
{
	NMDnsSystemdResolved *self = NM_DNS_SYSTEMD_RESOLVED (object);
	NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE (self);

	free_pending_updates (self);
	g_clear_object (&priv->resolve);
	nm_clear_g_cancellable (&priv->init_cancellable);
	nm_clear_g_cancellable (&priv->update_cancellable);
	nm_clear_g_cancellable (&priv->mdns_cancellable);

	G_OBJECT_CLASS (nm_dns_systemd_resolved_parent_class)->dispose (object);
}

static void
nm_dns_systemd_resolved_class_init (NMDnsSystemdResolvedClass *dns_class)
{
	NMDnsPluginClass *plugin_class = NM_DNS_PLUGIN_CLASS (dns_class);
	GObjectClass *object_class = G_OBJECT_CLASS (dns_class);

	object_class->dispose = dispose;

	plugin_class->is_caching = is_caching;
	plugin_class->update = update;
	plugin_class->update_mdns = update_mdns;
	plugin_class->get_name = get_name;
}
