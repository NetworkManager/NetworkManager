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
#include "nm-dbus-manager.h"
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

typedef struct {
	CList request_queue_lst;
	const char *operation;
	GVariant *argument;
} RequestItem;

/*****************************************************************************/

typedef struct {
	GDBusProxy *resolve;
	GCancellable *init_cancellable;
	GCancellable *update_cancellable;
	CList request_queue_lst_head;
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
_request_item_free (RequestItem *request_item)
{
	c_list_unlink_stale (&request_item->request_queue_lst);
	g_variant_unref (request_item->argument);
	g_slice_free (RequestItem, request_item);
}

static void
_request_item_append (CList *request_queue_lst_head,
                      const char *operation,
                      GVariant *argument)
{
	RequestItem *request_item;

	request_item = g_slice_new (RequestItem);
	request_item->operation = operation;
	request_item->argument = g_variant_ref_sink (argument);
	c_list_link_tail (request_queue_lst_head, &request_item->request_queue_lst);
}

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
		_LOGW ("Failed: %s", error->message);
		g_error_free (error);
	}
}

static void
update_add_ip_config (NMDnsSystemdResolved *self,
                      GVariantBuilder *dns,
                      GVariantBuilder *domains,
                      NMDnsIPConfigData *data)
{
	int addr_family;
	gsize addr_size;
	guint i, n;
	gboolean is_routing;
	const char **iter;
	const char *domain;

	addr_family = nm_ip_config_get_addr_family (data->ip_config);
	addr_size = nm_utils_addr_family_to_size (addr_family);

	if (!data->domains.search  || !data->domains.search[0])
		return;

	n = nm_ip_config_get_num_nameservers (data->ip_config);
	for (i = 0 ; i < n; i++) {
		g_variant_builder_open (dns, G_VARIANT_TYPE ("(iay)"));
		g_variant_builder_add (dns, "i", addr_family);
		g_variant_builder_add_value (dns,
		                             g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                                        nm_ip_config_get_nameserver (data->ip_config, i),
		                                                        addr_size,
		                                                        1));
		g_variant_builder_close (dns);
	}

	for (iter = data->domains.search; *iter; iter++) {
		domain = nm_utils_parse_dns_domain (*iter, &is_routing);
		g_variant_builder_add (domains, "(sb)", domain[0] ? domain : ".", is_routing);
	}
}

static void
free_pending_updates (NMDnsSystemdResolved *self)
{
	NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE (self);
	RequestItem *request_item, *request_item_safe;

	c_list_for_each_entry_safe (request_item,
	                            request_item_safe,
	                            &priv->request_queue_lst_head,
	                            request_queue_lst)
		_request_item_free (request_item);
}

static void
prepare_one_interface (NMDnsSystemdResolved *self, InterfaceConfig *ic)
{
	NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE (self);
	GVariantBuilder dns, domains;
	NMCListElem *elem;
	NMSettingConnectionMdns mdns = NM_SETTING_CONNECTION_MDNS_DEFAULT;
	NMSettingConnectionLlmnr llmnr = NM_SETTING_CONNECTION_LLMNR_DEFAULT;
	const char *mdns_arg = NULL, *llmnr_arg = NULL;

	g_variant_builder_init (&dns, G_VARIANT_TYPE ("(ia(iay))"));
	g_variant_builder_add (&dns, "i", ic->ifindex);
	g_variant_builder_open (&dns, G_VARIANT_TYPE ("a(iay)"));

	g_variant_builder_init (&domains, G_VARIANT_TYPE ("(ia(sb))"));
	g_variant_builder_add (&domains, "i", ic->ifindex);
	g_variant_builder_open (&domains, G_VARIANT_TYPE ("a(sb)"));

	c_list_for_each_entry (elem, &ic->configs_lst_head, lst) {
		NMDnsIPConfigData *data = elem->data;
		NMIPConfig *ip_config = data->ip_config;

		update_add_ip_config (self, &dns, &domains, data);

		if (NM_IS_IP4_CONFIG (ip_config)) {
			mdns = NM_MAX (mdns, nm_ip4_config_mdns_get (NM_IP4_CONFIG (ip_config)));
			llmnr = NM_MAX (llmnr, nm_ip4_config_llmnr_get (NM_IP4_CONFIG (ip_config)));
		}
	}

	g_variant_builder_close (&dns);
	g_variant_builder_close (&domains);

	switch (mdns) {
	case NM_SETTING_CONNECTION_MDNS_NO:
		mdns_arg = "no";
		break;
	case NM_SETTING_CONNECTION_MDNS_RESOLVE:
		mdns_arg = "resolve";
		break;
	case NM_SETTING_CONNECTION_MDNS_YES:
		mdns_arg = "yes";
		break;
	case NM_SETTING_CONNECTION_MDNS_DEFAULT:
		mdns_arg = "";
		break;
	}
	nm_assert (mdns_arg);

	switch (llmnr) {
	case NM_SETTING_CONNECTION_LLMNR_NO:
		llmnr_arg = "no";
		break;
	case NM_SETTING_CONNECTION_LLMNR_RESOLVE:
		llmnr_arg = "resolve";
		break;
	case NM_SETTING_CONNECTION_LLMNR_YES:
		llmnr_arg = "yes";
		break;
	case NM_SETTING_CONNECTION_LLMNR_DEFAULT:
		llmnr_arg = "";
		break;
	}
	nm_assert (llmnr_arg);

	_request_item_append (&priv->request_queue_lst_head,
	                      "SetLinkDNS",
	                      g_variant_builder_end (&dns));
	_request_item_append (&priv->request_queue_lst_head,
	                      "SetLinkDomains",
	                      g_variant_builder_end (&domains));
	_request_item_append (&priv->request_queue_lst_head,
	                      "SetLinkMulticastDNS",
	                      g_variant_new ("(is)", ic->ifindex, mdns_arg ?: ""));
	_request_item_append (&priv->request_queue_lst_head,
	                      "SetLinkLLMNR",
	                      g_variant_new ("(is)", ic->ifindex, llmnr_arg ?: ""));
}

static void
send_updates (NMDnsSystemdResolved *self)
{
	NMDnsSystemdResolvedPrivate *priv = NM_DNS_SYSTEMD_RESOLVED_GET_PRIVATE (self);
	RequestItem *request_item, *request_item_safe;

	nm_clear_g_cancellable (&priv->update_cancellable);

	if (!priv->resolve)
		return;

	priv->update_cancellable = g_cancellable_new ();

	c_list_for_each_entry_safe (request_item,
	                            request_item_safe,
	                            &priv->request_queue_lst_head,
	                            request_queue_lst) {
		g_dbus_proxy_call (priv->resolve,
		                   request_item->operation,
		                   request_item->argument,
		                   G_DBUS_CALL_FLAGS_NONE,
		                   -1,
		                   priv->update_cancellable,
		                   call_done,
		                   self);
		_request_item_free (request_item);
	}
}

static gboolean
update (NMDnsPlugin *plugin,
        const NMGlobalDnsConfig *global_config,
        const CList *ip_config_lst_head,
        const char *hostname)
{
	NMDnsSystemdResolved *self = NM_DNS_SYSTEMD_RESOLVED (plugin);
	gs_unref_hashtable GHashTable *interfaces = NULL;
	gs_free gpointer *interfaces_keys = NULL;
	guint interfaces_len;
	guint i;
	NMDnsIPConfigData *ip_data;

	interfaces = g_hash_table_new_full (nm_direct_hash, NULL,
	                                    NULL, (GDestroyNotify) _interface_config_free);

	c_list_for_each_entry (ip_data, ip_config_lst_head, ip_config_lst) {
		InterfaceConfig *ic = NULL;
		int ifindex;

		ifindex = ip_data->data->ifindex;
		nm_assert (ifindex == nm_ip_config_get_ifindex (ip_data->ip_config));

		ic = g_hash_table_lookup (interfaces, GINT_TO_POINTER (ifindex));
		if (!ic) {
			ic = g_slice_new (InterfaceConfig);
			ic->ifindex = ifindex;
			c_list_init (&ic->configs_lst_head);
			g_hash_table_insert (interfaces, GINT_TO_POINTER (ifindex), ic);
		}

		c_list_link_tail (&ic->configs_lst_head,
		                  &nm_c_list_elem_new_stale (ip_data)->lst);
	}

	free_pending_updates (self);

	interfaces_keys = nm_utils_hash_keys_to_array (interfaces,
	                                               nm_cmp_int2ptr_p_with_data,
	                                               NULL,
	                                               &interfaces_len);
	for (i = 0; i < interfaces_len; i++) {
		InterfaceConfig *ic = g_hash_table_lookup (interfaces, GINT_TO_POINTER (interfaces_keys[i]));

		prepare_one_interface (self, ic);
	}

	send_updates (self);

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

	c_list_init (&priv->request_queue_lst_head);

	priv->init_cancellable = g_cancellable_new ();
	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
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
	plugin_class->get_name = get_name;
}
