/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager
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
 * (C) Copyright 2016 Atul Anand <atulhjp@gmail.com>.
 */

#include "nm-default.h"

#include "nm-pacrunner-manager.h"

#include "nm-utils.h"
#include "platform/nm-platform.h"
#include "nm-proxy-config.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"

static void pacrunner_remove_done (GDBusProxy *proxy, GAsyncResult *res, gpointer user_data);

#define PACRUNNER_DBUS_SERVICE "org.pacrunner"
#define PACRUNNER_DBUS_INTERFACE "org.pacrunner.Manager"
#define PACRUNNER_DBUS_PATH "/org/pacrunner/manager"

/*****************************************************************************/

typedef struct {
	char *tag;
	NMPacrunnerManager *manager;
	GVariant *args;
	char *path;
	guint refcount;
	bool removed;
} Config;

typedef struct {
	char *iface;
	GDBusProxy *pacrunner;
	GCancellable *pacrunner_cancellable;
	GList *configs;
} NMPacrunnerManagerPrivate;

struct _NMPacrunnerManager {
	GObject parent;
	NMPacrunnerManagerPrivate _priv;
};

struct _NMPacrunnerManagerClass {
	GObjectClass parent;
};

G_DEFINE_TYPE (NMPacrunnerManager, nm_pacrunner_manager, G_TYPE_OBJECT)

#define NM_PACRUNNER_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMPacrunnerManager, NM_IS_PACRUNNER_MANAGER)

/*****************************************************************************/

NM_DEFINE_SINGLETON_GETTER (NMPacrunnerManager, nm_pacrunner_manager_get, NM_TYPE_PACRUNNER_MANAGER);

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_PROXY
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "pacrunner", __VA_ARGS__)

/*****************************************************************************/

static Config *
config_new (NMPacrunnerManager *manager, char *tag, GVariant *args)
{
	Config *config;

	config = g_slice_new0 (Config);
	config->manager = manager;
	config->tag = tag;
	config->args = g_variant_ref_sink (args);
	config->refcount = 1;

	return config;
}

static void
config_ref (Config *config)
{
	g_assert (config);
	g_assert (config->refcount > 0);

	config->refcount++;
}

static void
config_unref (Config *config)
{
	g_assert (config);
	g_assert (config->refcount > 0);

	if (config->refcount == 1) {
		g_free (config->tag);
		g_variant_unref (config->args);
		g_free (config->path);
		g_slice_free (Config, config);
	} else
		config->refcount--;
}

static void
add_proxy_config (GVariantBuilder *proxy_data, const NMProxyConfig *proxy_config)
{
	const char *pac_url, *pac_script;
	NMProxyConfigMethod method;

	method = nm_proxy_config_get_method (proxy_config);

	if (method == NM_PROXY_CONFIG_METHOD_AUTO) {
		pac_url = nm_proxy_config_get_pac_url (proxy_config);
		if (pac_url) {
			g_variant_builder_add (proxy_data, "{sv}",
			                       "URL",
			                       g_variant_new_string (pac_url));
		}

		pac_script = nm_proxy_config_get_pac_script (proxy_config);
		if (pac_script) {
			g_variant_builder_add (proxy_data, "{sv}",
			                       "Script",
			                       g_variant_new_string (pac_script));
		}
	}

	g_variant_builder_add (proxy_data, "{sv}",
	                       "BrowserOnly",
	                       g_variant_new_boolean (nm_proxy_config_get_browser_only (proxy_config)));
}

static void
get_ip4_domains (GPtrArray *domains, NMIP4Config *ip4)
{
	char *cidr;
	int i;

	/* Extract searches */
	for (i = 0; i < nm_ip4_config_get_num_searches (ip4); i++)
		g_ptr_array_add (domains, g_strdup (nm_ip4_config_get_search (ip4, i)));

	/* Extract domains */
	for (i = 0; i < nm_ip4_config_get_num_domains (ip4); i++)
		g_ptr_array_add (domains, g_strdup (nm_ip4_config_get_domain (ip4, i)));

	/* Add addresses and routes in CIDR form */
	for (i = 0; i < nm_ip4_config_get_num_addresses (ip4); i++) {
		const NMPlatformIP4Address *address = nm_ip4_config_get_address (ip4, i);

		cidr = g_strdup_printf ("%s/%u",
		                        nm_utils_inet4_ntop (address->address, NULL),
		                        address->plen);
		g_ptr_array_add (domains, cidr);
	}

	for (i = 0; i < nm_ip4_config_get_num_routes (ip4); i++) {
		const NMPlatformIP4Route *routes = nm_ip4_config_get_route (ip4, i);

		cidr = g_strdup_printf ("%s/%u",
		                        nm_utils_inet4_ntop (routes->network, NULL),
		                        routes->plen);
		g_ptr_array_add (domains, cidr);
	}
}

static void
get_ip6_domains (GPtrArray *domains, NMIP6Config *ip6)
{
	char *cidr;
	int i;

	/* Extract searches */
	for (i = 0; i < nm_ip6_config_get_num_searches (ip6); i++)
		g_ptr_array_add (domains, g_strdup (nm_ip6_config_get_search (ip6, i)));

	/* Extract domains */
	for (i = 0; i < nm_ip6_config_get_num_domains (ip6); i++)
		g_ptr_array_add (domains, g_strdup (nm_ip6_config_get_domain (ip6, i)));

	/* Add addresses and routes in CIDR form */
	for (i = 0; i < nm_ip6_config_get_num_addresses (ip6); i++) {
		const NMPlatformIP6Address *address = nm_ip6_config_get_address (ip6, i);

		cidr = g_strdup_printf ("%s/%u",
		                        nm_utils_inet6_ntop (&address->address, NULL),
		                        address->plen);
		g_ptr_array_add (domains, cidr);
	}

	for (i = 0; i < nm_ip6_config_get_num_routes (ip6); i++) {
		const NMPlatformIP6Route *routes = nm_ip6_config_get_route (ip6, i);

		cidr = g_strdup_printf ("%s/%u",
		                        nm_utils_inet6_ntop (&routes->network, NULL),
		                        routes->plen);
		g_ptr_array_add (domains, cidr);
	}
}

static void
pacrunner_send_done (GDBusProxy *proxy, GAsyncResult *res, gpointer user_data)
{
	Config *config = user_data;
	NMPacrunnerManager *self;
	NMPacrunnerManagerPrivate *priv;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *variant = NULL;
	const char *path = NULL;

	g_return_if_fail (!config->path);

	variant = g_dbus_proxy_call_finish (proxy, res, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		config_unref (config);
		return;
	}

	self = NM_PACRUNNER_MANAGER (config->manager);
	priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	if (!variant) {
		_LOGD ("send config for '%s' failed: %s", config->tag, error->message);
	} else {
		g_variant_get (variant, "(&o)", &path);

		config->path = g_strdup (path);
		_LOGD ("successfully sent config for '%s'", config->tag);

		if (config->removed) {
			g_dbus_proxy_call (priv->pacrunner,
			                   "DestroyProxyConfiguration",
			                   g_variant_new ("(o)", config->path),
			                   G_DBUS_CALL_FLAGS_NO_AUTO_START,
			                   -1,
			                   priv->pacrunner_cancellable,
			                   (GAsyncReadyCallback) pacrunner_remove_done,
			                   config);
		}
	}
	config_unref (config);
}

static void
pacrunner_send_config (NMPacrunnerManager *self, Config *config)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	if (priv->pacrunner) {
		gs_free char *args_str = NULL;

		_LOGT ("sending proxy config for '%s': %s", config->tag,
		       (args_str = g_variant_print (config->args, FALSE)));

		config_ref (config);
		g_clear_pointer (&config->path, g_free);

		g_dbus_proxy_call (priv->pacrunner,
		                   "CreateProxyConfiguration",
		                   config->args,
		                   G_DBUS_CALL_FLAGS_NO_AUTO_START,
		                   -1,
		                   priv->pacrunner_cancellable,
		                   (GAsyncReadyCallback) pacrunner_send_done,
		                   config);
	}
}

static void
name_owner_changed (GObject *object,
                    GParamSpec *pspec,
                    gpointer user_data)
{
	NMPacrunnerManager *self = NM_PACRUNNER_MANAGER (user_data);
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);
	gs_free char *owner = NULL;
	GList *iter = NULL;

	owner = g_dbus_proxy_get_name_owner (G_DBUS_PROXY (object));
	if (owner) {
		_LOGD ("name owner appeared (%s)", owner);
		for (iter = g_list_first (priv->configs); iter; iter = g_list_next (iter))
			pacrunner_send_config (self, iter->data);
	} else {
		_LOGD ("name owner disappeared");
	}
}

static void
pacrunner_proxy_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMPacrunnerManager *self = user_data;
	NMPacrunnerManagerPrivate *priv;
	GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (res, &error);
	if (!proxy) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			_LOGW ("failed to connect to pacrunner via DBus: %s", error->message);
		g_error_free (error);
		return;
	}

	priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	priv->pacrunner = proxy;
	nm_clear_g_cancellable (&priv->pacrunner_cancellable);

	g_signal_connect (priv->pacrunner, "notify::g-name-owner",
	                  G_CALLBACK (name_owner_changed), self);
}

/**
 * nm_pacrunner_manager_send:
 * @self: the #NMPacrunnerManager
 * @iface: the iface for the connection or %NULL
 * @tag: unique configuration identifier
 * @proxy_config: proxy config of the connection
 * @ip4_config: IP4 config of the connection to extract domain info from
 * @ip6_config: IP6 config of the connection to extract domain info from
 */
void
nm_pacrunner_manager_send (NMPacrunnerManager *self,
                           const char *iface,
                           const char *tag,
                           NMProxyConfig *proxy_config,
                           NMIP4Config *ip4_config,
                           NMIP6Config *ip6_config)
{
	char **strv = NULL;
	NMProxyConfigMethod method;
	NMPacrunnerManagerPrivate *priv;
	GVariantBuilder proxy_data;
	GPtrArray *domains;
	Config *config;

	g_return_if_fail (NM_IS_PACRUNNER_MANAGER (self));
	g_return_if_fail (proxy_config);

	priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	g_free (priv->iface);
	priv->iface = g_strdup (iface);

	g_variant_builder_init (&proxy_data, G_VARIANT_TYPE_VARDICT);

	if (iface) {
		g_variant_builder_add (&proxy_data, "{sv}",
		                       "Interface",
		                       g_variant_new_string (iface));
	}

	method = nm_proxy_config_get_method (proxy_config);
	switch (method) {
	case NM_PROXY_CONFIG_METHOD_AUTO:
		g_variant_builder_add (&proxy_data, "{sv}",
		                       "Method",
		                       g_variant_new_string ("auto"));

		break;
	case NM_PROXY_CONFIG_METHOD_NONE:
		g_variant_builder_add (&proxy_data, "{sv}",
		                       "Method",
		                       g_variant_new_string ("direct"));
	}


	/* Extract stuff from configs */
	add_proxy_config (&proxy_data, proxy_config);

	if (ip4_config || ip6_config) {
		domains = g_ptr_array_new_with_free_func (g_free);

		if (ip4_config)
			get_ip4_domains (domains, ip4_config);
		if (ip6_config)
			get_ip6_domains (domains, ip6_config);

		g_ptr_array_add (domains, NULL);
		strv = (char **) g_ptr_array_free (domains, (domains->len == 1));

		if (strv) {
			g_variant_builder_add (&proxy_data, "{sv}",
			                       "Domains",
			                       g_variant_new_strv ((const char *const *) strv, -1));
			g_strfreev (strv);
		}
	}

	config = config_new (self, g_strdup (tag),
	                     g_variant_new ("(a{sv})", &proxy_data));
	priv->configs = g_list_append (priv->configs, config);

	/* Send if pacrunner is available on bus, otherwise
	 * config has already been appended above to be
	 * sent when pacrunner appears.
	 */
	pacrunner_send_config (self, config);
}

static void
pacrunner_remove_done (GDBusProxy *proxy, GAsyncResult *res, gpointer user_data)
{
	Config *config = user_data;
	NMPacrunnerManager *self;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *ret = NULL;

	ret = g_dbus_proxy_call_finish (proxy, res, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		config_unref (config);
		return;
	}

	self = NM_PACRUNNER_MANAGER (config->manager);

	if (!ret)
		_LOGD ("couldn't remove config for '%s': %s", config->tag, error->message);
	else
		_LOGD ("successfully removed config for '%s'", config->tag);

	config_unref (config);
}

/**
 * nm_pacrunner_manager_remove:
 * @self: the #NMPacrunnerManager
 * @iface: the iface for the connection to be removed
 * from pacrunner
 */
void
nm_pacrunner_manager_remove (NMPacrunnerManager *self, const char *tag)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);
	GList *list;

	g_return_if_fail (tag);

	_LOGT ("removing config for '%s'", tag);

	for (list = g_list_first (priv->configs); list; list = g_list_next (list)) {
		Config *config = list->data;

		if (nm_streq (config->tag, tag)) {
			if (priv->pacrunner) {
				if (!config->path) {
					/* send() failed or is still pending. Mark the item as
					 * removed, so that we ask pacrunner to drop it when the
					 * send() completes.
					 */
					config->removed = TRUE;
					config_unref (config);
				} else {
					g_dbus_proxy_call (priv->pacrunner,
					                   "DestroyProxyConfiguration",
					                   g_variant_new ("(o)", config->path),
					                   G_DBUS_CALL_FLAGS_NO_AUTO_START,
					                   -1,
					                   priv->pacrunner_cancellable,
					                   (GAsyncReadyCallback) pacrunner_remove_done,
					                   config);
				}
			} else
				config_unref (config);
			priv->configs = g_list_delete_link (priv->configs, list);
			return;
		}
	}
	/* bug, remove() should always match a previous send() for a given tag */
	g_return_if_reached ();
}

/*****************************************************************************/

static void
nm_pacrunner_manager_init (NMPacrunnerManager *self)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	priv->pacrunner_cancellable = g_cancellable_new ();

	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_NONE,
	                          NULL,
	                          PACRUNNER_DBUS_SERVICE,
	                          PACRUNNER_DBUS_PATH,
	                          PACRUNNER_DBUS_INTERFACE,
	                          priv->pacrunner_cancellable,
	                          (GAsyncReadyCallback) pacrunner_proxy_cb,
	                          self);
}

static void
dispose (GObject *object)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE ((NMPacrunnerManager *) object);

	g_clear_pointer (&priv->iface, g_free);
	nm_clear_g_cancellable (&priv->pacrunner_cancellable);
	g_clear_object (&priv->pacrunner);

	g_list_free_full (priv->configs, (GDestroyNotify) config_unref);
	priv->configs = NULL;

	G_OBJECT_CLASS (nm_pacrunner_manager_parent_class)->dispose (object);
}

static void
nm_pacrunner_manager_class_init (NMPacrunnerManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;
}
