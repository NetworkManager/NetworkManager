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
#include "nm-utils/c-list.h"

#define PACRUNNER_DBUS_SERVICE "org.pacrunner"
#define PACRUNNER_DBUS_INTERFACE "org.pacrunner.Manager"
#define PACRUNNER_DBUS_PATH "/org/pacrunner/manager"

/*****************************************************************************/

struct _NMPacrunnerCallId {
	CList lst;

	/* this might be a dangling pointer after the async operation
	 * is cancelled. */
	NMPacrunnerManager *manager_maybe_dangling;

	GVariant *args;
	char *path;
	guint refcount;
};

typedef struct _NMPacrunnerCallId Config;

typedef struct {
	char *iface;
	GDBusProxy *pacrunner;
	GCancellable *cancellable;
	CList configs;
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

#define _NMLOG2_PREFIX_NAME "pacrunner"
#define _NMLOG2(level, config, ...) \
	G_STMT_START { \
		nm_log ((level), _NMLOG_DOMAIN, NULL, NULL, \
		        "%s%p]: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
		        _NMLOG2_PREFIX_NAME": call[", \
		        (config) \
		        _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
	} G_STMT_END

/*****************************************************************************/

static void pacrunner_remove_done (GObject *source, GAsyncResult *res, gpointer user_data);

/*****************************************************************************/

static Config *
config_new (NMPacrunnerManager *manager, GVariant *args)
{
	Config *config;

	config = g_slice_new0 (Config);
	config->manager_maybe_dangling = manager;
	config->args = g_variant_ref_sink (args);
	config->refcount = 1;
	c_list_link_tail (&NM_PACRUNNER_MANAGER_GET_PRIVATE (manager)->configs,
	                  &config->lst);

	return config;
}

static Config *
config_ref (Config *config)
{
	nm_assert (config);
	nm_assert (config->refcount > 0);

	config->refcount++;
	return config;
}

static void
config_unref (Config *config)
{
	nm_assert (config);
	nm_assert (config->refcount > 0);

	if (config->refcount == 1) {
		g_variant_unref (config->args);
		g_free (config->path);
		c_list_unlink_stale (&config->lst);
		g_slice_free (Config, config);
	} else
		config->refcount--;
}

/*****************************************************************************/

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
	NMDedupMultiIter ipconf_iter;
	char *cidr;
	const NMPlatformIP4Address *address;
	const NMPlatformIP4Route *routes;
	guint i;

	/* Extract searches */
	for (i = 0; i < nm_ip4_config_get_num_searches (ip4); i++)
		g_ptr_array_add (domains, g_strdup (nm_ip4_config_get_search (ip4, i)));

	/* Extract domains */
	for (i = 0; i < nm_ip4_config_get_num_domains (ip4); i++)
		g_ptr_array_add (domains, g_strdup (nm_ip4_config_get_domain (ip4, i)));

	/* Add addresses and routes in CIDR form */

	nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, ip4, &address) {
		cidr = g_strdup_printf ("%s/%u",
		                        nm_utils_inet4_ntop (address->address, NULL),
		                        address->plen);
		g_ptr_array_add (domains, cidr);
	}

	nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, ip4, &routes) {
		if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (routes))
			continue;
		cidr = g_strdup_printf ("%s/%u",
		                        nm_utils_inet4_ntop (routes->network, NULL),
		                        routes->plen);
		g_ptr_array_add (domains, cidr);
	}
}

static void
get_ip6_domains (GPtrArray *domains, NMIP6Config *ip6)
{
	NMDedupMultiIter ipconf_iter;
	char *cidr;
	const NMPlatformIP6Address *address;
	const NMPlatformIP6Route *routes;
	guint i;

	/* Extract searches */
	for (i = 0; i < nm_ip6_config_get_num_searches (ip6); i++)
		g_ptr_array_add (domains, g_strdup (nm_ip6_config_get_search (ip6, i)));

	/* Extract domains */
	for (i = 0; i < nm_ip6_config_get_num_domains (ip6); i++)
		g_ptr_array_add (domains, g_strdup (nm_ip6_config_get_domain (ip6, i)));

	/* Add addresses and routes in CIDR form */
	nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, ip6, &address) {
		cidr = g_strdup_printf ("%s/%u",
		                        nm_utils_inet6_ntop (&address->address, NULL),
		                        address->plen);
		g_ptr_array_add (domains, cidr);
	}

	nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, ip6, &routes) {
		if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (routes))
			continue;
		cidr = g_strdup_printf ("%s/%u",
		                        nm_utils_inet6_ntop (&routes->network, NULL),
		                        routes->plen);
		g_ptr_array_add (domains, cidr);
	}
}

/*****************************************************************************/

static GCancellable *
_ensure_cancellable (NMPacrunnerManagerPrivate *priv)
{
	if (G_UNLIKELY (!priv->cancellable))
		priv->cancellable = g_cancellable_new ();
	return priv->cancellable;
}

static void
pacrunner_send_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
	Config *config = user_data;
	NMPacrunnerManager *self;
	NMPacrunnerManagerPrivate *priv;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *variant = NULL;
	const char *path = NULL;

	nm_assert (!config->path);

	variant = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), res, &error);
	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		goto out;

	self = NM_PACRUNNER_MANAGER (config->manager_maybe_dangling);
	priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	if (!variant)
		_LOG2D (config, "sending failed: %s", error->message);
	else {
		g_variant_get (variant, "(&o)", &path);

		if (c_list_is_empty (&config->lst)) {
			_LOG2D (config, "sent (%s), but destory it right away", path);
			g_dbus_proxy_call (priv->pacrunner,
			                   "DestroyProxyConfiguration",
			                   g_variant_new ("(o)", path),
			                   G_DBUS_CALL_FLAGS_NO_AUTO_START,
			                   -1,
			                   _ensure_cancellable (priv),
			                   pacrunner_remove_done,
			                   config_ref (config));
		} else {
			_LOG2D (config, "sent (%s)", path);
			config->path = g_strdup (path);
		}
	}

out:
	config_unref (config);
}

static void
pacrunner_send_config (NMPacrunnerManager *self, Config *config)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	if (priv->pacrunner) {
		_LOG2T (config, "sending...");

		nm_assert (!config->path);
		g_dbus_proxy_call (priv->pacrunner,
		                   "CreateProxyConfiguration",
		                   config->args,
		                   G_DBUS_CALL_FLAGS_NO_AUTO_START,
		                   -1,
		                   _ensure_cancellable (priv),
		                   pacrunner_send_done,
		                   config_ref (config));
	}
}

static void
name_owner_changed (NMPacrunnerManager *self)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);
	gs_free char *owner = NULL;
	CList *iter;

	owner = g_dbus_proxy_get_name_owner (priv->pacrunner);
	if (owner) {
		_LOGD ("name owner appeared (%s)", owner);
		c_list_for_each (iter, &priv->configs)
			pacrunner_send_config (self, c_list_entry (iter, Config, lst));
	} else {
		_LOGD ("name owner disappeared");
		nm_clear_g_cancellable (&priv->cancellable);
		c_list_for_each (iter, &priv->configs)
			nm_clear_g_free (&c_list_entry (iter, Config, lst)->path);
	}
}

static void
name_owner_changed_cb (GObject *object,
                       GParamSpec *pspec,
                       gpointer user_data)
{
	name_owner_changed (user_data);
}

static void
pacrunner_proxy_cb (GObject *source, GAsyncResult *res, gpointer user_data)
{
	NMPacrunnerManager *self = user_data;
	NMPacrunnerManagerPrivate *priv;
	gs_free_error GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (res, &error);
	if (!proxy) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			_LOGE ("failed to create D-Bus proxy for pacrunner: %s", error->message);
		return;
	}

	priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	priv->pacrunner = proxy;
	g_signal_connect (priv->pacrunner, "notify::g-name-owner",
	                  G_CALLBACK (name_owner_changed_cb), self);
	name_owner_changed (self);
}

/**
 * nm_pacrunner_manager_send:
 * @self: the #NMPacrunnerManager
 * @iface: the iface for the connection or %NULL
 * @proxy_config: proxy config of the connection
 * @ip4_config: IP4 config of the connection to extract domain info from
 * @ip6_config: IP6 config of the connection to extract domain info from
 *
 * Returns: a #NMPacrunnerCallId call id. The function cannot
 *  fail and always returns a non NULL pointer. The call-id may
 *  be used to remove the configuration later via nm_pacrunner_manager_remove().
 *  Note that the call-id does not keep the @self instance alive.
 *  If you plan to remove the configuration later, you must keep
 *  the instance alive long enough. You can remove the configuration
 *  at most once using this call call-id.
 */
NMPacrunnerCallId *
nm_pacrunner_manager_send (NMPacrunnerManager *self,
                           const char *iface,
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

	g_return_val_if_fail (NM_IS_PACRUNNER_MANAGER (self), NULL);
	g_return_val_if_fail (proxy_config, NULL);

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

	config = config_new (self, g_variant_new ("(a{sv})", &proxy_data));

	{
		gs_free char *args_str = NULL;

		_LOG2D (config, "send: new config %s",
		        (args_str = g_variant_print (config->args, FALSE)));
	}

	/* Send if pacrunner is available on bus, otherwise
	 * config has already been appended above to be
	 * sent when pacrunner appears.
	 */
	pacrunner_send_config (self, config);

	return config;
}

static void
pacrunner_remove_done (GObject *source, GAsyncResult *res, gpointer user_data)
{
	Config *config = user_data;
	NMPacrunnerManager *self;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *ret = NULL;

	ret = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), res, &error);
	if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		goto out;

	self = NM_PACRUNNER_MANAGER (config->manager_maybe_dangling);
	if (!ret)
		_LOG2D (config, "remove failed: %s", error->message);
	else
		_LOG2D (config, "removed");

out:
	config_unref (config);
}

/**
 * nm_pacrunner_manager_remove:
 * @self: the #NMPacrunnerManager
 * @call_id: the call-id obtained from nm_pacrunner_manager_send()
 */
void
nm_pacrunner_manager_remove (NMPacrunnerManager *self, NMPacrunnerCallId *call_id)
{
	NMPacrunnerManagerPrivate *priv;
	Config *config;

	g_return_if_fail (NM_IS_PACRUNNER_MANAGER (self));
	g_return_if_fail (call_id);

	config = call_id;
	priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	_LOG2T (config, "removing...");

	nm_assert (c_list_contains (&priv->configs, &config->lst));

	if (priv->pacrunner) {
		if (!config->path) {
			/* send() failed or is still pending. The item is unlinked from
			 * priv->configs, so pacrunner_send_done() knows to call
			 * DestroyProxyConfiguration right away.
			 */
		} else {
			g_dbus_proxy_call (priv->pacrunner,
			                   "DestroyProxyConfiguration",
			                   g_variant_new ("(o)", config->path),
			                   G_DBUS_CALL_FLAGS_NO_AUTO_START,
			                   -1,
			                   _ensure_cancellable (priv),
			                   pacrunner_remove_done,
			                   config_ref (config));
			nm_clear_g_free (&config->path);
		}
	}

	c_list_unlink (&config->lst);
	config_unref (config);
}

gboolean
nm_pacrunner_manager_remove_clear (NMPacrunnerManager *self,
                                   NMPacrunnerCallId **p_call_id)
{
	g_return_val_if_fail (p_call_id, FALSE);

	/* if we have no call-id, allow for %NULL */
	g_return_val_if_fail ((!self && !*p_call_id) || NM_IS_PACRUNNER_MANAGER (self), FALSE);

	if (!*p_call_id)
		return FALSE;
	nm_pacrunner_manager_remove (self,
	                             g_steal_pointer (p_call_id));
	return TRUE;
}

/*****************************************************************************/

static void
nm_pacrunner_manager_init (NMPacrunnerManager *self)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	c_list_init (&priv->configs);
	g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
	                          G_DBUS_PROXY_FLAGS_NONE,
	                          NULL,
	                          PACRUNNER_DBUS_SERVICE,
	                          PACRUNNER_DBUS_PATH,
	                          PACRUNNER_DBUS_INTERFACE,
	                          _ensure_cancellable (priv),
	                          pacrunner_proxy_cb,
	                          self);
}

static void
dispose (GObject *object)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE ((NMPacrunnerManager *) object);
	CList *iter, *safe;

	c_list_for_each_safe (iter, safe, &priv->configs) {
		c_list_unlink (iter);
		config_unref (c_list_entry (iter, Config, lst));
	}

	/* we cancel all pending operations. Note that pacrunner automatically
	 * removes all configuration once NetworkManager disconnects from
	 * the bus -- which happens soon after we destroy the pacrunner manager.
	 */
	nm_clear_g_cancellable (&priv->cancellable);

	g_clear_pointer (&priv->iface, g_free);
	g_clear_object (&priv->pacrunner);

	G_OBJECT_CLASS (nm_pacrunner_manager_parent_class)->dispose (object);
}

static void
nm_pacrunner_manager_class_init (NMPacrunnerManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;
}
