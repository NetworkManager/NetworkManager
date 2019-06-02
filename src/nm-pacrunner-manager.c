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
#include "NetworkManagerUtils.h"
#include "platform/nm-platform.h"
#include "nm-dbus-manager.h"
#include "nm-proxy-config.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "c-list/src/c-list.h"
#include "nm-glib-aux/nm-dbus-aux.h"

#define PACRUNNER_DBUS_SERVICE "org.pacrunner"
#define PACRUNNER_DBUS_INTERFACE "org.pacrunner.Manager"
#define PACRUNNER_DBUS_PATH "/org/pacrunner/manager"

/*****************************************************************************/

struct _NMPacrunnerConfId {
	CList conf_id_lst;

	NMPacrunnerManager *self;

	GVariant *parameters;

	char *path;
	guint64 log_id;
	guint refcount;
};

typedef struct {
	GDBusConnection *dbus_connection;
	GCancellable *cancellable;
	CList conf_id_lst_head;
	guint64 log_id_counter;
	guint name_owner_changed_id;
	bool dbus_initied:1;
	bool has_name_owner:1;
	bool try_start_blocked:1;
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
#define _NMLOG2(level, conf_id, ...) \
	G_STMT_START { \
		nm_log ((level), _NMLOG_DOMAIN, NULL, NULL, \
		        "%s%"G_GUINT64_FORMAT"]: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
		        _NMLOG2_PREFIX_NAME": call[", \
		        (conf_id)->log_id \
		        _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
	} G_STMT_END

/*****************************************************************************/

static void _call_destroy_proxy_configuration (NMPacrunnerManager *self,
                                               NMPacrunnerConfId *conf_id,
                                               const char *path,
                                               gboolean verbose_log);

/*****************************************************************************/

static NMPacrunnerConfId *
conf_id_ref (NMPacrunnerConfId *conf_id)
{
	nm_assert (conf_id);
	nm_assert (conf_id->refcount > 0);

	conf_id->refcount++;
	return conf_id;
}

static void
conf_id_unref (NMPacrunnerConfId *conf_id)
{
	nm_assert (conf_id);
	nm_assert (conf_id->refcount > 0);

	if (conf_id->refcount == 1) {
		g_variant_unref (conf_id->parameters);
		g_free (conf_id->path);
		c_list_unlink_stale (&conf_id->conf_id_lst);
		g_object_unref (conf_id->self);
		g_slice_free (NMPacrunnerConfId, conf_id);
	} else
		conf_id->refcount--;
}

NM_AUTO_DEFINE_FCN0 (NMPacrunnerConfId *, _nm_auto_unref_conf_id, conf_id_unref);
#define nm_auto_unref_conf_id nm_auto (_nm_auto_unref_conf_id)

/*****************************************************************************/

static void
get_ip_domains (GPtrArray *domains, NMIPConfig *ip_config)
{
	NMDedupMultiIter ipconf_iter;
	char *cidr;
	guint i, num;
	char sbuf[NM_UTILS_INET_ADDRSTRLEN];
	int addr_family;

	if (!ip_config)
		return;

	addr_family = nm_ip_config_get_addr_family (ip_config);

	num = nm_ip_config_get_num_searches (ip_config);
	for (i = 0; i < num; i++)
		g_ptr_array_add (domains, g_strdup (nm_ip_config_get_search (ip_config, i)));

	num = nm_ip_config_get_num_domains (ip_config);
	for (i = 0; i < num; i++)
		g_ptr_array_add (domains, g_strdup (nm_ip_config_get_domain (ip_config, i)));

	if (addr_family == AF_INET) {
		const NMPlatformIP4Address *address;

		nm_ip_config_iter_ip4_address_for_each (&ipconf_iter, (NMIP4Config *) ip_config, &address) {
			cidr = g_strdup_printf ("%s/%u",
			                        nm_utils_inet4_ntop (address->address, sbuf),
			                        address->plen);
			g_ptr_array_add (domains, cidr);
		}
	} else {
		const NMPlatformIP6Address *address;

		nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, (NMIP6Config *) ip_config, &address) {
			cidr = g_strdup_printf ("%s/%u",
			                        nm_utils_inet6_ntop (&address->address, sbuf),
			                        address->plen);
			g_ptr_array_add (domains, cidr);
		}
	}

	if (addr_family == AF_INET) {
		const NMPlatformIP4Route *routes;

		nm_ip_config_iter_ip4_route_for_each (&ipconf_iter, (NMIP4Config *) ip_config, &routes) {
			if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (routes))
				continue;
			cidr = g_strdup_printf ("%s/%u",
			                        nm_utils_inet4_ntop (routes->network, sbuf),
			                        routes->plen);
			g_ptr_array_add (domains, cidr);
		}
	} else {
		const NMPlatformIP6Route *routes;

		nm_ip_config_iter_ip6_route_for_each (&ipconf_iter, (NMIP6Config *) ip_config, &routes) {
			if (NM_PLATFORM_IP_ROUTE_IS_DEFAULT (routes))
				continue;
			cidr = g_strdup_printf ("%s/%u",
			                        nm_utils_inet6_ntop (&routes->network, sbuf),
			                        routes->plen);
			g_ptr_array_add (domains, cidr);
		}
	}
}

static GVariant *
_make_request_create_proxy_configuration (NMProxyConfig *proxy_config,
                                          const char *iface,
                                          NMIP4Config *ip4_config,
                                          NMIP6Config *ip6_config)
{
	GVariantBuilder builder;
	NMProxyConfigMethod method;
	const char *pac_url;
	const char *pac_script;

	nm_assert (NM_IS_PROXY_CONFIG (proxy_config));

	g_variant_builder_init (&builder, G_VARIANT_TYPE_VARDICT);

	if (iface) {
		g_variant_builder_add (&builder, "{sv}",
		                       "Interface",
		                       g_variant_new_string (iface));
	}

	method = nm_proxy_config_get_method (proxy_config);
	switch (method) {
	case NM_PROXY_CONFIG_METHOD_AUTO:
		g_variant_builder_add (&builder, "{sv}",
		                       "Method",
		                       g_variant_new_string ("auto"));

		pac_url = nm_proxy_config_get_pac_url (proxy_config);
		if (pac_url) {
			g_variant_builder_add (&builder, "{sv}",
			                       "URL",
			                       g_variant_new_string (pac_url));
		}

		pac_script = nm_proxy_config_get_pac_script (proxy_config);
		if (pac_script) {
			g_variant_builder_add (&builder, "{sv}",
			                       "Script",
			                       g_variant_new_string (pac_script));
		}
		break;
	case NM_PROXY_CONFIG_METHOD_NONE:
		g_variant_builder_add (&builder, "{sv}",
		                       "Method",
		                       g_variant_new_string ("direct"));
		break;
	}

	g_variant_builder_add (&builder, "{sv}",
	                       "BrowserOnly",
	                       g_variant_new_boolean (nm_proxy_config_get_browser_only (proxy_config)));

	if (ip4_config || ip6_config) {
		gs_unref_ptrarray GPtrArray *domains = NULL;

		domains = g_ptr_array_new_with_free_func (g_free);

		get_ip_domains (domains, NM_IP_CONFIG_CAST (ip4_config));
		get_ip_domains (domains, NM_IP_CONFIG_CAST (ip6_config));

		if (domains->len > 0) {
			g_variant_builder_add (&builder, "{sv}",
			                       "Domains",
			                       g_variant_new_strv ((const char *const*) domains->pdata,
			                                           domains->len));
		}
	}

	return g_variant_new ("(a{sv})", &builder);
}

/*****************************************************************************/

static void
_call_destroy_proxy_configuration_cb (GObject *source,
                                      GAsyncResult *res,
                                      gpointer user_data)
{
	nm_auto_unref_conf_id NMPacrunnerConfId *conf_id = user_data;
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *ret = NULL;

	ret = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), res, &error);
	if (!ret) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			_LOG2T (conf_id, "destroy proxy configuration: failed with %s", error->message);
		else
			_LOG2T (conf_id, "destroy proxy configuration: cancelled");
		return;
	}
	_LOG2T (conf_id, "destroy proxy configuration: success");
}

static void
_call_create_proxy_configuration_cb (GObject *source,
                                     GAsyncResult *res,
                                     gpointer user_data)
{
	nm_auto_unref_conf_id NMPacrunnerConfId *conf_id = user_data;
	NMPacrunnerManager *self = NM_PACRUNNER_MANAGER (conf_id->self);
	gs_free_error GError *error = NULL;
	gs_unref_variant GVariant *variant = NULL;
	const char *path = NULL;

	nm_assert (!conf_id->path);

	variant = g_dbus_connection_call_finish (G_DBUS_CONNECTION (source), res, &error);

	if (!variant) {
		if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			_LOG2T (conf_id, "create proxy configuration failed: %s", error->message);
		else
			_LOG2T (conf_id, "create proxy configuration cancelled");
		return;
	}

	g_variant_get (variant, "(&o)", &path);

	if (c_list_is_empty (&conf_id->conf_id_lst)) {
		_LOG2T (conf_id, "create proxy configuration succeeded (%s), but destroy it right away", path);
		_call_destroy_proxy_configuration (self,
		                                   conf_id,
		                                   path,
		                                   FALSE);
	} else {
		_LOG2T (conf_id, "create proxy configuration succeeded (%s)", path);
		conf_id->path = g_strdup (path);
	}
}

static void
_call_destroy_proxy_configuration (NMPacrunnerManager *self,
                                   NMPacrunnerConfId *conf_id,
                                   const char *path,
                                   gboolean verbose_log)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	if (verbose_log)
		_LOG2T (conf_id, "destroy proxy configuration %s...", path);

	g_dbus_connection_call (priv->dbus_connection,
	                        PACRUNNER_DBUS_SERVICE,
	                        PACRUNNER_DBUS_PATH,
	                        PACRUNNER_DBUS_INTERFACE,
	                        "DestroyProxyConfiguration",
	                        g_variant_new ("(o)", path),
	                        G_VARIANT_TYPE ("()"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        NM_SHUTDOWN_TIMEOUT_MS,
	                        priv->cancellable,
	                        _call_destroy_proxy_configuration_cb,
	                        conf_id_ref (conf_id));
}

static void
_call_create_proxy_configuration (NMPacrunnerManager *self,
                                  NMPacrunnerConfId *conf_id,
                                  gboolean verbose_log)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	if (verbose_log)
		_LOG2T (conf_id, "create proxy configuration...");

	g_dbus_connection_call (priv->dbus_connection,
	                        PACRUNNER_DBUS_SERVICE,
	                        PACRUNNER_DBUS_PATH,
	                        PACRUNNER_DBUS_INTERFACE,
	                        "CreateProxyConfiguration",
	                        conf_id->parameters,
	                        G_VARIANT_TYPE ("(o)"),
	                        G_DBUS_CALL_FLAGS_NO_AUTO_START,
	                        NM_SHUTDOWN_TIMEOUT_MS,
	                        priv->cancellable,
	                        _call_create_proxy_configuration_cb,
	                        conf_id_ref (conf_id));
}

static gboolean
_try_start_service_by_name (NMPacrunnerManager *self)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	if (   priv->try_start_blocked
	    || !priv->dbus_initied)
		return FALSE;

	_LOGD ("try D-Bus activating pacrunner...");
	priv->try_start_blocked = TRUE;
	nm_dbus_connection_call_start_service_by_name (priv->dbus_connection,
	                                               PACRUNNER_DBUS_SERVICE,
	                                               -1,
	                                               NULL,
	                                               NULL,
	                                               NULL);
	return TRUE;
}

/*****************************************************************************/

/**
 * nm_pacrunner_manager_add:
 * @self: the #NMPacrunnerManager
 * @proxy_config: proxy config of the connection
 * @iface: the iface for the connection or %NULL
 * @ip4_config: IP4 config of the connection to extract domain info from
 * @ip6_config: IP6 config of the connection to extract domain info from
 *
 * Returns: a #NMPacrunnerConfId id. The function cannot
 *  fail and always returns a non NULL pointer. The conf-id may
 *  be used to remove the configuration later via nm_pacrunner_manager_remove().
 *  Note that the conf-id keeps the @self instance alive.
 */
NMPacrunnerConfId *
nm_pacrunner_manager_add (NMPacrunnerManager *self,
                          NMProxyConfig *proxy_config,
                          const char *iface,
                          NMIP4Config *ip4_config,
                          NMIP6Config *ip6_config)
{
	NMPacrunnerManagerPrivate *priv;
	NMPacrunnerConfId *conf_id;
	gs_free char *log_msg = NULL;

	g_return_val_if_fail (NM_IS_PACRUNNER_MANAGER (self), NULL);
	g_return_val_if_fail (proxy_config, NULL);

	priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	conf_id = g_slice_new (NMPacrunnerConfId);
	*conf_id = (NMPacrunnerConfId) {
		.log_id     = ++priv->log_id_counter,
		.refcount   = 1,
		.self       = g_object_ref (self),
		.parameters = g_variant_ref_sink (_make_request_create_proxy_configuration (proxy_config,
		                                                                            iface,
		                                                                            ip4_config,
		                                                                            ip6_config)),
	};
	c_list_link_tail (&priv->conf_id_lst_head,
	                  &conf_id->conf_id_lst);

	if (!priv->has_name_owner) {
		_LOG2T (conf_id, "add config: %s (%s)",
		        (log_msg = g_variant_print (conf_id->parameters, FALSE)),
		        "pacrunner D-Bus service not running");
		_try_start_service_by_name (self);
	} else {
		_LOG2T (conf_id, "add config: %s (%s)",
		        (log_msg = g_variant_print (conf_id->parameters, FALSE)),
		        "create proxy configuration");
		_call_create_proxy_configuration (self, conf_id, FALSE);
	}

	return conf_id;
}

/**
 * nm_pacrunner_manager_remove:
 * @conf_id: the conf id obtained from nm_pacrunner_manager_add()
 */
void
nm_pacrunner_manager_remove (NMPacrunnerConfId *conf_id)
{
	_nm_unused nm_auto_unref_conf_id NMPacrunnerConfId *conf_id_free = conf_id;
	NMPacrunnerManager *self;
	NMPacrunnerManagerPrivate *priv;

	g_return_if_fail (conf_id);

	self = conf_id->self;

	g_return_if_fail (NM_IS_PACRUNNER_MANAGER (self));

	priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	_LOG2T (conf_id, "removing...");

	nm_assert (c_list_contains (&priv->conf_id_lst_head, &conf_id->conf_id_lst));

	c_list_unlink (&conf_id->conf_id_lst);

	if (!conf_id->path) {
		/* There is no ID to destroy the configuration.
		 *
		 * That can happen because:
		 *
		 *  - pacrunner D-Bus service is not running (no name owner) and we didn't call CreateProxyConfiguration.
		 *  - CreateProxyConfiguration failed.
		 *  - CreateProxyConfiguration is in progress.
		 *
		 * In all cases there is nothing to do. Note that if CreateProxyConfiguration is in progress
		 * it has a reference on the conf-id and it will automatically destroy the configuration
		 * when it completes.
		 */
		return;
	}

	_call_destroy_proxy_configuration (self, conf_id, conf_id->path, TRUE);
}

gboolean
nm_pacrunner_manager_remove_clear (NMPacrunnerConfId **p_conf_id)
{
	g_return_val_if_fail (p_conf_id, FALSE);

	if (!*p_conf_id)
		return FALSE;
	nm_pacrunner_manager_remove (g_steal_pointer (p_conf_id));
	return TRUE;
}

/*****************************************************************************/

static void
name_owner_changed (NMPacrunnerManager *self,
                    const char *name_owner)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);
	NMPacrunnerConfId *conf_id;
	gboolean has_name_owner;

	has_name_owner = (name_owner && name_owner[0]);

	if (   priv->dbus_initied
	    && priv->has_name_owner == has_name_owner)
		return;

	priv->has_name_owner = has_name_owner;

	nm_clear_g_cancellable (&priv->cancellable);

	if (has_name_owner) {
		priv->dbus_initied = TRUE;
		priv->try_start_blocked = FALSE;
		_LOGD ("pacrunner appeared on D-Bus (%s)", name_owner);
		priv->cancellable = g_cancellable_new ();
		c_list_for_each_entry (conf_id, &priv->conf_id_lst_head, conf_id_lst)
			_call_create_proxy_configuration (self, conf_id, TRUE);
	} else {
		if (!priv->dbus_initied) {
			priv->dbus_initied = TRUE;
			nm_assert (!priv->try_start_blocked);
			_LOGD ("pacrunner not on D-Bus");
		} else
			_LOGD ("pacrunner disappeared from D-Bus");
		if (!c_list_is_empty (&priv->conf_id_lst_head)) {
			c_list_for_each_entry (conf_id, &priv->conf_id_lst_head, conf_id_lst)
				nm_clear_g_free (&conf_id->path);
			_try_start_service_by_name (self);
		}
	}
}

static void
name_owner_changed_cb (GDBusConnection *connection,
                       const char *sender_name,
                       const char *object_path,
                       const char *interface_name,
                       const char *signal_name,
                       GVariant *parameters,
                       gpointer user_data)
{
	const char *new_owner;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sss)")))
		return;

	g_variant_get (parameters,
	               "(&s&s&s)",
	               NULL,
	               NULL,
	               &new_owner);

	name_owner_changed (user_data, new_owner);
}

static void
get_name_owner_cb (const char *name_owner,
                   GError *error,
                   gpointer user_data)
{
	if (   !name_owner
	    && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	name_owner_changed (user_data, name_owner);
}

/*****************************************************************************/

static void
nm_pacrunner_manager_init (NMPacrunnerManager *self)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE (self);

	c_list_init (&priv->conf_id_lst_head);

	priv->dbus_connection = nm_g_object_ref (NM_MAIN_DBUS_CONNECTION_GET);

	if (!priv->dbus_connection) {
		_LOGD ("no D-Bus connection to talk to pacrunner");
		return;
	}

	priv->name_owner_changed_id = nm_dbus_connection_signal_subscribe_name_owner_changed (priv->dbus_connection,
	                                                                                      PACRUNNER_DBUS_SERVICE,
	                                                                                      name_owner_changed_cb,
	                                                                                      self,
	                                                                                      NULL);
	priv->cancellable = g_cancellable_new ();

	nm_dbus_connection_call_get_name_owner (priv->dbus_connection,
	                                        PACRUNNER_DBUS_SERVICE,
	                                        -1,
	                                        priv->cancellable,
	                                        get_name_owner_cb,
	                                        self);
}

static void
dispose (GObject *object)
{
	NMPacrunnerManagerPrivate *priv = NM_PACRUNNER_MANAGER_GET_PRIVATE ((NMPacrunnerManager *) object);

	nm_assert (c_list_is_empty (&priv->conf_id_lst_head));

	/* we cancel all pending operations. Note that pacrunner automatically
	 * removes all configuration once NetworkManager disconnects from
	 * the bus -- which happens soon after we destroy the pacrunner manager.
	 */
	nm_clear_g_cancellable (&priv->cancellable);

	nm_clear_g_dbus_connection_signal (priv->dbus_connection,
	                                   &priv->name_owner_changed_id);
	g_clear_object (&priv->dbus_connection);

	G_OBJECT_CLASS (nm_pacrunner_manager_parent_class)->dispose (object);
}

static void
nm_pacrunner_manager_class_init (NMPacrunnerManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->dispose = dispose;
}
