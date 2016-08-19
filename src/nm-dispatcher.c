/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
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
 * Copyright (C) 2004 - 2012 Red Hat, Inc.
 * Copyright (C) 2005 - 2008 Novell, Inc.
 */

#include "nm-default.h"

#include <string.h>
#include <errno.h>

#include "nm-dispatcher.h"
#include "nm-dispatcher-api.h"
#include "NetworkManagerUtils.h"
#include "nm-utils.h"
#include "nm-connectivity.h"
#include "nm-device.h"
#include "nm-dhcp4-config.h"
#include "nm-dhcp6-config.h"
#include "nm-proxy-config.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "nm-manager.h"
#include "nm-settings-connection.h"
#include "nm-platform.h"
#include "nm-core-internal.h"

#define CALL_TIMEOUT (1000 * 60 * 10)  /* 10 minutes for all scripts */

#define _NMLOG_DOMAIN         LOGD_DISPATCH
#define _NMLOG_PREFIX_NAME    "dispatcher"
#define _NMLOG(level, ...) \
    G_STMT_START { \
        nm_log ((level), _NMLOG_DOMAIN, \
                "%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                _NMLOG_PREFIX_NAME \
                _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
    } G_STMT_END

static GDBusProxy *dispatcher_proxy;
static GHashTable *requests = NULL;

typedef struct {
	GFileMonitor *monitor;
	const char *const description;
	const char *const dir;
	const guint16 dir_len;
	char has_scripts;
} Monitor;

enum {
	MONITOR_INDEX_DEFAULT,
	MONITOR_INDEX_PRE_UP,
	MONITOR_INDEX_PRE_DOWN,
};

static Monitor monitors[3] = {
#define MONITORS_INIT_SET(INDEX, USE, SCRIPT_DIR)   [INDEX] = { .dir_len = NM_STRLEN (SCRIPT_DIR), .dir = SCRIPT_DIR, .description = ("" USE), .has_scripts = TRUE }
	MONITORS_INIT_SET (MONITOR_INDEX_DEFAULT,  "default",  NMD_SCRIPT_DIR_DEFAULT),
	MONITORS_INIT_SET (MONITOR_INDEX_PRE_UP,   "pre-up",   NMD_SCRIPT_DIR_PRE_UP),
	MONITORS_INIT_SET (MONITOR_INDEX_PRE_DOWN, "pre-down", NMD_SCRIPT_DIR_PRE_DOWN),
};

static const Monitor*
_get_monitor_by_action (DispatcherAction action)
{
	switch (action) {
	case DISPATCHER_ACTION_PRE_UP:
	case DISPATCHER_ACTION_VPN_PRE_UP:
		return &monitors[MONITOR_INDEX_PRE_UP];
	case DISPATCHER_ACTION_PRE_DOWN:
	case DISPATCHER_ACTION_VPN_PRE_DOWN:
		return &monitors[MONITOR_INDEX_PRE_DOWN];
	default:
		return &monitors[MONITOR_INDEX_DEFAULT];
	}
}

static void
dump_proxy_to_props (NMProxyConfig *proxy, GVariantBuilder *builder)
{
	const char *const*proxies;
	const char *pac_url = NULL, *pac_script = NULL;

	if (nm_proxy_config_get_method (proxy) == NM_PROXY_CONFIG_METHOD_NONE)
		return;

	proxies = nm_proxy_config_get_proxies (proxy);
	if (proxies && proxies[0]) {
		g_variant_builder_add (builder, "{sv}",
		                       "proxies",
		                       g_variant_new_strv (proxies, -1));
	}

	pac_url = nm_proxy_config_get_pac_url (proxy);
	if (pac_url) {
		g_variant_builder_add (builder, "{sv}",
		                       "pac-url",
		                       g_variant_new_string (pac_url));
	}

	pac_script = nm_proxy_config_get_pac_script (proxy);
	if (pac_script) {
		g_variant_builder_add (builder, "{sv}",
		                       "pac-script",
		                       g_variant_new_string (pac_script));
	}
}

static void
dump_ip4_to_props (NMIP4Config *ip4, GVariantBuilder *builder)
{
	GVariantBuilder int_builder;
	guint n, i;
	const NMPlatformIP4Address *addr;
	const NMPlatformIP4Route *route;
	guint32 array[4];

	/* Addresses */
	g_variant_builder_init (&int_builder, G_VARIANT_TYPE ("aau"));
	n = nm_ip4_config_get_num_addresses (ip4);
	for (i = 0; i < n; i++) {
		addr = nm_ip4_config_get_address (ip4, i);
		array[0] = addr->address;
		array[1] = addr->plen;
		array[2] = (i == 0) ? nm_ip4_config_get_gateway (ip4) : 0;
		g_variant_builder_add (&int_builder, "@au",
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
		                                                  array, 3, sizeof (guint32)));
	}
	g_variant_builder_add (builder, "{sv}",
	                       "addresses",
	                       g_variant_builder_end (&int_builder));

	/* DNS servers */
	g_variant_builder_init (&int_builder, G_VARIANT_TYPE ("au"));
	n = nm_ip4_config_get_num_nameservers (ip4);
	for (i = 0; i < n; i++)
		g_variant_builder_add (&int_builder, "u", nm_ip4_config_get_nameserver (ip4, i));
	g_variant_builder_add (builder, "{sv}",
	                       "nameservers",
	                       g_variant_builder_end (&int_builder));

	/* Search domains */
	g_variant_builder_init (&int_builder, G_VARIANT_TYPE ("as"));
	n = nm_ip4_config_get_num_domains (ip4);
	for (i = 0; i < n; i++)
		g_variant_builder_add (&int_builder, "s", nm_ip4_config_get_domain (ip4, i));
	g_variant_builder_add (builder, "{sv}",
	                       "domains",
	                       g_variant_builder_end (&int_builder));

	/* WINS servers */
	g_variant_builder_init (&int_builder, G_VARIANT_TYPE ("au"));
	n = nm_ip4_config_get_num_wins (ip4);
	for (i = 0; i < n; i++)
		g_variant_builder_add (&int_builder, "u", nm_ip4_config_get_wins (ip4, i));
	g_variant_builder_add (builder, "{sv}",
	                       "wins-servers",
	                       g_variant_builder_end (&int_builder));

	/* Static routes */
	g_variant_builder_init (&int_builder, G_VARIANT_TYPE ("aau"));
	n = nm_ip4_config_get_num_routes (ip4);
	for (i = 0; i < n; i++) {
		route = nm_ip4_config_get_route (ip4, i);
		array[0] = route->network;
		array[1] = route->plen;
		array[2] = route->gateway;
		array[3] = route->metric;
		g_variant_builder_add (&int_builder, "@au",
		                       g_variant_new_fixed_array (G_VARIANT_TYPE_UINT32,
		                                                  array, 4, sizeof (guint32)));
	}
	g_variant_builder_add (builder, "{sv}",
	                       "routes",
	                       g_variant_builder_end (&int_builder));
}

static void
dump_ip6_to_props (NMIP6Config *ip6, GVariantBuilder *builder)
{
	GVariantBuilder int_builder;
	guint n, i;
	const NMPlatformIP6Address *addr;
	const struct in6_addr *gw_bytes;
	const NMPlatformIP6Route *route;
	GVariant *ip, *gw;

	/* Addresses */
	g_variant_builder_init (&int_builder, G_VARIANT_TYPE ("a(ayuay)"));
	n = nm_ip6_config_get_num_addresses (ip6);
	for (i = 0; i < n; i++) {
		addr = nm_ip6_config_get_address (ip6, i);
		gw_bytes = nm_ip6_config_get_gateway (ip6);
		ip = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                &addr->address,
		                                sizeof (struct in6_addr), 1);
		gw = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                (i == 0 && gw_bytes) ? gw_bytes : &in6addr_any,
		                                sizeof (struct in6_addr), 1);
		g_variant_builder_add (&int_builder, "(@ayu@ay)", ip, addr->plen, gw);
	}
	g_variant_builder_add (builder, "{sv}",
	                       "addresses",
	                       g_variant_builder_end (&int_builder));

	/* DNS servers */
	g_variant_builder_init (&int_builder, G_VARIANT_TYPE ("aay"));
	n = nm_ip6_config_get_num_nameservers (ip6);
	for (i = 0; i < n; i++) {
		ip = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                nm_ip6_config_get_nameserver (ip6, i),
		                                sizeof (struct in6_addr), 1);
		g_variant_builder_add (&int_builder, "@ay", ip);
	}
	g_variant_builder_add (builder, "{sv}",
	                       "nameservers",
	                       g_variant_builder_end (&int_builder));

	/* Search domains */
	g_variant_builder_init (&int_builder, G_VARIANT_TYPE ("as"));
	n = nm_ip6_config_get_num_domains (ip6);
	for (i = 0; i < n; i++)
		g_variant_builder_add (&int_builder, "s", nm_ip6_config_get_domain (ip6, i));
	g_variant_builder_add (builder, "{sv}",
	                       "domains",
	                       g_variant_builder_end (&int_builder));

	/* Static routes */
	g_variant_builder_init (&int_builder, G_VARIANT_TYPE ("a(ayuayu)"));
	n = nm_ip6_config_get_num_routes (ip6);
	for (i = 0; i < n; i++) {
		route = nm_ip6_config_get_route (ip6, i);
		ip = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                &route->network,
		                                sizeof (struct in6_addr), 1);
		gw = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                &route->gateway,
		                                sizeof (struct in6_addr), 1);
		g_variant_builder_add (&int_builder, "(@ayu@ayu)", ip, route->plen, gw, route->metric);
	}
	g_variant_builder_add (builder, "{sv}",
	                       "routes",
	                       g_variant_builder_end (&int_builder));
}

static void
fill_device_props (NMDevice *device,
                   GVariantBuilder *dev_builder,
                   GVariantBuilder *proxy_builder,
                   GVariantBuilder *ip4_builder,
                   GVariantBuilder *ip6_builder,
                   GVariant **dhcp4_props,
                   GVariant **dhcp6_props)
{
	NMProxyConfig *proxy_config;
	NMIP4Config *ip4_config;
	NMIP6Config *ip6_config;
	NMDhcp4Config *dhcp4_config;
	NMDhcp6Config *dhcp6_config;

	/* If the action is for a VPN, send the VPN's IP interface instead of the device's */
	g_variant_builder_add (dev_builder, "{sv}", NMD_DEVICE_PROPS_IP_INTERFACE,
	                       g_variant_new_string (nm_device_get_ip_iface (device)));
	g_variant_builder_add (dev_builder, "{sv}", NMD_DEVICE_PROPS_INTERFACE,
	                       g_variant_new_string (nm_device_get_iface (device)));
	g_variant_builder_add (dev_builder, "{sv}", NMD_DEVICE_PROPS_TYPE,
	                       g_variant_new_uint32 (nm_device_get_device_type (device)));
	g_variant_builder_add (dev_builder, "{sv}", NMD_DEVICE_PROPS_STATE,
	                       g_variant_new_uint32 (nm_device_get_state (device)));
	if (nm_exported_object_is_exported (NM_EXPORTED_OBJECT (device)))
		g_variant_builder_add (dev_builder, "{sv}", NMD_DEVICE_PROPS_PATH,
		                       g_variant_new_object_path (nm_exported_object_get_path (NM_EXPORTED_OBJECT (device))));

	proxy_config = nm_device_get_proxy_config (device);
	if (proxy_config)
		dump_proxy_to_props (proxy_config, proxy_builder);

	ip4_config = nm_device_get_ip4_config (device);
	if (ip4_config)
		dump_ip4_to_props (ip4_config, ip4_builder);

	ip6_config = nm_device_get_ip6_config (device);
	if (ip6_config)
		dump_ip6_to_props (ip6_config, ip6_builder);

	dhcp4_config = nm_device_get_dhcp4_config (device);
	if (dhcp4_config)
		*dhcp4_props = nm_dhcp4_config_get_options (dhcp4_config);

	dhcp6_config = nm_device_get_dhcp6_config (device);
	if (dhcp6_config)
		*dhcp6_props = nm_dhcp6_config_get_options (dhcp6_config);
}

static void
fill_vpn_props (NMProxyConfig *proxy_config,
                NMIP4Config *ip4_config,
                NMIP6Config *ip6_config,
                GVariantBuilder *proxy_builder,
                GVariantBuilder *ip4_builder,
                GVariantBuilder *ip6_builder)
{
	if (proxy_config)
		dump_proxy_to_props (proxy_config, proxy_builder);
	if (ip4_config)
		dump_ip4_to_props (ip4_config, ip4_builder);
	if (ip6_config)
		dump_ip6_to_props (ip6_config, ip6_builder);
}

typedef struct {
	DispatcherAction action;
	guint request_id;
	DispatcherFunc callback;
	gpointer user_data;
	guint idle_id;
} DispatchInfo;

static void
dispatcher_info_free (DispatchInfo *info)
{
	if (info->idle_id)
		g_source_remove (info->idle_id);
	g_free (info);
}

static void
_ensure_requests (void)
{
	if (G_UNLIKELY (requests == NULL)) {
		requests = g_hash_table_new_full (g_direct_hash,
		                                  g_direct_equal,
		                                  NULL,
		                                  (GDestroyNotify) dispatcher_info_free);
	}
}

static void
dispatcher_info_cleanup (DispatchInfo *info)
{
	g_hash_table_remove (requests, GUINT_TO_POINTER (info->request_id));
}

static const char *
dispatch_result_to_string (DispatchResult result)
{
	switch (result) {
	case DISPATCH_RESULT_UNKNOWN:
		return "unknown";
	case DISPATCH_RESULT_SUCCESS:
		return "success";
	case DISPATCH_RESULT_EXEC_FAILED:
		return "exec failed";
	case DISPATCH_RESULT_FAILED:
		return "failed";
	case DISPATCH_RESULT_TIMEOUT:
		return "timed out";
	}
	g_assert_not_reached ();
}

static void
dispatcher_results_process (guint request_id, DispatcherAction action, GVariantIter *results)
{
	const char *script, *err;
	guint32 result;
	const Monitor *monitor = _get_monitor_by_action (action);

	g_return_if_fail (results != NULL);

	if (g_variant_iter_n_children (results) == 0) {
		_LOGD ("(%u) succeeded but no scripts invoked", request_id);
		return;
	}

	while (g_variant_iter_next (results, "(&su&s)", &script, &result, &err)) {
		const char *script_validation_msg = "";

		if (!*script) {
			script_validation_msg = " (path is NULL)";
			script = "(unknown)";
		} else if (!strncmp (script, monitor->dir, monitor->dir_len)            /* check: prefixed by script directory */
		    && script[monitor->dir_len] == '/' && script[monitor->dir_len+1]    /* check: with additional "/?" */
		    && !strchr (&script[monitor->dir_len+1], '/')) {                    /* check: and no further '/' */
			/* we expect the script to lie inside monitor->dir. If it does,
			 * strip the directory name. Otherwise show the full path and a warning. */
			script += monitor->dir_len + 1;
		} else
			script_validation_msg = " (unexpected path)";

		if (result == DISPATCH_RESULT_SUCCESS) {
			_LOGD ("(%u) %s succeeded%s",
			       request_id,
			       script, script_validation_msg);
		} else {
			_LOGW ("(%u) %s failed (%s): %s%s",
			       request_id,
			       script,
			       dispatch_result_to_string (result),
			       err,
			       script_validation_msg);
		}
	}
}

static void
dispatcher_done_cb (GObject *proxy, GAsyncResult *result, gpointer user_data)
{
	DispatchInfo *info = user_data;
	GVariant *ret;
	GVariantIter *results;
	GError *error = NULL;

	ret = _nm_dbus_proxy_call_finish (G_DBUS_PROXY (proxy), result,
	                                  G_VARIANT_TYPE ("(a(sus))"),
	                                  &error);
	if (ret) {
		g_variant_get (ret, "(a(sus))", &results);
		dispatcher_results_process (info->request_id, info->action, results);
		g_variant_iter_free (results);
		g_variant_unref (ret);
	} else {
		if (_nm_dbus_error_has_name (error, "org.freedesktop.systemd1.LoadFailed")) {
			g_dbus_error_strip_remote_error (error);
			_LOGW ("(%u) failed to call dispatcher scripts: %s",
			       info->request_id, error->message);
		} else {
			_LOGD ("(%u) failed to call dispatcher scripts: %s",
			       info->request_id, error->message);
		}
		g_clear_error (&error);
	}

	if (info->callback)
		info->callback (info->request_id, info->user_data);

	dispatcher_info_cleanup (info);
}

static const char *action_table[] = {
	[DISPATCHER_ACTION_HOSTNAME]     = NMD_ACTION_HOSTNAME,
	[DISPATCHER_ACTION_PRE_UP]       = NMD_ACTION_PRE_UP,
	[DISPATCHER_ACTION_UP]           = NMD_ACTION_UP,
	[DISPATCHER_ACTION_PRE_DOWN]     = NMD_ACTION_PRE_DOWN,
	[DISPATCHER_ACTION_DOWN]         = NMD_ACTION_DOWN,
	[DISPATCHER_ACTION_VPN_PRE_UP]   = NMD_ACTION_VPN_PRE_UP,
	[DISPATCHER_ACTION_VPN_UP]       = NMD_ACTION_VPN_UP,
	[DISPATCHER_ACTION_VPN_PRE_DOWN] = NMD_ACTION_VPN_PRE_DOWN,
	[DISPATCHER_ACTION_VPN_DOWN]     = NMD_ACTION_VPN_DOWN,
	[DISPATCHER_ACTION_DHCP4_CHANGE] = NMD_ACTION_DHCP4_CHANGE,
	[DISPATCHER_ACTION_DHCP6_CHANGE] = NMD_ACTION_DHCP6_CHANGE,
	[DISPATCHER_ACTION_CONNECTIVITY_CHANGE] = NMD_ACTION_CONNECTIVITY_CHANGE
};

static const char *
action_to_string (DispatcherAction action)
{
	g_assert ((gsize) action < G_N_ELEMENTS (action_table));
	return action_table[action];
}

static gboolean
dispatcher_idle_cb (gpointer user_data)
{
	DispatchInfo *info = user_data;

	info->idle_id = 0;
	if (info->callback)
		info->callback (info->request_id, info->user_data);
	dispatcher_info_cleanup (info);
	return G_SOURCE_REMOVE;
}

static gboolean
_dispatcher_call (DispatcherAction action,
                  gboolean blocking,
                  NMSettingsConnection *settings_connection,
                  NMConnection *applied_connection,
                  NMDevice *device,
                  NMConnectivityState connectivity_state,
                  const char *vpn_iface,
                  NMProxyConfig *vpn_proxy_config,
                  NMIP4Config *vpn_ip4_config,
                  NMIP6Config *vpn_ip6_config,
                  DispatcherFunc callback,
                  gpointer user_data,
                  guint *out_call_id)
{
	GVariant *connection_dict;
	GVariantBuilder connection_props;
	GVariantBuilder device_props;
	GVariantBuilder device_proxy_props;
	GVariantBuilder device_ip4_props;
	GVariantBuilder device_ip6_props;
	GVariant *device_dhcp4_props = NULL;
	GVariant *device_dhcp6_props = NULL;
	GVariantBuilder vpn_proxy_props;
	GVariantBuilder vpn_ip4_props;
	GVariantBuilder vpn_ip6_props;
	DispatchInfo *info = NULL;
	gboolean success = FALSE;
	GError *error = NULL;
	static guint request_counter = 0;
	guint reqid = ++request_counter;

	if (!dispatcher_proxy)
		return FALSE;

	/* Wrapping protection */
	if (G_UNLIKELY (!reqid))
		reqid = ++request_counter;

	g_assert (!blocking || (!callback && !user_data));

	_ensure_requests ();

	/* All actions except 'hostname' and 'connectivity-change' require a device */
	if (   action == DISPATCHER_ACTION_HOSTNAME
	    || action == DISPATCHER_ACTION_CONNECTIVITY_CHANGE) {
		_LOGD ("(%u) dispatching action '%s'%s",
		       reqid, action_to_string (action),
		       blocking
		           ? " (blocking)"
		           : (callback ? " (with callback)" : ""));
	} else {
		g_return_val_if_fail (NM_IS_DEVICE (device), FALSE);

		_LOGD ("(%u) (%s) dispatching action '%s'%s",
		       reqid,
		       vpn_iface ? vpn_iface : nm_device_get_iface (device),
		       action_to_string (action),
		       blocking
		           ? " (blocking)"
		           : (callback ? " (with callback)" : ""));
	}

	if (!_get_monitor_by_action(action)->has_scripts) {
		if (blocking == FALSE && (out_call_id || callback)) {
			info = g_malloc0 (sizeof (*info));
			info->action = action;
			info->request_id = reqid;
			info->callback = callback;
			info->user_data = user_data;
			info->idle_id = g_idle_add (dispatcher_idle_cb, info);
			_LOGD ("(%u) simulate request; no scripts in %s",  reqid, _get_monitor_by_action(action)->dir);
		} else
			_LOGD ("(%u) ignoring request; no scripts in %s", reqid, _get_monitor_by_action(action)->dir);
		success = TRUE;
		goto done;
	}

	if (applied_connection)
		connection_dict = nm_connection_to_dbus (applied_connection, NM_CONNECTION_SERIALIZE_NO_SECRETS);
	else
		connection_dict = g_variant_new_array (G_VARIANT_TYPE ("{sa{sv}}"), NULL, 0);

	g_variant_builder_init (&connection_props, G_VARIANT_TYPE_VARDICT);
	if (settings_connection) {
		const char *connection_path;
		const char *filename;

		connection_path = nm_connection_get_path (NM_CONNECTION (settings_connection));
		if (connection_path) {
			g_variant_builder_add (&connection_props, "{sv}",
			                       NMD_CONNECTION_PROPS_PATH,
			                       g_variant_new_object_path (connection_path));
		}
		filename = nm_settings_connection_get_filename (settings_connection);
		if (filename) {
			g_variant_builder_add (&connection_props, "{sv}",
			                       NMD_CONNECTION_PROPS_FILENAME,
			                       g_variant_new_string (filename));
		}
		if (nm_settings_connection_get_nm_generated_assumed (settings_connection)) {
			g_variant_builder_add (&connection_props, "{sv}",
			                       NMD_CONNECTION_PROPS_EXTERNAL,
			                       g_variant_new_boolean (TRUE));
		}
	}

	g_variant_builder_init (&device_props, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&device_proxy_props, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&device_ip4_props, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&device_ip6_props, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&vpn_proxy_props, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&vpn_ip4_props, G_VARIANT_TYPE_VARDICT);
	g_variant_builder_init (&vpn_ip6_props, G_VARIANT_TYPE_VARDICT);

	/* hostname and connectivity-change actions don't send device data */
	if (   action != DISPATCHER_ACTION_HOSTNAME
	    && action != DISPATCHER_ACTION_CONNECTIVITY_CHANGE) {
		fill_device_props (device,
		                   &device_props,
		                   &device_proxy_props,
		                   &device_ip4_props,
		                   &device_ip6_props,
		                   &device_dhcp4_props,
		                   &device_dhcp6_props);
		if (vpn_ip4_config || vpn_ip6_config) {
			fill_vpn_props (vpn_proxy_config,
			                vpn_ip4_config,
			                vpn_ip6_config,
			                &vpn_proxy_props,
			                &vpn_ip4_props,
			                &vpn_ip6_props);
		}
	}

	if (!device_dhcp4_props)
		device_dhcp4_props = g_variant_ref_sink (g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0));
	if (!device_dhcp6_props)
		device_dhcp6_props = g_variant_ref_sink (g_variant_new_array (G_VARIANT_TYPE ("{sv}"), NULL, 0));

	/* Send the action to the dispatcher */
	if (blocking) {
		GVariant *ret;
		GVariantIter *results;

		ret = _nm_dbus_proxy_call_sync (dispatcher_proxy, "Action",
		                                g_variant_new ("(s@a{sa{sv}}a{sv}a{sv}a{sv}a{sv}a{sv}@a{sv}@a{sv}ssa{sv}a{sv}a{sv}b)",
		                                               action_to_string (action),
		                                               connection_dict,
		                                               &connection_props,
		                                               &device_props,
		                                               &device_proxy_props,
		                                               &device_ip4_props,
		                                               &device_ip6_props,
		                                               device_dhcp4_props,
		                                               device_dhcp6_props,
		                                               nm_connectivity_state_to_string (connectivity_state),
		                                               vpn_iface ? vpn_iface : "",
		                                               &vpn_proxy_props,
		                                               &vpn_ip4_props,
		                                               &vpn_ip6_props,
		                                               nm_logging_enabled (LOGL_DEBUG, LOGD_DISPATCH)),
		                                G_VARIANT_TYPE ("(a(sus))"),
		                                G_DBUS_CALL_FLAGS_NONE, CALL_TIMEOUT,
		                                NULL, &error);
		if (ret) {
			g_variant_get (ret, "(a(sus))", &results);
			dispatcher_results_process (reqid, action, results);
			g_variant_iter_free (results);
			g_variant_unref (ret);
			success = TRUE;
		} else {
			g_dbus_error_strip_remote_error (error);
			_LOGW ("(%u) failed: %s", reqid, error->message);
			g_clear_error (&error);
			success = FALSE;
		}
	} else {
		info = g_malloc0 (sizeof (*info));
		info->action = action;
		info->request_id = reqid;
		info->callback = callback;
		info->user_data = user_data;
		g_dbus_proxy_call (dispatcher_proxy, "Action",
		                   g_variant_new ("(s@a{sa{sv}}a{sv}a{sv}a{sv}a{sv}a{sv}@a{sv}@a{sv}ssa{sv}a{sv}a{sv}b)",
		                                  action_to_string (action),
		                                  connection_dict,
		                                  &connection_props,
		                                  &device_props,
		                                  &device_proxy_props,
		                                  &device_ip4_props,
		                                  &device_ip6_props,
		                                  device_dhcp4_props,
		                                  device_dhcp6_props,
		                                  nm_connectivity_state_to_string (connectivity_state),
		                                  vpn_iface ? vpn_iface : "",
		                                  &vpn_proxy_props,
		                                  &vpn_ip4_props,
		                                  &vpn_ip6_props,
		                                  nm_logging_enabled (LOGL_DEBUG, LOGD_DISPATCH)),
		                   G_DBUS_CALL_FLAGS_NONE, CALL_TIMEOUT,
		                   NULL, dispatcher_done_cb, info);
		success = TRUE;
	}

	g_variant_unref (device_dhcp4_props);
	g_variant_unref (device_dhcp6_props);

done:
	if (success && info) {
		/* Track the request in case of cancelation */
		g_hash_table_insert (requests, GUINT_TO_POINTER (info->request_id), info);
		if (out_call_id)
			*out_call_id = info->request_id;
	} else if (out_call_id)
		*out_call_id = 0;

	return success;
}

/**
 * nm_dispatcher_call:
 * @action: the %DispatcherAction
 * @settings_connection: the #NMSettingsConnection the action applies to
 * @applied_connection: the currently applied connection
 * @device: the #NMDevice the action applies to
 * @callback: a caller-supplied callback to execute when done
 * @user_data: caller-supplied pointer passed to @callback
 * @out_call_id: on success, a call identifier which can be passed to
 * nm_dispatcher_call_cancel()
 *
 * This method always invokes the dispatcher action asynchronously.  To ignore
 * the result, pass %NULL to @callback.
 *
 * Returns: %TRUE if the action was dispatched, %FALSE on failure
 */
gboolean
nm_dispatcher_call (DispatcherAction action,
                    NMSettingsConnection *settings_connection,
                    NMConnection *applied_connection,
                    NMDevice *device,
                    DispatcherFunc callback,
                    gpointer user_data,
                    guint *out_call_id)
{
	return _dispatcher_call (action, FALSE, settings_connection, applied_connection, device,
	                         NM_CONNECTIVITY_UNKNOWN, NULL, NULL, NULL, NULL,
	                         callback, user_data, out_call_id);
}

/**
 * nm_dispatcher_call_sync():
 * @action: the %DispatcherAction
 * @settings_connection: the #NMSettingsConnection the action applies to
 * @applied_connection: the currently applied connection
 * @device: the #NMDevice the action applies to
 *
 * This method always invokes the dispatcher action synchronously and it may
 * take a long time to return.
 *
 * Returns: %TRUE if the action was dispatched, %FALSE on failure
 */
gboolean
nm_dispatcher_call_sync (DispatcherAction action,
                         NMSettingsConnection *settings_connection,
                         NMConnection *applied_connection,
                         NMDevice *device)
{
	return _dispatcher_call (action, TRUE, settings_connection, applied_connection, device,
	                         NM_CONNECTIVITY_UNKNOWN, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

/**
 * nm_dispatcher_call_vpn():
 * @action: the %DispatcherAction
 * @settings_connection: the #NMSettingsConnection the action applies to
 * @applied_connection: the currently applied connection
 * @parent_device: the parent #NMDevice of the VPN connection
 * @vpn_iface: the IP interface of the VPN tunnel, if any
 * @vpn_proxy_config: the #NMProxyConfig of the VPN connection
 * @vpn_ip4_config: the #NMIP4Config of the VPN connection
 * @vpn_ip6_config: the #NMIP6Config of the VPN connection
 * @callback: a caller-supplied callback to execute when done
 * @user_data: caller-supplied pointer passed to @callback
 * @out_call_id: on success, a call identifier which can be passed to
 * nm_dispatcher_call_cancel()
 *
 * This method always invokes the dispatcher action asynchronously.  To ignore
 * the result, pass %NULL to @callback.
 *
 * Returns: %TRUE if the action was dispatched, %FALSE on failure
 */
gboolean
nm_dispatcher_call_vpn (DispatcherAction action,
                        NMSettingsConnection *settings_connection,
                        NMConnection *applied_connection,
                        NMDevice *parent_device,
                        const char *vpn_iface,
                        NMProxyConfig *vpn_proxy_config,
                        NMIP4Config *vpn_ip4_config,
                        NMIP6Config *vpn_ip6_config,
                        DispatcherFunc callback,
                        gpointer user_data,
                        guint *out_call_id)
{
	return _dispatcher_call (action, FALSE, settings_connection, applied_connection,
	                         parent_device, NM_CONNECTIVITY_UNKNOWN, vpn_iface, vpn_proxy_config,
	                         vpn_ip4_config, vpn_ip6_config, callback, user_data, out_call_id);
}

/**
 * nm_dispatcher_call_vpn_sync():
 * @action: the %DispatcherAction
 * @settings_connection: the #NMSettingsConnection the action applies to
 * @applied_connection: the currently applied connection
 * @parent_device: the parent #NMDevice of the VPN connection
 * @vpn_iface: the IP interface of the VPN tunnel, if any
 * @vpn_proxy_config: the #NMProxyConfig of the VPN connection
 * @vpn_ip4_config: the #NMIP4Config of the VPN connection
 * @vpn_ip6_config: the #NMIP6Config of the VPN connection
 *
 * This method always invokes the dispatcher action synchronously and it may
 * take a long time to return.
 *
 * Returns: %TRUE if the action was dispatched, %FALSE on failure
 */
gboolean
nm_dispatcher_call_vpn_sync (DispatcherAction action,
                             NMSettingsConnection *settings_connection,
                             NMConnection *applied_connection,
                             NMDevice *parent_device,
                             const char *vpn_iface,
                             NMProxyConfig *vpn_proxy_config,
                             NMIP4Config *vpn_ip4_config,
                             NMIP6Config *vpn_ip6_config)
{
	return _dispatcher_call (action, TRUE, settings_connection, applied_connection,
	                         parent_device, NM_CONNECTIVITY_UNKNOWN, vpn_iface, vpn_proxy_config,
	                         vpn_ip4_config, vpn_ip6_config, NULL, NULL, NULL);
}

/**
 * nm_dispatcher_call_connectivity():
 * @action: the %DispatcherAction
 * @connectivity_state: the #NMConnectivityState value
 *
 * This method does not block the caller.
 *
 * Returns: %TRUE if the action was dispatched, %FALSE on failure
 */
gboolean
nm_dispatcher_call_connectivity (DispatcherAction action,
                                 NMConnectivityState connectivity_state)
{
	return _dispatcher_call (action, FALSE, NULL, NULL, NULL, connectivity_state,
	                         NULL, NULL, NULL, NULL, NULL, NULL, NULL);
}

void
nm_dispatcher_call_cancel (guint call_id)
{
	DispatchInfo *info;

	_ensure_requests ();

	/* Canceling just means the callback doesn't get called, so set the
	 * DispatcherInfo's callback to NULL.
	 */
	info = g_hash_table_lookup (requests, GUINT_TO_POINTER (call_id));
	g_return_if_fail (info);

	if (info && info->callback) {
		_LOGD ("(%u) cancelling dispatcher callback action", call_id);
		info->callback = NULL;
	}
}

static void
dispatcher_dir_changed (GFileMonitor *monitor,
                        GFile *file,
                        GFile *other_file,
                        GFileMonitorEvent event_type,
                        Monitor *item)
{
	const char *name;
	char *full_name;
	GDir *dir;
	GError *error = NULL;

	dir = g_dir_open (item->dir, 0, &error);
	if (dir) {
		int errsv = 0;

		item->has_scripts = FALSE;
		errno = 0;
		while (!item->has_scripts
		    && (name = g_dir_read_name (dir))) {
			full_name = g_build_filename (item->dir, name, NULL);
			item->has_scripts = g_file_test (full_name, G_FILE_TEST_IS_EXECUTABLE);
			g_free (full_name);
		}
		errsv = errno;
		g_dir_close (dir);
		if (item->has_scripts)
			_LOGD ("%s script directory '%s' has scripts", item->description, item->dir);
		else if (errsv == 0)
			_LOGD ("%s script directory '%s' has no scripts", item->description, item->dir);
		else {
			_LOGD ("%s script directory '%s' error reading (%s)", item->description, item->dir, strerror (errsv));
			item->has_scripts = TRUE;
		}
	} else {
		if (g_error_matches (error, G_FILE_ERROR, G_FILE_ERROR_NOENT)) {
			_LOGD ("%s script directory '%s' does not exist", item->description, item->dir);
			item->has_scripts = FALSE;
		} else {
			_LOGD ("%s script directory '%s' error (%s)", item->description, item->dir, error->message);
			item->has_scripts = TRUE;
		}
		g_error_free (error);
	}

}

void
nm_dispatcher_init (void)
{
	GFile *file;
	guint i;
	GError *error = NULL;

	for (i = 0; i < G_N_ELEMENTS (monitors); i++) {
		file = g_file_new_for_path (monitors[i].dir);
		monitors[i].monitor = g_file_monitor_directory (file, G_FILE_MONITOR_NONE, NULL, NULL);
		if (monitors[i].monitor) {
			g_signal_connect (monitors[i].monitor, "changed", G_CALLBACK (dispatcher_dir_changed), &monitors[i]);
			dispatcher_dir_changed (monitors[i].monitor, file, NULL, 0, &monitors[i]);
		}
		g_object_unref (file);
	}

	dispatcher_proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
	                                                  G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES |
	                                                      G_DBUS_PROXY_FLAGS_DO_NOT_CONNECT_SIGNALS,
	                                                  NULL,
	                                                  NM_DISPATCHER_DBUS_SERVICE,
	                                                  NM_DISPATCHER_DBUS_PATH,
	                                                  NM_DISPATCHER_DBUS_INTERFACE,
	                                                  NULL, &error);
	if (!dispatcher_proxy) {
		_LOGE ("could not get dispatcher proxy! %s", error->message);
		g_clear_error (&error);
	}
}

