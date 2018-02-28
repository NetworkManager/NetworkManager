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
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2008 - 2012 Red Hat, Inc.
 */

#include "nm-default.h"

#include "nm-ppp-manager.h"

#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <sys/stat.h>

#include <linux/ppp_defs.h>
#ifndef aligned_u64
#define aligned_u64 unsigned long long __attribute__((aligned(8)))
#endif
#include <linux/if.h>
#include <linux/if_ppp.h>
#include <linux/rtnetlink.h>

#include "NetworkManagerUtils.h"
#include "platform/nm-platform.h"
#include "nm-core-internal.h"
#include "nm-act-request.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"

#include "nm-pppd-plugin.h"
#include "nm-ppp-plugin-api.h"
#include "nm-ppp-status.h"

#include "introspection/org.freedesktop.NetworkManager.PPP.h"

#define NM_PPPD_PLUGIN PPPD_PLUGIN_DIR "/nm-pppd-plugin.so"

static NM_CACHED_QUARK_FCN ("ppp-manager-secret-tries", ppp_manager_secret_tries_quark)

/*****************************************************************************/

#define NM_TYPE_PPP_MANAGER            (nm_ppp_manager_get_type ())
#define NM_PPP_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_PPP_MANAGER, NMPPPManager))
#define NM_PPP_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_PPP_MANAGER, NMPPPManagerClass))
#define NM_IS_PPP_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_PPP_MANAGER))
#define NM_IS_PPP_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_PPP_MANAGER))
#define NM_PPP_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_PPP_MANAGER, NMPPPManagerClass))

GType nm_ppp_manager_get_type (void);

/*****************************************************************************/

enum {
	STATE_CHANGED,
	IP4_CONFIG,
	IP6_CONFIG,
	STATS,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

NM_GOBJECT_PROPERTIES_DEFINE_BASE (
	PROP_PARENT_IFACE,
);

typedef struct {
	GPid pid;

	char *parent_iface;

	NMActRequest *act_req;
	GDBusMethodInvocation *pending_secrets_context;
	NMActRequestGetSecretsCallId *secrets_id;
	const char *secrets_setting_name;

	guint ppp_watch_id;
	guint ppp_timeout_handler;

	/* Monitoring */
	char *ip_iface;
	int monitor_fd;
	guint monitor_id;

	guint32 ip4_route_table;
	guint32 ip4_route_metric;
	guint32 ip6_route_table;
	guint32 ip6_route_metric;
} NMPPPManagerPrivate;

struct _NMPPPManager {
	NMExportedObject parent;
	NMPPPManagerPrivate _priv;
};

typedef struct {
	NMExportedObjectClass parent;
} NMPPPManagerClass;

G_DEFINE_TYPE (NMPPPManager, nm_ppp_manager, NM_TYPE_EXPORTED_OBJECT)

#define NM_PPP_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMPPPManager, NM_IS_PPP_MANAGER)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_PPP
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "ppp-manager", __VA_ARGS__)

/*****************************************************************************/

static void _ppp_cleanup  (NMPPPManager *manager);
static void _ppp_kill (NMPPPManager *manager);

/*****************************************************************************/

static void
_ppp_manager_set_route_parameters (NMPPPManager *self,
                                   guint32 ip4_route_table,
                                   guint32 ip4_route_metric,
                                   guint32 ip6_route_table,
                                   guint32 ip6_route_metric)
{
	NMPPPManagerPrivate *priv;

	g_return_if_fail (NM_IS_PPP_MANAGER (self));

	priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	if (   priv->ip4_route_table  != ip4_route_table
	    || priv->ip4_route_metric != ip4_route_metric
	    || priv->ip6_route_table  != ip6_route_table
	    || priv->ip6_route_metric != ip6_route_metric) {
		priv->ip4_route_table = ip4_route_table;
		priv->ip4_route_metric = ip4_route_metric;
		priv->ip6_route_table = ip6_route_table;
		priv->ip6_route_metric = ip6_route_metric;

		_LOGT ("route-parameters: table-v4: %u, metric-v4: %u, table-v6: %u, metric-v6: %u",
		       priv->ip4_route_table,
		       priv->ip4_route_metric,
		       priv->ip6_route_table,
		       priv->ip6_route_metric);
	}
}

/*****************************************************************************/

static gboolean
monitor_cb (gpointer user_data)
{
	NMPPPManager *manager = NM_PPP_MANAGER (user_data);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	struct ifreq req;
	struct ppp_stats stats;

	memset (&req, 0, sizeof (req));
	memset (&stats, 0, sizeof (stats));
	req.ifr_data = (caddr_t) &stats;

	strncpy (req.ifr_name, priv->ip_iface, sizeof (req.ifr_name));
	if (ioctl (priv->monitor_fd, SIOCGPPPSTATS, &req) < 0) {
		if (errno != ENODEV)
			_LOGW ("could not read ppp stats: %s", strerror (errno));
	} else {
		g_signal_emit (manager, signals[STATS], 0,
		               (guint) stats.p.ppp_ibytes,
		               (guint) stats.p.ppp_obytes);
	}

	return TRUE;
}

static void
monitor_stats (NMPPPManager *manager)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);

	/* already monitoring */
	if (priv->monitor_fd >= 0)
		return;

	priv->monitor_fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (priv->monitor_fd >= 0) {
		g_warn_if_fail (priv->monitor_id == 0);
		if (priv->monitor_id)
			g_source_remove (priv->monitor_id);
		priv->monitor_id = g_timeout_add_seconds (5, monitor_cb, manager);
	} else
		_LOGW ("could not monitor PPP stats: %s", strerror (errno));
}

/*****************************************************************************/

static void
cancel_get_secrets (NMPPPManager *self)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);

	if (priv->secrets_id)
		nm_act_request_cancel_secrets (priv->act_req, priv->secrets_id);

	g_return_if_fail (!priv->secrets_id && !priv->secrets_setting_name);
}

static gboolean
extract_details_from_connection (NMConnection *connection,
                                 const char *secrets_setting_name,
                                 const char **username,
                                 const char **password,
                                 GError **error)
{
	NMSettingConnection *s_con;
	NMSetting *setting;
	const char *setting_name;

	g_return_val_if_fail (connection != NULL, FALSE);
	g_return_val_if_fail (username != NULL, FALSE);
	g_return_val_if_fail (password != NULL, FALSE);

	if (secrets_setting_name)
		setting_name = secrets_setting_name;
	else {
		/* Get the setting matching the connection type */
		s_con = nm_connection_get_setting_connection (connection);
		g_assert (s_con);

		setting_name = nm_setting_connection_get_connection_type (s_con);
		g_assert (setting_name);

		/* In case of bluetooth connection, use GSM or CDMA setting */
		if (strcmp (setting_name, NM_SETTING_BLUETOOTH_SETTING_NAME) == 0) {
			if (nm_connection_get_setting_gsm (connection))
				setting_name = NM_SETTING_GSM_SETTING_NAME;
			else
				setting_name = NM_SETTING_CDMA_SETTING_NAME;
		}
	}

	setting = nm_connection_get_setting_by_name (connection, setting_name);
	if (!setting) {
		/* This shouldn't ever happen */
		g_set_error_literal (error, NM_MANAGER_ERROR, NM_MANAGER_ERROR_FAILED,
		                     "Missing type-specific setting; no secrets could be found.");
		return FALSE;
	}

	if (NM_IS_SETTING_PPPOE (setting)) {
		*username = nm_setting_pppoe_get_username (NM_SETTING_PPPOE (setting));
		*password = nm_setting_pppoe_get_password (NM_SETTING_PPPOE (setting));
	} else if (NM_IS_SETTING_ADSL (setting)) {
		*username = nm_setting_adsl_get_username (NM_SETTING_ADSL (setting));
		*password = nm_setting_adsl_get_password (NM_SETTING_ADSL (setting));
	} else if (NM_IS_SETTING_GSM (setting)) {
		*username = nm_setting_gsm_get_username (NM_SETTING_GSM (setting));
		*password = nm_setting_gsm_get_password (NM_SETTING_GSM (setting));
	} else if (NM_IS_SETTING_CDMA (setting)) {
		*username = nm_setting_cdma_get_username (NM_SETTING_CDMA (setting));
		*password = nm_setting_cdma_get_password (NM_SETTING_CDMA (setting));
	}

	return TRUE;
}

static void
ppp_secrets_cb (NMActRequest *req,
                NMActRequestGetSecretsCallId *call_id,
                NMSettingsConnection *settings_connection, /* unused (we pass NULL here) */
                GError *error,
                gpointer user_data)
{
	NMPPPManager *self = NM_PPP_MANAGER (user_data);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	const char *username = NULL;
	const char *password = NULL;
	GError *local = NULL;
	NMConnection *applied_connection;

	g_return_if_fail (priv->pending_secrets_context != NULL);
	g_return_if_fail (req == priv->act_req);
	g_return_if_fail (call_id == priv->secrets_id);

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		goto out;

	if (error) {
		_LOGW ("%s", error->message);
		g_dbus_method_invocation_return_gerror (priv->pending_secrets_context, error);
		goto out;
	}

	applied_connection = nm_act_request_get_applied_connection (req);

	if (!extract_details_from_connection (applied_connection, priv->secrets_setting_name, &username, &password, &local)) {
		_LOGW ("%s", local->message);
		g_dbus_method_invocation_take_error (priv->pending_secrets_context, local);
		goto out;
	}

	/* This is sort of a hack but...
	 * pppd plugin only ever needs username and password. Passing the full
	 * connection there would mean some bloat: the plugin would need to link
	 * against libnm just to parse this. So instead, let's just send what
	 * it needs.
	 */
	g_dbus_method_invocation_return_value (
		priv->pending_secrets_context,
		g_variant_new ("(ss)", username ? username : "", password ? password : ""));

 out:
	priv->pending_secrets_context = NULL;
	priv->secrets_id = NULL;
	priv->secrets_setting_name = NULL;
}

static void
impl_ppp_manager_need_secrets (NMPPPManager *manager,
                               GDBusMethodInvocation *context)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	NMConnection *applied_connection;
	const char *username = NULL;
	const char *password = NULL;
	guint32 tries;
	GPtrArray *hints = NULL;
	GError *error = NULL;
	NMSecretAgentGetSecretsFlags flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

	nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (priv->act_req));

	applied_connection = nm_act_request_get_applied_connection (priv->act_req);

	priv->secrets_setting_name = nm_connection_need_secrets (applied_connection, &hints);
	if (!priv->secrets_setting_name) {
		/* Use existing secrets from the connection */
		if (extract_details_from_connection (applied_connection, NULL, &username, &password, &error)) {
			/* Send existing secrets to the PPP plugin */
			priv->pending_secrets_context = context;
			ppp_secrets_cb (priv->act_req, priv->secrets_id, NULL, NULL, manager);
		} else {
			_LOGW ("%s", error->message);
			g_dbus_method_invocation_take_error (priv->pending_secrets_context, error);
		}
		return;
	}

	/* Only ask for completely new secrets after retrying them once; some devices
	 * appear to ask a few times when they actually don't even care what you
	 * pass back.
	 */
	tries = GPOINTER_TO_UINT (g_object_get_qdata (G_OBJECT (applied_connection), ppp_manager_secret_tries_quark()));
	if (tries > 1)
		flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;

	priv->secrets_id = nm_act_request_get_secrets (priv->act_req,
	                                               FALSE,
	                                               priv->secrets_setting_name,
	                                               flags,
	                                               hints ? g_ptr_array_index (hints, 0) : NULL,
	                                               ppp_secrets_cb,
	                                               manager);
	g_object_set_qdata (G_OBJECT (applied_connection), ppp_manager_secret_tries_quark (), GUINT_TO_POINTER (++tries));
	priv->pending_secrets_context = context;

	if (hints)
		g_ptr_array_free (hints, TRUE);
}

static void
impl_ppp_manager_set_state (NMPPPManager *manager,
                            GDBusMethodInvocation *context,
                            guint32 state)
{
	g_signal_emit (manager, signals[STATE_CHANGED], 0, (guint) state);

	g_dbus_method_invocation_return_value (context, NULL);
}

static gboolean
set_ip_config_common (NMPPPManager *self,
                      GVariant *config_dict,
                      const char *iface_prop,
                      guint32 *out_mtu)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	NMConnection *applied_connection;
	NMSettingPpp *s_ppp;
	const char *iface;

	if (!g_variant_lookup (config_dict, iface_prop, "&s", &iface)) {
		_LOGE ("no interface received!");
		return FALSE;
	}
	if (priv->ip_iface == NULL)
		priv->ip_iface = g_strdup (iface);

	/* Got successful IP config; obviously the secrets worked */
	applied_connection = nm_act_request_get_applied_connection (priv->act_req);
	g_object_set_qdata (G_OBJECT (applied_connection), ppp_manager_secret_tries_quark (), NULL);

	if (out_mtu) {
		/* Get any custom MTU */
		s_ppp = nm_connection_get_setting_ppp (applied_connection);
		*out_mtu = s_ppp ? nm_setting_ppp_get_mtu (s_ppp) : 0;
	}

	monitor_stats (self);
	return TRUE;
}

static void
impl_ppp_manager_set_ip4_config (NMPPPManager *manager,
                                 GDBusMethodInvocation *context,
                                 GVariant *config_dict)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	gs_unref_object NMIP4Config *config = NULL;
	NMPlatformIP4Address address;
	guint32 u32, mtu;
	GVariantIter *iter;
	int ifindex;

	_LOGI ("(IPv4 Config Get) reply received.");

	nm_clear_g_source (&priv->ppp_timeout_handler);

	if (!set_ip_config_common (manager, config_dict, NM_PPP_IP4_CONFIG_INTERFACE, &mtu))
		goto out;

	ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, priv->ip_iface);
	if (ifindex <= 0)
		goto out;

	config = nm_ip4_config_new (nm_platform_get_multi_idx (NM_PLATFORM_GET), ifindex);

	if (mtu)
		nm_ip4_config_set_mtu (config, mtu, NM_IP_CONFIG_SOURCE_PPP);

	memset (&address, 0, sizeof (address));
	address.plen = 32;

	if (g_variant_lookup (config_dict, NM_PPP_IP4_CONFIG_ADDRESS, "u", &u32))
		address.address = u32;

	if (g_variant_lookup (config_dict, NM_PPP_IP4_CONFIG_GATEWAY, "u", &u32)) {
		const NMPlatformIP4Route r = {
			.ifindex   = ifindex,
			.rt_source = NM_IP_CONFIG_SOURCE_PPP,
			.gateway   = u32,
			.table_coerced = nm_platform_route_table_coerce (priv->ip4_route_table),
			.metric    = priv->ip4_route_metric,
		};

		nm_ip4_config_add_route (config, &r, NULL);
		address.peer_address = u32;
	} else
		address.peer_address = address.address;

	if (g_variant_lookup (config_dict, NM_PPP_IP4_CONFIG_PREFIX, "u", &u32))
		address.plen = u32;

	if (address.address && address.plen && address.plen <= 32) {
		address.addr_source = NM_IP_CONFIG_SOURCE_PPP;
		nm_ip4_config_add_address (config, &address);
	} else {
		_LOGE ("invalid IPv4 address received!");
		goto out;
	}

	if (g_variant_lookup (config_dict, NM_PPP_IP4_CONFIG_DNS, "au", &iter)) {
		while (g_variant_iter_next (iter, "u", &u32))
			nm_ip4_config_add_nameserver (config, u32);
		g_variant_iter_free (iter);
	}

	if (g_variant_lookup (config_dict, NM_PPP_IP4_CONFIG_WINS, "au", &iter)) {
		while (g_variant_iter_next (iter, "u", &u32))
			nm_ip4_config_add_wins (config, u32);
		g_variant_iter_free (iter);
	}

	/* Push the IP4 config up to the device */
	g_signal_emit (manager, signals[IP4_CONFIG], 0, priv->ip_iface, config);

out:
	g_dbus_method_invocation_return_value (context, NULL);
}

/* Converts the named Interface Identifier item to an IPv6 LL address and
 * returns the IID.
 */
static gboolean
iid_value_to_ll6_addr (GVariant *dict,
                       const char *prop,
                       struct in6_addr *out_addr,
                       NMUtilsIPv6IfaceId *out_iid)
{
	guint64 iid;

	if (!g_variant_lookup (dict, prop, "t", &iid)) {
		_LOGD ("pppd plugin property '%s' missing or not a uint64", prop);
		return FALSE;
	}
	g_return_val_if_fail (iid != 0, FALSE);

	/* Construct an IPv6 LL address from the interface identifier.  See
	 * http://tools.ietf.org/html/rfc4291#section-2.5.1 (IPv6) and
	 * http://tools.ietf.org/html/rfc5072#section-4.1 (IPv6 over PPP).
	 */
	memset (out_addr->s6_addr, 0, sizeof (out_addr->s6_addr));
	out_addr->s6_addr16[0] = htons (0xfe80);
	memcpy (out_addr->s6_addr + 8, &iid, sizeof (iid));
	if (out_iid)
		nm_utils_ipv6_interface_identifier_get_from_addr (out_iid, out_addr);
	return TRUE;
}

static void
impl_ppp_manager_set_ip6_config (NMPPPManager *manager,
                                 GDBusMethodInvocation *context,
                                 GVariant *config_dict)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	gs_unref_object NMIP6Config *config = NULL;
	NMPlatformIP6Address addr;
	struct in6_addr a;
	NMUtilsIPv6IfaceId iid = NM_UTILS_IPV6_IFACE_ID_INIT;
	gboolean has_peer = FALSE;
	int ifindex;

	_LOGI ("(IPv6 Config Get) reply received.");

	nm_clear_g_source (&priv->ppp_timeout_handler);

	if (!set_ip_config_common (manager, config_dict, NM_PPP_IP6_CONFIG_INTERFACE, NULL))
		goto out;

	ifindex = nm_platform_link_get_ifindex (NM_PLATFORM_GET, priv->ip_iface);
	if (ifindex <= 0)
		goto out;

	config = nm_ip6_config_new (nm_platform_get_multi_idx (NM_PLATFORM_GET), ifindex);

	memset (&addr, 0, sizeof (addr));
	addr.plen = 64;

	if (iid_value_to_ll6_addr (config_dict, NM_PPP_IP6_CONFIG_PEER_IID, &a, NULL)) {
		const NMPlatformIP6Route r = {
			.ifindex   = ifindex,
			.rt_source = NM_IP_CONFIG_SOURCE_PPP,
			.gateway   = a,
			.table_coerced = nm_platform_route_table_coerce (priv->ip6_route_table),
			.metric    = priv->ip6_route_metric,
		};

		nm_ip6_config_add_route (config, &r, NULL);
		addr.peer_address = a;
		has_peer = TRUE;
	}

	if (iid_value_to_ll6_addr (config_dict, NM_PPP_IP6_CONFIG_OUR_IID, &addr.address, &iid)) {
		if (!has_peer)
			addr.peer_address = addr.address;
		nm_ip6_config_add_address (config, &addr);

		/* Push the IPv6 config and interface identifier up to the device */
		g_signal_emit (manager, signals[IP6_CONFIG], 0, priv->ip_iface, &iid, config);
	} else
		_LOGE ("invalid IPv6 address received!");

out:
	g_dbus_method_invocation_return_value (context, NULL);
}

/*****************************************************************************/

typedef struct {
	GPtrArray *array;
	GStringChunk *chunk;
} NMCmdLine;

static NMCmdLine *
nm_cmd_line_new (void)
{
	NMCmdLine *cmd;

	cmd = g_slice_new (NMCmdLine);
	cmd->array = g_ptr_array_new ();
	cmd->chunk = g_string_chunk_new (1024);

	return cmd;
}

static void
nm_cmd_line_destroy (NMCmdLine *cmd)
{
	g_ptr_array_free (cmd->array, TRUE);
	g_string_chunk_free (cmd->chunk);
	g_slice_free (NMCmdLine, cmd);
}

static char *
nm_cmd_line_to_str (NMCmdLine *cmd)
{
	char *str;

	g_ptr_array_add (cmd->array, NULL);
	str = g_strjoinv (" ", (gchar **) cmd->array->pdata);
	g_ptr_array_remove_index (cmd->array, cmd->array->len - 1);

	return str;
}

static void
nm_cmd_line_add_string (NMCmdLine *cmd, const char *str)
{
	g_ptr_array_add (cmd->array, g_string_chunk_insert (cmd->chunk, str));
}

static void
nm_cmd_line_add_int (NMCmdLine *cmd, int i)
{
	char *str;

	str = g_strdup_printf ("%d", i);
	nm_cmd_line_add_string (cmd, str);
	g_free (str);
}

/*****************************************************************************/

NM_UTILS_LOOKUP_STR_DEFINE_STATIC (pppd_exit_code_to_str, int,
	NM_UTILS_LOOKUP_DEFAULT ("Unknown error"),
	NM_UTILS_LOOKUP_STR_ITEM ( 1, "Fatal pppd error");
	NM_UTILS_LOOKUP_STR_ITEM ( 2, "pppd options error"),
	NM_UTILS_LOOKUP_STR_ITEM ( 3, "No root priv error"),
	NM_UTILS_LOOKUP_STR_ITEM ( 4, "No ppp module error"),
	NM_UTILS_LOOKUP_STR_ITEM ( 5, "pppd received a signal"),
	NM_UTILS_LOOKUP_STR_ITEM ( 6, "Serial port lock failed"),
	NM_UTILS_LOOKUP_STR_ITEM ( 7, "Serial port open failed"),
	NM_UTILS_LOOKUP_STR_ITEM ( 8, "Connect script failed"),
	NM_UTILS_LOOKUP_STR_ITEM ( 9, "Pty program error"),
	NM_UTILS_LOOKUP_STR_ITEM (10, "PPP negotiation failed"),
	NM_UTILS_LOOKUP_STR_ITEM (11, "Peer didn't authenticatie itself"),
	NM_UTILS_LOOKUP_STR_ITEM (12, "Link idle: Idle Seconds reached."),
	NM_UTILS_LOOKUP_STR_ITEM (13, "Connect time limit reached."),
	NM_UTILS_LOOKUP_STR_ITEM (14, "Callback negotiated, call should come back."),
	NM_UTILS_LOOKUP_STR_ITEM (15, "Lack of LCP echo responses"),
	NM_UTILS_LOOKUP_STR_ITEM (16, "A modem hung up the phone"),
	NM_UTILS_LOOKUP_STR_ITEM (17, "Loopback detected"),
	NM_UTILS_LOOKUP_STR_ITEM (18, "The init script failed"),
	NM_UTILS_LOOKUP_STR_ITEM (19, "Authentication error. "
	                              "We failed to authenticate ourselves to the peer. "
	                              "Maybe bad account or password?"),
);

static void
ppp_watch_cb (GPid pid, int status, gpointer user_data)
{
	NMPPPManager *manager = NM_PPP_MANAGER (user_data);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	int err;
	const long long lpid = (long long) pid;

	g_return_if_fail (pid == priv->pid);

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err) {
			_LOGW ("pppd pid %lld exited with error %d: %s",
			       lpid, err,
			       pppd_exit_code_to_str (err));
		} else
			_LOGD ("pppd pid %lld exited with success", lpid);
	} else if (WIFSTOPPED (status)) {
		_LOGW ("pppd pid %lld stopped unexpectedly with signal %d",
		       lpid, WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		_LOGW ("pppd pid %lld died with signal %d",
		       lpid, WTERMSIG (status));
	} else
		_LOGW ("pppd pid %lld died from an unknown cause", lpid);

	priv->pid = 0;
	priv->ppp_watch_id = 0;
	_ppp_cleanup (manager);
	g_signal_emit (manager, signals[STATE_CHANGED], 0, (guint) NM_PPP_STATUS_DEAD);
}

static gboolean
pppd_timed_out (gpointer data)
{
	NMPPPManager *manager = NM_PPP_MANAGER (data);

	_LOGW ("pppd timed out or didn't initialize our dbus module");
	_ppp_cleanup (manager);
	_ppp_kill (manager);

	g_signal_emit (manager, signals[STATE_CHANGED], 0, (guint) NM_PPP_STATUS_DEAD);

	return FALSE;
}

static NMCmdLine *
create_pppd_cmd_line (NMPPPManager *self,
                      NMSettingPpp *setting,
                      NMSettingPppoe *pppoe,
                      NMSettingAdsl  *adsl,
                      const char *ppp_name,
                      guint baud_override,
                      gboolean ip4_enabled,
                      gboolean ip6_enabled,
                      GError **err)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	const char *pppd_binary = NULL;
	NMCmdLine *cmd;
	gboolean ppp_debug;
	static int unit;

	g_return_val_if_fail (setting != NULL, NULL);

	pppd_binary = nm_utils_find_helper ("pppd", NULL, err);
	if (!pppd_binary)
		return NULL;

	if (!ip4_enabled && !ip6_enabled) {
		g_set_error_literal (err,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_FAILED,
		                     "Neither IPv4 or IPv6 allowed.");
		return NULL;
	}

	/* Create pppd command line */
	cmd = nm_cmd_line_new ();
	nm_cmd_line_add_string (cmd, pppd_binary);

	nm_cmd_line_add_string (cmd, "nodetach");
	nm_cmd_line_add_string (cmd, "lock");

	/* NM handles setting the default route */
	nm_cmd_line_add_string (cmd, "nodefaultroute");

	if (!ip4_enabled)
		nm_cmd_line_add_string (cmd, "noip");

	if (ip6_enabled) {
		/* Allow IPv6 to be configured by IPV6CP */
		nm_cmd_line_add_string (cmd, "ipv6");
		nm_cmd_line_add_string (cmd, ",");
	} else
		nm_cmd_line_add_string (cmd, "noipv6");

	ppp_debug = !!getenv ("NM_PPP_DEBUG");
	if (nm_logging_enabled (LOGL_DEBUG, LOGD_PPP))
		ppp_debug = TRUE;

	if (ppp_debug)
		nm_cmd_line_add_string (cmd, "debug");

	if (ppp_name) {
		nm_cmd_line_add_string (cmd, "user");
		nm_cmd_line_add_string (cmd, ppp_name);
	}

	if (pppoe) {
		char *dev_str;
		const char *pppoe_service;

		nm_cmd_line_add_string (cmd, "plugin");
		nm_cmd_line_add_string (cmd, "rp-pppoe.so");

		dev_str = g_strdup_printf ("nic-%s", priv->parent_iface);
		nm_cmd_line_add_string (cmd, dev_str);
		g_free (dev_str);

		pppoe_service = nm_setting_pppoe_get_service (pppoe);
		if (pppoe_service) {
			nm_cmd_line_add_string (cmd, "rp_pppoe_service");
			nm_cmd_line_add_string (cmd, pppoe_service);
		}
	} else if (adsl) {
		const gchar *protocol = nm_setting_adsl_get_protocol (adsl);

		if (!strcmp (protocol, NM_SETTING_ADSL_PROTOCOL_PPPOA)) {
			guint32 vpi = nm_setting_adsl_get_vpi (adsl);
			guint32 vci = nm_setting_adsl_get_vci (adsl);
			const char *encaps = nm_setting_adsl_get_encapsulation (adsl);
			gchar *vpivci;

			nm_cmd_line_add_string (cmd, "plugin");
			nm_cmd_line_add_string (cmd, "pppoatm.so");

			vpivci = g_strdup_printf("%d.%d", vpi, vci);
			nm_cmd_line_add_string (cmd, vpivci);
			g_free (vpivci);

			if (g_strcmp0 (encaps, NM_SETTING_ADSL_ENCAPSULATION_LLC) == 0)
				nm_cmd_line_add_string (cmd, "llc-encaps");
			else /*if (g_strcmp0 (encaps, NM_SETTING_ADSL_ENCAPSULATION_VCMUX) == 0)*/
				nm_cmd_line_add_string (cmd, "vc-encaps");

		} else if (!strcmp (protocol, NM_SETTING_ADSL_PROTOCOL_PPPOE)) {
			nm_cmd_line_add_string (cmd, "plugin");
			nm_cmd_line_add_string (cmd, "rp-pppoe.so");
			nm_cmd_line_add_string (cmd, priv->parent_iface);
		}

		nm_cmd_line_add_string (cmd, "noipdefault");
	} else {
		nm_cmd_line_add_string (cmd, priv->parent_iface);
		/* Don't send some random address as the local address */
		nm_cmd_line_add_string (cmd, "noipdefault");
	}

	if (nm_setting_ppp_get_baud (setting))
		nm_cmd_line_add_int (cmd, nm_setting_ppp_get_baud (setting));
	else if (baud_override)
		nm_cmd_line_add_int (cmd, (int) baud_override);

	/* noauth by default, because we certainly don't have any information
	 * with which to verify anything the peer gives us if we ask it to
	 * authenticate itself, which is what 'auth' really means.
	 */
	nm_cmd_line_add_string (cmd, "noauth");

	if (nm_setting_ppp_get_refuse_eap (setting))
		nm_cmd_line_add_string (cmd, "refuse-eap");
	if (nm_setting_ppp_get_refuse_pap (setting))
		nm_cmd_line_add_string (cmd, "refuse-pap");
	if (nm_setting_ppp_get_refuse_chap (setting))
		nm_cmd_line_add_string (cmd, "refuse-chap");
	if (nm_setting_ppp_get_refuse_mschap (setting))
		nm_cmd_line_add_string (cmd, "refuse-mschap");
	if (nm_setting_ppp_get_refuse_mschapv2 (setting))
		nm_cmd_line_add_string (cmd, "refuse-mschap-v2");
	if (nm_setting_ppp_get_nobsdcomp (setting))
		nm_cmd_line_add_string (cmd, "nobsdcomp");
	if (nm_setting_ppp_get_no_vj_comp (setting))
		nm_cmd_line_add_string (cmd, "novj");
	if (nm_setting_ppp_get_nodeflate (setting))
		nm_cmd_line_add_string (cmd, "nodeflate");
	if (nm_setting_ppp_get_require_mppe (setting))
		nm_cmd_line_add_string (cmd, "require-mppe");
	if (nm_setting_ppp_get_require_mppe_128 (setting))
		nm_cmd_line_add_string (cmd, "require-mppe-128");
	if (nm_setting_ppp_get_mppe_stateful (setting))
		nm_cmd_line_add_string (cmd, "mppe-stateful");
	if (nm_setting_ppp_get_crtscts (setting))
		nm_cmd_line_add_string (cmd, "crtscts");

	/* Always ask for DNS, we don't have to use them if the connection
	 * overrides the returned servers.
	 */
	nm_cmd_line_add_string (cmd, "usepeerdns");

	if (nm_setting_ppp_get_mru (setting)) {
		nm_cmd_line_add_string (cmd, "mru");
		nm_cmd_line_add_int (cmd, nm_setting_ppp_get_mru (setting));
	}

	if (nm_setting_ppp_get_mtu (setting)) {
		nm_cmd_line_add_string (cmd, "mtu");
		nm_cmd_line_add_int (cmd, nm_setting_ppp_get_mtu (setting));
	}

	nm_cmd_line_add_string (cmd, "lcp-echo-failure");
	nm_cmd_line_add_int (cmd, nm_setting_ppp_get_lcp_echo_failure (setting));

	nm_cmd_line_add_string (cmd, "lcp-echo-interval");
	nm_cmd_line_add_int (cmd, nm_setting_ppp_get_lcp_echo_interval (setting));

	/* Avoid pppd to exit if no traffic going through */
	nm_cmd_line_add_string (cmd, "idle");
	nm_cmd_line_add_int (cmd, 0);

	nm_cmd_line_add_string (cmd, "ipparam");
	nm_cmd_line_add_string (cmd, nm_exported_object_get_path (NM_EXPORTED_OBJECT (self)));

	nm_cmd_line_add_string (cmd, "plugin");
	nm_cmd_line_add_string (cmd, NM_PPPD_PLUGIN);

	if (pppoe && nm_setting_pppoe_get_parent (pppoe)) {
		/* The PPP interface is going to be renamed, so pass a
		 * different unit each time so that activations don't
		 * race with each others. */
		nm_cmd_line_add_string (cmd, "unit");
		nm_cmd_line_add_int (cmd, unit);
		unit = unit < G_MAXINT ? unit + 1 : 0;
	}

	return cmd;
}

static void
pppoe_fill_defaults (NMSettingPpp *setting)
{
	if (!nm_setting_ppp_get_mtu (setting))
		g_object_set (setting, NM_SETTING_PPP_MTU, (guint32) 1492, NULL);

	if (!nm_setting_ppp_get_mru (setting))
		g_object_set (setting, NM_SETTING_PPP_MRU, (guint32) 1492, NULL);

	g_object_set (setting,
	              NM_SETTING_PPP_NOAUTH, TRUE,
	              NM_SETTING_PPP_NODEFLATE, TRUE,
	              NULL);

	/* FIXME: These commented settings should be set as well, update NMSettingPpp first. */
#if 0
	setting->noipdefault = TRUE;
	setting->default_asyncmap = TRUE;
	setting->defaultroute = TRUE;
	setting->hide_password = TRUE;
	setting->noaccomp = TRUE;
	setting->nopcomp = TRUE;
	setting->novj = TRUE;
	setting->novjccomp = TRUE;
#endif
}

static gboolean
_ppp_manager_start (NMPPPManager *manager,
                    NMActRequest *req,
                    const char *ppp_name,
                    guint32 timeout_secs,
                    guint baud_override,
                    GError **err)
{
	NMPPPManagerPrivate *priv;
	NMConnection *connection;
	NMSettingPpp *s_ppp;
	gs_unref_object NMSettingPpp *s_ppp_free = NULL;
	NMSettingPppoe *pppoe_setting;
	NMSettingAdsl *adsl_setting;
	NMCmdLine *ppp_cmd;
	char *cmd_str;
	struct stat st;
	const char *ip6_method, *ip4_method;
	gboolean ip6_enabled = FALSE;
	gboolean ip4_enabled = FALSE;

	g_return_val_if_fail (NM_IS_PPP_MANAGER (manager), FALSE);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), FALSE);

	priv = NM_PPP_MANAGER_GET_PRIVATE (manager);

#if !WITH_PPP
	/* PPP support disabled */
	g_set_error_literal (err,
	                     NM_MANAGER_ERROR,
	                     NM_MANAGER_ERROR_FAILED,
	                     "PPP support is not enabled.");
	return FALSE;
#endif

	nm_exported_object_export (NM_EXPORTED_OBJECT (manager));

	priv->pid = 0;

	/* Make sure /dev/ppp exists (bgo #533064) */
	if (stat ("/dev/ppp", &st) || !S_ISCHR (st.st_mode))
		nm_utils_modprobe (NULL, FALSE, "ppp_generic", NULL);

	connection = nm_act_request_get_applied_connection (req);
	g_return_val_if_fail (connection, FALSE);

	s_ppp = nm_connection_get_setting_ppp (connection);
	if (!s_ppp) {
		/* If the PPP settings are all default we may not have a PPP setting yet,
		 * so just make a default one here.
		 */
		s_ppp = s_ppp_free = NM_SETTING_PPP (nm_setting_ppp_new ());
	}

	pppoe_setting = nm_connection_get_setting_pppoe (connection);
	if (pppoe_setting) {
		/* We can't modify the applied connection's setting, make a copy */
		if (!s_ppp_free)
			s_ppp = s_ppp_free = NM_SETTING_PPP (nm_setting_duplicate ((NMSetting *) s_ppp));
		pppoe_fill_defaults (s_ppp);
	}

	adsl_setting = (NMSettingAdsl *) nm_connection_get_setting (connection, NM_TYPE_SETTING_ADSL);

	/* Figure out what address methods should be enabled */
	ip4_method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);
	ip4_enabled = g_strcmp0 (ip4_method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) == 0;
	ip6_method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);
	ip6_enabled = g_strcmp0 (ip6_method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) == 0;

	ppp_cmd = create_pppd_cmd_line (manager,
	                                s_ppp,
	                                pppoe_setting,
	                                adsl_setting,
	                                ppp_name,
	                                baud_override,
	                                ip4_enabled,
	                                ip6_enabled,
	                                err);
	if (!ppp_cmd)
		goto out;

	g_ptr_array_add (ppp_cmd->array, NULL);

	_LOGI ("starting PPP connection");

	cmd_str = nm_cmd_line_to_str (ppp_cmd);
	_LOGD ("command line: %s", cmd_str);
	g_free (cmd_str);

	priv->pid = 0;
	if (!g_spawn_async (NULL, (char **) ppp_cmd->array->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD,
	                    nm_utils_setpgid, NULL,
	                    &priv->pid, err)) {
		goto out;
	}

	_LOGI ("pppd started with pid %lld", (long long) priv->pid);

	priv->ppp_watch_id = g_child_watch_add (priv->pid, (GChildWatchFunc) ppp_watch_cb, manager);
	priv->ppp_timeout_handler = g_timeout_add_seconds (timeout_secs, pppd_timed_out, manager);
	priv->act_req = g_object_ref (req);

out:
	if (ppp_cmd)
		nm_cmd_line_destroy (ppp_cmd);

	if (priv->pid <= 0)
		nm_exported_object_unexport (NM_EXPORTED_OBJECT (manager));

	return priv->pid > 0;
}

static void
_ppp_kill (NMPPPManager *manager)
{
	NMPPPManagerPrivate *priv;

	g_return_if_fail (NM_IS_PPP_MANAGER (manager));

	priv = NM_PPP_MANAGER_GET_PRIVATE (manager);

	if (priv->pid) {
		nm_utils_kill_child_async (priv->pid, SIGTERM, LOGD_PPP, "pppd", 2000, NULL, NULL);
		priv->pid = 0;
	}
}

static void
_ppp_cleanup (NMPPPManager *manager)
{
	NMPPPManagerPrivate *priv;

	g_return_if_fail (NM_IS_PPP_MANAGER (manager));

	priv = NM_PPP_MANAGER_GET_PRIVATE (manager);

	cancel_get_secrets (manager);

	nm_clear_g_source (&priv->monitor_id);

	if (priv->monitor_fd >= 0) {
		/* Get the stats one last time */
		monitor_cb (manager);
		nm_close (priv->monitor_fd);
		priv->monitor_fd = -1;
	}

	nm_clear_g_source (&priv->ppp_timeout_handler);
	nm_clear_g_source (&priv->ppp_watch_id);
}

/*****************************************************************************/

typedef struct {
	NMPPPManager *manager;
	GSimpleAsyncResult *result;
	GCancellable *cancellable;
} StopContext;

static void
stop_context_complete (StopContext *ctx)
{
	if (ctx->cancellable)
		g_object_unref (ctx->cancellable);
	g_simple_async_result_complete_in_idle (ctx->result);
	g_object_unref (ctx->result);
	g_object_unref (ctx->manager);
	g_slice_free (StopContext, ctx);
}

static gboolean
stop_context_complete_if_cancelled (StopContext *ctx)
{
	GError *error = NULL;

	if (g_cancellable_set_error_if_cancelled (ctx->cancellable, &error)) {
		g_simple_async_result_take_error (ctx->result, error);
		stop_context_complete (ctx);
		return TRUE;
	}
	return FALSE;
}

static gboolean
_ppp_manager_stop_finish (NMPPPManager *manager,
                          GAsyncResult *res,
                          GError **error)
{
	return !g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error);
}

static void
kill_child_ready  (pid_t pid,
                   gboolean success,
                   int child_status,
                   StopContext *ctx)
{
	if (stop_context_complete_if_cancelled (ctx))
		return;
	stop_context_complete (ctx);
}

static void
_ppp_manager_stop_async (NMPPPManager *manager,
                         GCancellable *cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	StopContext *ctx;

	nm_exported_object_unexport (NM_EXPORTED_OBJECT (manager));

	ctx = g_slice_new0 (StopContext);
	ctx->manager = g_object_ref (manager);
	ctx->result = g_simple_async_result_new (G_OBJECT (manager),
	                                         callback,
	                                         user_data,
	                                         _ppp_manager_stop_async);

	/* Setup cancellable */
	ctx->cancellable = cancellable ? g_object_ref (cancellable) : NULL;
	if (stop_context_complete_if_cancelled (ctx))
		return;

	/* Cleanup internals */
	_ppp_cleanup (manager);

	/* If no pppd running, we're done */
	if (!priv->pid) {
		stop_context_complete (ctx);
		return;
	}

	/* No cancellable operation, so just wait until it returns always */
	nm_utils_kill_child_async (priv->pid,
	                           SIGTERM,
	                           LOGD_PPP,
	                           "pppd",
	                           2000,
	                           (NMUtilsKillChildAsyncCb) kill_child_ready,
	                           ctx);
	priv->pid = 0;
}

static void
_ppp_manager_stop_sync (NMPPPManager *manager)
{
	NMExportedObject *exported = NM_EXPORTED_OBJECT (manager);

	if (nm_exported_object_is_exported (exported))
		nm_exported_object_unexport (exported);

	_ppp_cleanup (manager);
	_ppp_kill (manager);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE ((NMPPPManager *) object);

	switch (prop_id) {
	case PROP_PARENT_IFACE:
		g_value_set_string (value, priv->parent_iface);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE ((NMPPPManager *) object);

	switch (prop_id) {
	case PROP_PARENT_IFACE:
		/* construct-only */
		priv->parent_iface = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_ppp_manager_init (NMPPPManager *manager)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);

	priv->monitor_fd = -1;
	priv->ip4_route_table = RT_TABLE_MAIN;
	priv->ip4_route_metric = 460;
	priv->ip6_route_table = RT_TABLE_MAIN;
	priv->ip6_route_metric = 460;
}

static NMPPPManager *
_ppp_manager_new (const char *iface)
{
	g_return_val_if_fail (iface != NULL, NULL);

	return (NMPPPManager *) g_object_new (NM_TYPE_PPP_MANAGER,
	                                      NM_PPP_MANAGER_PARENT_IFACE, iface,
	                                      NULL);
}

static void
dispose (GObject *object)
{
	NMPPPManager *self = (NMPPPManager *) object;
	NMExportedObject *exported = NM_EXPORTED_OBJECT (self);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);

	if (nm_exported_object_is_exported (exported))
		nm_exported_object_unexport (exported);

	_ppp_cleanup (self);
	_ppp_kill (self);

	g_clear_object (&priv->act_req);

	G_OBJECT_CLASS (nm_ppp_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE ((NMPPPManager *) object);

	g_free (priv->ip_iface);
	g_free (priv->parent_iface);

	G_OBJECT_CLASS (nm_ppp_manager_parent_class)->finalize (object);
}

static void
nm_ppp_manager_class_init (NMPPPManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);
	NMExportedObjectClass *exported_object_class = NM_EXPORTED_OBJECT_CLASS (manager_class);

	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	exported_object_class->export_path = NM_EXPORT_PATH_NUMBERED (NM_DBUS_PATH"/PPP");

	obj_properties[PROP_PARENT_IFACE] =
	     g_param_spec_string (NM_PPP_MANAGER_PARENT_IFACE, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[STATE_CHANGED] =
	    g_signal_new (NM_PPP_MANAGER_SIGNAL_STATE_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  G_TYPE_UINT);

	signals[IP4_CONFIG] =
	    g_signal_new (NM_PPP_MANAGER_SIGNAL_IP4_CONFIG,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2,
	                  G_TYPE_STRING,
	                  G_TYPE_OBJECT);

	signals[IP6_CONFIG] =
	    g_signal_new (NM_PPP_MANAGER_SIGNAL_IP6_CONFIG,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 3, G_TYPE_STRING, G_TYPE_POINTER, G_TYPE_OBJECT);

	signals[STATS] =
	    g_signal_new (NM_PPP_MANAGER_SIGNAL_STATS,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2,
	                  G_TYPE_UINT /*guint32 in_bytes*/,
	                  G_TYPE_UINT /*guint32 out_bytes*/);

	nm_exported_object_class_add_interface (NM_EXPORTED_OBJECT_CLASS (manager_class),
	                                        NMDBUS_TYPE_PPP_MANAGER_SKELETON,
	                                        "NeedSecrets", impl_ppp_manager_need_secrets,
	                                        "SetIp4Config", impl_ppp_manager_set_ip4_config,
	                                        "SetIp6Config", impl_ppp_manager_set_ip6_config,
	                                        "SetState", impl_ppp_manager_set_state,
	                                        NULL);
}

NMPPPOps ppp_ops = {
	.create               = _ppp_manager_new,
	.set_route_parameters = _ppp_manager_set_route_parameters,
	.start                = _ppp_manager_start,
	.stop_async           = _ppp_manager_stop_async,
	.stop_finish          = _ppp_manager_stop_finish,
	.stop_sync            = _ppp_manager_stop_sync,
};
