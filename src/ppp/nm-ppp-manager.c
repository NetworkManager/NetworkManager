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
#include <unistd.h>
#include <arpa/inet.h>
#include <stdlib.h>
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
#include "nm-dbus-object.h"

#include "nm-pppd-plugin.h"
#include "nm-ppp-plugin-api.h"
#include "nm-ppp-status.h"

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
	IFINDEX_SET,
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
	char *ip_iface;
	int ifindex;

	NMActRequest *act_req;
	GDBusMethodInvocation *pending_secrets_context;
	NMActRequestGetSecretsCallId *secrets_id;
	const char *secrets_setting_name;

	guint ppp_watch_id;
	guint ppp_timeout_handler;

	/* Monitoring */
	int monitor_fd;
	guint monitor_id;

	guint32 ip4_route_table;
	guint32 ip4_route_metric;
	guint32 ip6_route_table;
	guint32 ip6_route_metric;
} NMPPPManagerPrivate;

struct _NMPPPManager {
	NMDBusObject parent;
	NMPPPManagerPrivate _priv;
};

typedef struct {
	NMDBusObjectClass parent;
} NMPPPManagerClass;

G_DEFINE_TYPE (NMPPPManager, nm_ppp_manager, NM_TYPE_DBUS_OBJECT)

#define NM_PPP_MANAGER_GET_PRIVATE(self) _NM_GET_PRIVATE (self, NMPPPManager, NM_IS_PPP_MANAGER, NMDBusObject)

/*****************************************************************************/

#define _NMLOG_DOMAIN      LOGD_PPP
#define _NMLOG(level, ...) __NMLOG_DEFAULT (level, _NMLOG_DOMAIN, "ppp-manager", __VA_ARGS__)

/*****************************************************************************/

static void _ppp_cleanup  (NMPPPManager *self);

static NMPPPManagerStopHandle *_ppp_manager_stop (NMPPPManager *self,
                                                  GCancellable *cancellable,
                                                  NMPPPManagerStopCallback callback,
                                                  gpointer user_data);

static void _ppp_manager_stop_cancel (NMPPPManagerStopHandle *handle);

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
	NMPPPManager *self = NM_PPP_MANAGER (user_data);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	const char *ifname;
	int errsv;

	ifname = nm_platform_link_get_name (NM_PLATFORM_GET, priv->ifindex);

	if (ifname) {
		struct ppp_stats stats = { };
		struct ifreq req = {
			.ifr_data = (caddr_t) &stats,
		};

		nm_utils_ifname_cpy (req.ifr_name, ifname);
		if (ioctl (priv->monitor_fd, SIOCGPPPSTATS, &req) < 0) {
			errsv = errno;
			if (errsv != ENODEV)
				_LOGW ("could not read ppp stats: %s", nm_strerror_native (errsv));
		} else {
			g_signal_emit (self, signals[STATS], 0,
			               (guint) stats.p.ppp_ibytes,
			               (guint) stats.p.ppp_obytes);
		}
	}

	return G_SOURCE_CONTINUE;
}

static void
monitor_stats (NMPPPManager *self)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	int errsv;

	/* already monitoring */
	if (priv->monitor_fd >= 0)
		return;

	priv->monitor_fd = socket (AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (priv->monitor_fd < 0) {
		errsv = errno;
		_LOGW ("could not monitor PPP stats: %s", nm_strerror_native (errsv));
		return;
	}

	g_warn_if_fail (priv->monitor_id == 0);
	if (priv->monitor_id)
		g_source_remove (priv->monitor_id);
	priv->monitor_id = g_timeout_add_seconds (5, monitor_cb, self);
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
	g_dbus_method_invocation_return_value (priv->pending_secrets_context,
	                                       g_variant_new ("(ss)",
	                                                      username ?: "",
	                                                      password ?: ""));

out:
	priv->pending_secrets_context = NULL;
	priv->secrets_id = NULL;
	priv->secrets_setting_name = NULL;
}

static void
impl_ppp_manager_need_secrets (NMDBusObject *obj,
                               const NMDBusInterfaceInfoExtended *interface_info,
                               const NMDBusMethodInfoExtended *method_info,
                               GDBusConnection *connection,
                               const char *sender,
                               GDBusMethodInvocation *invocation,
                               GVariant *parameters)
{
	NMPPPManager *self = NM_PPP_MANAGER (obj);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	NMConnection *applied_connection;
	const char *username = NULL;
	const char *password = NULL;
	guint32 tries;
	gs_unref_ptrarray GPtrArray *hints = NULL;
	GError *error = NULL;
	NMSecretAgentGetSecretsFlags flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

	nm_active_connection_clear_secrets (NM_ACTIVE_CONNECTION (priv->act_req));

	applied_connection = nm_act_request_get_applied_connection (priv->act_req);

	priv->secrets_setting_name = nm_connection_need_secrets (applied_connection, &hints);
	if (!priv->secrets_setting_name) {
		/* Use existing secrets from the connection */
		if (extract_details_from_connection (applied_connection, NULL, &username, &password, &error)) {
			/* Send existing secrets to the PPP plugin */
			priv->pending_secrets_context = invocation;
			ppp_secrets_cb (priv->act_req, priv->secrets_id, NULL, NULL, self);
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

	if (hints)
		g_ptr_array_add (hints, NULL);

	priv->secrets_id = nm_act_request_get_secrets (priv->act_req,
	                                               FALSE,
	                                               priv->secrets_setting_name,
	                                               flags,
	                                               hints ? (const char *const*) hints->pdata : NULL,
	                                               ppp_secrets_cb,
	                                               self);
	g_object_set_qdata (G_OBJECT (applied_connection), ppp_manager_secret_tries_quark (), GUINT_TO_POINTER (++tries));
	priv->pending_secrets_context = invocation;
}

static void
impl_ppp_manager_set_state (NMDBusObject *obj,
                            const NMDBusInterfaceInfoExtended *interface_info,
                            const NMDBusMethodInfoExtended *method_info,
                            GDBusConnection *connection,
                            const char *sender,
                            GDBusMethodInvocation *invocation,
                            GVariant *parameters)
{
	NMPPPManager *self = NM_PPP_MANAGER (obj);
	guint32 state;

	g_variant_get (parameters, "(u)", &state);
	g_signal_emit (self, signals[STATE_CHANGED], 0, (guint) state);
	g_dbus_method_invocation_return_value (invocation, NULL);
}

static void
impl_ppp_manager_set_ifindex (NMDBusObject *obj,
                              const NMDBusInterfaceInfoExtended *interface_info,
                              const NMDBusMethodInfoExtended *method_info,
                              GDBusConnection *connection,
                              const char *sender,
                              GDBusMethodInvocation *invocation,
                              GVariant *parameters)
{
	NMPPPManager *self = NM_PPP_MANAGER (obj);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	const NMPlatformLink *plink = NULL;
	nm_auto_nmpobj const NMPObject *obj_keep_alive = NULL;
	gint32 ifindex;

	g_variant_get (parameters, "(i)", &ifindex);

	if (priv->ifindex >= 0) {
		if (priv->ifindex == ifindex)
			_LOGD ("set-ifindex: ignore repeated calls setting ifindex to %d", (int) ifindex);
		else
			_LOGW ("set-ifindex: can't change the ifindex from %d to %d", priv->ifindex, (int) ifindex);
		goto out;
	}

	if (ifindex > 0) {
		plink = nm_platform_link_get (NM_PLATFORM_GET, ifindex);
		if (!plink) {
			nm_platform_process_events (NM_PLATFORM_GET);
			plink = nm_platform_link_get (NM_PLATFORM_GET, ifindex);
		}
	}

	if (!plink) {
		_LOGW ("set-ifindex: unknown interface with ifindex %d", ifindex);
		ifindex = 0;
	} else {
		obj_keep_alive = nmp_object_ref (NMP_OBJECT_UP_CAST (plink));
		_LOGD ("set-ifindex: %d, name \"%s\"", (int) ifindex, plink->name);
	}

	priv->ifindex = ifindex;

	g_signal_emit (self,
	               signals[IFINDEX_SET],
	               0,
	               ifindex,
	               plink ? plink->name : NULL);

out:
	g_dbus_method_invocation_return_value (invocation, NULL);
}

static gboolean
set_ip_config_common (NMPPPManager *self,
                      GVariant *config_dict,
                      guint32 *out_mtu)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	NMConnection *applied_connection;
	NMSettingPpp *s_ppp;

	if (priv->ifindex <= 0)
		return FALSE;

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
impl_ppp_manager_set_ip4_config (NMDBusObject *obj,
                                 const NMDBusInterfaceInfoExtended *interface_info,
                                 const NMDBusMethodInfoExtended *method_info,
                                 GDBusConnection *connection,
                                 const char *sender,
                                 GDBusMethodInvocation *invocation,
                                 GVariant *parameters)
{
	NMPPPManager *self = NM_PPP_MANAGER (obj);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	gs_unref_object NMIP4Config *config = NULL;
	NMPlatformIP4Address address;
	guint32 u32, mtu;
	GVariantIter *iter;
	gs_unref_variant GVariant *config_dict = NULL;

	_LOGI ("(IPv4 Config Get) reply received.");

	g_variant_get (parameters, "(@a{sv})", &config_dict);

	nm_clear_g_source (&priv->ppp_timeout_handler);

	if (!set_ip_config_common (self, config_dict, &mtu))
		goto out;

	config = nm_ip4_config_new (nm_platform_get_multi_idx (NM_PLATFORM_GET), priv->ifindex);

	if (mtu)
		nm_ip4_config_set_mtu (config, mtu, NM_IP_CONFIG_SOURCE_PPP);

	memset (&address, 0, sizeof (address));
	address.plen = 32;

	if (g_variant_lookup (config_dict, NM_PPP_IP4_CONFIG_ADDRESS, "u", &u32))
		address.address = u32;

	if (g_variant_lookup (config_dict, NM_PPP_IP4_CONFIG_GATEWAY, "u", &u32)) {
		const NMPlatformIP4Route r = {
			.ifindex   = priv->ifindex,
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
	g_signal_emit (self, signals[IP4_CONFIG], 0, config);

out:
	g_dbus_method_invocation_return_value (invocation, NULL);
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
impl_ppp_manager_set_ip6_config (NMDBusObject *obj,
                                 const NMDBusInterfaceInfoExtended *interface_info,
                                 const NMDBusMethodInfoExtended *method_info,
                                 GDBusConnection *connection,
                                 const char *sender,
                                 GDBusMethodInvocation *invocation,
                                 GVariant *parameters)
{
	NMPPPManager *self = NM_PPP_MANAGER (obj);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	gs_unref_object NMIP6Config *config = NULL;
	NMPlatformIP6Address addr;
	struct in6_addr a;
	NMUtilsIPv6IfaceId iid = NM_UTILS_IPV6_IFACE_ID_INIT;
	gboolean has_peer = FALSE;
	gs_unref_variant GVariant *config_dict = NULL;

	_LOGI ("(IPv6 Config Get) reply received.");

	g_variant_get (parameters, "(@a{sv})", &config_dict);

	nm_clear_g_source (&priv->ppp_timeout_handler);

	if (!set_ip_config_common (self, config_dict, NULL))
		goto out;

	config = nm_ip6_config_new (nm_platform_get_multi_idx (NM_PLATFORM_GET), priv->ifindex);

	memset (&addr, 0, sizeof (addr));
	addr.plen = 64;

	if (iid_value_to_ll6_addr (config_dict, NM_PPP_IP6_CONFIG_PEER_IID, &a, NULL)) {
		const NMPlatformIP6Route r = {
			.ifindex   = priv->ifindex,
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
		g_signal_emit (self, signals[IP6_CONFIG], 0, &iid, config);
	} else
		_LOGE ("invalid IPv6 address received!");

out:
	g_dbus_method_invocation_return_value (invocation, NULL);
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
	NMPPPManager *self = NM_PPP_MANAGER (user_data);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
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
	_ppp_cleanup (self);
	g_signal_emit (self, signals[STATE_CHANGED], 0, (guint) NM_PPP_STATUS_DEAD);
}

static gboolean
pppd_timed_out (gpointer data)
{
	NMPPPManager *self = NM_PPP_MANAGER (data);

	_LOGW ("pppd timed out or didn't initialize our dbus module");
	_ppp_manager_stop (self, NULL, NULL, NULL);

	g_signal_emit (self, signals[STATE_CHANGED], 0, (guint) NM_PPP_STATUS_DEAD);

	return FALSE;
}

static GPtrArray *
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
	gs_unref_ptrarray GPtrArray *cmd = NULL;
	gboolean ppp_debug;

	g_return_val_if_fail (setting != NULL, NULL);

#ifndef PPPD_PATH
#define PPPD_PATH NULL
#endif

	pppd_binary = nm_utils_find_helper ("pppd", PPPD_PATH, err);
	if (!pppd_binary)
		return NULL;

	if (!ip4_enabled && !ip6_enabled) {
		g_set_error_literal (err,
		                     NM_MANAGER_ERROR,
		                     NM_MANAGER_ERROR_FAILED,
		                     "Neither IPv4 or IPv6 allowed.");
		return NULL;
	}

	cmd = g_ptr_array_new_with_free_func (g_free);

	nm_strv_ptrarray_add_string_dup (cmd, pppd_binary);

	nm_strv_ptrarray_add_string_dup (cmd, "nodetach");
	nm_strv_ptrarray_add_string_dup (cmd, "lock");

	/* NM handles setting the default route */
	nm_strv_ptrarray_add_string_dup (cmd, "nodefaultroute");

	if (!ip4_enabled)
		nm_strv_ptrarray_add_string_dup (cmd, "noip");

	if (ip6_enabled) {
		/* Allow IPv6 to be configured by IPV6CP */
		nm_strv_ptrarray_add_string_dup (cmd, "ipv6");
		nm_strv_ptrarray_add_string_dup (cmd, ",");
	} else
		nm_strv_ptrarray_add_string_dup (cmd, "noipv6");

	ppp_debug = !!getenv ("NM_PPP_DEBUG");
	if (nm_logging_enabled (LOGL_DEBUG, LOGD_PPP))
		ppp_debug = TRUE;

	if (ppp_debug)
		nm_strv_ptrarray_add_string_dup (cmd, "debug");

	if (ppp_name) {
		nm_strv_ptrarray_add_string_dup (cmd, "user");
		nm_strv_ptrarray_add_string_dup (cmd, ppp_name);
	}

	if (pppoe) {
		const char *pppoe_service;

		nm_strv_ptrarray_add_string_dup (cmd, "plugin");
		nm_strv_ptrarray_add_string_dup (cmd, "rp-pppoe.so");

		nm_strv_ptrarray_add_string_concat (cmd, "nic-", priv->parent_iface);

		pppoe_service = nm_setting_pppoe_get_service (pppoe);
		if (pppoe_service) {
			nm_strv_ptrarray_add_string_dup (cmd, "rp_pppoe_service");
			nm_strv_ptrarray_add_string_dup (cmd, pppoe_service);
		}
	} else if (adsl) {
		const char *protocol = nm_setting_adsl_get_protocol (adsl);

		if (!strcmp (protocol, NM_SETTING_ADSL_PROTOCOL_PPPOA)) {
			guint32 vpi = nm_setting_adsl_get_vpi (adsl);
			guint32 vci = nm_setting_adsl_get_vci (adsl);
			const char *encaps = nm_setting_adsl_get_encapsulation (adsl);

			nm_strv_ptrarray_add_string_dup (cmd, "plugin");
			nm_strv_ptrarray_add_string_dup (cmd, "pppoatm.so");

			nm_strv_ptrarray_add_string_printf (cmd, "%d.%d", vpi, vci);

			if (g_strcmp0 (encaps, NM_SETTING_ADSL_ENCAPSULATION_LLC) == 0)
				nm_strv_ptrarray_add_string_dup (cmd, "llc-encaps");
			else /*if (g_strcmp0 (encaps, NM_SETTING_ADSL_ENCAPSULATION_VCMUX) == 0)*/
				nm_strv_ptrarray_add_string_dup (cmd, "vc-encaps");

		} else if (!strcmp (protocol, NM_SETTING_ADSL_PROTOCOL_PPPOE)) {
			nm_strv_ptrarray_add_string_dup (cmd, "plugin");
			nm_strv_ptrarray_add_string_dup (cmd, "rp-pppoe.so");
			nm_strv_ptrarray_add_string_dup (cmd, priv->parent_iface);
		}

		nm_strv_ptrarray_add_string_dup (cmd, "noipdefault");
	} else {
		nm_strv_ptrarray_add_string_dup (cmd, priv->parent_iface);
		/* Don't send some random address as the local address */
		nm_strv_ptrarray_add_string_dup (cmd, "noipdefault");
	}

	if (nm_setting_ppp_get_baud (setting))
		nm_strv_ptrarray_add_int (cmd, nm_setting_ppp_get_baud (setting));
	else if (baud_override)
		nm_strv_ptrarray_add_int (cmd, baud_override);

	/* noauth by default, because we certainly don't have any information
	 * with which to verify anything the peer gives us if we ask it to
	 * authenticate itself, which is what 'auth' really means.
	 */
	nm_strv_ptrarray_add_string_dup (cmd, "noauth");

	if (nm_setting_ppp_get_refuse_eap (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "refuse-eap");
	if (nm_setting_ppp_get_refuse_pap (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "refuse-pap");
	if (nm_setting_ppp_get_refuse_chap (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "refuse-chap");
	if (nm_setting_ppp_get_refuse_mschap (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "refuse-mschap");
	if (nm_setting_ppp_get_refuse_mschapv2 (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "refuse-mschap-v2");
	if (nm_setting_ppp_get_nobsdcomp (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "nobsdcomp");
	if (nm_setting_ppp_get_no_vj_comp (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "novj");
	if (nm_setting_ppp_get_nodeflate (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "nodeflate");
	if (nm_setting_ppp_get_require_mppe (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "require-mppe");
	if (nm_setting_ppp_get_require_mppe_128 (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "require-mppe-128");
	if (nm_setting_ppp_get_mppe_stateful (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "mppe-stateful");
	if (nm_setting_ppp_get_crtscts (setting))
		nm_strv_ptrarray_add_string_dup (cmd, "crtscts");

	/* Always ask for DNS, we don't have to use them if the connection
	 * overrides the returned servers.
	 */
	nm_strv_ptrarray_add_string_dup (cmd, "usepeerdns");

	if (nm_setting_ppp_get_mru (setting)) {
		nm_strv_ptrarray_add_string_dup (cmd, "mru");
		nm_strv_ptrarray_add_int (cmd, nm_setting_ppp_get_mru (setting));
	}

	if (nm_setting_ppp_get_mtu (setting)) {
		nm_strv_ptrarray_add_string_dup (cmd, "mtu");
		nm_strv_ptrarray_add_int (cmd, nm_setting_ppp_get_mtu (setting));
	}

	nm_strv_ptrarray_add_string_dup (cmd, "lcp-echo-failure");
	nm_strv_ptrarray_add_int (cmd, nm_setting_ppp_get_lcp_echo_failure (setting));

	nm_strv_ptrarray_add_string_dup (cmd, "lcp-echo-interval");
	nm_strv_ptrarray_add_int (cmd, nm_setting_ppp_get_lcp_echo_interval (setting));

	/* Avoid pppd to exit if no traffic going through */
	nm_strv_ptrarray_add_string_dup (cmd, "idle");
	nm_strv_ptrarray_add_string_dup (cmd, "0");

	nm_strv_ptrarray_add_string_dup (cmd, "ipparam");
	nm_strv_ptrarray_add_string_dup (cmd, nm_dbus_object_get_path (NM_DBUS_OBJECT (self)));

	nm_strv_ptrarray_add_string_dup (cmd, "plugin");
	nm_strv_ptrarray_add_string_dup (cmd, NM_PPPD_PLUGIN);

	if (pppoe && nm_setting_pppoe_get_parent (pppoe)) {
		static int unit;

		/* The PPP interface is going to be renamed, so pass a
		 * different unit each time so that activations don't
		 * race with each others. */
		nm_strv_ptrarray_add_string_dup (cmd, "unit");
		nm_strv_ptrarray_add_int (cmd, unit);
		unit = unit < G_MAXINT ? unit + 1 : 0;
	}

	g_ptr_array_add (cmd, NULL);
	return g_steal_pointer (&cmd);
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
_ppp_manager_start (NMPPPManager *self,
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
	gs_unref_ptrarray GPtrArray *ppp_cmd = NULL;
	gs_free char *cmd_str = NULL;
	struct stat st;
	const char *ip6_method, *ip4_method;
	gboolean ip6_enabled = FALSE;
	gboolean ip4_enabled = FALSE;

	g_return_val_if_fail (NM_IS_PPP_MANAGER (self), FALSE);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), FALSE);

	priv = NM_PPP_MANAGER_GET_PRIVATE (self);

#if !WITH_PPP
	/* PPP support disabled */
	g_set_error_literal (err,
	                     NM_MANAGER_ERROR,
	                     NM_MANAGER_ERROR_FAILED,
	                     "PPP support is not enabled.");
	return FALSE;
#endif

	nm_dbus_object_export (NM_DBUS_OBJECT (self));

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
	ip4_method = nm_utils_get_ip_config_method (connection, AF_INET);
	ip4_enabled = nm_streq (ip4_method, NM_SETTING_IP4_CONFIG_METHOD_AUTO);
	ip6_method = nm_utils_get_ip_config_method (connection, AF_INET6);
	ip6_enabled = nm_streq (ip6_method, NM_SETTING_IP6_CONFIG_METHOD_AUTO);

	ppp_cmd = create_pppd_cmd_line (self,
	                                s_ppp,
	                                pppoe_setting,
	                                adsl_setting,
	                                ppp_name,
	                                baud_override,
	                                ip4_enabled,
	                                ip6_enabled,
	                                err);
	if (!ppp_cmd)
		goto fail;

	_LOGI ("starting PPP connection");

	_LOGD ("command line: %s",
	       (cmd_str = g_strjoinv (" ", (char **) ppp_cmd->pdata)));

	priv->pid = 0;
	if (!g_spawn_async (NULL,
	                    (char **) ppp_cmd->pdata,
	                    NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD,
	                    nm_utils_setpgid,
	                    NULL,
	                    &priv->pid,
	                    err))
		goto fail;

	nm_assert (priv->pid > 0);

	_LOGI ("pppd started with pid %lld", (long long) priv->pid);

	priv->ppp_watch_id = g_child_watch_add (priv->pid, (GChildWatchFunc) ppp_watch_cb, self);
	priv->ppp_timeout_handler = g_timeout_add_seconds (timeout_secs, pppd_timed_out, self);
	priv->act_req = g_object_ref (req);

	return TRUE;
fail:
	nm_dbus_object_unexport (NM_DBUS_OBJECT (self));
	return FALSE;
}

static void
_ppp_cleanup (NMPPPManager *self)
{
	NMPPPManagerPrivate *priv;

	g_return_if_fail (NM_IS_PPP_MANAGER (self));

	priv = NM_PPP_MANAGER_GET_PRIVATE (self);

	cancel_get_secrets (self);

	nm_clear_g_source (&priv->monitor_id);

	if (priv->monitor_fd >= 0) {
		/* Get the stats one last time */
		monitor_cb (self);
		nm_close (priv->monitor_fd);
		priv->monitor_fd = -1;
	}

	nm_clear_g_source (&priv->ppp_timeout_handler);
	nm_clear_g_source (&priv->ppp_watch_id);
}

/*****************************************************************************/

struct _NMPPPManagerStopHandle {
	NMPPPManager *self;
	NMPPPManagerStopCallback callback;
	gpointer user_data;

	/* this object delays shutdown, because we still need to wait until
	 * pppd process terminated. */
	GObject *shutdown_waitobj;

	GCancellable *cancellable;

	gulong cancellable_id;

	guint idle_id;
};

static void
_stop_handle_complete (NMPPPManagerStopHandle *handle, gboolean was_cancelled)
{
	gs_unref_object NMPPPManager *self = NULL;
	NMPPPManagerStopCallback callback;

	if (handle->cancellable_id) {
		g_cancellable_disconnect (handle->cancellable,
		                          nm_steal_int (&handle->cancellable_id));
	}

	g_clear_object (&handle->cancellable);

	self = g_steal_pointer (&handle->self);
	if (!self)
		return;

	if (!handle->callback)
		return;

	callback = handle->callback;
	handle->callback = NULL;
	callback (self, handle, was_cancelled, handle->user_data);
}

static void
_stop_handle_destroy (NMPPPManagerStopHandle *handle, gboolean was_cancelled)
{
	_stop_handle_complete (handle, was_cancelled);
	nm_clear_g_source (&handle->idle_id);
	g_clear_object (&handle->shutdown_waitobj);
	g_slice_free (NMPPPManagerStopHandle, handle);
}

static void
_stop_child_cb (pid_t pid,
                gboolean success,
                int child_status,
                gpointer user_data)
{
	_stop_handle_destroy (user_data, FALSE);
}

static gboolean
_stop_idle_cb (gpointer user_data)
{
	NMPPPManagerStopHandle *handle = user_data;

	handle->idle_id = 0;
	_stop_handle_destroy (handle, FALSE);
	return G_SOURCE_REMOVE;
}

static void
_stop_cancelled_cb (GCancellable *cancellable,
                    gpointer user_data)
{
	NMPPPManagerStopHandle *handle = user_data;

	nm_clear_g_signal_handler (handle->cancellable,
	                           &handle->cancellable_id);
	_ppp_manager_stop_cancel (handle);
}

static NMPPPManagerStopHandle *
_ppp_manager_stop (NMPPPManager *self,
                   GCancellable *cancellable,
                   NMPPPManagerStopCallback callback,
                   gpointer user_data)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	NMDBusObject *dbus = NM_DBUS_OBJECT (self);
	NMPPPManagerStopHandle *handle;

	if (nm_dbus_object_is_exported (dbus))
		nm_dbus_object_unexport (dbus);

	_ppp_cleanup (self);

	if (   !priv->pid
	    && !callback) {
		/* nothing to do further...
		 *
		 * In this case, we return a %NULL handle. The caller cannot cancel this
		 * event, but clearly he is not waiting for a callback anyway. */
		return NULL;
	}

	handle = g_slice_new0 (NMPPPManagerStopHandle);
	handle->self = g_object_ref (self);
	handle->callback = callback;
	handle->user_data = user_data;
	if (cancellable) {
		handle->cancellable = g_object_ref (cancellable);
		handle->cancellable_id = g_cancellable_connect (cancellable,
		                                                G_CALLBACK (_stop_cancelled_cb),
		                                                handle,
		                                                NULL);
	}

	if (!priv->pid) {
		/* No PID. There is nothing to kill, however, invoke the callback in
		 * an idle handler.
		 *
		 * Note that we don't register nm_shutdown_wait_obj_register().
		 * In order for shutdown to work properly, the caller must always
		 * explicitly cancel the action to go down. With the idle-handler,
		 * cancelling the handle completes the request. */
		handle->idle_id = g_idle_add (_stop_idle_cb, handle);
		return handle;
	}

	/* we really want to kill the process and delay shutdown of NetworkManager
	 * until the process terminated. We do that, by registering an object
	 * that delays shutdown. */
	handle->shutdown_waitobj = g_object_new (G_TYPE_OBJECT, NULL);
	nm_shutdown_wait_obj_register (handle->shutdown_waitobj, "ppp-manager-wait-kill-pppd");
	nm_utils_kill_child_async (nm_steal_int (&priv->pid),
	                           SIGTERM, LOGD_PPP, "pppd",
	                           NM_SHUTDOWN_TIMEOUT_MS,
	                           _stop_child_cb, handle);

	return handle;
}

/*****************************************************************************/

static void
_ppp_manager_stop_cancel (NMPPPManagerStopHandle *handle)
{
	g_return_if_fail (handle);
	g_return_if_fail (NM_IS_PPP_MANAGER (handle->self));

	if (handle->idle_id) {
		/* we can complete this fake handle right away. */
		_stop_handle_destroy (handle, TRUE);
		return;
	}

	/* a real handle. Only invoke the callback (synchronously). This marks
	 * the handle as handled, but it keeps shutdown_waitobj around, until
	 * nm_utils_kill_child_async() returns. */
	_stop_handle_complete (handle, TRUE);
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
nm_ppp_manager_init (NMPPPManager *self)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);

	priv->ifindex = -1;
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
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);

	/* we expect the user to first stop the manager. As fallback,
	 * still stop. */
	g_warn_if_fail (!priv->pid);
	g_warn_if_fail (!nm_dbus_object_is_exported (NM_DBUS_OBJECT (self)));
	_ppp_manager_stop (self, NULL, NULL, NULL);

	g_clear_object (&priv->act_req);

	G_OBJECT_CLASS (nm_ppp_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE ((NMPPPManager *) object);

	g_free (priv->parent_iface);

	G_OBJECT_CLASS (nm_ppp_manager_parent_class)->finalize (object);
}

static const NMDBusInterfaceInfoExtended interface_info_ppp = {
	.parent = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
		NM_DBUS_INTERFACE_PPP,
		.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"NeedSecrets",
					.out_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("username", "s"),
						NM_DEFINE_GDBUS_ARG_INFO ("password", "s"),
					),
				),
				.handle = impl_ppp_manager_need_secrets,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"SetIp4Config",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("config", "a{sv}"),
					),
				),
				.handle = impl_ppp_manager_set_ip4_config,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"SetIp6Config",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("config", "a{sv}"),
					),
				),
				.handle = impl_ppp_manager_set_ip6_config,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"SetState",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("state", "u"),
					),
				),
				.handle = impl_ppp_manager_set_state,
			),
			NM_DEFINE_DBUS_METHOD_INFO_EXTENDED (
				NM_DEFINE_GDBUS_METHOD_INFO_INIT (
					"SetIfindex",
					.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
						NM_DEFINE_GDBUS_ARG_INFO ("ifindex", "i"),
					),
				),
				.handle = impl_ppp_manager_set_ifindex,
			),
		),
	),
};

static void
nm_ppp_manager_class_init (NMPPPManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);
	NMDBusObjectClass *dbus_object_class = NM_DBUS_OBJECT_CLASS (manager_class);

	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	dbus_object_class->export_path = NM_DBUS_EXPORT_PATH_NUMBERED (NM_DBUS_PATH"/PPP");
	dbus_object_class->interface_infos = NM_DBUS_INTERFACE_INFOS (&interface_info_ppp);

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

	signals[IFINDEX_SET] =
	    g_signal_new (NM_PPP_MANAGER_SIGNAL_IFINDEX_SET,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2,
	                  G_TYPE_INT,
	                  G_TYPE_STRING);

	signals[IP4_CONFIG] =
	    g_signal_new (NM_PPP_MANAGER_SIGNAL_IP4_CONFIG,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 1,
	                  G_TYPE_OBJECT);

	signals[IP6_CONFIG] =
	    g_signal_new (NM_PPP_MANAGER_SIGNAL_IP6_CONFIG,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2,
	                  G_TYPE_POINTER,
	                  G_TYPE_OBJECT);

	signals[STATS] =
	    g_signal_new (NM_PPP_MANAGER_SIGNAL_STATS,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0,
	                  NULL, NULL, NULL,
	                  G_TYPE_NONE, 2,
	                  G_TYPE_UINT /*guint32 in_bytes*/,
	                  G_TYPE_UINT /*guint32 out_bytes*/);
}

NMPPPOps ppp_ops = {
	.create               = _ppp_manager_new,
	.set_route_parameters = _ppp_manager_set_route_parameters,
	.start                = _ppp_manager_start,
	.stop                 = _ppp_manager_stop,
	.stop_cancel          = _ppp_manager_stop_cancel,
};
