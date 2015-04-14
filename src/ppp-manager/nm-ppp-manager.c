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

#include "config.h"

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

#include "NetworkManagerUtils.h"
#include "nm-glib-compat.h"
#include "nm-ppp-manager.h"
#include "nm-dbus-manager.h"
#include "nm-logging.h"
#include "nm-platform.h"
#include "nm-core-internal.h"

static void impl_ppp_manager_need_secrets (NMPPPManager *manager,
                                           DBusGMethodInvocation *context);

static gboolean impl_ppp_manager_set_state (NMPPPManager *manager,
                                            guint32 state,
                                            GError **err);

static gboolean impl_ppp_manager_set_ip4_config (NMPPPManager *manager,
                                                 GHashTable *config,
                                                 GError **err);

static gboolean impl_ppp_manager_set_ip6_config (NMPPPManager *manager,
                                                 GHashTable *config,
                                                 GError **err);

#include "nm-ppp-manager-glue.h"

static void _ppp_cleanup  (NMPPPManager *manager);
static void _ppp_kill (NMPPPManager *manager);

#define NM_PPPD_PLUGIN PPPD_PLUGIN_DIR "/nm-pppd-plugin.so"
#define PPP_MANAGER_SECRET_TRIES "ppp-manager-secret-tries"

typedef struct {
	GPid pid;
	char *dbus_path;

	char *parent_iface;

	NMActRequest *act_req;
	DBusGMethodInvocation *pending_secrets_context;
	guint32 secrets_id;
	const char *secrets_setting_name;

	guint32 ppp_watch_id;
	guint32 ppp_timeout_handler;

	/* Monitoring */
	char *ip_iface;
	int monitor_fd;
	guint monitor_id;
} NMPPPManagerPrivate;

#define NM_PPP_MANAGER_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_PPP_MANAGER, NMPPPManagerPrivate))

G_DEFINE_TYPE (NMPPPManager, nm_ppp_manager, G_TYPE_OBJECT)

enum {
	STATE_CHANGED,
	IP4_CONFIG,
	IP6_CONFIG,
	STATS,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

enum {
	PROP_0,
	PROP_PARENT_IFACE,
	LAST_PROP
};

static void
nm_ppp_manager_init (NMPPPManager *manager)
{
	NM_PPP_MANAGER_GET_PRIVATE (manager)->monitor_fd = -1;
}

static void
constructed (GObject *object)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (object);
	DBusGConnection *connection;
	static guint32 counter = 0;

	priv->dbus_path = g_strdup_printf (NM_DBUS_PATH "/PPP/%d", counter++);
	connection = nm_dbus_manager_get_connection (nm_dbus_manager_get ());
	dbus_g_connection_register_g_object (connection, priv->dbus_path, object);

	G_OBJECT_CLASS (nm_ppp_manager_parent_class)->constructed (object);
}

static void
dispose (GObject *object)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (object);

	_ppp_cleanup (NM_PPP_MANAGER (object));
	_ppp_kill (NM_PPP_MANAGER (object));

	g_clear_object (&priv->act_req);

	G_OBJECT_CLASS (nm_ppp_manager_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (object);

	g_free (priv->ip_iface);
	g_free (priv->parent_iface);

	G_OBJECT_CLASS (nm_ppp_manager_parent_class)->finalize (object);
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PARENT_IFACE:
		g_free (priv->parent_iface);
		priv->parent_iface = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PARENT_IFACE:
		g_value_set_string (value, priv->parent_iface);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

NMPPPManager *
nm_ppp_manager_new (const char *iface)
{
	g_return_val_if_fail (iface != NULL, NULL);

	return (NMPPPManager *) g_object_new (NM_TYPE_PPP_MANAGER,
	                                      NM_PPP_MANAGER_PARENT_IFACE, iface,
	                                      NULL);
}

/*******************************************/

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
			nm_log_warn (LOGD_PPP, "could not read ppp stats: %s", strerror (errno));
	} else {
		g_signal_emit (manager, signals[STATS], 0, 
		               stats.p.ppp_ibytes,
		               stats.p.ppp_obytes);
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

	priv->monitor_fd = socket (AF_INET, SOCK_DGRAM, 0);
	if (priv->monitor_fd >= 0) {
		g_warn_if_fail (priv->monitor_id == 0);
		if (priv->monitor_id)
			g_source_remove (priv->monitor_id);
		priv->monitor_id = g_timeout_add_seconds (5, monitor_cb, manager);
	} else
		nm_log_warn (LOGD_PPP, "could not monitor PPP stats: %s", strerror (errno));
}

/*******************************************/

static void
remove_timeout_handler (NMPPPManager *manager)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	
	if (priv->ppp_timeout_handler) {
		g_source_remove (priv->ppp_timeout_handler);
		priv->ppp_timeout_handler = 0;
	}
}

static void
cancel_get_secrets (NMPPPManager *self)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);

	if (priv->secrets_id) {
		nm_act_request_cancel_secrets (priv->act_req, priv->secrets_id);
		priv->secrets_id = 0;
	}
	priv->secrets_setting_name = NULL;
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
                guint32 call_id,
                NMConnection *connection,
                GError *error,
                gpointer user_data)
{
	NMPPPManager *self = NM_PPP_MANAGER (user_data);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	const char *username = NULL;
	const char *password = NULL;
	GError *local = NULL;

	g_return_if_fail (priv->pending_secrets_context != NULL);
	g_return_if_fail (req == priv->act_req);
	g_return_if_fail (call_id == priv->secrets_id);

	if (error) {
		nm_log_warn (LOGD_PPP, "%s", error->message);
		dbus_g_method_return_error (priv->pending_secrets_context, error);
		goto out;
	}

	if (!extract_details_from_connection (connection, priv->secrets_setting_name, &username, &password, &local)) {
		nm_log_warn (LOGD_PPP, "%s", local->message);
		dbus_g_method_return_error (priv->pending_secrets_context, local);
		g_clear_error (&local);
		goto out;
	}

	/* This is sort of a hack but...
	 * pppd plugin only ever needs username and password. Passing the full
	 * connection there would mean some bloat: the plugin would need to link
	 * against libnm just to parse this. So instead, let's just send what
	 * it needs.
	 */
	dbus_g_method_return (priv->pending_secrets_context, username, password);

 out:
	priv->pending_secrets_context = NULL;
	priv->secrets_id = 0;
	priv->secrets_setting_name = NULL;
}

static void
impl_ppp_manager_need_secrets (NMPPPManager *manager,
                               DBusGMethodInvocation *context)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	NMConnection *connection;
	const char *username = NULL;
	const char *password = NULL;
	guint32 tries;
	GPtrArray *hints = NULL;
	GError *error = NULL;
	NMSecretAgentGetSecretsFlags flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

	connection = nm_act_request_get_connection (priv->act_req);

	nm_connection_clear_secrets (connection);
	priv->secrets_setting_name = nm_connection_need_secrets (connection, &hints);
	if (!priv->secrets_setting_name) {
		/* Use existing secrets from the connection */
		if (extract_details_from_connection (connection, NULL, &username, &password, &error)) {
			/* Send existing secrets to the PPP plugin */
			priv->pending_secrets_context = context;
			ppp_secrets_cb (priv->act_req, priv->secrets_id, connection, NULL, manager);
		} else {
			nm_log_warn (LOGD_PPP, "%s", error->message);
			dbus_g_method_return_error (priv->pending_secrets_context, error);
			g_clear_error (&error);
		}
		return;
	}

	/* Only ask for completely new secrets after retrying them once; some devices
	 * appear to ask a few times when they actually don't even care what you
	 * pass back.
	 */
	tries = GPOINTER_TO_UINT (g_object_get_data (G_OBJECT (connection), PPP_MANAGER_SECRET_TRIES));
	if (tries > 1)
		flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;

	priv->secrets_id = nm_act_request_get_secrets (priv->act_req,
	                                               priv->secrets_setting_name,
	                                               flags,
	                                               hints ? g_ptr_array_index (hints, 0) : NULL,
	                                               ppp_secrets_cb,
	                                               manager);
	g_object_set_data (G_OBJECT (connection), PPP_MANAGER_SECRET_TRIES, GUINT_TO_POINTER (++tries));
	priv->pending_secrets_context = context;

	if (hints)
		g_ptr_array_free (hints, TRUE);
}

static gboolean impl_ppp_manager_set_state (NMPPPManager *manager,
                                            guint32 state,
                                            GError **err)
{
	g_signal_emit (manager, signals[STATE_CHANGED], 0, state);

	return TRUE;
}

static gboolean
set_ip_config_common (NMPPPManager *self,
                      GHashTable *hash,
                      const char *iface_prop,
                      guint32 *out_mtu)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	NMConnection *connection;
	NMSettingPpp *s_ppp;
	GValue *val;

	val = g_hash_table_lookup (hash, iface_prop);
	if (!val || !G_VALUE_HOLDS_STRING (val)) {
		nm_log_err (LOGD_PPP, "no interface received!");
		return FALSE;
	}
	if (priv->ip_iface == NULL)
		priv->ip_iface = g_value_dup_string (val);

	/* Got successful IP config; obviously the secrets worked */
	connection = nm_act_request_get_connection (priv->act_req);
	g_assert (connection);
	g_object_set_data (G_OBJECT (connection), PPP_MANAGER_SECRET_TRIES, NULL);

	/* Get any custom MTU */
	s_ppp = nm_connection_get_setting_ppp (connection);
	if (s_ppp && out_mtu)
		*out_mtu = nm_setting_ppp_get_mtu (s_ppp);

	monitor_stats (self);
	return TRUE;
}

static gboolean
impl_ppp_manager_set_ip4_config (NMPPPManager *manager,
                                 GHashTable *config_hash,
                                 GError **err)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	NMIP4Config *config;
	NMPlatformIP4Address address;
	GValue *val;
	int i;
	guint32 mtu = 0;

	nm_log_info (LOGD_PPP, "PPP manager (IPv4 Config Get) reply received.");

	remove_timeout_handler (manager);

	config = nm_ip4_config_new (nm_platform_link_get_ifindex (NM_PLATFORM_GET, priv->ip_iface));

	memset (&address, 0, sizeof (address));
	address.plen = 32;

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_GATEWAY);
	if (val) {
		nm_ip4_config_set_gateway (config, g_value_get_uint (val));
		address.peer_address = g_value_get_uint (val);
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_ADDRESS);
	if (val)
		address.address = g_value_get_uint (val);

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_PREFIX);
	if (val)
		address.plen = g_value_get_uint (val);

	if (address.address && address.plen) {
		address.source = NM_IP_CONFIG_SOURCE_PPP;
		nm_ip4_config_add_address (config, &address);
	} else {
		nm_log_err (LOGD_PPP, "invalid IPv4 address received!");
		goto out;
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_DNS);
	if (val) {
		GArray *dns = (GArray *) g_value_get_boxed (val);

		for (i = 0; i < dns->len; i++)
			nm_ip4_config_add_nameserver (config, g_array_index (dns, guint, i));
	}

	val = (GValue *) g_hash_table_lookup (config_hash, NM_PPP_IP4_CONFIG_WINS);
	if (val) {
		GArray *wins = (GArray *) g_value_get_boxed (val);

		for (i = 0; i < wins->len; i++)
			nm_ip4_config_add_wins (config, g_array_index (wins, guint, i));
	}

	if (!set_ip_config_common (manager, config_hash, NM_PPP_IP4_CONFIG_INTERFACE, &mtu))
		goto out;

	if (mtu)
		nm_ip4_config_set_mtu (config, mtu, NM_IP_CONFIG_SOURCE_PPP);

	/* Push the IP4 config up to the device */
	g_signal_emit (manager, signals[IP4_CONFIG], 0, priv->ip_iface, config);

out:
	g_object_unref (config);
	return TRUE;
}

/* Converts the named Interface Identifier item to an IPv6 LL address and
 * returns the IID.
 */
static gboolean
iid_value_to_ll6_addr (GHashTable *hash,
                       const char *prop,
                       struct in6_addr *out_addr,
                       NMUtilsIPv6IfaceId *out_iid)
{
	GValue *val;
	guint64 iid;

	val = g_hash_table_lookup (hash, prop);
	if (!val || !G_VALUE_HOLDS (val, G_TYPE_UINT64)) {
		nm_log_dbg (LOGD_PPP, "pppd plugin property '%s' missing or not a uint64", prop);
		return FALSE;
	}

	iid = g_value_get_uint64 (val);
	g_return_val_if_fail (iid != 0, FALSE);

	/* Construct an IPv6 LL address from the interface identifier.  See
	 * http://tools.ietf.org/html/rfc4291#section-2.5.1 (IPv6) and
	 * http://tools.ietf.org/html/rfc5072#section-4.1 (IPv6 over PPP).
	 */
	memset (out_addr->s6_addr, 0, sizeof (out_addr->s6_addr));
	out_addr->s6_addr16[0] = htons (0xfe80);
	memcpy (out_addr->s6_addr + 8, &iid, sizeof (iid));
	if (out_iid)
		nm_utils_ipv6_interface_identfier_get_from_addr (out_iid, out_addr);
	return TRUE;
}

static gboolean
impl_ppp_manager_set_ip6_config (NMPPPManager *manager,
                                 GHashTable *hash,
                                 GError **err)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	NMIP6Config *config;
	NMPlatformIP6Address addr;
	struct in6_addr a;
	NMUtilsIPv6IfaceId iid = NM_UTILS_IPV6_IFACE_ID_INIT;

	nm_log_info (LOGD_PPP, "PPP manager (IPv6 Config Get) reply received.");

	remove_timeout_handler (manager);

	config = nm_ip6_config_new (nm_platform_link_get_ifindex (NM_PLATFORM_GET, priv->ip_iface));

	memset (&addr, 0, sizeof (addr));
	addr.plen = 64;

	if (iid_value_to_ll6_addr (hash, NM_PPP_IP6_CONFIG_PEER_IID, &a, NULL)) {
		nm_ip6_config_set_gateway (config, &a);
		addr.peer_address = a;
	}

	if (iid_value_to_ll6_addr (hash, NM_PPP_IP6_CONFIG_OUR_IID, &addr.address, &iid)) {
		nm_ip6_config_add_address (config, &addr);

		if (set_ip_config_common (manager, hash, NM_PPP_IP6_CONFIG_INTERFACE, NULL)) {
			/* Push the IPv6 config and interface identifier up to the device */
			g_signal_emit (manager, signals[IP6_CONFIG], 0, priv->ip_iface, &iid, config);
		}
	} else
		nm_log_err (LOGD_PPP, "invalid IPv6 address received!");

	g_object_unref (config);
	return TRUE;
}

static void
nm_ppp_manager_class_init (NMPPPManagerClass *manager_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (manager_class);

	g_type_class_add_private (manager_class, sizeof (NMPPPManagerPrivate));

	object_class->constructed = constructed;
	object_class->dispose = dispose;
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_PARENT_IFACE,
		 g_param_spec_string (NM_PPP_MANAGER_PARENT_IFACE, "", "",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
		                      G_PARAM_STATIC_STRINGS));

	/* signals */
	signals[STATE_CHANGED] =
		g_signal_new ("state-changed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMPPPManagerClass, state_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1,
		              G_TYPE_UINT);

	signals[IP4_CONFIG] =
		g_signal_new ("ip4-config",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMPPPManagerClass, ip4_config),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2,
		              G_TYPE_STRING,
		              G_TYPE_OBJECT);

	signals[IP6_CONFIG] =
		g_signal_new ("ip6-config",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMPPPManagerClass, ip6_config),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 3, G_TYPE_STRING, G_TYPE_POINTER, G_TYPE_OBJECT);

	signals[STATS] =
		g_signal_new ("stats",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMPPPManagerClass, stats),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2,
		              G_TYPE_UINT, G_TYPE_UINT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (manager_class),
	                                 &dbus_glib_nm_ppp_manager_object_info);
}

/*******************************************/



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

/*******************************************/

static void
ppp_exit_code (guint pppd_exit_status, GPid pid)
{
	const char *msg;

	switch (pppd_exit_status) {
	case  1: 
		msg = "Fatal pppd error"; 
		break;
	case  2: 
		msg = "pppd options error"; 
		break;
	case  3: 
		msg = "No root priv error"; 
		break;
	case  4: 
		msg = "No ppp module error"; 
		break;
	case  5: 
		msg = "pppd received a signal"; 
		break;
	case  6: 
		msg = "Serial port lock failed"; 
		break;
	case  7: 
		msg = "Serial port open failed"; 
		break;
	case  8: 
		msg = "Connect script failed"; 
		break;
	case  9: 
		msg = "Pty program error"; 
		break;
	case 10: 
		msg = "PPP negotiation failed"; 
		break;
	case 11: 
		msg = "Peer didn't authenticatie itself"; 
		break;
	case 12: 
		msg = "Link idle: Idle Seconds reached."; 
		break;
	case 13: 
		msg = "Connect time limit reached."; 
		break;
	case 14: 
		msg = "Callback negotiated, call should come back.";
		break;
	case 15: 
		msg = "Lack of LCP echo responses"; 
		break;
	case 16: 
		msg = "A modem hung up the phone"; 
		break;
	case 17: 
		msg = "Loopback detected"; 
		break;
	case 18: 
		msg = "The init script failed"; 
		break;
	case 19: 
		msg = "Authentication error.\n"
			"We failed to authenticate ourselves to the peer.\n"
			"Maybe bad account or password?";
		break;
	default:
		msg = "Unknown error";
	}

	nm_log_warn (LOGD_PPP, "pppd pid %d exited with error: %s", pid, msg);
}

static void
ppp_watch_cb (GPid pid, gint status, gpointer user_data)
{
	NMPPPManager *manager = NM_PPP_MANAGER (user_data);
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	guint err;

	g_assert (pid == priv->pid);

	if (WIFEXITED (status)) {
		err = WEXITSTATUS (status);
		if (err != 0)
			ppp_exit_code (err, priv->pid);
	} else if (WIFSTOPPED (status)) {
		nm_log_info (LOGD_PPP, "pppd pid %d stopped unexpectedly with signal %d", priv->pid, WSTOPSIG (status));
	} else if (WIFSIGNALED (status)) {
		nm_log_info (LOGD_PPP, "pppd pid %d died with signal %d", priv->pid, WTERMSIG (status));
	} else
		nm_log_info (LOGD_PPP, "pppd pid %d died from an unknown cause", priv->pid);

	nm_log_dbg (LOGD_PPP, "pppd pid %d cleaned up", priv->pid);
	priv->pid = 0;
	g_signal_emit (manager, signals[STATE_CHANGED], 0, NM_PPP_STATUS_DEAD);
}

static gboolean
pppd_timed_out (gpointer data)
{
	NMPPPManager *manager = NM_PPP_MANAGER (data);

	nm_log_warn (LOGD_PPP, "pppd timed out or didn't initialize our dbus module");
	_ppp_cleanup (manager);
	_ppp_kill (manager);

	g_signal_emit (manager, signals[STATE_CHANGED], 0, NM_PPP_STATUS_DEAD);

	return FALSE;
}

static NMCmdLine *
create_pppd_cmd_line (NMPPPManager *self,
                      NMSettingPpp *setting,
                      NMSettingPppoe *pppoe,
                      NMSettingAdsl  *adsl,
                      const char *ppp_name,
                      GError **err)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (self);
	const char *pppd_binary = NULL;
	NMCmdLine *cmd;
	gboolean ppp_debug;

	g_return_val_if_fail (setting != NULL, NULL);

	pppd_binary = nm_utils_find_helper ("pppd", NULL, err);
	if (!pppd_binary)
		return NULL;

	/* Create pppd command line */
	cmd = nm_cmd_line_new ();
	nm_cmd_line_add_string (cmd, pppd_binary);

	nm_cmd_line_add_string (cmd, "nodetach");
	nm_cmd_line_add_string (cmd, "lock");

	/* NM handles setting the default route */
	nm_cmd_line_add_string (cmd, "nodefaultroute");

	/* Allow IPv6 to be configured by IPV6CP */
	nm_cmd_line_add_string (cmd, "ipv6");
	nm_cmd_line_add_string (cmd, ",");

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
	nm_cmd_line_add_string (cmd, priv->dbus_path);

	nm_cmd_line_add_string (cmd, "plugin");
	nm_cmd_line_add_string (cmd, NM_PPPD_PLUGIN);

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

gboolean
nm_ppp_manager_start (NMPPPManager *manager,
                      NMActRequest *req,
                      const char *ppp_name,
                      guint32 timeout_secs,
                      GError **err)
{
	NMPPPManagerPrivate *priv;
	NMConnection *connection;
	NMSettingPpp *s_ppp;
	gboolean s_ppp_created = FALSE;
	NMSettingPppoe *pppoe_setting;
	NMSettingAdsl *adsl_setting;
	NMCmdLine *ppp_cmd;
	char *cmd_str;
	struct stat st;

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

	priv->pid = 0;

	/* Make sure /dev/ppp exists (bgo #533064) */
	if (stat ("/dev/ppp", &st) || !S_ISCHR (st.st_mode))
		nm_utils_modprobe (NULL, FALSE, "ppp_generic", NULL);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	s_ppp = nm_connection_get_setting_ppp (connection);
	if (!s_ppp) {
		/* If the PPP settings are all default we may not have a PPP setting yet,
		 * so just make a default one here.
		 */
		s_ppp = NM_SETTING_PPP (nm_setting_ppp_new ());
		s_ppp_created = TRUE;
	}
	
	pppoe_setting = nm_connection_get_setting_pppoe (connection);
	if (pppoe_setting)
		pppoe_fill_defaults (s_ppp);

	adsl_setting = (NMSettingAdsl *) nm_connection_get_setting (connection, NM_TYPE_SETTING_ADSL);

	ppp_cmd = create_pppd_cmd_line (manager, s_ppp, pppoe_setting, adsl_setting, ppp_name, err);
	if (!ppp_cmd)
		goto out;

	g_ptr_array_add (ppp_cmd->array, NULL);

	nm_log_info (LOGD_PPP, "starting PPP connection");

	cmd_str = nm_cmd_line_to_str (ppp_cmd);
	nm_log_dbg (LOGD_PPP, "command line: %s", cmd_str);
	g_free (cmd_str);

	priv->pid = 0;
	if (!g_spawn_async (NULL, (char **) ppp_cmd->array->pdata, NULL,
	                    G_SPAWN_DO_NOT_REAP_CHILD,
	                    nm_utils_setpgid, NULL,
	                    &priv->pid, err)) {
		goto out;
	}

	nm_log_info (LOGD_PPP, "pppd started with pid %d", priv->pid);

	priv->ppp_watch_id = g_child_watch_add (priv->pid, (GChildWatchFunc) ppp_watch_cb, manager);
	priv->ppp_timeout_handler = g_timeout_add_seconds (timeout_secs, pppd_timed_out, manager);
	priv->act_req = g_object_ref (req);

out:
	if (s_ppp_created)
		g_object_unref (s_ppp);

	if (ppp_cmd)
		nm_cmd_line_destroy (ppp_cmd);

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

	if (priv->monitor_id) {
		g_source_remove (priv->monitor_id);
		priv->monitor_id = 0;
	}

	if (priv->monitor_fd >= 0) {
		/* Get the stats one last time */
		monitor_cb (manager);
		close (priv->monitor_fd);
		priv->monitor_fd = -1;
	}

	if (priv->ppp_timeout_handler) {
		g_source_remove (priv->ppp_timeout_handler);
		priv->ppp_timeout_handler = 0;
	}

	if (priv->ppp_watch_id) {
		g_source_remove (priv->ppp_watch_id);
		priv->ppp_watch_id = 0;
	}
}

/***********************************************************/

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

gboolean
nm_ppp_manager_stop_finish (NMPPPManager *manager,
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

void
nm_ppp_manager_stop (NMPPPManager *manager,
                     GCancellable *cancellable,
                     GAsyncReadyCallback callback,
                     gpointer user_data)
{
	NMPPPManagerPrivate *priv = NM_PPP_MANAGER_GET_PRIVATE (manager);
	StopContext *ctx;

	ctx = g_slice_new0 (StopContext);
	ctx->manager = g_object_ref (manager);
	ctx->result = g_simple_async_result_new (G_OBJECT (manager),
	                                         callback,
	                                         user_data,
	                                         nm_ppp_manager_stop);

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
