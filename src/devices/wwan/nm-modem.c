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
 * Copyright (C) 2009 - 2014 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#include "nm-default.h"

#include "nm-modem.h"

#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <linux/rtnetlink.h>

#include "nm-core-internal.h"
#include "platform/nm-platform.h"
#include "nm-setting-connection.h"
#include "NetworkManagerUtils.h"
#include "devices/nm-device-private.h"
#include "nm-netns.h"
#include "nm-act-request.h"
#include "nm-ip4-config.h"
#include "nm-ip6-config.h"
#include "ppp/nm-ppp-manager-call.h"
#include "ppp/nm-ppp-status.h"

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMModem,
	PROP_CONTROL_PORT,
	PROP_IP_IFINDEX,
	PROP_PATH,
	PROP_UID,
	PROP_DRIVER,
	PROP_STATE,
	PROP_DEVICE_ID,
	PROP_SIM_ID,
	PROP_IP_TYPES,
	PROP_SIM_OPERATOR_ID,
);

enum {
	PPP_STATS,
	PPP_FAILED,
	PREPARE_RESULT,
	IP4_CONFIG_RESULT,
	IP6_CONFIG_RESULT,
	AUTH_REQUESTED,
	AUTH_RESULT,
	REMOVED,
	STATE_CHANGED,
	LAST_SIGNAL,
};

static guint signals[LAST_SIGNAL] = { 0 };

typedef struct _NMModemPrivate {
	char *uid;
	char *path;
	char *driver;
	char *control_port;
	char *data_port;

	/* TODO: ip_iface is solely used for nm_modem_owns_port().
	 * We should rework the code that it's not necessary */
	char *ip_iface;

	int ip_ifindex;
	NMModemIPMethod ip4_method;
	NMModemIPMethod ip6_method;
	NMUtilsIPv6IfaceId iid;
	NMModemState state;
	NMModemState prev_state;  /* revert to this state if enable/disable fails */
	char *device_id;
	char *sim_id;
	NMModemIPType ip_types;
	char *sim_operator_id;

	NMPPPManager *ppp_manager;

	NMActRequest *act_request;
	guint32 secrets_tries;
	NMActRequestGetSecretsCallId *secrets_id;

	guint mm_ip_timeout;

	guint32 ip4_route_table;
	guint32 ip4_route_metric;
	guint32 ip6_route_table;
	guint32 ip6_route_metric;

	/* PPP stats */
	guint32 in_bytes;
	guint32 out_bytes;
} NMModemPrivate;

G_DEFINE_TYPE (NMModem, nm_modem, G_TYPE_OBJECT)

#define NM_MODEM_GET_PRIVATE(self) _NM_GET_PRIVATE_PTR (self, NMModem, NM_IS_MODEM)

/*****************************************************************************/

#define _NMLOG_PREFIX_BUFLEN              64
#define _NMLOG_PREFIX_NAME                "modem"
#define _NMLOG_DOMAIN                     LOGD_MB

static const char *
_nmlog_prefix (char *prefix, NMModem *self)
{
	const char *uuid;
	int c;

	if (!self)
		return "";

	uuid = nm_modem_get_uid (self);

	if (uuid) {
		char pp[_NMLOG_PREFIX_BUFLEN - 5];

		c = g_snprintf (prefix, _NMLOG_PREFIX_BUFLEN, "[%s]",
		                nm_strquote (pp, sizeof (pp), uuid));
	} else
		c = g_snprintf (prefix, _NMLOG_PREFIX_BUFLEN, "[%p]", self);
	nm_assert (c < _NMLOG_PREFIX_BUFLEN);

	return prefix;
}

#define _NMLOG(level, ...) \
    G_STMT_START { \
        char _prefix[_NMLOG_PREFIX_BUFLEN]; \
        \
        nm_log ((level), _NMLOG_DOMAIN, NULL, NULL, \
                "%s%s: " _NM_UTILS_MACRO_FIRST (__VA_ARGS__), \
                _NMLOG_PREFIX_NAME, \
                _nmlog_prefix (_prefix, (self)) \
                _NM_UTILS_MACRO_REST (__VA_ARGS__)); \
    } G_STMT_END

/*****************************************************************************/

static void _set_ip_ifindex (NMModem *self, int ifindex, const char *ifname);

/*****************************************************************************/
/* State/enabled/connected */

static const char *state_table[] = {
	[NM_MODEM_STATE_UNKNOWN]       = "unknown",
	[NM_MODEM_STATE_FAILED]        = "failed",
	[NM_MODEM_STATE_INITIALIZING]  = "initializing",
	[NM_MODEM_STATE_LOCKED]        = "locked",
	[NM_MODEM_STATE_DISABLED]      = "disabled",
	[NM_MODEM_STATE_DISABLING]     = "disabling",
	[NM_MODEM_STATE_ENABLING]      = "enabling",
	[NM_MODEM_STATE_ENABLED]       = "enabled",
	[NM_MODEM_STATE_SEARCHING]     = "searching",
	[NM_MODEM_STATE_REGISTERED]    = "registered",
	[NM_MODEM_STATE_DISCONNECTING] = "disconnecting",
	[NM_MODEM_STATE_CONNECTING]    = "connecting",
	[NM_MODEM_STATE_CONNECTED]     = "connected",
};

const char *
nm_modem_state_to_string (NMModemState state)
{
	if ((gsize) state < G_N_ELEMENTS (state_table))
		return state_table[state];
	return NULL;
}

NMModemState
nm_modem_get_state (NMModem *self)
{
	return NM_MODEM_GET_PRIVATE (self)->state;
}

void
nm_modem_set_state (NMModem *self,
                    NMModemState new_state,
                    const char *reason)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	NMModemState old_state = priv->state;

	priv->prev_state = NM_MODEM_STATE_UNKNOWN;

	if (new_state != old_state) {
		_LOGI ("modem state changed, '%s' --> '%s' (reason: %s)",
		       nm_modem_state_to_string (old_state),
		       nm_modem_state_to_string (new_state),
		       reason ?: "none");

		priv->state = new_state;
		_notify (self, PROP_STATE);
		g_signal_emit (self, signals[STATE_CHANGED], 0, (int) new_state, (int) old_state);
	}
}

void
nm_modem_set_prev_state (NMModem *self, const char *reason)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	/* Reset modem to previous state if the state hasn't already changed */
	if (priv->prev_state != NM_MODEM_STATE_UNKNOWN)
		nm_modem_set_state (self, priv->prev_state, reason);
}

void
nm_modem_set_mm_enabled (NMModem *self,
                         gboolean enabled)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	NMModemState prev_state = priv->state;

	if (enabled && priv->state >= NM_MODEM_STATE_ENABLING) {
		_LOGD ("cannot enable modem: already enabled");
		return;
	}
	if (!enabled && priv->state <= NM_MODEM_STATE_DISABLING) {
		_LOGD ("cannot disable modem: already disabled");
		return;
	}

	if (priv->state <= NM_MODEM_STATE_INITIALIZING) {
		_LOGD ("cannot enable/disable modem: initializing or failed");
		return;
	} else if (priv->state == NM_MODEM_STATE_LOCKED) {
		/* Don't try to enable if the modem is locked since that will fail */
		_LOGW ("cannot enable/disable modem: locked");

		/* Try to unlock the modem if it's being enabled */
		if (enabled)
			g_signal_emit (self, signals[AUTH_REQUESTED], 0);
		return;
	}

	/* Not all modem classes support set_mm_enabled */
	if (NM_MODEM_GET_CLASS (self)->set_mm_enabled)
		NM_MODEM_GET_CLASS (self)->set_mm_enabled (self, enabled);

	/* Pre-empt the state change signal */
	nm_modem_set_state (self,
	                    enabled ? NM_MODEM_STATE_ENABLING : NM_MODEM_STATE_DISABLING,
	                    "user preference");
	priv->prev_state = prev_state;
}

void
nm_modem_emit_removed (NMModem *self)
{
	g_signal_emit (self, signals[REMOVED], 0);
}

void
nm_modem_emit_prepare_result (NMModem *self, gboolean success, NMDeviceStateReason reason)
{
	nm_assert (NM_IS_MODEM (self));

	g_signal_emit (self, signals[PREPARE_RESULT], 0, success, (guint) reason);
}

void
nm_modem_emit_ppp_failed (NMModem *self, NMDeviceStateReason reason)
{
	nm_assert (NM_IS_MODEM (self));

	g_signal_emit (self, signals[PPP_FAILED], 0, (guint) reason);
}

NMModemIPType
nm_modem_get_supported_ip_types (NMModem *self)
{
	return NM_MODEM_GET_PRIVATE (self)->ip_types;
}

const gchar *
nm_modem_ip_type_to_string (NMModemIPType ip_type)
{
	switch (ip_type) {
	case NM_MODEM_IP_TYPE_IPV4:
		return "ipv4";
	case NM_MODEM_IP_TYPE_IPV6:
		return "ipv6";
	case NM_MODEM_IP_TYPE_IPV4V6:
		return "ipv4v6";
	default:
		g_return_val_if_reached ("unknown");
	}
}

static GArray *
build_single_ip_type_array (NMModemIPType type)
{
	return g_array_append_val (g_array_sized_new (FALSE, FALSE, sizeof (NMModemIPType), 1), type);
}

/**
 * nm_modem_get_connection_ip_type:
 * @self: the #NMModem
 * @connection: the #NMConnection to determine IP type to use
 *
 * Given a modem and a connection, determine which #NMModemIPTypes to use
 * when connecting.
 *
 * Returns: an array of #NMModemIpType values, in the order in which they
 * should be tried.
 */
GArray *
nm_modem_get_connection_ip_type (NMModem *self,
                                 NMConnection *connection,
                                 GError **error)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	NMSettingIPConfig *s_ip4, *s_ip6;
	const char *method;
	gboolean ip4 = TRUE, ip6 = TRUE;
	gboolean ip4_may_fail = TRUE, ip6_may_fail = TRUE;

	s_ip4 = nm_connection_get_setting_ip4_config (connection);
	if (s_ip4) {
		method = nm_setting_ip_config_get_method (s_ip4);
		if (g_strcmp0 (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0)
			ip4 = FALSE;
		ip4_may_fail = nm_setting_ip_config_get_may_fail (s_ip4);
	}

	s_ip6 = nm_connection_get_setting_ip6_config (connection);
	if (s_ip6) {
		method = nm_setting_ip_config_get_method (s_ip6);
		if (g_strcmp0 (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0)
			ip6 = FALSE;
		ip6_may_fail = nm_setting_ip_config_get_may_fail (s_ip6);
	}

	if (ip4 && !ip6) {
		if (!(priv->ip_types & NM_MODEM_IP_TYPE_IPV4)) {
			g_set_error_literal (error,
			                     NM_DEVICE_ERROR,
			                     NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			                     "Connection requested IPv4 but IPv4 is "
			                     "unsupported by the modem.");
			return NULL;
		}
		return build_single_ip_type_array (NM_MODEM_IP_TYPE_IPV4);
	}

	if (ip6 && !ip4) {
		if (!(priv->ip_types & NM_MODEM_IP_TYPE_IPV6)) {
			g_set_error_literal (error,
			                     NM_DEVICE_ERROR,
			                     NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
			                     "Connection requested IPv6 but IPv6 is "
			                     "unsupported by the modem.");
			return NULL;
		}
		return build_single_ip_type_array (NM_MODEM_IP_TYPE_IPV6);
	}

	if (ip4 && ip6) {
		NMModemIPType type;
		GArray *out;

		out = g_array_sized_new (FALSE, FALSE, sizeof (NMModemIPType), 3);

		/* Modem supports dual-stack? */
		if (priv->ip_types & NM_MODEM_IP_TYPE_IPV4V6) {
			type = NM_MODEM_IP_TYPE_IPV4V6;
			g_array_append_val (out, type);
		}

		/* If IPv6 may-fail=false, we should NOT try IPv4 as fallback */
		if ((priv->ip_types & NM_MODEM_IP_TYPE_IPV4) && ip6_may_fail) {
			type = NM_MODEM_IP_TYPE_IPV4;
			g_array_append_val (out, type);
		}

		/* If IPv4 may-fail=false, we should NOT try IPv6 as fallback */
		if ((priv->ip_types & NM_MODEM_IP_TYPE_IPV6) && ip4_may_fail) {
			type = NM_MODEM_IP_TYPE_IPV6;
			g_array_append_val (out, type);
		}

		if (out->len > 0)
			return out;

		/* Error... */
		g_array_unref (out);
		g_set_error_literal (error,
		                     NM_DEVICE_ERROR,
		                     NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
		                     "Connection requested both IPv4 and IPv6 "
		                     "but dual-stack addressing is unsupported "
		                     "by the modem.");
		return NULL;
	}

	g_set_error_literal (error,
	                     NM_DEVICE_ERROR,
	                     NM_DEVICE_ERROR_INCOMPATIBLE_CONNECTION,
	                     "Connection specified no IP configuration!");
	return NULL;
}

const char *
nm_modem_get_device_id (NMModem *self)
{
	return NM_MODEM_GET_PRIVATE (self)->device_id;
}

const char *
nm_modem_get_sim_id (NMModem *self)
{
	return NM_MODEM_GET_PRIVATE (self)->sim_id;
}

const char *
nm_modem_get_sim_operator_id (NMModem *self)
{
	return NM_MODEM_GET_PRIVATE (self)->sim_operator_id;
}

/*****************************************************************************/
/* IP method PPP */

static void
ppp_state_changed (NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
	switch (status) {
	case NM_PPP_STATUS_DISCONNECT:
		nm_modem_emit_ppp_failed (user_data, NM_DEVICE_STATE_REASON_PPP_DISCONNECT);
		break;
	case NM_PPP_STATUS_DEAD:
		nm_modem_emit_ppp_failed (user_data, NM_DEVICE_STATE_REASON_PPP_FAILED);
		break;
	default:
		break;
	}
}

static void
ppp_ifindex_set (NMPPPManager *ppp_manager,
                 int ifindex,
                 const char *iface,
                 gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);

	nm_assert (ifindex >= 0);
	nm_assert (NM_MODEM_GET_PRIVATE (self)->ppp_manager == ppp_manager);

	if (ifindex <= 0 && iface) {
		/* this might happen, if the ifname was already deleted
		 * and we failed to resolve ifindex.
		 *
		 * Forget about the name. */
		iface = NULL;
	}
	_set_ip_ifindex (self, ifindex, iface);
}

static void
ppp_ip4_config (NMPPPManager *ppp_manager,
                NMIP4Config *config,
                gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);
	guint32 i, num;
	guint32 bad_dns1 = htonl (0x0A0B0C0D);
	guint32 good_dns1 = htonl (0x04020201);  /* GTE nameserver */
	guint32 bad_dns2 = htonl (0x0A0B0C0E);
	guint32 good_dns2 = htonl (0x04020202);  /* GTE nameserver */
	gboolean dns_workaround = FALSE;

	/* Work around a PPP bug (#1732) which causes many mobile broadband
	 * providers to return 10.11.12.13 and 10.11.12.14 for the DNS servers.
	 * Apparently fixed in ppp-2.4.5 but we've had some reports that this is
	 * not the case.
	 *
	 * http://git.ozlabs.org/?p=ppp.git;a=commitdiff_plain;h=2e09ef6886bbf00bc5a9a641110f801e372ffde6
	 * http://git.ozlabs.org/?p=ppp.git;a=commitdiff_plain;h=f8191bf07df374f119a07910a79217c7618f113e
	 */

	num = nm_ip4_config_get_num_nameservers (config);
	if (num == 2) {
		gboolean found1 = FALSE, found2 = FALSE;

		for (i = 0; i < num; i++) {
			guint32 ns = nm_ip4_config_get_nameserver (config, i);

			if (ns == bad_dns1)
				found1 = TRUE;
			else if (ns == bad_dns2)
				found2 = TRUE;
		}

		/* Be somewhat conservative about substitutions; the "bad" nameservers
		 * could actually be valid in some cases, so only substitute if ppp
		 * returns *only* the two bad nameservers.
		 */
		dns_workaround = (found1 && found2);
	}

	if (!num || dns_workaround) {
		_LOGW ("compensating for invalid PPP-provided nameservers");
		nm_ip4_config_reset_nameservers (config);
		nm_ip4_config_add_nameserver (config, good_dns1);
		nm_ip4_config_add_nameserver (config, good_dns2);
	}

	g_signal_emit (self, signals[IP4_CONFIG_RESULT], 0, config, NULL);
}

static void
ppp_ip6_config (NMPPPManager *ppp_manager,
                const NMUtilsIPv6IfaceId *iid,
                NMIP6Config *config,
                gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);

	NM_MODEM_GET_PRIVATE (self)->iid = *iid;

	nm_modem_emit_ip6_config_result (self, config, NULL);
}

static void
ppp_stats (NMPPPManager *ppp_manager,
           guint i_in_bytes,
           guint i_out_bytes,
           gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	guint32 in_bytes = i_in_bytes;
	guint32 out_bytes = i_out_bytes;

	if (priv->in_bytes != in_bytes || priv->out_bytes != out_bytes) {
		priv->in_bytes = in_bytes;
		priv->out_bytes = out_bytes;
		g_signal_emit (self, signals[PPP_STATS], 0, (guint) in_bytes, (guint) out_bytes);
	}
}

static gboolean
port_speed_is_zero (const char *port)
{
	struct termios options;
	nm_auto_close int fd = -1;
	gs_free char *path = NULL;

	nm_assert (port);

	if (port[0] != '/') {
		if (   !port[0]
		    || strchr (port, '/')
		    || NM_IN_STRSET (port, ".", ".."))
			return FALSE;
		path = g_build_path ("/sys/class/tty", port, NULL);
		port = path;
	}

	fd = open (port, O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);
	if (fd < 0)
		return FALSE;

	memset (&options, 0, sizeof (struct termios));
	if (tcgetattr (fd, &options) != 0)
		return FALSE;

	return cfgetospeed (&options) == B0;
}

static NMActStageReturn
ppp_stage3_ip_config_start (NMModem *self,
                            NMActRequest *req,
                            NMDeviceStateReason *out_failure_reason)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	const char *ppp_name = NULL;
	GError *error = NULL;
	guint ip_timeout = 30;
	guint baud_override = 0;

	g_return_val_if_fail (NM_IS_MODEM (self), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NM_ACT_STAGE_RETURN_FAILURE);

	/* If we're already running PPP don't restart it; for example, if both
	 * IPv4 and IPv6 are requested, IPv4 gets started first, but we use the
	 * same pppd for both v4 and v6.
	 */
	if (priv->ppp_manager)
		return NM_ACT_STAGE_RETURN_POSTPONE;

	if (NM_MODEM_GET_CLASS (self)->get_user_pass) {
		NMConnection *connection = nm_act_request_get_applied_connection (req);

		g_assert (connection);
		if (!NM_MODEM_GET_CLASS (self)->get_user_pass (self, connection, &ppp_name, NULL))
			return NM_ACT_STAGE_RETURN_FAILURE;
	}

	if (!priv->data_port) {
		_LOGE ("error starting PPP (no data port)");
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_PPP_START_FAILED);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	/* Check if ModemManager requested a specific IP timeout to be used. If 0 reported,
	 * use the default one (30s) */
	if (priv->mm_ip_timeout > 0) {
		_LOGI ("using modem-specified IP timeout: %u seconds",
		       priv->mm_ip_timeout);
		ip_timeout = priv->mm_ip_timeout;
	}

	/* Some tty drivers and modems ignore port speed, but pppd requires the
	 * port speed to be > 0 or it exits. If the port speed is 0 pass an
	 * explicit speed to pppd to prevent the exit.
	 * https://bugzilla.redhat.com/show_bug.cgi?id=1281731
	 */
	if (port_speed_is_zero (priv->data_port))
		baud_override = 57600;

	priv->ppp_manager = nm_ppp_manager_create (priv->data_port, &error);

	if (priv->ppp_manager) {
		nm_ppp_manager_set_route_parameters (priv->ppp_manager,
		                                     priv->ip4_route_table,
		                                     priv->ip4_route_metric,
		                                     priv->ip6_route_table,
		                                     priv->ip6_route_metric);
	}

	if (   !priv->ppp_manager
	    || !nm_ppp_manager_start (priv->ppp_manager, req, ppp_name,
	                              ip_timeout, baud_override, &error)) {
		_LOGE ("error starting PPP: %s", error->message);
		g_error_free (error);
		g_clear_object (&priv->ppp_manager);
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_PPP_START_FAILED);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_SIGNAL_STATE_CHANGED,
	                  G_CALLBACK (ppp_state_changed),
	                  self);
	g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_SIGNAL_IFINDEX_SET,
	                  G_CALLBACK (ppp_ifindex_set),
	                  self);
	g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_SIGNAL_IP4_CONFIG,
	                  G_CALLBACK (ppp_ip4_config),
	                  self);
	g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_SIGNAL_IP6_CONFIG,
	                  G_CALLBACK (ppp_ip6_config),
	                  self);
	g_signal_connect (priv->ppp_manager, NM_PPP_MANAGER_SIGNAL_STATS,
	                  G_CALLBACK (ppp_stats),
	                  self);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

NMActStageReturn
nm_modem_stage3_ip4_config_start (NMModem *self,
                                  NMDevice *device,
                                  NMDeviceClass *device_class,
                                  NMDeviceStateReason *out_failure_reason)
{
	NMModemPrivate *priv;
	NMActRequest *req;
	NMConnection *connection;
	const char *method;
	NMActStageReturn ret;

	_LOGD ("ip4_config_start");

	g_return_val_if_fail (NM_IS_MODEM (self), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_DEVICE (device), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_DEVICE_CLASS (device_class), NM_ACT_STAGE_RETURN_FAILURE);

	req = nm_device_get_act_request (device);
	g_return_val_if_fail (req, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_applied_connection (req);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	nm_modem_set_route_parameters_from_device (self, device);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP4_CONFIG);

	/* Only Disabled and Auto methods make sense for WWAN */
	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_DISABLED) == 0)
		return NM_ACT_STAGE_RETURN_SUCCESS;

	if (strcmp (method, NM_SETTING_IP4_CONFIG_METHOD_AUTO) != 0) {
		_LOGE ("unhandled WWAN IPv4 method '%s'; will fail", method);
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_IP_METHOD_UNSUPPORTED);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	priv = NM_MODEM_GET_PRIVATE (self);
	switch (priv->ip4_method) {
	case NM_MODEM_IP_METHOD_PPP:
		ret = ppp_stage3_ip_config_start (self, req, out_failure_reason);
		break;
	case NM_MODEM_IP_METHOD_STATIC:
		_LOGD ("MODEM_IP_METHOD_STATIC");
		ret = NM_MODEM_GET_CLASS (self)->static_stage3_ip4_config_start (self, req, out_failure_reason);
		break;
	case NM_MODEM_IP_METHOD_AUTO:
		_LOGD ("MODEM_IP_METHOD_AUTO");
		ret = device_class->act_stage3_ip4_config_start (device, NULL, out_failure_reason);
		break;
	default:
		_LOGI ("IPv4 configuration disabled");
		ret = NM_ACT_STAGE_RETURN_IP_FAIL;
		break;
	}

	return ret;
}

void
nm_modem_ip4_pre_commit (NMModem *modem,
                         NMDevice *device,
                         NMIP4Config *config)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (modem);

	/* If the modem has an ethernet-type data interface (ie, not PPP and thus
	 * not point-to-point) and IP config has a /32 prefix, then we assume that
	 * ARP will be pointless and we turn it off.
	 */
	if (   priv->ip4_method == NM_MODEM_IP_METHOD_STATIC
	    || priv->ip4_method == NM_MODEM_IP_METHOD_AUTO) {
		const NMPlatformIP4Address *address = nm_ip4_config_get_first_address (config);

		g_assert (address);
		if (address->plen == 32)
			nm_platform_link_set_noarp (nm_device_get_platform (device), nm_device_get_ip_ifindex (device));
	}
}

/*****************************************************************************/

void
nm_modem_emit_ip6_config_result (NMModem *self,
                                 NMIP6Config *config,
                                 GError *error)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	NMDedupMultiIter ipconf_iter;
	const NMPlatformIP6Address *addr;
	gboolean do_slaac = TRUE;

	if (error) {
		g_signal_emit (self, signals[IP6_CONFIG_RESULT], 0, NULL, FALSE, error);
		return;
	}

	if (config) {
		/* If the IPv6 configuration only included a Link-Local address, then
		 * we have to run SLAAC to get the full IPv6 configuration.
		 */
		nm_ip_config_iter_ip6_address_for_each (&ipconf_iter, config, &addr) {
			if (IN6_IS_ADDR_LINKLOCAL (&addr->address)) {
				if (!priv->iid.id)
					priv->iid.id = ((guint64 *)(&addr->address.s6_addr))[1];
			} else
				do_slaac = FALSE;
		}
	}
	g_assert (config || do_slaac);

	g_signal_emit (self, signals[IP6_CONFIG_RESULT], 0, config, do_slaac, NULL);
}

static NMActStageReturn
stage3_ip6_config_request (NMModem *self, NMDeviceStateReason *out_failure_reason)
{
	NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	return NM_ACT_STAGE_RETURN_FAILURE;
}

NMActStageReturn
nm_modem_stage3_ip6_config_start (NMModem *self,
                                  NMDevice *device,
                                  NMDeviceStateReason *out_failure_reason)
{
	NMModemPrivate *priv;
	NMActRequest *req;
	NMActStageReturn ret;
	NMConnection *connection;
	const char *method;

	g_return_val_if_fail (NM_IS_MODEM (self), NM_ACT_STAGE_RETURN_FAILURE);

	req = nm_device_get_act_request (device);
	g_return_val_if_fail (req, NM_ACT_STAGE_RETURN_FAILURE);

	connection = nm_act_request_get_applied_connection (req);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	nm_modem_set_route_parameters_from_device (self, device);

	method = nm_utils_get_ip_config_method (connection, NM_TYPE_SETTING_IP6_CONFIG);

	/* Only Ignore and Auto methods make sense for WWAN */
	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_IGNORE) == 0)
		return NM_ACT_STAGE_RETURN_IP_DONE;

	if (strcmp (method, NM_SETTING_IP6_CONFIG_METHOD_AUTO) != 0) {
		_LOGW ("unhandled WWAN IPv6 method '%s'; will fail",
		       method);
		NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	priv = NM_MODEM_GET_PRIVATE (self);
	switch (priv->ip6_method) {
	case NM_MODEM_IP_METHOD_PPP:
		ret = ppp_stage3_ip_config_start (self, req, out_failure_reason);
		break;
	case NM_MODEM_IP_METHOD_STATIC:
	case NM_MODEM_IP_METHOD_AUTO:
		/* Both static and DHCP/Auto retrieve a base IP config from the modem
		 * which in the static case is the full config, and the DHCP/Auto case
		 * is just the IPv6LL address to use for SLAAC.
		 */
		ret = NM_MODEM_GET_CLASS (self)->stage3_ip6_config_request (self, out_failure_reason);
		break;
	default:
		_LOGI ("IPv6 configuration disabled");
		ret = NM_ACT_STAGE_RETURN_IP_FAIL;
		break;
	}

	return ret;
}

guint32
nm_modem_get_configured_mtu (NMDevice *self, NMDeviceMtuSource *out_source)
{
	NMConnection *connection;
	NMSetting *setting;
	gint64 mtu_default;
	guint mtu = 0;
	const char *property_name;

	nm_assert (NM_IS_DEVICE (self));
	nm_assert (out_source);

	connection = nm_device_get_applied_connection (self);
	if (!connection)
		g_return_val_if_reached (0);

	setting = (NMSetting *) nm_connection_get_setting_gsm (connection);
	if (!setting)
		setting = (NMSetting *) nm_connection_get_setting_cdma (connection);

	if (setting) {
		g_object_get (setting, "mtu", &mtu, NULL);
		if (mtu) {
			*out_source = NM_DEVICE_MTU_SOURCE_CONNECTION;
			return mtu;
		}

		property_name = NM_IS_SETTING_GSM (setting) ? "gsm.mtu" : "cdma.mtu";
		mtu_default = nm_device_get_configured_mtu_from_connection_default (self, property_name);
		if (mtu_default >= 0) {
			*out_source = NM_DEVICE_MTU_SOURCE_CONNECTION;
			return (guint32) mtu_default;
		}
	}

	*out_source = NM_DEVICE_MTU_SOURCE_NONE;
	return 0;
}

/*****************************************************************************/

static void
cancel_get_secrets (NMModem *self)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	if (priv->secrets_id)
		nm_act_request_cancel_secrets (priv->act_request, priv->secrets_id);
}

static void
modem_secrets_cb (NMActRequest *req,
                  NMActRequestGetSecretsCallId *call_id,
                  NMSettingsConnection *connection,
                  GError *error,
                  gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	g_return_if_fail (call_id == priv->secrets_id);

	priv->secrets_id = NULL;

	if (g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
		return;

	if (error)
		_LOGW ("modem-secrets: %s", error->message);

	g_signal_emit (self, signals[AUTH_RESULT], 0, error);
}

void
nm_modem_get_secrets (NMModem *self,
                      const char *setting_name,
                      gboolean request_new,
                      const char *hint)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	NMSecretAgentGetSecretsFlags flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;

	cancel_get_secrets (self);

	if (request_new)
		flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;
	priv->secrets_id = nm_act_request_get_secrets (priv->act_request,
	                                               FALSE,
	                                               setting_name,
	                                               flags,
	                                               hint,
	                                               modem_secrets_cb,
	                                               self);
	g_return_if_fail (priv->secrets_id);
	g_signal_emit (self, signals[AUTH_REQUESTED], 0);
}

/*****************************************************************************/

static NMActStageReturn
act_stage1_prepare (NMModem *modem,
                    NMConnection *connection,
                    NMDeviceStateReason *out_failure_reason)
{
	NM_SET_OUT (out_failure_reason, NM_DEVICE_STATE_REASON_UNKNOWN);
	return NM_ACT_STAGE_RETURN_FAILURE;
}

NMActStageReturn
nm_modem_act_stage1_prepare (NMModem *self,
                             NMActRequest *req,
                             NMDeviceStateReason *out_failure_reason)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	gs_unref_ptrarray GPtrArray *hints = NULL;
	const char *setting_name = NULL;
	NMSecretAgentGetSecretsFlags flags = NM_SECRET_AGENT_GET_SECRETS_FLAG_ALLOW_INTERACTION;
	NMConnection *connection;

	if (priv->act_request)
		g_object_unref (priv->act_request);
	priv->act_request = g_object_ref (req);

	connection = nm_act_request_get_applied_connection (req);
	g_return_val_if_fail (connection, NM_ACT_STAGE_RETURN_FAILURE);

	setting_name = nm_connection_need_secrets (connection, &hints);
	if (!setting_name) {
		/* Ready to connect */
		g_assert (!hints);
		return NM_MODEM_GET_CLASS (self)->act_stage1_prepare (self, connection, out_failure_reason);
	}

	/* Secrets required... */
	if (priv->secrets_tries++)
		flags |= NM_SECRET_AGENT_GET_SECRETS_FLAG_REQUEST_NEW;

	priv->secrets_id = nm_act_request_get_secrets (req,
	                                               FALSE,
	                                               setting_name,
	                                               flags,
	                                               hints ? g_ptr_array_index (hints, 0) : NULL,
	                                               modem_secrets_cb,
	                                               self);
	g_return_val_if_fail (priv->secrets_id, NM_ACT_STAGE_RETURN_FAILURE);
	g_signal_emit (self, signals[AUTH_REQUESTED], 0);
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

NMActStageReturn
nm_modem_act_stage2_config (NMModem *self,
                            NMActRequest *req,
                            NMDeviceStateReason *out_failure_reason)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	/* Clear secrets tries counter since secrets were successfully used
	 * already if we get here.
	 */
	priv->secrets_tries = 0;

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*****************************************************************************/

gboolean
nm_modem_check_connection_compatible (NMModem *self, NMConnection *connection)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	NMSettingConnection *s_con;

	s_con = nm_connection_get_setting_connection (connection);
	g_assert (s_con);

	if (g_str_equal (nm_setting_connection_get_connection_type (s_con),
	                 NM_SETTING_GSM_SETTING_NAME)) {
		NMSettingGsm *s_gsm;
		const char *str;

		s_gsm = nm_connection_get_setting_gsm (connection);
		if (!s_gsm)
			return FALSE;

		str = nm_setting_gsm_get_device_id (s_gsm);
		if (str) {
			if (!priv->device_id) {
				_LOGD ("%s/%s has device-id, device does not",
				       nm_connection_get_uuid (connection),
				       nm_connection_get_id (connection));
				return FALSE;
			}
			if (strcmp (str, priv->device_id)) {
				_LOGD ("%s/%s device-id mismatch",
				       nm_connection_get_uuid (connection),
				       nm_connection_get_id (connection));
				return FALSE;
			}
		}

		/* SIM properties may not be available before the SIM is unlocked, so
		 * to ensure that autoconnect works, the connection's SIM properties
		 * are only compared if present on the device.
		 */

		str = nm_setting_gsm_get_sim_id (s_gsm);
		if (str && priv->sim_id) {
			if (strcmp (str, priv->sim_id)) {
				_LOGD ("%s/%s sim-id mismatch",
				       nm_connection_get_uuid (connection),
				       nm_connection_get_id (connection));
				return FALSE;
			}
		}

		str = nm_setting_gsm_get_sim_operator_id (s_gsm);
		if (str && priv->sim_operator_id) {
			if (strcmp (str, priv->sim_operator_id)) {
				_LOGD ("%s/%s sim-operator-id mismatch",
				       nm_connection_get_uuid (connection),
				       nm_connection_get_id (connection));
				return FALSE;
			}
		}
	}

	if (NM_MODEM_GET_CLASS (self)->check_connection_compatible)
		return NM_MODEM_GET_CLASS (self)->check_connection_compatible (self, connection);
	return FALSE;
}

/*****************************************************************************/

gboolean
nm_modem_complete_connection (NMModem *self,
                              NMConnection *connection,
                              NMConnection *const*existing_connections,
                              GError **error)
{
	NMModemClass *klass;

	klass = NM_MODEM_GET_CLASS (self);
	if (!klass->complete_connection) {
		g_set_error (error, NM_DEVICE_ERROR, NM_DEVICE_ERROR_INVALID_CONNECTION,
		             "Modem class %s had no complete_connection method",
		             G_OBJECT_TYPE_NAME (self));
		return FALSE;
	}

	return klass->complete_connection (self, connection, existing_connections, error);
}

/*****************************************************************************/

static void
deactivate_cleanup (NMModem *self, NMDevice *device)
{
	NMModemPrivate *priv;
	int ifindex;

	g_return_if_fail (NM_IS_MODEM (self));

	priv = NM_MODEM_GET_PRIVATE (self);

	priv->secrets_tries = 0;

	if (priv->act_request) {
		cancel_get_secrets (self);
		g_object_unref (priv->act_request);
		priv->act_request = NULL;
	}

	priv->in_bytes = priv->out_bytes = 0;

	if (priv->ppp_manager) {
		g_signal_handlers_disconnect_by_data (priv->ppp_manager, self);
		nm_ppp_manager_stop (priv->ppp_manager, NULL, NULL);
		g_clear_object (&priv->ppp_manager);
	}

	if (device) {
		g_return_if_fail (NM_IS_DEVICE (device));

		if (priv->ip4_method == NM_MODEM_IP_METHOD_STATIC ||
		    priv->ip4_method == NM_MODEM_IP_METHOD_AUTO ||
		    priv->ip6_method == NM_MODEM_IP_METHOD_STATIC ||
		    priv->ip6_method == NM_MODEM_IP_METHOD_AUTO) {
			ifindex = nm_device_get_ip_ifindex (device);
			if (ifindex > 0) {
				NMPlatform *platform = nm_device_get_platform (device);

				nm_platform_ip_route_flush (platform, AF_UNSPEC, ifindex);
				nm_platform_ip_address_flush (platform, AF_UNSPEC, ifindex);
				nm_platform_link_set_down (platform, ifindex);
			}
		}
	}

	nm_clear_g_free (&priv->data_port);
	priv->mm_ip_timeout = 0;
	priv->ip4_method = NM_MODEM_IP_METHOD_UNKNOWN;
	priv->ip6_method = NM_MODEM_IP_METHOD_UNKNOWN;
	_set_ip_ifindex (self, -1, NULL);
}

/*****************************************************************************/

typedef enum {
	DEACTIVATE_CONTEXT_STEP_FIRST,
	DEACTIVATE_CONTEXT_STEP_CLEANUP,
	DEACTIVATE_CONTEXT_STEP_PPP_MANAGER_STOP,
	DEACTIVATE_CONTEXT_STEP_MM_DISCONNECT,
	DEACTIVATE_CONTEXT_STEP_LAST
} DeactivateContextStep;

typedef struct {
	NMModem *self;
	NMDevice *device;
	GCancellable *cancellable;
	GSimpleAsyncResult *result;
	DeactivateContextStep step;
	NMPPPManager *ppp_manager;
	NMPPPManagerStopHandle *ppp_stop_handle;
	gulong ppp_stop_cancellable_id;
} DeactivateContext;

static void
deactivate_context_complete (DeactivateContext *ctx)
{
	if (ctx->ppp_stop_handle)
		nm_ppp_manager_stop_cancel (ctx->ppp_stop_handle);

	nm_assert (!ctx->ppp_stop_handle);
	nm_assert (ctx->ppp_stop_cancellable_id == 0);

	if (ctx->ppp_manager)
		g_object_unref (ctx->ppp_manager);
	if (ctx->cancellable)
		g_object_unref (ctx->cancellable);
	g_simple_async_result_complete_in_idle (ctx->result);
	g_object_unref (ctx->result);
	g_object_unref (ctx->device);
	g_object_unref (ctx->self);
	g_slice_free (DeactivateContext, ctx);
}

gboolean
nm_modem_deactivate_async_finish (NMModem *self,
                                  GAsyncResult *res,
                                  GError **error)
{
	return !g_simple_async_result_propagate_error (G_SIMPLE_ASYNC_RESULT (res), error);
}

static void deactivate_step (DeactivateContext *ctx);

static void
disconnect_ready (NMModem *self,
                  GAsyncResult *res,
                  DeactivateContext *ctx)
{
	GError *error = NULL;

	if (!NM_MODEM_GET_CLASS (self)->disconnect_finish (self, res, &error)) {
		g_simple_async_result_take_error (ctx->result, error);
		deactivate_context_complete (ctx);
		return;
	}

	/* Go on */
	ctx->step++;
	deactivate_step (ctx);
}

static void
ppp_manager_stop_ready (NMPPPManager *ppp_manager,
                        NMPPPManagerStopHandle *handle,
                        gboolean was_cancelled,
                        gpointer user_data)
{
	DeactivateContext *ctx = user_data;

	nm_assert (ctx->ppp_stop_handle == handle);
	ctx->ppp_stop_handle = NULL;

	if (ctx->ppp_stop_cancellable_id) {
		g_cancellable_disconnect (ctx->cancellable,
		                          nm_steal_int (&ctx->ppp_stop_cancellable_id));
	}

	if (was_cancelled)
		return;

	ctx->step++;
	deactivate_step (ctx);
}

static void
ppp_manager_stop_cancelled (GCancellable *cancellable,
                            gpointer user_data)
{
	DeactivateContext *ctx = user_data;

	nm_ppp_manager_stop_cancel (ctx->ppp_stop_handle);
}

static void
deactivate_step (DeactivateContext *ctx)
{
	NMModem *self = ctx->self;
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	GError *error = NULL;

	/* Check cancellable in each step */
	if (g_cancellable_set_error_if_cancelled (ctx->cancellable, &error)) {
		g_simple_async_result_take_error (ctx->result, error);
		deactivate_context_complete (ctx);
		return;
	}

	switch (ctx->step) {
	case DEACTIVATE_CONTEXT_STEP_FIRST:
		ctx->step++;
		/* fall through */
	case DEACTIVATE_CONTEXT_STEP_CLEANUP:
		/* Make sure we keep a ref to the PPP manager if there is one */
		if (priv->ppp_manager)
			ctx->ppp_manager = g_object_ref (priv->ppp_manager);
		/* Run cleanup */
		NM_MODEM_GET_CLASS (self)->deactivate_cleanup (self, ctx->device);
		ctx->step++;
		/* fall through */
	case DEACTIVATE_CONTEXT_STEP_PPP_MANAGER_STOP:
		/* If we have a PPP manager, stop it */
		if (ctx->ppp_manager) {
			nm_assert (!ctx->ppp_stop_handle);
			if (ctx->cancellable) {
				ctx->ppp_stop_cancellable_id = g_cancellable_connect (ctx->cancellable,
				                                                      G_CALLBACK (ppp_manager_stop_cancelled),
				                                                      ctx,
				                                                      NULL);
			}
			ctx->ppp_stop_handle = nm_ppp_manager_stop (ctx->ppp_manager,
			                                            ppp_manager_stop_ready,
			                                            ctx);
			return;
		}
		ctx->step++;
		/* fall through */
	case DEACTIVATE_CONTEXT_STEP_MM_DISCONNECT:
		/* Disconnect asynchronously */
		NM_MODEM_GET_CLASS (self)->disconnect (self,
		                                       FALSE,
		                                       ctx->cancellable,
		                                       (GAsyncReadyCallback) disconnect_ready,
		                                       ctx);
		return;

	case DEACTIVATE_CONTEXT_STEP_LAST:
		_LOGD ("modem deactivation finished");
		deactivate_context_complete (ctx);
		return;
	}

	g_assert_not_reached ();
}

void
nm_modem_deactivate_async (NMModem *self,
                           NMDevice *device,
                           GCancellable *cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
	DeactivateContext *ctx;

	ctx = g_slice_new0 (DeactivateContext);
	ctx->self = g_object_ref (self);
	ctx->device = g_object_ref (device);
	ctx->result = g_simple_async_result_new (G_OBJECT (self),
	                                         callback,
	                                         user_data,
	                                         nm_modem_deactivate_async);
	/* FIXME(shutdown): we always require a cancellable, otherwise we cannot
	 * do a coordinated shutdown. */
	ctx->cancellable = nm_g_object_ref (cancellable);

	/* Start */
	ctx->step = DEACTIVATE_CONTEXT_STEP_FIRST;
	deactivate_step (ctx);
}

/*****************************************************************************/

void
nm_modem_deactivate (NMModem *self, NMDevice *device)
{
	/* First cleanup */
	NM_MODEM_GET_CLASS (self)->deactivate_cleanup (self, device);
	/* Then disconnect without waiting */
	NM_MODEM_GET_CLASS (self)->disconnect (self, FALSE, NULL, NULL, NULL);
}

/*****************************************************************************/

void
nm_modem_device_state_changed (NMModem *self,
                               NMDeviceState new_state,
                               NMDeviceState old_state)
{
	gboolean was_connected = FALSE, warn = TRUE;
	NMModemPrivate *priv;

	g_return_if_fail (NM_IS_MODEM (self));

	if (old_state >= NM_DEVICE_STATE_PREPARE && old_state <= NM_DEVICE_STATE_DEACTIVATING)
		was_connected = TRUE;

	priv = NM_MODEM_GET_PRIVATE (self);

	/* Make sure we don't leave the serial device open */
	switch (new_state) {
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_FAILED:
	case NM_DEVICE_STATE_DISCONNECTED:
		if (priv->act_request) {
			cancel_get_secrets (self);
			g_object_unref (priv->act_request);
			priv->act_request = NULL;
		}

		if (was_connected) {
			/* Don't bother warning on FAILED since the modem is already gone */
			if (new_state == NM_DEVICE_STATE_FAILED || new_state == NM_DEVICE_STATE_DISCONNECTED)
				warn = FALSE;
			/* First cleanup */
			NM_MODEM_GET_CLASS (self)->deactivate_cleanup (self, NULL);
			NM_MODEM_GET_CLASS (self)->disconnect (self, warn, NULL, NULL, NULL);
		}
		break;
	default:
		break;
	}
}

/*****************************************************************************/

const char *
nm_modem_get_uid (NMModem *self)
{
	g_return_val_if_fail (NM_IS_MODEM (self), NULL);

	return NM_MODEM_GET_PRIVATE (self)->uid;
}

const char *
nm_modem_get_path (NMModem *self)
{
	g_return_val_if_fail (NM_IS_MODEM (self), NULL);

	return NM_MODEM_GET_PRIVATE (self)->path;
}

const char *
nm_modem_get_driver (NMModem *self)
{
	g_return_val_if_fail (NM_IS_MODEM (self), NULL);

	return NM_MODEM_GET_PRIVATE (self)->driver;
}

const char *
nm_modem_get_control_port (NMModem *self)
{
	g_return_val_if_fail (NM_IS_MODEM (self), NULL);

	return NM_MODEM_GET_PRIVATE (self)->control_port;
}

int
nm_modem_get_ip_ifindex (NMModem *self)
{
	NMModemPrivate *priv;

	g_return_val_if_fail (NM_IS_MODEM (self), 0);

	priv = NM_MODEM_GET_PRIVATE (self);

	/* internally we track an unset ip_ifindex as -1.
	 * For the caller of nm_modem_get_ip_ifindex(), this
	 * shall be zero too. */
	return priv->ip_ifindex != -1 ? priv->ip_ifindex : 0;
}

static void
_set_ip_ifindex (NMModem *self, int ifindex, const char *ifname)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	nm_assert (ifindex >= -1);
	nm_assert ((ifindex > 0) == !!ifname);

	if (!nm_streq0 (priv->ip_iface, ifname)) {
		g_free (priv->ip_iface);
		priv->ip_iface = g_strdup (ifname);
	}

	if (priv->ip_ifindex != ifindex) {
		priv->ip_ifindex = ifindex;
		_notify (self, PROP_IP_IFINDEX);
	}
}

gboolean
nm_modem_set_data_port (NMModem *self,
                        NMPlatform *platform,
                        const char *data_port,
                        NMModemIPMethod ip4_method,
                        NMModemIPMethod ip6_method,
                        guint timeout,
                        GError **error)
{
	NMModemPrivate *priv;
	gboolean is_ppp;
	int ifindex = -1;

	g_return_val_if_fail (NM_IS_MODEM (self), FALSE);
	g_return_val_if_fail (NM_IS_PLATFORM (platform), FALSE);
	g_return_val_if_fail (!error || !*error, FALSE);

	priv = NM_MODEM_GET_PRIVATE (self);

	if (   priv->ppp_manager
	    || priv->data_port
	    || priv->ip_ifindex != -1) {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     "cannot set data port in activated state");
		/* this really shouldn't happen. Assert. */
		g_return_val_if_reached (FALSE);
	}

	if (!data_port) {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     "missing data port");
		return FALSE;
	}

	is_ppp =    (ip4_method == NM_MODEM_IP_METHOD_PPP)
	         || (ip6_method == NM_MODEM_IP_METHOD_PPP);
	if (is_ppp) {
		if (   !NM_IN_SET (ip4_method, NM_MODEM_IP_METHOD_UNKNOWN, NM_MODEM_IP_METHOD_PPP)
		    || !NM_IN_SET (ip6_method, NM_MODEM_IP_METHOD_UNKNOWN, NM_MODEM_IP_METHOD_PPP)) {
			g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			                     "conflicting ip methods");
			return FALSE;
		}
	} else if (   !NM_IN_SET (ip4_method, NM_MODEM_IP_METHOD_UNKNOWN, NM_MODEM_IP_METHOD_STATIC, NM_MODEM_IP_METHOD_AUTO)
	           || !NM_IN_SET (ip6_method, NM_MODEM_IP_METHOD_UNKNOWN, NM_MODEM_IP_METHOD_STATIC, NM_MODEM_IP_METHOD_AUTO)
	           || (   ip4_method == NM_MODEM_IP_METHOD_UNKNOWN
	               && ip6_method == NM_MODEM_IP_METHOD_UNKNOWN)) {
		g_set_error_literal (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
		                     "invalid ip methods");
		return FALSE;
	}

	if (!is_ppp) {
		ifindex = nm_platform_if_nametoindex (platform, data_port);
		if (ifindex <= 0) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			             "cannot find network interface %s", data_port);
			return FALSE;
		}
		if (!nm_platform_process_events_ensure_link (platform, ifindex, data_port)) {
			g_set_error (error, NM_UTILS_ERROR, NM_UTILS_ERROR_UNKNOWN,
			             "cannot find network interface %s in platform cache", data_port);
			return FALSE;
		}
	}

	priv->mm_ip_timeout = timeout;
	priv->ip4_method = ip4_method;
	priv->ip6_method = ip6_method;
	if (is_ppp) {
		priv->data_port = g_strdup (data_port);
		_set_ip_ifindex (self, -1, NULL);
	} else {
		priv->data_port = NULL;
		_set_ip_ifindex (self, ifindex, data_port);
	}
	return TRUE;
}

gboolean
nm_modem_owns_port (NMModem *self, const char *iface)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	g_return_val_if_fail (iface != NULL, FALSE);

	if (NM_MODEM_GET_CLASS (self)->owns_port)
		return NM_MODEM_GET_CLASS (self)->owns_port (self, iface);

	return NM_IN_STRSET (iface,
	                     priv->ip_iface,
	                     priv->data_port,
	                     priv->control_port);
}

gboolean
nm_modem_get_iid (NMModem *self, NMUtilsIPv6IfaceId *out_iid)
{
	g_return_val_if_fail (NM_IS_MODEM (self), FALSE);

	*out_iid = NM_MODEM_GET_PRIVATE (self)->iid;
	return TRUE;
}

/*****************************************************************************/

void
nm_modem_get_route_parameters (NMModem *self,
                               guint32 *out_ip4_route_table,
                               guint32 *out_ip4_route_metric,
                               guint32 *out_ip6_route_table,
                               guint32 *out_ip6_route_metric)
{
	NMModemPrivate *priv;

	g_return_if_fail (NM_IS_MODEM (self));

	priv = NM_MODEM_GET_PRIVATE (self);
	NM_SET_OUT (out_ip4_route_table, priv->ip4_route_table);
	NM_SET_OUT (out_ip4_route_metric, priv->ip4_route_metric);
	NM_SET_OUT (out_ip6_route_table, priv->ip6_route_table);
	NM_SET_OUT (out_ip6_route_metric, priv->ip6_route_metric);
}

void
nm_modem_set_route_parameters (NMModem *self,
                               guint32 ip4_route_table,
                               guint32 ip4_route_metric,
                               guint32 ip6_route_table,
                               guint32 ip6_route_metric)
{
	NMModemPrivate *priv;

	g_return_if_fail (NM_IS_MODEM (self));

	priv = NM_MODEM_GET_PRIVATE (self);
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

	if (priv->ppp_manager) {
		nm_ppp_manager_set_route_parameters (priv->ppp_manager,
		                                     priv->ip4_route_table,
		                                     priv->ip4_route_metric,
		                                     priv->ip6_route_table,
		                                     priv->ip6_route_metric);
	}
}

void
nm_modem_set_route_parameters_from_device (NMModem *self,
                                           NMDevice *device)
{
	g_return_if_fail (NM_IS_DEVICE (device));

	nm_modem_set_route_parameters (self,
	                               nm_device_get_route_table (device, AF_INET, TRUE),
	                               nm_device_get_route_metric (device, AF_INET),
	                               nm_device_get_route_table (device, AF_INET6, TRUE),
	                               nm_device_get_route_metric (device, AF_INET6));
}

/*****************************************************************************/

void
nm_modem_get_capabilities (NMModem *self,
                           NMDeviceModemCapabilities *modem_caps,
                           NMDeviceModemCapabilities *current_caps)
{
	g_return_if_fail (NM_IS_MODEM (self));

	NM_MODEM_GET_CLASS (self)->get_capabilities (self, modem_caps, current_caps);
}

/*****************************************************************************/

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMModem *self = NM_MODEM (object);
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	switch (prop_id) {
	case PROP_PATH:
		g_value_set_string (value, priv->path);
		break;
	case PROP_DRIVER:
		g_value_set_string (value, priv->driver);
		break;
	case PROP_CONTROL_PORT:
		g_value_set_string (value, priv->control_port);
		break;
	case PROP_IP_IFINDEX:
		g_value_set_int (value, nm_modem_get_ip_ifindex (self));
		break;
	case PROP_UID:
		g_value_set_string (value, priv->uid);
		break;
	case PROP_STATE:
		g_value_set_int (value, priv->state);
		break;
	case PROP_DEVICE_ID:
		g_value_set_string (value, priv->device_id);
		break;
	case PROP_SIM_ID:
		g_value_set_string (value, priv->sim_id);
		break;
	case PROP_IP_TYPES:
		g_value_set_uint (value, priv->ip_types);
		break;
	case PROP_SIM_OPERATOR_ID:
		g_value_set_string (value, priv->sim_operator_id);
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
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE ((NMModem *) object);
	const char *s;

	switch (prop_id) {
	case PROP_PATH:
		/* construct-only */
		priv->path = g_value_dup_string (value);
		g_return_if_fail (priv->path);
		break;
	case PROP_DRIVER:
		/* construct-only */
		priv->driver = g_value_dup_string (value);
		break;
	case PROP_CONTROL_PORT:
		/* construct-only */
		priv->control_port = g_value_dup_string (value);
		break;
	case PROP_UID:
		/* construct-only */
		priv->uid = g_value_dup_string (value);
		break;
	case PROP_STATE:
		/* construct-only */
		priv->state = g_value_get_int (value);
		break;
	case PROP_DEVICE_ID:
		/* construct-only */
		priv->device_id = g_value_dup_string (value);
		break;
	case PROP_SIM_ID:
		g_free (priv->sim_id);
		priv->sim_id = g_value_dup_string (value);
		break;
	case PROP_IP_TYPES:
		priv->ip_types = g_value_get_uint (value);
		break;
	case PROP_SIM_OPERATOR_ID:
		g_clear_pointer (&priv->sim_operator_id, g_free);
		s = g_value_get_string (value);
		if (s && s[0])
			priv->sim_operator_id = g_strdup (s);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

/*****************************************************************************/

static void
nm_modem_init (NMModem *self)
{
	NMModemPrivate *priv;

	self->_priv = G_TYPE_INSTANCE_GET_PRIVATE (self, NM_TYPE_MODEM, NMModemPrivate);
	priv = self->_priv;

	priv->ip_ifindex = -1;
	priv->ip4_route_table = RT_TABLE_MAIN;
	priv->ip4_route_metric = 700;
	priv->ip6_route_table = RT_TABLE_MAIN;
	priv->ip6_route_metric = 700;
}

static void
constructed (GObject *object)
{
	NMModemPrivate *priv;

	G_OBJECT_CLASS (nm_modem_parent_class)->constructed (object);

	priv = NM_MODEM_GET_PRIVATE (NM_MODEM (object));

	g_return_if_fail (priv->control_port);
}

/*****************************************************************************/

static void
dispose (GObject *object)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE ((NMModem *) object);

	g_clear_object (&priv->act_request);

	G_OBJECT_CLASS (nm_modem_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE ((NMModem *) object);

	g_free (priv->uid);
	g_free (priv->path);
	g_free (priv->driver);
	g_free (priv->control_port);
	g_free (priv->data_port);
	g_free (priv->ip_iface);
	g_free (priv->device_id);
	g_free (priv->sim_id);
	g_free (priv->sim_operator_id);

	G_OBJECT_CLASS (nm_modem_parent_class)->finalize (object);
}

static void
nm_modem_class_init (NMModemClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemPrivate));

	object_class->constructed = constructed;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	klass->act_stage1_prepare = act_stage1_prepare;
	klass->stage3_ip6_config_request = stage3_ip6_config_request;
	klass->deactivate_cleanup = deactivate_cleanup;

	obj_properties[PROP_UID] =
	     g_param_spec_string (NM_MODEM_UID, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_PATH] =
	     g_param_spec_string (NM_MODEM_PATH, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_DRIVER] =
	     g_param_spec_string (NM_MODEM_DRIVER, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_CONTROL_PORT] =
	     g_param_spec_string (NM_MODEM_CONTROL_PORT, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_IP_IFINDEX] =
	     g_param_spec_int (NM_MODEM_IP_IFINDEX, "", "",
	                       0, G_MAXINT, 0,
	                       G_PARAM_READABLE |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_STATE] =
	     g_param_spec_int (NM_MODEM_STATE, "", "",
	                       NM_MODEM_STATE_UNKNOWN, _NM_MODEM_STATE_LAST, NM_MODEM_STATE_UNKNOWN,
	                       G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                       G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_DEVICE_ID] =
	     g_param_spec_string (NM_MODEM_DEVICE_ID, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_SIM_ID] =
	     g_param_spec_string (NM_MODEM_SIM_ID, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_IP_TYPES] =
	     g_param_spec_uint (NM_MODEM_IP_TYPES,
	                        "IP Types",
	                        "Supported IP types",
	                        0, G_MAXUINT32, NM_MODEM_IP_TYPE_IPV4,
	                        G_PARAM_READWRITE | G_PARAM_CONSTRUCT |
	                        G_PARAM_STATIC_STRINGS);

	obj_properties[PROP_SIM_OPERATOR_ID] =
	     g_param_spec_string (NM_MODEM_SIM_OPERATOR_ID, "", "",
	                          NULL,
	                          G_PARAM_READWRITE | G_PARAM_CONSTRUCT |
	                          G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class, _PROPERTY_ENUMS_LAST, obj_properties);

	signals[PPP_STATS] =
	    g_signal_new (NM_MODEM_PPP_STATS,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 2,
	                  G_TYPE_UINT /*guint32 in_bytes*/,
	                  G_TYPE_UINT /*guint32 out_bytes*/);

	signals[PPP_FAILED] =
	    g_signal_new (NM_MODEM_PPP_FAILED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[IP4_CONFIG_RESULT] =
	    g_signal_new (NM_MODEM_IP4_CONFIG_RESULT,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_POINTER);

	/**
	 * NMModem::ip6-config-result:
	 * @modem: the #NMModem  on which the signal is emitted
	 * @config: the #NMIP6Config to apply to the modem's data port
	 * @do_slaac: %TRUE if IPv6 SLAAC should be started
	 * @error: a #GError if any error occurred during IP configuration
	 *
	 * This signal is emitted when IPv6 configuration has completed or failed.
	 * If @error is set the configuration failed.  If @config is set, then
	 * the details should be applied to the data port before any further
	 * configuration (like SLAAC) is done.  @do_slaac indicates whether SLAAC
	 * should be started after applying @config to the data port.
	 */
	signals[IP6_CONFIG_RESULT] =
	    g_signal_new (NM_MODEM_IP6_CONFIG_RESULT,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 3, G_TYPE_OBJECT, G_TYPE_BOOLEAN, G_TYPE_POINTER);

	signals[PREPARE_RESULT] =
	    g_signal_new (NM_MODEM_PREPARE_RESULT,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_BOOLEAN, G_TYPE_UINT);

	signals[AUTH_REQUESTED] =
	    g_signal_new (NM_MODEM_AUTH_REQUESTED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);

	signals[AUTH_RESULT] =
	    g_signal_new (NM_MODEM_AUTH_RESULT,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[REMOVED] =
	    g_signal_new (NM_MODEM_REMOVED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 0);

	signals[STATE_CHANGED] =
	    g_signal_new (NM_MODEM_STATE_CHANGED,
	                  G_OBJECT_CLASS_TYPE (object_class),
	                  G_SIGNAL_RUN_FIRST,
	                  0, NULL, NULL, NULL,
	                  G_TYPE_NONE, 2, G_TYPE_INT, G_TYPE_INT);
}
