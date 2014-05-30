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

#include <string.h>
#include "nm-modem.h"
#include "nm-platform.h"
#include "nm-dbus-manager.h"
#include "nm-setting-connection.h"
#include "nm-properties-changed-signal.h"
#include "nm-logging.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-dbus-glib-types.h"
#include "nm-modem-enum-types.h"

G_DEFINE_TYPE (NMModem, nm_modem, G_TYPE_OBJECT)

#define NM_MODEM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM, NMModemPrivate))

enum {
	PROP_0,
	PROP_CONTROL_PORT,
	PROP_DATA_PORT,
	PROP_PATH,
	PROP_UID,
	PROP_DRIVER,
	PROP_IP_METHOD,
	PROP_IP_TIMEOUT,
	PROP_STATE,
	PROP_DEVICE_ID,
	PROP_SIM_ID,

	LAST_PROP
};

typedef struct {
	char *uid;
	char *path;
	char *driver;
	char *control_port;
	char *data_port;
	char *ppp_iface;
	guint32 ip_method;
	NMModemState state;
	NMModemState prev_state;  /* revert to this state if enable/disable fails */
	char *device_id;
	char *sim_id;

	NMPPPManager *ppp_manager;

	NMActRequest *act_request;
	guint32 secrets_tries;
	guint32 secrets_id;

	guint32 mm_ip_timeout;

	/* PPP stats */
	guint32 in_bytes;
	guint32 out_bytes;
} NMModemPrivate;

enum {
	PPP_STATS,
	PPP_FAILED,
	PREPARE_RESULT,
	IP4_CONFIG_RESULT,
	AUTH_REQUESTED,
	AUTH_RESULT,
	REMOVED,
	STATE_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


/*****************************************************************************/

GQuark
nm_modem_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-modem-error");
	return quark;
}

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
	if (state >= 0 && state < G_N_ELEMENTS (state_table))
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
		nm_log_info (LOGD_MB, "(%s): modem state changed, '%s' --> '%s' (reason: %s)\n",
		             nm_modem_get_uid (self),
		             nm_modem_state_to_string (old_state),
		             nm_modem_state_to_string (new_state),
		             reason ? reason : "none");

		priv->state = new_state;
		g_object_notify (G_OBJECT (self), NM_MODEM_STATE);
		g_signal_emit (self, signals[STATE_CHANGED], 0, new_state, old_state, reason);
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
		nm_log_dbg (LOGD_MB, "(%s) cannot enable modem: already enabled",
		            nm_modem_get_uid (self));
		return;
	}
	if (!enabled && priv->state <= NM_MODEM_STATE_DISABLING) {
		nm_log_dbg (LOGD_MB, "(%s) cannot disable modem: already disabled",
		            nm_modem_get_uid (self));
		return;
	}

	if (priv->state <= NM_MODEM_STATE_INITIALIZING) {
		nm_log_dbg (LOGD_MB, "(%s) cannot enable/disable modem: initializing or failed",
		            nm_modem_get_uid (self));
		return;
	} else if (priv->state == NM_MODEM_STATE_LOCKED) {
		/* Don't try to enable if the modem is locked since that will fail */
		nm_log_warn (LOGD_MB, "(%s) cannot enable/disable modem: locked",
		             nm_modem_get_uid (self));

		/* Try to unlock the modem if it's being enabled */
		if (enabled)
			g_signal_emit_by_name (self, NM_MODEM_AUTH_REQUESTED, 0);
		return;
	}

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

/*****************************************************************************/
/* IP method PPP */

static void
ppp_state_changed (NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
	switch (status) {
	case NM_PPP_STATUS_DISCONNECT:
		g_signal_emit (NM_MODEM (user_data), signals[PPP_FAILED], 0, NM_DEVICE_STATE_REASON_PPP_DISCONNECT);
		break;
	case NM_PPP_STATUS_DEAD:
		g_signal_emit (NM_MODEM (user_data), signals[PPP_FAILED], 0, NM_DEVICE_STATE_REASON_PPP_FAILED);
		break;
	default:
		break;
	}
}

static void
ppp_ip4_config (NMPPPManager *ppp_manager,
				const char *iface,
				NMIP4Config *config,
				gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	guint32 i, num;
	guint32 bad_dns1 = htonl (0x0A0B0C0D);
	guint32 good_dns1 = htonl (0x04020201);  /* GTE nameserver */
	guint32 bad_dns2 = htonl (0x0A0B0C0E);
	guint32 good_dns2 = htonl (0x04020202);  /* GTE nameserver */
	gboolean dns_workaround = FALSE;

	/* Notify about the new data port to use */
	g_free (priv->ppp_iface);
	priv->ppp_iface = g_strdup (iface);
	g_object_notify (G_OBJECT (self), NM_MODEM_DATA_PORT);

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
		nm_log_warn (LOGD_PPP, "compensating for invalid PPP-provided nameservers");
		nm_ip4_config_reset_nameservers (config);
		nm_ip4_config_add_nameserver (config, good_dns1);
		nm_ip4_config_add_nameserver (config, good_dns2);
	}

	g_signal_emit (self, signals[IP4_CONFIG_RESULT], 0, config, NULL);
}

static void
ppp_stats (NMPPPManager *ppp_manager,
		   guint32 in_bytes,
		   guint32 out_bytes,
		   gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	if (priv->in_bytes != in_bytes || priv->out_bytes != out_bytes) {
		priv->in_bytes = in_bytes;
		priv->out_bytes = out_bytes;

		g_signal_emit (self, signals[PPP_STATS], 0, in_bytes, out_bytes);
	}
}

static NMActStageReturn
ppp_stage3_ip4_config_start (NMModem *self,
                             NMActRequest *req,
                             NMDeviceStateReason *reason)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	const char *ppp_name = NULL;
	GError *error = NULL;
	NMActStageReturn ret;
	guint ip_timeout = 20;

	g_return_val_if_fail (NM_IS_MODEM (self), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_ACT_REQUEST (req), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (reason !=	NULL, NM_ACT_STAGE_RETURN_FAILURE);

	if (NM_MODEM_GET_CLASS (self)->get_user_pass) {
		NMConnection *connection = nm_act_request_get_connection (req);

		g_assert (connection);
		if (!NM_MODEM_GET_CLASS (self)->get_user_pass (self, connection, &ppp_name, NULL))
			return NM_ACT_STAGE_RETURN_FAILURE;
	}

	/* Check if ModemManager requested a specific IP timeout to be used. If 0 reported,
	 * use the default one (20s) */
	if (priv->mm_ip_timeout > 0) {
		nm_log_info (LOGD_PPP, "using modem-specified IP timeout: %u seconds",
		             priv->mm_ip_timeout);
		ip_timeout = priv->mm_ip_timeout;
	}

	priv->ppp_manager = nm_ppp_manager_new (priv->data_port);
	if (nm_ppp_manager_start (priv->ppp_manager, req, ppp_name, ip_timeout, &error)) {
		g_signal_connect (priv->ppp_manager, "state-changed",
		                  G_CALLBACK (ppp_state_changed),
		                  self);
		g_signal_connect (priv->ppp_manager, "ip4-config",
		                  G_CALLBACK (ppp_ip4_config),
		                  self);
		g_signal_connect (priv->ppp_manager, "stats",
		                  G_CALLBACK (ppp_stats),
		                  self);

		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		nm_log_err (LOGD_PPP, "error starting PPP: (%d) %s",
		            error ? error->code : -1,
		            error && error->message ? error->message : "(unknown)");
		g_error_free (error);

		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;

		*reason = NM_DEVICE_STATE_REASON_PPP_START_FAILED;
		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	return ret;
}

/*****************************************************************************/

NMActStageReturn
nm_modem_stage3_ip4_config_start (NMModem *self,
                                  NMDevice *device,
                                  NMDeviceClass *device_class,
                                  NMDeviceStateReason *reason)
{
	NMModemPrivate *priv;
	NMActRequest *req;
	NMActStageReturn ret;

	g_return_val_if_fail (NM_IS_MODEM (self), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_DEVICE (device), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_DEVICE_CLASS (device_class), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (reason != NULL, NM_ACT_STAGE_RETURN_FAILURE);

	req = nm_device_get_act_request (device);
	g_assert (req);

	priv = NM_MODEM_GET_PRIVATE (self);
	switch (priv->ip_method) {
	case MM_MODEM_IP_METHOD_PPP:
		ret = ppp_stage3_ip4_config_start (self, req, reason);
		break;
	case MM_MODEM_IP_METHOD_STATIC:
		ret = NM_MODEM_GET_CLASS (self)->static_stage3_ip4_config_start (self, req, reason);
		break;
	case MM_MODEM_IP_METHOD_DHCP:
		ret = device_class->act_stage3_ip4_config_start (device, NULL, reason);
		break;
	default:
		nm_log_err (LOGD_MB, "unknown IP method %d", priv->ip_method);
		ret = NM_ACT_STAGE_RETURN_FAILURE;
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
	if (   priv->ip_method == MM_MODEM_IP_METHOD_STATIC
	    || priv->ip_method == MM_MODEM_IP_METHOD_DHCP) {
		const NMPlatformIP4Address *address = nm_ip4_config_get_address (config, 0);

		g_assert (address);
		if (address->plen == 32)
			nm_platform_link_set_noarp (nm_device_get_ip_ifindex (device));
	}
}

/*****************************************************************************/

NMActStageReturn
nm_modem_stage3_ip6_config_start (NMModem *self,
                                  NMDevice *device,
                                  NMDeviceClass *device_class,
                                  NMDeviceStateReason *reason)
{
	/* FIXME: We don't support IPv6 on modems quite yet... */
	nm_device_activate_schedule_ip6_config_timeout (device);
	return NM_ACT_STAGE_RETURN_POSTPONE;
}

/*****************************************************************************/

static void
cancel_get_secrets (NMModem *self)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	if (priv->secrets_id) {
		nm_act_request_cancel_secrets (priv->act_request, priv->secrets_id);
		priv->secrets_id = 0;
	}
}

static void
modem_secrets_cb (NMActRequest *req,
                  guint32 call_id,
                  NMConnection *connection,
                  GError *error,
                  gpointer user_data)
{
	NMModem *self = NM_MODEM (user_data);
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	g_return_if_fail (call_id == priv->secrets_id);

	priv->secrets_id = 0;

	if (error)
		nm_log_warn (LOGD_MB, "%s", error->message);

	g_signal_emit (self, signals[AUTH_RESULT], 0, error);
}

gboolean
nm_modem_get_secrets (NMModem *self,
                      const char *setting_name,
                      gboolean request_new,
                      const char *hint)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	NMSettingsGetSecretsFlags flags = NM_SETTINGS_GET_SECRETS_FLAG_ALLOW_INTERACTION;

	cancel_get_secrets (self);

	if (request_new)
		flags |= NM_SETTINGS_GET_SECRETS_FLAG_REQUEST_NEW;
	priv->secrets_id = nm_act_request_get_secrets (priv->act_request,
	                                               setting_name,
	                                               flags,
	                                               hint,
	                                               modem_secrets_cb,
	                                               self);
	if (priv->secrets_id)
		g_signal_emit (self, signals[AUTH_REQUESTED], 0);

	return !!(priv->secrets_id);
}

/*****************************************************************************/

static NMActStageReturn
act_stage1_prepare (NMModem *modem,
                    NMConnection *connection,
                    NMDeviceStateReason *reason)
{
	*reason = NM_DEVICE_STATE_REASON_UNKNOWN;
	return NM_ACT_STAGE_RETURN_FAILURE;
}

NMActStageReturn
nm_modem_act_stage1_prepare (NMModem *self,
                             NMActRequest *req,
                             NMDeviceStateReason *reason)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);
	NMActStageReturn ret;
	GPtrArray *hints = NULL;
	const char *setting_name = NULL;
	NMSettingsGetSecretsFlags flags = NM_SETTINGS_GET_SECRETS_FLAG_ALLOW_INTERACTION;
	NMConnection *connection;

	if (priv->act_request)
		g_object_unref (priv->act_request);
	priv->act_request = g_object_ref (req);

	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	setting_name = nm_connection_need_secrets (connection, &hints);
	if (!setting_name) {
		/* Ready to connect */
		g_assert (!hints);
		return NM_MODEM_GET_CLASS (self)->act_stage1_prepare (self, connection, reason);
	}

	/* Secrets required... */
	if (priv->secrets_tries++)
		flags |= NM_SETTINGS_GET_SECRETS_FLAG_REQUEST_NEW;

	priv->secrets_id = nm_act_request_get_secrets (req,
	                                               setting_name,
	                                               flags,
	                                               hints ? g_ptr_array_index (hints, 0) : NULL,
	                                               modem_secrets_cb,
	                                               self);
	if (priv->secrets_id) {
		g_signal_emit (self, signals[AUTH_REQUESTED], 0);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		*reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	if (hints)
		g_ptr_array_free (hints, TRUE);

	return ret;
}

/*****************************************************************************/

NMActStageReturn
nm_modem_act_stage2_config (NMModem *self,
                            NMActRequest *req,
                            NMDeviceStateReason *reason)
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
	if (NM_MODEM_GET_CLASS (self)->check_connection_compatible)
		return NM_MODEM_GET_CLASS (self)->check_connection_compatible (self, connection);
	return FALSE;
}

/*****************************************************************************/

gboolean
nm_modem_complete_connection (NMModem *self,
                              NMConnection *connection,
                              const GSList *existing_connections,
                              GError **error)
{
	if (NM_MODEM_GET_CLASS (self)->complete_connection)
		return NM_MODEM_GET_CLASS (self)->complete_connection (self, connection, existing_connections, error);
	return FALSE;
}

/*****************************************************************************/

static void
deactivate (NMModem *self, NMDevice *device)
{
	NMModemPrivate *priv;
	int ifindex;

	g_return_if_fail (NM_IS_MODEM (self));
	g_return_if_fail (NM_IS_DEVICE (device));

	priv = NM_MODEM_GET_PRIVATE (self);

	priv->secrets_tries = 0;

	if (priv->act_request) {
		cancel_get_secrets (self);
		g_object_unref (priv->act_request);
		priv->act_request = NULL;
	}

	priv->in_bytes = priv->out_bytes = 0;

	if (priv->ppp_manager) {
		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;
	}

	switch (priv->ip_method) {
	case MM_MODEM_IP_METHOD_PPP:
		break;
	case MM_MODEM_IP_METHOD_STATIC:
	case MM_MODEM_IP_METHOD_DHCP:
		ifindex = nm_device_get_ip_ifindex (device);
		if (ifindex > 0) {
			nm_platform_route_flush (ifindex);
			nm_platform_address_flush (ifindex);
			nm_platform_link_set_down (ifindex);
		}
		break;
	default:
		nm_log_err (LOGD_MB, "unknown IP method %d", priv->ip_method);
		break;
	}

	g_free (priv->ppp_iface);
	priv->ppp_iface = NULL;
}

/*****************************************************************************/

void
nm_modem_deactivate (NMModem *self, NMDevice *device)
{
	NM_MODEM_GET_CLASS (self)->deactivate (self, device);
}

/*****************************************************************************/

void
nm_modem_device_state_changed (NMModem *self,
                               NMDeviceState new_state,
                               NMDeviceState old_state,
                               NMDeviceStateReason reason)
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
	case NM_DEVICE_STATE_DISCONNECTED:
	case NM_DEVICE_STATE_FAILED:
		if (priv->act_request) {
			cancel_get_secrets (self);
			g_object_unref (priv->act_request);
			priv->act_request = NULL;
		}

		if (was_connected) {
			/* Don't bother warning on FAILED since the modem is already gone */
			if (new_state == NM_DEVICE_STATE_FAILED)
				warn = FALSE;
			NM_MODEM_GET_CLASS (self)->disconnect (self, warn);
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

const char *
nm_modem_get_data_port (NMModem *self)
{
	g_return_val_if_fail (NM_IS_MODEM (self), NULL);

	/* The ppp_iface takes precedence over the data interface when PPP is used,
	 * since data_iface is the TTY over which PPP is run, and that TTY can't
	 * do IP.  The caller really wants the thing that's doing IP.
	 */
	return NM_MODEM_GET_PRIVATE (self)->ppp_iface ?
		NM_MODEM_GET_PRIVATE (self)->ppp_iface : NM_MODEM_GET_PRIVATE (self)->data_port;
}

gboolean
nm_modem_owns_port (NMModem *self, const char *iface)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (self);

	g_return_val_if_fail (iface != NULL, FALSE);

	if (NM_MODEM_GET_CLASS (self)->owns_port)
		return NM_MODEM_GET_CLASS (self)->owns_port (self, iface);

	/* Fall back to data/control ports */
	if (priv->ppp_iface && (strcmp (priv->ppp_iface, iface) == 0))
		return TRUE;
	if (priv->data_port && (strcmp (priv->data_port, iface) == 0))
		return TRUE;
	if (priv->control_port && (strcmp (priv->control_port, iface) == 0))
		return TRUE;

	return FALSE;
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
nm_modem_init (NMModem *self)
{
}

static GObject*
constructor (GType type,
			 guint n_construct_params,
			 GObjectConstructParam *construct_params)
{
	GObject *object;
	NMModemPrivate *priv;

	object = G_OBJECT_CLASS (nm_modem_parent_class)->constructor (type,
	                                                              n_construct_params,
	                                                              construct_params);
	if (!object)
		return NULL;

	priv = NM_MODEM_GET_PRIVATE (object);

	if (!priv->data_port && !priv->control_port) {
		nm_log_err (LOGD_HW, "neither modem command nor data interface provided");
		goto err;
	}

	if (!priv->path) {
		nm_log_err (LOGD_HW, "D-Bus path not provided");
		goto err;
	}

	return object;

 err:
	g_object_unref (object);
	return NULL;
}

static void
get_property (GObject *object, guint prop_id,
              GValue *value, GParamSpec *pspec)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (object);

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
	case PROP_DATA_PORT:
		g_value_set_string (value, nm_modem_get_data_port (NM_MODEM (object)));
		break;
	case PROP_UID:
		g_value_set_string (value, priv->uid);
		break;
	case PROP_IP_METHOD:
		g_value_set_uint (value, priv->ip_method);
		break;
	case PROP_IP_TIMEOUT:
		g_value_set_uint (value, priv->mm_ip_timeout);
		break;
	case PROP_STATE:
		g_value_set_enum (value, priv->state);
		break;
	case PROP_DEVICE_ID:
		g_value_set_string (value, priv->device_id);
		break;
	case PROP_SIM_ID:
		g_value_set_string (value, priv->sim_id);
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
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_PATH:
		/* Construct only */
		priv->path = g_value_dup_string (value);
		break;
	case PROP_DRIVER:
		/* Construct only */
		priv->driver = g_value_dup_string (value);
		break;
	case PROP_CONTROL_PORT:
		priv->control_port = g_value_dup_string (value);
		break;
	case PROP_DATA_PORT:
		priv->data_port = g_value_dup_string (value);
		break;
	case PROP_UID:
		/* Construct only */
		priv->uid = g_value_dup_string (value);
		break;
	case PROP_IP_METHOD:
		priv->ip_method = g_value_get_uint (value);
		break;
	case PROP_IP_TIMEOUT:
		priv->mm_ip_timeout = g_value_get_uint (value);
		break;
	case PROP_STATE:
		priv->state = g_value_get_enum (value);
		break;
	case PROP_DEVICE_ID:
		/* construct only */
		priv->device_id = g_value_dup_string (value);
		break;
	case PROP_SIM_ID:
		g_free (priv->sim_id);
		priv->sim_id = g_value_dup_string (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
dispose (GObject *object)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (object);

	if (priv->act_request) {
		g_object_unref (priv->act_request);
		priv->act_request = NULL;
	}

	G_OBJECT_CLASS (nm_modem_parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	NMModemPrivate *priv = NM_MODEM_GET_PRIVATE (object);

	g_free (priv->uid);
	g_free (priv->path);
	g_free (priv->driver);
	g_free (priv->control_port);
	g_free (priv->data_port);
	g_free (priv->device_id);
	g_free (priv->sim_id);

	G_OBJECT_CLASS (nm_modem_parent_class)->finalize (object);
}

static void
nm_modem_class_init (NMModemClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemPrivate));

	/* Virtual methods */
	object_class->constructor = constructor;
	object_class->set_property = set_property;
	object_class->get_property = get_property;
	object_class->dispose = dispose;
	object_class->finalize = finalize;

	klass->act_stage1_prepare = act_stage1_prepare;
	klass->deactivate = deactivate;

	/* Properties */

	g_object_class_install_property
		(object_class, PROP_UID,
		 g_param_spec_string (NM_MODEM_UID,
		                      "UID",
		                      "Modem unique ID",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_PATH,
		 g_param_spec_string (NM_MODEM_PATH,
		                      "DBus path",
		                      "DBus path",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_DRIVER,
		 g_param_spec_string (NM_MODEM_DRIVER,
		                      "Driver",
		                      "Driver",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_CONTROL_PORT,
		 g_param_spec_string (NM_MODEM_CONTROL_PORT,
		                      "Control port",
		                      "The port controlling the modem",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_DATA_PORT,
		 g_param_spec_string (NM_MODEM_DATA_PORT,
		                      "Data port",
		                      "The port to connect to",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	g_object_class_install_property
		(object_class, PROP_IP_METHOD,
		 g_param_spec_uint (NM_MODEM_IP_METHOD,
		                    "IP method",
		                    "IP method",
		                    MM_MODEM_IP_METHOD_PPP,
		                    MM_MODEM_IP_METHOD_DHCP,
		                    MM_MODEM_IP_METHOD_PPP,
		                    G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_IP_TIMEOUT,
		 g_param_spec_uint (NM_MODEM_IP_TIMEOUT,
		                    "IP timeout",
		                    "IP timeout",
		                    0, 360, 20,
		                    G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_STATE,
		 g_param_spec_enum (NM_MODEM_STATE,
		                   "State",
		                   "State",
		                   NM_TYPE_MODEM_STATE,
		                   NM_MODEM_STATE_UNKNOWN,
		                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_DEVICE_ID,
		 g_param_spec_string (NM_MODEM_DEVICE_ID,
		                      "DeviceId",
		                      "Device ID",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_SIM_ID,
		 g_param_spec_string (NM_MODEM_SIM_ID,
		                      "SimId",
		                      "Sim ID",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT));

	/* Signals */

	signals[PPP_STATS] =
		g_signal_new ("ppp-stats",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, ppp_stats),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2,
		              G_TYPE_UINT, G_TYPE_UINT);

	signals[PPP_FAILED] =
		g_signal_new ("ppp-failed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, ppp_failed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[IP4_CONFIG_RESULT] =
		g_signal_new (NM_MODEM_IP4_CONFIG_RESULT,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, ip4_config_result),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_POINTER);

	signals[PREPARE_RESULT] =
		g_signal_new (NM_MODEM_PREPARE_RESULT,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, prepare_result),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, G_TYPE_BOOLEAN, G_TYPE_UINT);

	signals[AUTH_REQUESTED] =
		g_signal_new (NM_MODEM_AUTH_REQUESTED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, auth_requested),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	signals[AUTH_RESULT] =
		g_signal_new (NM_MODEM_AUTH_RESULT,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, auth_result),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);

	signals[REMOVED] =
		g_signal_new (NM_MODEM_REMOVED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, removed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 0);

	signals[STATE_CHANGED] =
		g_signal_new (NM_MODEM_STATE_CHANGED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, state_changed),
		              NULL, NULL, NULL,
		              G_TYPE_NONE, 2, NM_TYPE_MODEM_STATE, NM_TYPE_MODEM_STATE);

	dbus_g_error_domain_register (NM_MODEM_ERROR,
	                              NM_DBUS_INTERFACE_DEVICE_MODEM,
	                              NM_TYPE_MODEM_ERROR);
}
