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
 * Copyright (C) 2009 - 2011 Red Hat, Inc.
 * Copyright (C) 2009 Novell, Inc.
 */

#include <string.h>
#include "nm-modem.h"
#include "nm-system.h"
#include "nm-dbus-manager.h"
#include "nm-setting-connection.h"
#include "nm-marshal.h"
#include "nm-properties-changed-signal.h"
#include "nm-modem-types.h"
#include "nm-logging.h"
#include "NetworkManagerUtils.h"
#include "nm-device-private.h"
#include "nm-dbus-glib-types.h"

G_DEFINE_TYPE (NMModem, nm_modem, G_TYPE_OBJECT)

#define NM_MODEM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM, NMModemPrivate))

enum {
	PROP_0,
	PROP_CONTROL_PORT,
	PROP_DATA_PORT,
	PROP_PATH,
	PROP_UID,
	PROP_IP_METHOD,
	PROP_IP_TIMEOUT,
	PROP_ENABLED,
	PROP_CONNECTED,

	LAST_PROP
};

typedef struct {
	char *uid;
	char *path;
	char *control_port;
	char *data_port;
	guint32 ip_method;

	NMPPPManager *ppp_manager;

	NMActRequest *act_request;
	guint32 secrets_tries;
	guint32 secrets_id;

	gboolean mm_enabled;
	guint32 mm_ip_timeout;
	gboolean mm_connected;

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

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

/*****************************************************************************/
/* Get/Set enabled/connected */

gboolean
nm_modem_get_mm_enabled (NMModem *self)
{
	return NM_MODEM_GET_PRIVATE (self)->mm_enabled;
}

void
nm_modem_set_mm_enabled (NMModem *self,
                         gboolean enabled)
{
	NMModemPrivate *priv;

	priv = NM_MODEM_GET_PRIVATE (self);

	if (priv->mm_enabled != enabled)
		NM_MODEM_GET_CLASS (self)->set_mm_enabled (self, enabled);
}

gboolean
nm_modem_get_mm_connected (NMModem *self)
{
	return NM_MODEM_GET_PRIVATE (self)->mm_connected;
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
	g_free (priv->data_port);
	priv->data_port = g_strdup (iface);
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

	g_return_val_if_fail (self != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_MODEM (self), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (req != NULL, NM_ACT_STAGE_RETURN_FAILURE);
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

	g_return_val_if_fail (self != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_MODEM (self), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (device != NULL, NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (NM_IS_DEVICE (device), NM_ACT_STAGE_RETURN_FAILURE);
	g_return_val_if_fail (device_class != NULL, NM_ACT_STAGE_RETURN_FAILURE);
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
		NMIP4Address *addr = nm_ip4_config_get_address (config, 0);

		g_assert (addr);
		if (nm_ip4_address_get_prefix (addr) == 32)
			nm_system_iface_set_arp (nm_device_get_ip_ifindex (device), FALSE);
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
                    NMActRequest *req,
                    GPtrArray **out_hints,
                    const char **out_setting_name,
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

	if (priv->act_request)
		g_object_unref (priv->act_request);
	priv->act_request = g_object_ref (req);

	ret = NM_MODEM_GET_CLASS (self)->act_stage1_prepare (self,
	                                                     req,
	                                                     &hints,
	                                                     &setting_name,
	                                                     reason);
	if ((ret == NM_ACT_STAGE_RETURN_POSTPONE) && setting_name) {
		if (priv->secrets_tries++)
			flags |= NM_SETTINGS_GET_SECRETS_FLAG_REQUEST_NEW;

		priv->secrets_id = nm_act_request_get_secrets (req,
		                                               setting_name,
		                                               flags,
		                                               hints ? g_ptr_array_index (hints, 0) : NULL,
		                                               modem_secrets_cb,
		                                               self);
		if (priv->secrets_id)
			g_signal_emit (self, signals[AUTH_REQUESTED], 0);
		else {
			*reason = NM_DEVICE_STATE_REASON_NO_SECRETS;
			ret = NM_ACT_STAGE_RETURN_FAILURE;
		}

		if (hints)
			g_ptr_array_free (hints, TRUE);
	}

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

NMConnection *
nm_modem_get_best_auto_connection (NMModem *self,
                                   GSList *connections,
                                   char **specific_object)
{
	if (NM_MODEM_GET_CLASS (self)->get_best_auto_connection)
		return NM_MODEM_GET_CLASS (self)->get_best_auto_connection (self, connections, specific_object);
	return NULL;
}

/*****************************************************************************/

gboolean
nm_modem_check_connection_compatible (NMModem *self,
                                      NMConnection *connection,
                                      GError **error)
{
	if (NM_MODEM_GET_CLASS (self)->check_connection_compatible)
		return NM_MODEM_GET_CLASS (self)->check_connection_compatible (self, connection, error);
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

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_MODEM (self));
	g_return_if_fail (device != NULL);
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
			/* FIXME: use AF_UNSPEC here when we have IPv6 support */
			nm_system_iface_flush_routes (ifindex, AF_INET);
			nm_system_iface_flush_addresses (ifindex, AF_UNSPEC);
			nm_system_iface_set_up (ifindex, FALSE, NULL);
		}
		break;
	default:
		nm_log_err (LOGD_MB, "unknown IP method %d", priv->ip_method);
		break;
	}
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

	g_return_if_fail (self != NULL);
	g_return_if_fail (NM_IS_MODEM (self));

	if (old_state >= NM_DEVICE_STATE_PREPARE && old_state <= NM_DEVICE_STATE_ACTIVATED)
		was_connected = TRUE;

	priv = NM_MODEM_GET_PRIVATE (self);

	/* Make sure we don't leave the serial device open */
	switch (new_state) {
	case NM_DEVICE_STATE_NEED_AUTH:
		if (priv->ppp_manager)
			break;
		/* else fall through */
	case NM_DEVICE_STATE_UNMANAGED:
	case NM_DEVICE_STATE_UNAVAILABLE:
	case NM_DEVICE_STATE_FAILED:
	case NM_DEVICE_STATE_DISCONNECTED:
		if (new_state != NM_DEVICE_STATE_NEED_AUTH) {
			if (priv->act_request) {
				cancel_get_secrets (self);
				g_object_unref (priv->act_request);
				priv->act_request = NULL;
			}
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
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_MODEM (self), NULL);

	return NM_MODEM_GET_PRIVATE (self)->uid;
}

const char *
nm_modem_get_path (NMModem *self)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_MODEM (self), NULL);

	return NM_MODEM_GET_PRIVATE (self)->path;
}

const char *
nm_modem_get_control_port (NMModem *self)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_MODEM (self), NULL);

	return NM_MODEM_GET_PRIVATE (self)->control_port;
}

const char *
nm_modem_get_data_port (NMModem *self)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_MODEM (self), NULL);

	return NM_MODEM_GET_PRIVATE (self)->data_port;
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
	case PROP_CONTROL_PORT:
		g_value_set_string (value, priv->control_port);
		break;
	case PROP_DATA_PORT:
		g_value_set_string (value, priv->data_port);
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
	case PROP_ENABLED:
		g_value_set_boolean (value, priv->mm_enabled);
		break;
	case PROP_CONNECTED:
		g_value_set_boolean (value, priv->mm_connected);
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
	case PROP_ENABLED:
		priv->mm_enabled = g_value_get_boolean (value);
		break;
	case PROP_CONNECTED:
		priv->mm_connected = g_value_get_boolean (value);
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
	g_free (priv->control_port);
	g_free (priv->data_port);

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
		(object_class, PROP_ENABLED,
		 g_param_spec_boolean (NM_MODEM_ENABLED,
		                       "Enabled",
		                       "Enabled",
		                       TRUE,
		                       G_PARAM_READWRITE));

	g_object_class_install_property
		(object_class, PROP_CONNECTED,
		 g_param_spec_boolean (NM_MODEM_CONNECTED,
		                       "Connected",
		                       "Connected",
		                       TRUE,
		                       G_PARAM_READWRITE));

	/* Signals */

	signals[PPP_STATS] =
		g_signal_new ("ppp-stats",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, ppp_stats),
		              NULL, NULL,
		              _nm_marshal_VOID__UINT_UINT,
		              G_TYPE_NONE, 2,
		              G_TYPE_UINT, G_TYPE_UINT);

	signals[PPP_FAILED] =
		g_signal_new ("ppp-failed",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, ppp_failed),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__UINT,
		              G_TYPE_NONE, 1, G_TYPE_UINT);

	signals[IP4_CONFIG_RESULT] =
		g_signal_new (NM_MODEM_IP4_CONFIG_RESULT,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, ip4_config_result),
		              NULL, NULL,
		              _nm_marshal_VOID__OBJECT_POINTER,
		              G_TYPE_NONE, 2, G_TYPE_OBJECT, G_TYPE_POINTER);

	signals[PREPARE_RESULT] =
		g_signal_new (NM_MODEM_PREPARE_RESULT,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, prepare_result),
		              NULL, NULL,
		              _nm_marshal_VOID__BOOLEAN_UINT,
		              G_TYPE_NONE, 2, G_TYPE_BOOLEAN, G_TYPE_UINT);

	signals[AUTH_REQUESTED] =
		g_signal_new (NM_MODEM_AUTH_REQUESTED,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, auth_requested),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__VOID,
		              G_TYPE_NONE, 0);

	signals[AUTH_RESULT] =
		g_signal_new (NM_MODEM_AUTH_RESULT,
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMModemClass, auth_result),
		              NULL, NULL,
		              g_cclosure_marshal_VOID__POINTER,
		              G_TYPE_NONE, 1, G_TYPE_POINTER);
}
