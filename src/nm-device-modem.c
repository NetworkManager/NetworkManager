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
 */

#include "config.h"

#include <glib.h>

#include "nm-device-modem.h"
#include "nm-modem.h"
#include "nm-modem-cdma.h"
#include "nm-modem-gsm.h"
#include "nm-device-private.h"
#include "nm-properties-changed-signal.h"
#include "nm-rfkill.h"
#include "nm-marshal.h"
#include "nm-logging.h"
#include "nm-system.h"

#if WITH_MODEM_MANAGER_1
#include "nm-modem-broadband.h"
#endif

G_DEFINE_TYPE (NMDeviceModem, nm_device_modem, NM_TYPE_DEVICE)

#define NM_DEVICE_MODEM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_MODEM, NMDeviceModemPrivate))

#include "nm-device-modem-glue.h"

typedef struct {
	NMModem *modem;
	NMDeviceModemCapabilities caps;
	NMDeviceModemCapabilities current_caps;
} NMDeviceModemPrivate;

enum {
	PROP_0,
	PROP_MODEM,
	PROP_CAPABILITIES,
	PROP_CURRENT_CAPABILITIES,
};

enum {
	PROPERTIES_CHANGED,
	ENABLE_CHANGED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

static void set_enabled (NMDevice *device, gboolean enabled);

/*****************************************************************************/

static void
ppp_failed (NMModem *modem, NMDeviceStateReason reason, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (nm_device_get_state (device)) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
		break;
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_IP_CHECK:
	case NM_DEVICE_STATE_SECONDARIES:
	case NM_DEVICE_STATE_ACTIVATED:
		if (nm_device_activate_ip4_state_in_conf (device))
			nm_device_activate_schedule_ip4_config_timeout (device);
		else {
			nm_device_state_changed (device,
			                         NM_DEVICE_STATE_FAILED,
			                         NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
		}
		break;
	default:
		break;
	}
}

static void
modem_prepare_result (NMModem *modem,
                      gboolean success,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceState state;

	state = nm_device_get_state (device);
	g_return_if_fail (state == NM_DEVICE_STATE_PREPARE);

	if (success)
		nm_device_activate_schedule_stage2_device_config (device);
	else
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
}

static void
modem_auth_requested (NMModem *modem, gpointer user_data)
{
	nm_device_state_changed (NM_DEVICE (user_data),
	                         NM_DEVICE_STATE_NEED_AUTH,
	                         NM_DEVICE_STATE_REASON_NONE);
}

static void
modem_auth_result (NMModem *modem, GError *error, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	if (error) {
		nm_device_state_changed (device,
		                         NM_DEVICE_STATE_FAILED,
		                         NM_DEVICE_STATE_REASON_NO_SECRETS);
	} else {
		/* Otherwise, on success for modem secrets we need to schedule stage1 again */
		g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
		nm_device_activate_schedule_stage1_device_prepare (device);
	}
}

static void
modem_ip4_config_result (NMModem *self,
                         NMIP4Config *config,
                         GError *error,
                         gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	g_return_if_fail (nm_device_activate_ip4_state_in_conf (device) == TRUE);

	if (error) {
		nm_log_warn (LOGD_MB | LOGD_IP4, "retrieving IP4 configuration failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");

		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	} else
		nm_device_activate_schedule_ip4_config_result (device, config);
}

static void
data_port_changed_cb (NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
	NMDevice *self = NM_DEVICE (user_data);

	/* We set the IP iface in the device as soon as we know it, so that we
	 * properly ifup it if needed */
	nm_device_set_ip_iface (self, nm_modem_get_data_port (modem));
}

static void
modem_enabled_cb (NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (user_data);
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);

	set_enabled (NM_DEVICE (self), nm_modem_get_mm_enabled (priv->modem));

	g_signal_emit (G_OBJECT (self), signals[ENABLE_CHANGED], 0);
}

static void
modem_connected_cb (NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (user_data);
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);

	if (   nm_device_get_state (NM_DEVICE (self)) == NM_DEVICE_STATE_ACTIVATED
	    && !nm_modem_get_mm_connected (priv->modem)) {
		/* Fail the device if the modem disconnects unexpectedly */
		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_MODEM_NO_CARRIER);
	}
}

/*****************************************************************************/

NMModem *
nm_device_modem_get_modem (NMDeviceModem *self)
{
	g_return_val_if_fail (self != NULL, NULL);
	g_return_val_if_fail (NM_IS_DEVICE_MODEM (self), NULL);

	return NM_DEVICE_MODEM_GET_PRIVATE (self)->modem;
}

/*****************************************************************************/

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason)
{
	nm_modem_device_state_changed (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem,
	                               new_state,
	                               old_state,
	                               reason);
}

static guint32
get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_NM_SUPPORTED;
}

static NMConnection *
get_best_auto_connection (NMDevice *device,
                          GSList *connections,
                          char **specific_object)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);

	return nm_modem_get_best_auto_connection (priv->modem, connections, specific_object);
}

static gboolean
check_connection_compatible (NMDevice *device,
                             NMConnection *connection,
                             GError **error)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);

	return nm_modem_check_connection_compatible (priv->modem, connection, error);
}

static gboolean
complete_connection (NMDevice *device,
                     NMConnection *connection,
                     const char *specific_object,
                     const GSList *existing_connections,
                     GError **error)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);

	return nm_modem_complete_connection (priv->modem, connection, existing_connections, error);
}

static void
deactivate (NMDevice *device)
{
	nm_modem_deactivate (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, device);
}

static NMActStageReturn
act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActRequest *req;

	req = nm_device_get_act_request (device);
	g_assert (req);

	return nm_modem_act_stage1_prepare (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, req, reason);
}

static NMActStageReturn
act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActRequest *req;

	req = nm_device_get_act_request (device);
	g_assert (req);

	return nm_modem_act_stage2_config (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, req, reason);
}

static NMActStageReturn
act_stage3_ip4_config_start (NMDevice *device,
                             NMIP4Config **out_config,
                             NMDeviceStateReason *reason)
{
	return nm_modem_stage3_ip4_config_start (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem,
	                                         device,
	                                         NM_DEVICE_CLASS (nm_device_modem_parent_class),
	                                         reason);
}

static void
ip4_config_pre_commit (NMDevice *device, NMIP4Config *config)
{
	nm_modem_ip4_pre_commit (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, device, config);
}

static NMActStageReturn
act_stage3_ip6_config_start (NMDevice *device,
                             NMIP6Config **out_config,
                             NMDeviceStateReason *reason)
{
	return nm_modem_stage3_ip6_config_start (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem,
	                                         device,
	                                         NM_DEVICE_CLASS (nm_device_modem_parent_class),
	                                         reason);
}

/*****************************************************************************/

static gboolean
get_enabled (NMDevice *device)
{
	return nm_modem_get_mm_enabled (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem);
}

static void
set_enabled (NMDevice *device, gboolean enabled)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (device);
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);
	NMDeviceState state;

	if (priv->modem) {
		nm_modem_set_mm_enabled (priv->modem, enabled);

		if (enabled == FALSE) {
			state = nm_device_get_state (device);
			if (nm_device_is_activating (device) || state == NM_DEVICE_STATE_ACTIVATED) {
				/* user-initiated action, hence DISCONNECTED not FAILED */
				nm_device_state_changed (device,
				                         NM_DEVICE_STATE_DISCONNECTED,
				                         NM_DEVICE_STATE_REASON_USER_REQUESTED);
			}
		}
	}
}

/*****************************************************************************/

NMDevice *
nm_device_modem_new (NMModem *modem, const char *driver)
{
	NMDeviceModemCapabilities caps = NM_DEVICE_MODEM_CAPABILITY_NONE;
	NMDeviceModemCapabilities current_caps = NM_DEVICE_MODEM_CAPABILITY_NONE;
	const gchar *type_desc = NULL;
	const gchar *ip_iface = NULL;

	g_return_val_if_fail (modem != NULL, NULL);
	g_return_val_if_fail (NM_IS_MODEM (modem), NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	if (NM_IS_MODEM_CDMA (modem)) {
		caps = NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO;
		current_caps = caps;
		type_desc = "CDMA/EVDO";
		ip_iface = nm_modem_get_data_port (modem);
	} else if (NM_IS_MODEM_GSM (modem)) {
		caps = NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS;
		current_caps = caps;
		type_desc = "GSM/UMTS";
		ip_iface = nm_modem_get_data_port (modem);
	}
#if WITH_MODEM_MANAGER_1
	else if (NM_IS_MODEM_BROADBAND (modem)) {
		nm_modem_broadband_get_capabilities (NM_MODEM_BROADBAND (modem), &caps, &current_caps);
		type_desc = "Broadband";
		/* data port not yet known in broadband modems */
	}
#endif
	else {
		nm_log_warn (LOGD_MB, "unhandled modem type %s", G_OBJECT_TYPE_NAME (modem));
		return NULL;
	}

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_MODEM,
	                                  NM_DEVICE_UDI, nm_modem_get_path (modem),
	                                  NM_DEVICE_IFACE, nm_modem_get_uid (modem),
	                                  NM_DEVICE_IP_IFACE, ip_iface,
	                                  NM_DEVICE_DRIVER, driver,
	                                  NM_DEVICE_TYPE_DESC, type_desc,
	                                  NM_DEVICE_DEVICE_TYPE, NM_DEVICE_TYPE_MODEM,
	                                  NM_DEVICE_RFKILL_TYPE, RFKILL_TYPE_WWAN,
	                                  NM_DEVICE_MODEM_MODEM, modem,
	                                  NM_DEVICE_MODEM_CAPABILITIES, caps,
	                                  NM_DEVICE_MODEM_CURRENT_CAPABILITIES, caps,
	                                  NULL);
}

static void
nm_device_modem_init (NMDeviceModem *self)
{
}

static void
set_modem (NMDeviceModem *self, NMModem *modem)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);

	g_return_if_fail (modem != NULL);

	priv->modem = g_object_ref (modem);

	g_signal_connect (modem, NM_MODEM_PPP_FAILED, G_CALLBACK (ppp_failed), self);
	g_signal_connect (modem, NM_MODEM_PREPARE_RESULT, G_CALLBACK (modem_prepare_result), self);
	g_signal_connect (modem, NM_MODEM_IP4_CONFIG_RESULT, G_CALLBACK (modem_ip4_config_result), self);
	g_signal_connect (modem, NM_MODEM_AUTH_REQUESTED, G_CALLBACK (modem_auth_requested), self);
	g_signal_connect (modem, NM_MODEM_AUTH_RESULT, G_CALLBACK (modem_auth_result), self);
	g_signal_connect (modem, "notify::" NM_MODEM_ENABLED, G_CALLBACK (modem_enabled_cb), self);
	g_signal_connect (modem, "notify::" NM_MODEM_CONNECTED, G_CALLBACK (modem_connected_cb), self);

	/* In the old ModemManager the data port is known from the very beginning;
	 * while in the new ModemManager the data port is set afterwards when the bearer gets
	 * created */
	g_signal_connect (modem, "notify::" NM_MODEM_DATA_PORT, G_CALLBACK (data_port_changed_cb), self);
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MODEM:
		/* construct-only */
		set_modem (NM_DEVICE_MODEM (object), g_value_get_object (value));
		break;
	case PROP_CAPABILITIES:
		priv->caps = g_value_get_uint (value);
		break;
	case PROP_CURRENT_CAPABILITIES:
		priv->current_caps = g_value_get_uint (value);
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
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MODEM:
		g_value_set_object (value, priv->modem);
		break;
	case PROP_CAPABILITIES:
		g_value_set_uint (value, priv->caps);
		break;
	case PROP_CURRENT_CAPABILITIES:
		g_value_set_uint (value, priv->current_caps);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (object);

	g_object_unref (priv->modem);
	priv->modem = NULL;

	G_OBJECT_CLASS (nm_device_modem_parent_class)->finalize (object);
}

static void
nm_device_modem_class_init (NMDeviceModemClass *mclass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (mclass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (mclass);

	g_type_class_add_private (object_class, sizeof (NMDeviceModemPrivate));

	/* Virtual methods */
	object_class->finalize = finalize;
	object_class->get_property = get_property;
	object_class->set_property = set_property;

	device_class->get_generic_capabilities = get_generic_capabilities;
	device_class->get_best_auto_connection = get_best_auto_connection;
	device_class->check_connection_compatible = check_connection_compatible;
	device_class->complete_connection = complete_connection;
	device_class->deactivate = deactivate;
	device_class->act_stage1_prepare = act_stage1_prepare;
	device_class->act_stage2_config = act_stage2_config;
	device_class->act_stage3_ip4_config_start = act_stage3_ip4_config_start;
	device_class->act_stage3_ip6_config_start = act_stage3_ip6_config_start;
	device_class->ip4_config_pre_commit = ip4_config_pre_commit;
	device_class->get_enabled = get_enabled;
	device_class->set_enabled = set_enabled;

	device_class->state_changed = device_state_changed;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_MODEM,
		 g_param_spec_object (NM_DEVICE_MODEM_MODEM,
		                      "Modem",
		                      "Modem",
		                      NM_TYPE_MODEM,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | NM_PROPERTY_PARAM_NO_EXPORT));

	g_object_class_install_property (object_class, PROP_CAPABILITIES,
		g_param_spec_uint (NM_DEVICE_MODEM_CAPABILITIES,
		                   "Modem Capabilities",
		                   "Modem Capabilities",
		                   0, G_MAXUINT32, NM_DEVICE_MODEM_CAPABILITY_NONE,
		                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property (object_class, PROP_CURRENT_CAPABILITIES,
		g_param_spec_uint (NM_DEVICE_MODEM_CURRENT_CAPABILITIES,
		                   "Current modem Capabilities",
		                   "Current modem Capabilities",
		                   0, G_MAXUINT32, NM_DEVICE_MODEM_CAPABILITY_NONE,
		                   G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* Signals */
	signals[PROPERTIES_CHANGED] =
		nm_properties_changed_signal_new (object_class,
		                                  G_STRUCT_OFFSET (NMDeviceModemClass, properties_changed));

	signals[ENABLE_CHANGED] =
		g_signal_new (NM_DEVICE_MODEM_ENABLE_CHANGED,
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  0, NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (mclass),
	                                 &dbus_glib_nm_device_modem_object_info);
}
