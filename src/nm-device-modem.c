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
 * Copyright (C) 2009 - 2010 Red Hat, Inc.
 */

#include <glib.h>

#include "nm-device-modem.h"
#include "nm-device-interface.h"
#include "nm-modem.h"
#include "nm-device-private.h"
#include "nm-properties-changed-signal.h"
#include "nm-marshal.h"
#include "nm-logging.h"

static void device_interface_init (NMDeviceInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (NMDeviceModem, nm_device_modem, NM_TYPE_DEVICE, G_TYPE_FLAG_ABSTRACT,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_INTERFACE, device_interface_init))

#define NM_DEVICE_MODEM_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_MODEM, NMDeviceModemPrivate))

typedef struct {
	NMModem *modem;
} NMDeviceModemPrivate;

enum {
	PROP_0,
	PROP_MODEM
};

enum {
	PPP_STATS,
	ENABLE_CHANGED,
	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

static void real_set_enabled (NMDeviceInterface *device, gboolean enabled);

/*****************************************************************************/

static void
ppp_stats (NMModem *modem,
		   guint32 in_bytes,
		   guint32 out_bytes,
		   gpointer user_data)
{
	g_signal_emit (G_OBJECT (user_data), signals[PPP_STATS], 0, in_bytes, out_bytes);
}

static void
ppp_failed (NMModem *modem, NMDeviceStateReason reason, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (nm_device_interface_get_state (NM_DEVICE_INTERFACE (device))) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_ACTIVATED:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
		break;
	case NM_DEVICE_STATE_IP_CONFIG:
		if (nm_device_ip_config_should_fail (device, FALSE)) {
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

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));
	g_return_if_fail (state == NM_DEVICE_STATE_PREPARE);

	if (success)
		nm_device_activate_schedule_stage2_device_config (device);
	else
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
}

static void
modem_need_auth (NMModem *modem,
	             const char *setting_name,
	             gboolean retry,
	             RequestSecretsCaller caller,
	             const char *hint1,
	             const char *hint2,
	             gpointer user_data)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (user_data);
	NMActRequest *req;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_assert (req);

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);
	nm_act_request_get_secrets (req, setting_name, retry, caller, hint1, hint2);
}

static void
modem_ip4_config_result (NMModem *self,
                         const char *iface,
                         NMIP4Config *config,
                         GError *error,
                         gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	NMDeviceState state;

	state = nm_device_interface_get_state (NM_DEVICE_INTERFACE (device));
	g_return_if_fail (state == NM_DEVICE_STATE_IP_CONFIG);

	if (error) {
		nm_log_warn (LOGD_MB | LOGD_IP4, "retrieving IP4 configuration failed: (%d) %s",
		             error ? error->code : -1,
		             error && error->message ? error->message : "(unknown)");

		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	} else {
		if (iface)
			nm_device_set_ip_iface (device, iface);

		nm_device_activate_schedule_stage4_ip4_config_get (device);
	}
}

static void
modem_enabled_cb (NMModem *modem, GParamSpec *pspec, gpointer user_data)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (user_data);
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);

	real_set_enabled (NM_DEVICE_INTERFACE (self), nm_modem_get_mm_enabled (priv->modem));

	g_signal_emit (G_OBJECT (self), signals[ENABLE_CHANGED], 0);
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
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	nm_modem_device_state_changed (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem,
	                               new_state,
	                               old_state,
	                               reason);
}

static guint32
real_get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_NM_SUPPORTED;
}

static NMConnection *
real_get_best_auto_connection (NMDevice *device,
							   GSList *connections,
							   char **specific_object)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);

	return nm_modem_get_best_auto_connection (priv->modem, connections, specific_object);
}

static void
real_connection_secrets_updated (NMDevice *device,
								 NMConnection *connection,
								 GSList *updated_settings,
								 RequestSecretsCaller caller)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);
	NMActRequest *req;

	g_return_if_fail (IS_ACTIVATING_STATE (nm_device_get_state (device)));

	req = nm_device_get_act_request (device);
	g_assert (req);

	if (!nm_modem_connection_secrets_updated (priv->modem,
                                              req,
                                              connection,
                                              updated_settings,
                                              caller)) {
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NO_SECRETS);
		return;
	}

	/* PPP handles stuff itself... */
	if (caller == SECRETS_CALLER_PPP)
		return;

	/* Otherwise, on success for modem secrets we need to schedule stage1 again */
	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
	nm_device_activate_schedule_stage1_device_prepare (device);
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);

	return nm_modem_check_connection_compatible (priv->modem, connection, error);
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	return nm_modem_hw_is_up (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, device);
}

static gboolean
real_hw_bring_up (NMDevice *device, gboolean *no_firmware)
{
	return nm_modem_hw_bring_up (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, device, no_firmware);
}

static void
real_deactivate_quickly (NMDevice *device)
{
	nm_modem_deactivate_quickly (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, device);
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActRequest *req;

	req = nm_device_get_act_request (device);
	g_assert (req);

	return nm_modem_act_stage1_prepare (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, req, reason);
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActRequest *req;

	req = nm_device_get_act_request (device);
	g_assert (req);

	return nm_modem_act_stage2_config (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, req, reason);
}

static NMActStageReturn
real_act_stage3_ip4_config_start (NMDevice *device, NMDeviceStateReason *reason)
{
	return nm_modem_stage3_ip4_config_start (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem,
	                                         device,
	                                         NM_DEVICE_CLASS (nm_device_modem_parent_class),
	                                         reason);
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *device,
                                NMIP4Config **config,
                                NMDeviceStateReason *reason)
{
	return nm_modem_stage4_get_ip4_config (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem,
	                                       device,
	                                       NM_DEVICE_CLASS (nm_device_modem_parent_class),
	                                       config,
	                                       reason);
}

/*****************************************************************************/

static gboolean
real_get_enabled (NMDeviceInterface *device)
{
	return nm_modem_get_mm_enabled (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem);
}

static void
real_set_enabled (NMDeviceInterface *device, gboolean enabled)
{
	NMDeviceModem *self = NM_DEVICE_MODEM (device);
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);
	NMDeviceState state;

	if (priv->modem) {
		nm_modem_set_mm_enabled (priv->modem, enabled);

		if (enabled == FALSE) {
			state = nm_device_interface_get_state (device);
			if (state == NM_DEVICE_STATE_ACTIVATED) {
				nm_device_state_changed (NM_DEVICE (device),
				                         NM_DEVICE_STATE_DISCONNECTED,
				                         NM_DEVICE_STATE_REASON_NONE);
			}
		}
	}
}

/*****************************************************************************/

static void
device_interface_init (NMDeviceInterface *iface_class)
{
    iface_class->get_enabled = real_get_enabled;
    iface_class->set_enabled = real_set_enabled;
}

static void
nm_device_modem_init (NMDeviceModem *self)
{
	g_signal_connect (self, "state-changed", G_CALLBACK (device_state_changed), self);
}

static void
set_modem (NMDeviceModem *self, NMModem *modem)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (self);

	g_return_if_fail (modem != NULL);

	priv->modem = g_object_ref (modem);

	g_signal_connect (modem, NM_MODEM_PPP_STATS, G_CALLBACK (ppp_stats), self);
	g_signal_connect (modem, NM_MODEM_PPP_FAILED, G_CALLBACK (ppp_failed), self);
	g_signal_connect (modem, NM_MODEM_PREPARE_RESULT, G_CALLBACK (modem_prepare_result), self);
	g_signal_connect (modem, NM_MODEM_IP4_CONFIG_RESULT, G_CALLBACK (modem_ip4_config_result), self);
	g_signal_connect (modem, NM_MODEM_NEED_AUTH, G_CALLBACK (modem_need_auth), self);
	g_signal_connect (modem, "notify::" NM_MODEM_ENABLED, G_CALLBACK (modem_enabled_cb), self);
}

static void
set_property (GObject *object, guint prop_id,
			  const GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_MODEM:
		/* construct-only */
		set_modem (NM_DEVICE_MODEM (object), g_value_get_object (value));
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

	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
	device_class->check_connection_compatible = real_check_connection_compatible;
	device_class->hw_is_up = real_hw_is_up;
	device_class->hw_bring_up = real_hw_bring_up;
	device_class->deactivate_quickly = real_deactivate_quickly;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
	device_class->act_stage2_config = real_act_stage2_config;
	device_class->act_stage3_ip4_config_start = real_act_stage3_ip4_config_start;
	device_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_MODEM,
		 g_param_spec_object (NM_DEVICE_MODEM_MODEM,
		                      "Modem",
		                      "Modem",
		                      NM_TYPE_MODEM,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | NM_PROPERTY_PARAM_NO_EXPORT));

	/* Signals */
	signals[PPP_STATS] =
		g_signal_new ("ppp-stats",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDeviceModemClass, ppp_stats),
					  NULL, NULL,
					  _nm_marshal_VOID__UINT_UINT,
					  G_TYPE_NONE, 2,
					  G_TYPE_UINT, G_TYPE_UINT);

	signals[ENABLE_CHANGED] =
		g_signal_new (NM_DEVICE_MODEM_ENABLE_CHANGED,
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  0,
					  NULL, NULL,
					  g_cclosure_marshal_VOID__VOID,
					  G_TYPE_NONE, 0);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (mclass),
	                                 nm_modem_get_serial_dbus_info ());
}

