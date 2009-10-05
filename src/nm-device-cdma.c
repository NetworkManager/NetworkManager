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
 * Copyright (C) 2009 Red Hat, Inc.
 */

#include <string.h>

#include "nm-dbus-glib-types.h"
#include "nm-modem.h"
#include "nm-modem-cdma.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-device-cdma.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"
#include "nm-marshal.h"
#include "nm-properties-changed-signal.h"

#include "nm-device-cdma-glue.h"
#include "nm-serial-device-glue.h"

G_DEFINE_TYPE (NMDeviceCdma, nm_device_cdma, NM_TYPE_DEVICE)

#define NM_DEVICE_CDMA_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_CDMA, NMDeviceCdmaPrivate))

typedef struct {
	gboolean disposed;

	NMModem *modem;
} NMDeviceCdmaPrivate;

enum {
	PPP_STATS,
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

static void
ppp_stats (NMModem *modem,
		   guint32 in_bytes,
		   guint32 out_bytes,
		   gpointer user_data)
{
	g_signal_emit (NM_DEVICE_CDMA (user_data), signals[PPP_STATS], 0, in_bytes, out_bytes);
}

static void
ppp_failed (NMModem *modem, NMDeviceStateReason reason, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	
	switch (nm_device_interface_get_state (NM_DEVICE_INTERFACE (device))) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CONFIG:
	case NM_DEVICE_STATE_ACTIVATED:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, reason);
		break;
	default:
		break;
	}
}

static void
device_state_changed (NMDevice *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceCdmaPrivate *priv = NM_DEVICE_CDMA_GET_PRIVATE (device);

	nm_modem_device_state_changed (priv->modem, new_state, old_state, reason);
}

static gboolean
real_hw_is_up (NMDevice *device)
{
	return nm_modem_hw_is_up (NM_DEVICE_CDMA_GET_PRIVATE (device)->modem, device);
}

static gboolean
real_hw_bring_up (NMDevice *device, gboolean *no_firmware)
{
	return nm_modem_hw_bring_up (NM_DEVICE_CDMA_GET_PRIVATE (device)->modem, device, no_firmware);
}

static NMConnection *
real_get_best_auto_connection (NMDevice *device,
							   GSList *connections,
							   char **specific_object)
{
	NMDeviceCdmaPrivate *priv = NM_DEVICE_CDMA_GET_PRIVATE (device);

	return nm_modem_get_best_auto_connection (priv->modem, connections, specific_object);
}

static void
real_connection_secrets_updated (NMDevice *device,
								 NMConnection *connection,
								 GSList *updated_settings,
								 RequestSecretsCaller caller)
{
	NMDeviceCdmaPrivate *priv = NM_DEVICE_CDMA_GET_PRIVATE (device);
	NMActRequest *req;

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

	/* Otherwise, on success for CDMA secrets we need to schedule stage1 again */
	g_return_if_fail (nm_device_get_state (device) == NM_DEVICE_STATE_NEED_AUTH);
	nm_device_activate_schedule_stage1_device_prepare (device);
}

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMDeviceCdmaPrivate *priv = NM_DEVICE_CDMA_GET_PRIVATE (device);

	return nm_modem_check_connection_compatible (priv->modem, connection, error);
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
	NMDeviceCdma *self = NM_DEVICE_CDMA (self);
	NMActRequest *req;

	req = nm_device_get_act_request (NM_DEVICE (self));
	g_assert (req);

	nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);
	nm_act_request_get_secrets (req, setting_name, retry, caller, hint1, hint2);
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

static NMActStageReturn
real_act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActRequest *req;

	req = nm_device_get_act_request (device);
	g_assert (req);

	return nm_modem_act_stage1_prepare (NM_DEVICE_CDMA_GET_PRIVATE (device)->modem, req, reason);
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMActRequest *req;

	req = nm_device_get_act_request (device);
	g_assert (req);

	return nm_modem_act_stage2_config (NM_DEVICE_CDMA_GET_PRIVATE (device)->modem, req, reason);
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
		nm_warning ("%s: retrieving IP4 configuration failed: (%d) %s",
		            __func__,
		            error ? error->code : -1,
		            error && error->message ? error->message : "(unknown)");

		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_IP_CONFIG_UNAVAILABLE);
	} else {
		if (iface)
			nm_device_set_ip_iface (device, iface);

		nm_device_activate_schedule_stage4_ip4_config_get (device);	
	}
}

static NMActStageReturn
real_act_stage3_ip4_config_start (NMDevice *device, NMDeviceStateReason *reason)
{
	return nm_modem_stage3_ip4_config_start (NM_DEVICE_CDMA_GET_PRIVATE (device)->modem,
	                                         device,
	                                         NM_DEVICE_CLASS (nm_device_cdma_parent_class),
	                                         reason);
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *device,
                                NMIP4Config **config,
                                NMDeviceStateReason *reason)
{
	return nm_modem_stage4_get_ip4_config (NM_DEVICE_CDMA_GET_PRIVATE (device)->modem,
	                                       device,
	                                       NM_DEVICE_CLASS (nm_device_cdma_parent_class),
	                                       config,
	                                       reason);
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMDeviceCdmaPrivate *priv = NM_DEVICE_CDMA_GET_PRIVATE (device);

	nm_modem_deactivate_quickly (priv->modem, device);
}

static guint32
real_get_generic_capabilities (NMDevice *device)
{
	return NM_DEVICE_CAP_NM_SUPPORTED;
}

/*****************************************************************************/

NMDevice *
nm_device_cdma_new (NMModemCdma *modem, const char *driver)
{
	NMDevice *device;

	g_return_val_if_fail (modem != NULL, NULL);
	g_return_val_if_fail (NM_IS_MODEM_CDMA (modem), NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	device = (NMDevice *) g_object_new (NM_TYPE_DEVICE_CDMA,
	                                    NM_DEVICE_INTERFACE_UDI, nm_modem_get_path (NM_MODEM (modem)),
	                                    NM_DEVICE_INTERFACE_IFACE, nm_modem_get_iface (NM_MODEM (modem)),
	                                    NM_DEVICE_INTERFACE_DRIVER, driver,
	                                    NM_DEVICE_INTERFACE_TYPE_DESC, "CDMA",
	                                    NM_DEVICE_INTERFACE_DEVICE_TYPE, NM_DEVICE_TYPE_CDMA,
	                                    NULL);
	if (device) {
		NM_DEVICE_CDMA_GET_PRIVATE (device)->modem = g_object_ref (modem);
		g_signal_connect (device, "state-changed", G_CALLBACK (device_state_changed), device);

		g_signal_connect (modem, NM_MODEM_PPP_STATS, G_CALLBACK (ppp_stats), device);
		g_signal_connect (modem, NM_MODEM_PPP_FAILED, G_CALLBACK (ppp_failed), device);
		g_signal_connect (modem, NM_MODEM_PREPARE_RESULT, G_CALLBACK (modem_prepare_result), device);
		g_signal_connect (modem, NM_MODEM_IP4_CONFIG_RESULT, G_CALLBACK (modem_ip4_config_result), device);
		g_signal_connect (modem, NM_MODEM_NEED_AUTH, G_CALLBACK (modem_need_auth), device);
	}

	return device;
}

static void
nm_device_cdma_init (NMDeviceCdma *self)
{
}

static void
dispose (GObject *object)
{
	NMDeviceCdmaPrivate *priv = NM_DEVICE_CDMA_GET_PRIVATE (object);

	if (priv->disposed) {
		G_OBJECT_CLASS (nm_device_cdma_parent_class)->dispose (object);
		return;
	}
	priv->disposed = TRUE;

	g_object_unref (priv->modem);
	priv->modem = NULL;

	G_OBJECT_CLASS (nm_device_cdma_parent_class)->dispose (object);	
}

static void
nm_device_cdma_class_init (NMDeviceCdmaClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceCdmaPrivate));

	/* Virtual methods */
	object_class->dispose = dispose;

	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
	device_class->check_connection_compatible = real_check_connection_compatible;
	device_class->hw_is_up = real_hw_is_up;
	device_class->hw_bring_up = real_hw_bring_up;
	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
	device_class->act_stage2_config = real_act_stage2_config;
	device_class->act_stage3_ip4_config_start = real_act_stage3_ip4_config_start;
	device_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	device_class->deactivate_quickly = real_deactivate_quickly;

	/* Signals */
	signals[PPP_STATS] =
		g_signal_new ("ppp-stats",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMDeviceCdmaClass, ppp_stats),
					  NULL, NULL,
					  _nm_marshal_VOID__UINT_UINT,
					  G_TYPE_NONE, 2,
					  G_TYPE_UINT, G_TYPE_UINT);

	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class,
										  G_STRUCT_OFFSET (NMDeviceCdmaClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_serial_device_object_info);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
	                                 &dbus_glib_nm_device_cdma_object_info);
}

