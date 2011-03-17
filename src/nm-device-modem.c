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

#include <glib.h>

#include "nm-device-modem.h"
#include "nm-device-interface.h"
#include "nm-modem.h"
#include "nm-modem-cdma.h"
#include "nm-modem-gsm.h"
#include "nm-device-private.h"
#include "nm-properties-changed-signal.h"
#include "nm-rfkill.h"
#include "nm-marshal.h"
#include "nm-logging.h"

static void device_interface_init (NMDeviceInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (NMDeviceModem, nm_device_modem, NM_TYPE_DEVICE, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_DEVICE_INTERFACE, device_interface_init))

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

static void real_set_enabled (NMDeviceInterface *device, gboolean enabled);

/*****************************************************************************/

static void
ppp_failed (NMModem *modem, NMDeviceStateReason reason, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (nm_device_interface_get_state (NM_DEVICE_INTERFACE (device))) {
	case NM_DEVICE_STATE_PREPARE:
	case NM_DEVICE_STATE_CONFIG:
	case NM_DEVICE_STATE_NEED_AUTH:
	case NM_DEVICE_STATE_IP_CHECK:
	case NM_DEVICE_STATE_SECONDARIES:
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

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);

	return nm_modem_check_connection_compatible (priv->modem, connection, error);
}

static gboolean
real_complete_connection (NMDevice *device,
                          NMConnection *connection,
                          const char *specific_object,
                          const GSList *existing_connections,
                          GError **error)
{
	NMDeviceModemPrivate *priv = NM_DEVICE_MODEM_GET_PRIVATE (device);

	return nm_modem_complete_connection (priv->modem, connection, existing_connections, error);
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
real_deactivate (NMDevice *device)
{
	nm_modem_deactivate (NM_DEVICE_MODEM_GET_PRIVATE (device)->modem, device);
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

NMDevice *
nm_device_modem_new (NMModem *modem, const char *driver)
{
	NMDeviceModemCapabilities caps = NM_DEVICE_MODEM_CAPABILITY_NONE;
	const char *type_desc = NULL;

	g_return_val_if_fail (modem != NULL, NULL);
	g_return_val_if_fail (NM_IS_MODEM (modem), NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	if (NM_IS_MODEM_CDMA (modem)) {
		caps = NM_DEVICE_MODEM_CAPABILITY_CDMA_EVDO;
		type_desc = "CDMA/EVDO";
	} else if (NM_IS_MODEM_GSM (modem)) {
		caps = NM_DEVICE_MODEM_CAPABILITY_GSM_UMTS;
		type_desc = "GSM/UMTS";
	} else {
		nm_log_warn (LOGD_MB, "unhandled modem type %s", G_OBJECT_TYPE_NAME (modem));
		return NULL;
	}

	return (NMDevice *) g_object_new (NM_TYPE_DEVICE_MODEM,
	                                  NM_DEVICE_INTERFACE_UDI, nm_modem_get_path (modem),
	                                  NM_DEVICE_INTERFACE_IFACE, nm_modem_get_iface (modem),
	                                  NM_DEVICE_INTERFACE_DRIVER, driver,
	                                  NM_DEVICE_INTERFACE_TYPE_DESC, type_desc,
	                                  NM_DEVICE_INTERFACE_DEVICE_TYPE, NM_DEVICE_TYPE_MODEM,
	                                  NM_DEVICE_INTERFACE_RFKILL_TYPE, RFKILL_TYPE_WWAN,
	                                  NM_DEVICE_MODEM_MODEM, modem,
	                                  NM_DEVICE_MODEM_CAPABILITIES, caps,
	                                  NM_DEVICE_MODEM_CURRENT_CAPABILITIES, caps,
	                                  NULL);
}

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

	g_signal_connect (modem, NM_MODEM_PPP_FAILED, G_CALLBACK (ppp_failed), self);
	g_signal_connect (modem, NM_MODEM_PREPARE_RESULT, G_CALLBACK (modem_prepare_result), self);
	g_signal_connect (modem, NM_MODEM_IP4_CONFIG_RESULT, G_CALLBACK (modem_ip4_config_result), self);
	g_signal_connect (modem, NM_MODEM_AUTH_REQUESTED, G_CALLBACK (modem_auth_requested), self);
	g_signal_connect (modem, NM_MODEM_AUTH_RESULT, G_CALLBACK (modem_auth_result), self);
	g_signal_connect (modem, "notify::" NM_MODEM_ENABLED, G_CALLBACK (modem_enabled_cb), self);
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

	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->check_connection_compatible = real_check_connection_compatible;
	device_class->complete_connection = real_complete_connection;
	device_class->hw_is_up = real_hw_is_up;
	device_class->hw_bring_up = real_hw_bring_up;
	device_class->deactivate = real_deactivate;
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

