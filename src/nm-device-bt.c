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

#include <stdio.h>
#include <string.h>
#include "nm-glib-compat.h"
#include "nm-bluez-common.h"
#include "nm-dbus-manager.h"
#include "nm-device-bt.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-utils.h"
#include "nm-marshal.h"
#include "ppp-manager/nm-ppp-manager.h"
#include "nm-properties-changed-signal.h"
#include "nm-setting-connection.h"
#include "nm-setting-bluetooth.h"
#include "nm-setting-cdma.h"
#include "nm-setting-gsm.h"
#include "nm-device-bt-glue.h"

#define BLUETOOTH_DUN_UUID "dun"
#define BLUETOOTH_NAP_UUID "nap"

G_DEFINE_TYPE (NMDeviceBt, nm_device_bt, NM_TYPE_DEVICE)

#define NM_DEVICE_BT_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_DEVICE_BT, NMDeviceBtPrivate))

typedef struct {
	char *bdaddr;
	char *name;
	guint32 capabilities;

	guint state_to_disconnected_id;
	DBusGProxy *type_proxy;

	NMPPPManager *ppp_manager;
	char *rfcomm_iface;
	guint32 in_bytes;
	guint32 out_bytes;

	NMIP4Config *pending_ip4_config;
	guint32 bt_type;  /* BT type of the current connection */
} NMDeviceBtPrivate;

enum {
	PROP_0,
	PROP_HW_ADDRESS,
	PROP_BT_NAME,
	PROP_BT_CAPABILITIES,

	LAST_PROP
};

enum {
	PPP_STATS,
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};
static guint signals[LAST_SIGNAL] = { 0 };

NMDeviceBt *
nm_device_bt_new (const char *udi,
                  const char *bdaddr,
                  const char *name,
                  guint32 capabilities,
                  gboolean managed)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (bdaddr != NULL, NULL);
	g_return_val_if_fail (name != NULL, NULL);
	g_return_val_if_fail (capabilities != NM_BT_CAPABILITY_NONE, NULL);

	return (NMDeviceBt *) g_object_new (NM_TYPE_DEVICE_BT,
	                                    NM_DEVICE_INTERFACE_UDI, udi,
	                                    NM_DEVICE_INTERFACE_IFACE, bdaddr,
	                                    NM_DEVICE_INTERFACE_DRIVER, "bluez",
	                                    NM_DEVICE_BT_HW_ADDRESS, bdaddr,
	                                    NM_DEVICE_BT_NAME, name,
	                                    NM_DEVICE_BT_CAPABILITIES, capabilities,
	                                    NM_DEVICE_INTERFACE_MANAGED, managed,
	                                    NULL);
}

static guint32
get_connection_bt_type (NMConnection *connection)
{
	NMSettingBluetooth *s_bt;
	const char *bt_type;

	s_bt = (NMSettingBluetooth *) nm_connection_get_setting (connection, NM_TYPE_SETTING_BLUETOOTH);
	if (!s_bt)
		return NM_BT_CAPABILITY_NONE;

	bt_type = nm_setting_bluetooth_get_connection_type (s_bt);
	g_assert (bt_type);

	if (!strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_DUN))
		return NM_BT_CAPABILITY_DUN;
	else if (!strcmp (bt_type, NM_SETTING_BLUETOOTH_TYPE_PANU))
		return NM_BT_CAPABILITY_NAP;

	return NM_BT_CAPABILITY_NONE;
}

static NMConnection *
real_get_best_auto_connection (NMDevice *device,
                               GSList *connections,
                               char **specific_object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;
		guint32 bt_type;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_BLUETOOTH_SETTING_NAME))
			continue;

		bt_type = get_connection_bt_type (connection);
		if (!(bt_type & priv->capabilities))
			continue;

		return connection;
	}
	return NULL;
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_NM_SUPPORTED;
}

/*****************************************************************************/
/* IP method PPP */

static void
ppp_state_changed (NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (status) {
	case NM_PPP_STATUS_NETWORK:
		nm_device_state_changed (device, NM_DEVICE_STATE_IP_CONFIG, NM_DEVICE_STATE_REASON_NONE);
		break;
	case NM_PPP_STATUS_DISCONNECT:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_DISCONNECT);
		break;
	case NM_PPP_STATUS_DEAD:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_PPP_FAILED);
		break;
	case NM_PPP_STATUS_AUTHENTICATE:
		nm_device_state_changed (device, NM_DEVICE_STATE_NEED_AUTH, NM_DEVICE_STATE_REASON_NONE);
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
	NMDevice *device = NM_DEVICE (user_data);

	nm_device_set_ip_iface (device, iface);
	NM_DEVICE_BT_GET_PRIVATE (device)->pending_ip4_config = g_object_ref (config);
	nm_device_activate_schedule_stage4_ip_config_get (device);
}

static void
ppp_stats (NMPPPManager *ppp_manager,
           guint32 in_bytes,
           guint32 out_bytes,
           gpointer user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	if (priv->in_bytes != in_bytes || priv->out_bytes != out_bytes) {
		priv->in_bytes = in_bytes;
		priv->out_bytes = out_bytes;

		g_signal_emit (self, signals[PPP_STATS], 0, in_bytes, out_bytes);
	}
}

static gboolean
get_ppp_credentials (NMConnection *connection,
                     const char **username,
                     const char **password)
{
	NMSettingGsm *s_gsm;
	NMSettingCdma *s_cdma = NULL;

	s_gsm = (NMSettingGsm *) nm_connection_get_setting (connection, NM_TYPE_SETTING_GSM);
	if (s_gsm) {
		if (username)
			*username = nm_setting_gsm_get_username (s_gsm);
		if (password)
			*password = nm_setting_gsm_get_password (s_gsm);
	} else {
		/* Try CDMA then */
		s_cdma = (NMSettingCdma *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CDMA);
		if (s_cdma) {
			if (username)
				*username = nm_setting_cdma_get_username (s_cdma);
			if (password)
				*password = nm_setting_cdma_get_password (s_cdma);
		}
	}

	return (s_cdma || s_gsm) ? TRUE : FALSE;
}


static void
real_connection_secrets_updated (NMDevice *device,
                                 NMConnection *connection,
                                 GSList *updated_settings,
                                 RequestSecretsCaller caller)
{
	NMDeviceBt *self = NM_DEVICE_BT (device);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	NMActRequest *req;
	const char *username = NULL, *password = NULL;
	gboolean success = FALSE;

	if (caller != SECRETS_CALLER_PPP)
		return;

	g_return_if_fail (priv->ppp_manager);

	req = nm_device_get_act_request (device);
	g_assert (req);

	success = get_ppp_credentials (nm_act_request_get_connection (req),
	                               &username,
	                               &password);
	if (success) {
		nm_ppp_manager_update_secrets (priv->ppp_manager,
		                               nm_device_get_ip_iface (device),
		                               username ? username : "",
		                               password ? password : "",
		                               NULL);
		return;
	}

	/* Shouldn't ever happen */
	nm_ppp_manager_update_secrets (priv->ppp_manager,
	                               nm_device_get_ip_iface (device),
	                               NULL,
	                               NULL,
	                               "missing GSM/CDMA setting; no secrets could be found.");
}

static NMActStageReturn
ppp_stage3_start (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceBt *self = NM_DEVICE_BT (device);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	NMActRequest *req;
	const char *ppp_name = NULL;
	GError *err = NULL;
	NMActStageReturn ret;
	gboolean success;

	req = nm_device_get_act_request (device);
	g_assert (req);

	success = get_ppp_credentials (nm_act_request_get_connection (req),
	                               &ppp_name,
	                               NULL);
	if (!success) {
		// FIXME: set reason to something plausible
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	priv->ppp_manager = nm_ppp_manager_new (priv->rfcomm_iface);
	if (nm_ppp_manager_start (priv->ppp_manager, req, ppp_name, &err)) {
		g_signal_connect (priv->ppp_manager, "state-changed",
						  G_CALLBACK (ppp_state_changed),
						  device);
		g_signal_connect (priv->ppp_manager, "ip4-config",
						  G_CALLBACK (ppp_ip4_config),
						  device);
		g_signal_connect (priv->ppp_manager, "stats",
						  G_CALLBACK (ppp_stats),
						  device);

		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		nm_warning ("%s", err->message);
		g_error_free (err);

		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;

		*reason = NM_DEVICE_STATE_REASON_PPP_START_FAILED;
		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	return ret;
}

static NMActStageReturn
ppp_stage4 (NMDevice *device, NMIP4Config **config, NMDeviceStateReason *reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);

	*config = priv->pending_ip4_config;
	priv->pending_ip4_config = NULL;

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

/*****************************************************************************/

static void
nm_device_bt_connect_cb (DBusGProxy       *proxy,
                         DBusGProxyCall   *call_id,
                         void             *user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);
	GError *error = NULL;
	char *device;

	if (dbus_g_proxy_end_call (proxy, call_id, &error,
				   G_TYPE_STRING, &device,
				   G_TYPE_INVALID) == FALSE) {
		nm_warning ("Error connecting with bluez: %s",
		            error && error->message ? error->message : "(unknown)");
		g_clear_error (&error);

		// FIXME: get a better reason code
		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NONE);
		return;
	}

	if (!device || !strlen (device)) {
		nm_warning ("Invalid network device returned by bluez");

		// FIXME: get a better reason code
		nm_device_state_changed (NM_DEVICE (self), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NONE);
	}

	if (priv->bt_type == NM_BT_CAPABILITY_DUN) {
		g_free (priv->rfcomm_iface);
		priv->rfcomm_iface = device;
	} else if (priv->bt_type == NM_BT_CAPABILITY_NAP) {
		nm_device_set_ip_iface (NM_DEVICE (self), device);
		g_free (device);
	}

	nm_device_activate_schedule_stage3_ip_config_start (NM_DEVICE (self));
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMActRequest *req;
	NMDBusManager *dbus_mgr;
	DBusGConnection *g_connection;

	req = nm_device_get_act_request (device);
	g_assert (req);

	priv->bt_type = get_connection_bt_type (nm_act_request_get_connection (req));
	if (priv->bt_type == NM_BT_CAPABILITY_NONE) {
		// FIXME: set a reason code
		return NM_ACT_STAGE_RETURN_FAILURE;
	}

	dbus_mgr = nm_dbus_manager_get ();
	g_connection = nm_dbus_manager_get_connection (dbus_mgr);
	g_object_unref (dbus_mgr);

	if (priv->bt_type == NM_BT_CAPABILITY_DUN) {
		priv->type_proxy = dbus_g_proxy_new_for_name (g_connection,
							      BLUEZ_SERVICE,
							      BLUEZ_SERIAL_INTERFACE,
							      nm_device_get_udi (device));
		if (!priv->type_proxy) {
			// FIXME: set a reason code
			return NM_ACT_STAGE_RETURN_FAILURE;
		}

		dbus_g_proxy_begin_call_with_timeout (priv->type_proxy, "Connect",
		                                      nm_device_bt_connect_cb,
		                                      device,
		                                      NULL,
		                                      20000,
		                                      G_TYPE_STRING, BLUETOOTH_DUN_UUID,
		                                      G_TYPE_INVALID);
	} else if (priv->bt_type == NM_BT_CAPABILITY_NAP) {
		priv->type_proxy = dbus_g_proxy_new_for_name (g_connection,
							      BLUEZ_SERVICE,
							      BLUEZ_NETWORK_INTERFACE,
							      nm_device_get_udi (device));
		if (!priv->type_proxy) {
			// FIXME: set a reason code
			return NM_ACT_STAGE_RETURN_FAILURE;
		}

		dbus_g_proxy_begin_call_with_timeout (priv->type_proxy, "Connect",
		                                      nm_device_bt_connect_cb,
		                                      device,
		                                      NULL,
		                                      20000,
		                                      G_TYPE_STRING, BLUETOOTH_NAP_UUID,
		                                      G_TYPE_INVALID);
	}

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMActStageReturn
real_act_stage3_ip_config_start (NMDevice *device, NMDeviceStateReason *reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMActStageReturn ret;

	if (priv->bt_type == NM_BT_CAPABILITY_DUN)
		ret = ppp_stage3_start (device, reason);
	else
		ret = NM_DEVICE_CLASS (nm_device_bt_parent_class)->act_stage3_ip_config_start (device, reason);

	return ret;
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *device,
                                NMIP4Config **config,
                                NMDeviceStateReason *reason)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);
	NMActStageReturn ret;

	if (priv->bt_type == NM_BT_CAPABILITY_DUN)
		ret = ppp_stage4 (device, config, reason);
	else
		ret = NM_DEVICE_CLASS (nm_device_bt_parent_class)->act_stage4_get_ip4_config (device, config, reason);

	return ret;
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (device);

	if (priv->pending_ip4_config) {
		g_object_unref (priv->pending_ip4_config);
		priv->pending_ip4_config = NULL;
	}

	priv->in_bytes = priv->out_bytes = 0;

	if (priv->bt_type == NM_BT_CAPABILITY_DUN) {
		if (priv->ppp_manager) {
			g_object_unref (priv->ppp_manager);
			priv->ppp_manager = NULL;
		}

		if (priv->type_proxy) {
			/* Don't ever pass NULL through dbus; rfcomm_iface
			 * might happen to be NULL for some reason.
			 */
			if (priv->rfcomm_iface) {
				dbus_g_proxy_call_no_reply (priv->type_proxy, "Disconnect",
				                            G_TYPE_STRING, priv->rfcomm_iface,
				                            G_TYPE_INVALID);
			}
			g_object_unref (priv->type_proxy);
			priv->type_proxy = NULL;
		}
	} else if (priv->bt_type == NM_BT_CAPABILITY_NAP) {
		if (priv->type_proxy) {
			dbus_g_proxy_call_no_reply (priv->type_proxy, "Disconnect",
			                            G_TYPE_INVALID);
			g_object_unref (priv->type_proxy);
			priv->type_proxy = NULL;
		}
	}

	priv->bt_type = NM_BT_CAPABILITY_NONE;

	g_free (priv->rfcomm_iface);
	priv->rfcomm_iface = NULL;

	if (NM_DEVICE_CLASS (nm_device_bt_parent_class)->deactivate_quickly)
		NM_DEVICE_CLASS (nm_device_bt_parent_class)->deactivate_quickly (device);
}

static void
nm_device_bt_init (NMDeviceBt *self)
{
	nm_device_set_device_type (NM_DEVICE (self), NM_DEVICE_TYPE_BT);
}

static gboolean
unavailable_to_disconnected (gpointer user_data)
{
	nm_device_state_changed (NM_DEVICE (user_data),
	                         NM_DEVICE_STATE_DISCONNECTED,
	                         NM_DEVICE_STATE_REASON_NONE);
	return FALSE;
}

static void
device_state_changed (NMDeviceInterface *device,
                      NMDeviceState new_state,
                      NMDeviceState old_state,
                      NMDeviceStateReason reason,
                      gpointer user_data)
{
	NMDeviceBt *self = NM_DEVICE_BT (user_data);
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (self);

	/* Remove any previous delayed transition to disconnected */
	if (priv->state_to_disconnected_id) {
		g_source_remove (priv->state_to_disconnected_id);
		priv->state_to_disconnected_id = 0;
	}

	/* Transition to DISCONNECTED from an idle handler */
	if (new_state == NM_DEVICE_STATE_UNAVAILABLE)
		priv->state_to_disconnected_id = g_idle_add (unavailable_to_disconnected, self);
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;

	object = G_OBJECT_CLASS (nm_device_bt_parent_class)->constructor (type,
	                                                                  n_construct_params,
	                                                                  construct_params);
	if (!object)
		return NULL;

	g_signal_connect (NM_DEVICE (object), "state-changed",
	                  G_CALLBACK (device_state_changed), NM_DEVICE_BT (object));

	return object;
}

static void
set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		/* Construct only */
		priv->bdaddr = g_value_dup_string (value);
		break;
	case PROP_BT_NAME:
		/* Construct only */
		priv->name = g_value_dup_string (value);
		break;
	case PROP_BT_CAPABILITIES:
		/* Construct only */
		priv->capabilities = g_value_get_uint (value);
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
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_HW_ADDRESS:
		g_value_set_string (value, priv->bdaddr);
		break;
	case PROP_BT_NAME:
		g_value_set_string (value, priv->name);
		break;
	case PROP_BT_CAPABILITIES:
		g_value_set_uint (value, priv->capabilities);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMDeviceBtPrivate *priv = NM_DEVICE_BT_GET_PRIVATE (object);

	if (priv->type_proxy)
		g_object_unref (priv->type_proxy);

	g_free (priv->bdaddr);
	g_free (priv->name);

	if (priv->state_to_disconnected_id) {
		g_source_remove (priv->state_to_disconnected_id);
		priv->state_to_disconnected_id = 0;
	}

	G_OBJECT_CLASS (nm_device_bt_parent_class)->finalize (object);
}

static void
nm_device_bt_class_init (NMDeviceBtClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMDeviceBtPrivate));

	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize = finalize;

	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
	device_class->deactivate_quickly = real_deactivate_quickly;
	device_class->act_stage2_config = real_act_stage2_config;
	device_class->act_stage3_ip_config_start = real_act_stage3_ip_config_start;
	device_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_HW_ADDRESS,
		 g_param_spec_string (NM_DEVICE_BT_HW_ADDRESS,
		                      "Bluetooth address",
		                      "Bluetooth address",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_BT_NAME,
		 g_param_spec_string (NM_DEVICE_BT_NAME,
		                      "Bluetooth device name",
		                      "Bluetooth device name",
		                      NULL,
		                      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property
		(object_class, PROP_BT_CAPABILITIES,
		 g_param_spec_uint (NM_DEVICE_BT_CAPABILITIES,
		                    "Bluetooth device capabilities",
		                    "Bluetooth device capabilities",
		                    NM_BT_CAPABILITY_NONE, G_MAXUINT, NM_BT_CAPABILITY_NONE,
		                    G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* Signals */
	signals[PPP_STATS] =
		g_signal_new ("ppp-stats",
		              G_OBJECT_CLASS_TYPE (object_class),
		              G_SIGNAL_RUN_FIRST,
		              G_STRUCT_OFFSET (NMDeviceBtClass, ppp_stats),
		              NULL, NULL,
		              _nm_marshal_VOID__UINT_UINT,
		              G_TYPE_NONE, 2,
		              G_TYPE_UINT, G_TYPE_UINT);

	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class,
		                                  G_STRUCT_OFFSET (NMDeviceBtClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
	                                 &dbus_glib_nm_device_bt_object_info);
}
