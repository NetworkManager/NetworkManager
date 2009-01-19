/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <string.h>

#include "nm-modem-cdma.h"
#include "nm-modem-types.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-dbus-manager.h"
#include "nm-setting-connection.h"
#include "nm-setting-cdma.h"
#include "nm-utils.h"

#include "nm-device-cdma-glue.h"

G_DEFINE_TYPE (NMModemCdma, nm_modem_cdma, NM_TYPE_MODEM)

#define NM_MODEM_CDMA_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_MODEM_CDMA, NMModemCdmaPrivate))

enum {
	MODEM_STATE_BEGIN,
	MODEM_STATE_ENABLE,
	MODEM_STATE_CONNECT
};

typedef struct {
	int modem_state;
} NMModemCdmaPrivate;

enum {
	SIGNAL_QUALITY,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

NMDevice *
nm_modem_cdma_new (const char *path,
				   const char *data_device,
				   const char *driver)
{
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (data_device != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_MODEM_CDMA,
									  NM_DEVICE_INTERFACE_UDI, path,
									  NM_DEVICE_INTERFACE_IFACE, data_device,
									  NM_DEVICE_INTERFACE_DRIVER, driver,
									  NM_DEVICE_INTERFACE_MANAGED, TRUE,
									  NM_MODEM_PATH, path,
									  NULL);
}

static NMSetting *
get_setting (NMModemCdma *self, GType setting_type)
{
	NMActRequest *req;
	NMSetting *setting = NULL;

	req = nm_device_get_act_request (NM_DEVICE (self));
	if (req) {
		NMConnection *connection;

		connection = nm_act_request_get_connection (req);
		if (connection)
			setting = nm_connection_get_setting (connection, setting_type);
	}

	return setting;
}

static void
state_machine (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMModemCdma *modem = NM_MODEM_CDMA (user_data);
	NMModemCdmaPrivate *priv = NM_MODEM_CDMA_GET_PRIVATE (modem);
	NMSettingCdma *setting;
	GError *error = NULL;

	setting = NM_SETTING_CDMA (get_setting (modem, NM_TYPE_SETTING_CDMA));

	if (call_id)
		dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID);

	if (error) {
		nm_warning ("CDMA modem connection failed: %s", error->message);
		nm_device_state_changed (NM_DEVICE (modem), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NONE);
		return;
	}

	switch (priv->modem_state) {
	case MODEM_STATE_BEGIN:
		priv->modem_state = MODEM_STATE_ENABLE;
		dbus_g_proxy_begin_call (nm_modem_get_proxy (NM_MODEM (modem), NULL),
								 "Enable", state_machine,
								 modem, NULL,
								 G_TYPE_BOOLEAN, TRUE,
								 G_TYPE_INVALID);
		break;
	case MODEM_STATE_ENABLE:
		priv->modem_state = MODEM_STATE_CONNECT;
		dbus_g_proxy_begin_call (nm_modem_get_proxy (NM_MODEM (modem), NULL),
								 "Connect", state_machine,
								 modem, NULL,
								 G_TYPE_STRING, nm_setting_cdma_get_number (setting),
								 G_TYPE_INVALID);
		break;
	case MODEM_STATE_CONNECT:
		nm_device_activate_schedule_stage2_device_config (NM_DEVICE (modem));
		break;
	default:
		nm_warning ("Invalid modem state %d", priv->modem_state);
		nm_device_state_changed (NM_DEVICE (modem), NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NONE);
		break;
	}
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMModemCdmaPrivate *priv = NM_MODEM_CDMA_GET_PRIVATE (device);

	priv->modem_state = MODEM_STATE_BEGIN;
	state_machine (NULL, NULL, device);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static NMConnection *
real_get_best_auto_connection (NMDevice *dev,
							   GSList *connections,
							   char **specific_object)
{
	GSList *iter;

	for (iter = connections; iter; iter = g_slist_next (iter)) {
		NMConnection *connection = NM_CONNECTION (iter->data);
		NMSettingConnection *s_con;

		s_con = (NMSettingConnection *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION);
		g_assert (s_con);

		if (!nm_setting_connection_get_autoconnect (s_con))
			continue;

		if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_CDMA_SETTING_NAME))
			continue;

		return connection;
	}
	return NULL;
}

static void
real_connection_secrets_updated (NMDevice *dev,
								 NMConnection *connection,
								 GSList *updated_settings,
								 RequestSecretsCaller caller)
{
	NMActRequest *req;
	gboolean found = FALSE;
	GSList *iter;

	if (caller == SECRETS_CALLER_PPP) {
		NMPPPManager *ppp_manager;
		NMSettingCdma *s_cdma = NULL;

		ppp_manager = nm_modem_get_ppp_manager (NM_MODEM (dev));
		g_return_if_fail (ppp_manager != NULL);

		s_cdma = (NMSettingCdma *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CDMA);
		if (!s_cdma) {
			/* Shouldn't ever happen */
			nm_ppp_manager_update_secrets (ppp_manager,
										   nm_device_get_iface (dev),
										   NULL,
										   NULL,
										   "missing CDMA setting; no secrets could be found.");
		} else {
			const char *username = nm_setting_cdma_get_username (s_cdma);
			const char *password = nm_setting_cdma_get_password (s_cdma);

			nm_ppp_manager_update_secrets (ppp_manager,
										   nm_device_get_iface (dev),
										   username ? username : "",
										   password ? password : "",
										   NULL);
		}
		return;
	}

	g_return_if_fail (caller == SECRETS_CALLER_CDMA);
	g_return_if_fail (nm_device_get_state (dev) == NM_DEVICE_STATE_NEED_AUTH);

	for (iter = updated_settings; iter; iter = g_slist_next (iter)) {
		const char *setting_name = (const char *) iter->data;

		if (!strcmp (setting_name, NM_SETTING_CDMA_SETTING_NAME))
			found = TRUE;
		else
			nm_warning ("Ignoring updated secrets for setting '%s'.", setting_name);
	}

	if (!found)
		return;

	req = nm_device_get_act_request (dev);
	g_assert (req);

	g_return_if_fail (nm_act_request_get_connection (req) == connection);

	nm_device_activate_schedule_stage1_device_prepare (dev);
}

static const char *
real_get_ppp_name (NMModem *device, NMConnection *connection)
{
	NMSettingCdma *s_cdma;

	s_cdma = (NMSettingCdma *) nm_connection_get_setting (connection, NM_TYPE_SETTING_CDMA);
	g_assert (s_cdma);

	return nm_setting_cdma_get_username (s_cdma);
}

/*****************************************************************************/

static void
nm_modem_cdma_init (NMModemCdma *self)
{
	nm_device_set_device_type (NM_DEVICE (self), NM_DEVICE_TYPE_CDMA);
}

static void
nm_modem_cdma_class_init (NMModemCdmaClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMModemCdmaPrivate));

	/* Virtual methods */
	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
	modem_class->get_ppp_name = real_get_ppp_name;

	/* Signals */
	signals[SIGNAL_QUALITY] =
		g_signal_new ("signal-quality",
					  G_OBJECT_CLASS_TYPE (object_class),
					  G_SIGNAL_RUN_FIRST,
					  G_STRUCT_OFFSET (NMModemCdmaClass, signal_quality),
					  NULL, NULL,
					  g_cclosure_marshal_VOID__UINT,
					  G_TYPE_NONE, 1,
					  G_TYPE_UINT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_device_cdma_object_info);
}
