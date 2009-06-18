/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <string.h>

#include "nm-dbus-glib-types.h"
#include "nm-modem-cdma.h"
#include "nm-modem-types.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-dbus-manager.h"
#include "nm-setting-connection.h"
#include "nm-setting-cdma.h"
#include "nm-utils.h"
#include "NetworkManagerUtils.h"

#include "nm-device-cdma-glue.h"

G_DEFINE_TYPE (NMModemCdma, nm_modem_cdma, NM_TYPE_MODEM)


typedef enum {
	NM_CDMA_ERROR_CONNECTION_NOT_CDMA = 0,
	NM_CDMA_ERROR_CONNECTION_INVALID,
	NM_CDMA_ERROR_CONNECTION_INCOMPATIBLE,
} NMCdmaError;

#define NM_CDMA_ERROR (nm_cdma_error_quark ())
#define NM_TYPE_CDMA_ERROR (nm_cdma_error_get_type ())

static GQuark
nm_cdma_error_quark (void)
{
	static GQuark quark = 0;
	if (!quark)
		quark = g_quark_from_static_string ("nm-cdma-error");
	return quark;
}

/* This should really be standard. */
#define ENUM_ENTRY(NAME, DESC) { NAME, "" #NAME "", DESC }

static GType
nm_cdma_error_get_type (void)
{
	static GType etype = 0;

	if (etype == 0) {
		static const GEnumValue values[] = {
			/* Connection was not a CDMA connection. */
			ENUM_ENTRY (NM_CDMA_ERROR_CONNECTION_NOT_CDMA, "ConnectionNotCdma"),
			/* Connection was not a valid CDMA connection. */
			ENUM_ENTRY (NM_CDMA_ERROR_CONNECTION_INVALID, "ConnectionInvalid"),
			/* Connection does not apply to this device. */
			ENUM_ENTRY (NM_CDMA_ERROR_CONNECTION_INCOMPATIBLE, "ConnectionIncompatible"),
			{ 0, 0, 0 }
		};
		etype = g_enum_register_static ("NMCdmaError", values);
	}
	return etype;
}


NMDevice *
nm_modem_cdma_new (const char *path,
                   const char *device,
                   const char *data_device,
                   const char *driver)
{
	g_return_val_if_fail (path != NULL, NULL);
	g_return_val_if_fail (device != NULL, NULL);
	g_return_val_if_fail (data_device != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMDevice *) g_object_new (NM_TYPE_MODEM_CDMA,
									  NM_DEVICE_INTERFACE_UDI, path,
									  NM_DEVICE_INTERFACE_IFACE, data_device,
									  NM_DEVICE_INTERFACE_DRIVER, driver,
									  NM_DEVICE_INTERFACE_MANAGED, TRUE,
									  NM_MODEM_PATH, path,
									  NM_MODEM_DEVICE, device,
									  NULL);
}

static void
stage1_prepare_done (DBusGProxy *proxy, DBusGProxyCall *call_id, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);
	GError *error = NULL;

	dbus_g_proxy_end_call (proxy, call_id, &error, G_TYPE_INVALID);
	if (!error)
		nm_device_activate_schedule_stage2_device_config (device);
	else {
		nm_warning ("CDMA modem connection failed: %s", error->message);
		g_error_free (error);
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED, NM_DEVICE_STATE_REASON_NONE);
	}
}

static GHashTable *
create_connect_properties (NMConnection *connection)
{
	NMSettingCdma *setting;
	GHashTable *properties;
	const char *str;

	setting = NM_SETTING_CDMA (nm_connection_get_setting (connection, NM_TYPE_SETTING_CDMA));
	properties = value_hash_create ();

	str = nm_setting_cdma_get_number (setting);
	if (str)
		value_hash_add_str (properties, "number", str);

	return properties;
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *device, NMDeviceStateReason *reason)
{
	NMConnection *connection;
	GHashTable *properties;

	connection = nm_act_request_get_connection (nm_device_get_act_request (device));
	g_assert (connection);

	properties = create_connect_properties (connection);
	dbus_g_proxy_begin_call_with_timeout (nm_modem_get_proxy (NM_MODEM (device), MM_DBUS_INTERFACE_MODEM_SIMPLE),
										  "Connect", stage1_prepare_done,
										  device, NULL, 120000,
										  DBUS_TYPE_G_MAP_OF_VARIANT, properties,
										  G_TYPE_INVALID);

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

static gboolean
real_check_connection_compatible (NMDevice *device,
                                  NMConnection *connection,
                                  GError **error)
{
	NMSettingConnection *s_con;
	NMSettingCdma *s_cdma;

	s_con = NM_SETTING_CONNECTION (nm_connection_get_setting (connection, NM_TYPE_SETTING_CONNECTION));
	g_assert (s_con);

	if (strcmp (nm_setting_connection_get_connection_type (s_con), NM_SETTING_CDMA_SETTING_NAME)) {
		g_set_error (error,
		             NM_CDMA_ERROR, NM_CDMA_ERROR_CONNECTION_NOT_CDMA,
		             "The connection was not a CDMA connection.");
		return FALSE;
	}

	s_cdma = NM_SETTING_CDMA (nm_connection_get_setting (connection, NM_TYPE_SETTING_CDMA));
	if (!s_cdma) {
		g_set_error (error,
		             NM_CDMA_ERROR, NM_CDMA_ERROR_CONNECTION_INVALID,
		             "The connection was not a valid CDMA connection.");
		return FALSE;
	}

	return TRUE;
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
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);
	NMModemClass *modem_class = NM_MODEM_CLASS (klass);

	/* Virtual methods */
	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
	device_class->check_connection_compatible = real_check_connection_compatible;

	modem_class->get_ppp_name = real_get_ppp_name;

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
	                                 &dbus_glib_nm_device_cdma_object_info);

	dbus_g_error_domain_register (NM_CDMA_ERROR, NULL, NM_TYPE_CDMA_ERROR);
}
