/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include <string.h>
#include "nm-umts-device.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-setting-umts.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMUmtsDevice, nm_umts_device, NM_TYPE_SERIAL_DEVICE)

typedef enum {
	NM_UMTS_SECRET_NONE = 0,
	NM_UMTS_SECRET_PIN,
	NM_UMTS_SECRET_PUK
} NMUmtsSecret;

#define NM_UMTS_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_UMTS_DEVICE, NMUmtsDevicePrivate))

typedef struct {
	NMUmtsSecret need_secret;
} NMUmtsDevicePrivate;


static void enter_pin (NMSerialDevice *device, gboolean retry);

NMUmtsDevice *
nm_umts_device_new (const char *udi,
				const char *iface,
				const char *driver)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMUmtsDevice *) g_object_new (NM_TYPE_UMTS_DEVICE,
								   NM_DEVICE_INTERFACE_UDI, udi,
								   NM_DEVICE_INTERFACE_IFACE, iface,
								   NM_DEVICE_INTERFACE_DRIVER, driver,
								   NULL);
}

static NMSetting *
umts_device_get_setting (NMUmtsDevice *device, GType setting_type)
{
	NMActRequest *req;
	NMSetting *setting = NULL;

	req = nm_device_get_act_request (NM_DEVICE (device));
	if (req) {
		NMConnection *connection;

		connection = nm_act_request_get_connection (req);
		if (connection)
			setting = nm_connection_get_setting (connection, setting_type);
	}

	return setting;
}

static void
dial_done (NMSerialDevice *device,
		 int reply_index,
		 gpointer user_data)
{
	gboolean success = FALSE;

	switch (reply_index) {
	case 0:
		nm_info ("Connected, Woo!");
		success = TRUE;
		break;
	case 1:
		nm_info ("Busy");
		break;
	case 2:
		nm_warning ("No dial tone");
		break;
	case 3:
		nm_warning ("No carrier");
		break;
	case -1:
		nm_warning ("Dialing timed out");
		break;
	default:
		nm_warning ("Dialing failed");
		break;
	}

	if (success)
		nm_device_activate_schedule_stage2_device_config (NM_DEVICE (device));
	else
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
}

static void
do_dial (NMSerialDevice *device)
{
	NMSettingUmts *setting;
	char *command;
	char *responses[] = { "CONNECT", "BUSY", "NO DIAL TONE", "NO CARRIER", NULL };

	setting = NM_SETTING_UMTS (umts_device_get_setting (NM_UMTS_DEVICE (device), NM_TYPE_SETTING_UMTS));

	command = g_strconcat ("ATDT", setting->number, NULL);
	nm_serial_device_send_command_string (device, command);
	g_free (command);

	nm_serial_device_wait_for_reply (device, 60, responses, dial_done, NULL);
}

static void
manual_registration_done (NMSerialDevice *device,
					 int reply_index,
					 gpointer user_data)
{
	switch (reply_index) {
	case 0:
		do_dial (device);
		break;
	case -1:
		nm_warning ("Manual registration timed out");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		break;
	default:
		nm_warning ("Manual registration failed");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		break;
	}
}

static void
manual_registration (NMSerialDevice *device)
{
	NMSettingUmts *setting;
	char *command;
	char *responses[] = { "OK", "ERROR", "ERR", NULL };

	setting = NM_SETTING_UMTS (umts_device_get_setting (NM_UMTS_DEVICE (device), NM_TYPE_SETTING_UMTS));

	command = g_strdup_printf ("AT+COPS=1,2,\"%s\"", setting->network_id);
	nm_serial_device_send_command_string (device, command);
	g_free (command);

	nm_serial_device_wait_for_reply (device, 30, responses, manual_registration_done, NULL);
}

static void
get_network_done (NMSerialDevice *device,
			   const char *response,
			   gpointer user_data)
{
	if (response)
		nm_info ("Associated with network: %s", response);
	else
		nm_warning ("Couldn't read active network name");

	do_dial (device);
}

static void
automatic_registration_get_network (NMSerialDevice *device)
{
	const char terminators[] = { '\r', '\n', '\0' };

	nm_serial_device_send_command_string (device, "AT+COPS?");
	nm_serial_device_get_reply (device, 10, terminators, get_network_done, NULL);
}

static void
automatic_registration_response (NMSerialDevice *device,
						   int reply_index,
						   gpointer user_data)
{
	switch (reply_index) {
	case 0:
		nm_info ("Registered on Home network");
		automatic_registration_get_network (device);
		break;
	case 1:
		nm_info ("Registered on Roaming network");
		automatic_registration_get_network (device);
		break;
	case -1:
		nm_warning ("Automatic registration timed out");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		break;
	default:
		nm_warning ("Automatic registration failed");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		break;
	}
}

static void
automatic_registration (NMSerialDevice *device)
{
	char *responses[] = { "+CREG: 0,1", "+CREG: 0,5", NULL };

	nm_serial_device_send_command_string (device, "AT+CREG?");
	nm_serial_device_wait_for_reply (device, 60, responses, automatic_registration_response, NULL);
}

static void
do_register (NMSerialDevice *device)
{
	NMSettingUmts *setting;

	setting = NM_SETTING_UMTS (umts_device_get_setting (NM_UMTS_DEVICE (device), NM_TYPE_SETTING_UMTS));

	if (setting->network_id)
		manual_registration (device);
	else
		automatic_registration (device);
}

static void
enter_pin_done (NMSerialDevice *device,
			 int reply_index,
			 gpointer user_data)
{
	NMSettingUmts *setting;
	
	switch (reply_index) {
	case 0:
		do_register (device);
		break;
	case -1:
		nm_warning ("Did not receive response for secret");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		break;
	default:
		nm_warning ("Invalid secret");
		setting = NM_SETTING_UMTS (umts_device_get_setting (NM_UMTS_DEVICE (device), NM_TYPE_SETTING_UMTS));

		/* Make sure we don't use the invalid PIN/PUK again
		    as it may lock up the SIM card */

		switch (NM_UMTS_DEVICE_GET_PRIVATE (device)->need_secret) {
		case NM_UMTS_SECRET_PIN:
			g_free (setting->pin);
			setting->pin = NULL;
			break;
		case NM_UMTS_SECRET_PUK:
			g_free (setting->puk);
			setting->puk = NULL;
			break;
		default:
			break;
		}

		enter_pin (device, TRUE);
		break;
	}
}

static void
enter_pin (NMSerialDevice *device, gboolean retry)
{
	NMSettingUmts *setting;
	NMActRequest *req;
	NMConnection *connection;
	char *secret;
	char *secret_setting_name;

	req = nm_device_get_act_request (NM_DEVICE (device));
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	setting = NM_SETTING_UMTS (nm_connection_get_setting (connection, NM_TYPE_SETTING_UMTS));

	switch (NM_UMTS_DEVICE_GET_PRIVATE (device)->need_secret) {
	case NM_UMTS_SECRET_PIN:
		secret = setting->pin;
		secret_setting_name = NM_SETTING_UMTS_PIN;
		break;
	case NM_UMTS_SECRET_PUK:
		secret = setting->puk;
		secret_setting_name = NM_SETTING_UMTS_PIN;
		break;
	default:
		do_register (device);
		return;
	}

	if (secret) {
		char *command;
		char *responses[] = { "OK", "ERROR", "ERR", NULL };

		command = g_strdup_printf ("AT+CPIN=\"%s\"", secret);
		nm_serial_device_send_command_string (device, command);
		g_free (command);

		nm_serial_device_wait_for_reply (device, 3, responses, enter_pin_done, NULL);
	} else {
		nm_info ("%s required", secret_setting_name);
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_NEED_AUTH);
		nm_act_request_request_connection_secrets (req, secret_setting_name, retry);
	}
}

static void
check_pin_done (NMSerialDevice *device,
			 int reply_index,
			 gpointer user_data)
{
	switch (reply_index) {
	case 0:
		do_register (device);
		break;
	case 1:
		NM_UMTS_DEVICE_GET_PRIVATE (device)->need_secret = NM_UMTS_SECRET_PIN;
		enter_pin (device, FALSE);
		break;
	case 2:
		NM_UMTS_DEVICE_GET_PRIVATE (device)->need_secret = NM_UMTS_SECRET_PUK;
		enter_pin (device, FALSE);
		break;
	case -1:
		nm_warning ("PIN checking timed out");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		break;
	default:
		nm_warning ("PIN checking failed");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		return;
	}
}

static void
check_pin (NMSerialDevice *device)
{
	char *responses[] = { "READY", "SIM PIN", "SIM PUK", "ERROR", "ERR", NULL };

	nm_serial_device_send_command_string (device, "AT+CPIN?");
	nm_serial_device_wait_for_reply (device, 3, responses, check_pin_done, NULL);
}

static void
init_done (NMSerialDevice *device,
		 int reply_index,
		 gpointer user_data)
{
	switch (reply_index) {
	case 0:
		check_pin (device);
		break;
	case -1:
		nm_warning ("Modem initialization timed out");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		break;
	default:
		nm_warning ("Modem initialization failed");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		return;
	}
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *device)
{
	NMSerialDevice *serial_device = NM_SERIAL_DEVICE (device);
	char *responses[] = { "OK", "ERR", NULL };

	NM_UMTS_DEVICE_GET_PRIVATE (serial_device)->need_secret = NM_UMTS_SECRET_NONE;

	if (!nm_serial_device_open (NM_SERIAL_DEVICE (device)))
		return NM_ACT_STAGE_RETURN_FAILURE;

	nm_serial_device_send_command_string (serial_device, "ATZ E0");
	nm_serial_device_wait_for_reply (serial_device, 10, responses, init_done, NULL);

	return NM_ACT_STAGE_RETURN_POSTPONE;
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_NM_SUPPORTED;
}

static gboolean
real_check_connection (NMDevice *dev, NMConnection *connection)
{
	NMSettingUmts *umts;

	umts = (NMSettingUmts *) nm_connection_get_setting (connection, NM_TYPE_SETTING_UMTS);
	if (!umts) {
		nm_warning ("Connection check failed: umts setting not present.");
		return FALSE;
	}

	if (!umts->number) {
		nm_warning ("Connection check failed: Phone number not set.");
		return FALSE;
	}

	return NM_DEVICE_CLASS (nm_umts_device_parent_class)->check_connection (dev, connection);
}

static void
real_connection_secrets_updated (NMDevice *dev,
                                 NMConnection *connection,
                                 const char *setting_name)
{
	NMActRequest *req;

	if (nm_device_get_state (dev) != NM_DEVICE_STATE_NEED_AUTH)
		return;

	if (strcmp (setting_name, NM_SETTING_UMTS_SETTING_NAME) != 0) {
		nm_warning ("Ignoring updated secrets for setting '%s'.", setting_name);
		return;
	}

	req = nm_device_get_act_request (dev);
	g_assert (req);

	g_return_if_fail (nm_act_request_get_connection (req) == connection);

	nm_device_activate_schedule_stage1_device_prepare (dev);
}

/*****************************************************************************/

static void
nm_umts_device_init (NMUmtsDevice *self)
{
	nm_device_set_device_type (NM_DEVICE (self), DEVICE_TYPE_UMTS);
}

static void
nm_umts_device_class_init (NMUmtsDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMUmtsDevicePrivate));

	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->check_connection = real_check_connection;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
}
