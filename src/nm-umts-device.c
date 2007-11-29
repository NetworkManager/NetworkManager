/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#include "nm-umts-device.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-setting-umts.h"
#include "nm-utils.h"

G_DEFINE_TYPE (NMUmtsDevice, nm_umts_device, NM_TYPE_SERIAL_DEVICE)

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
		nm_warning ("Manual registration timed out");
		break;
	default:
		nm_warning ("Manual registration failed");
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
		nm_info ("Associated with network: %s\n", response);
	else
		nm_warning ("Couldn't read active network name");

	do_dial (device);
}

static void
automatic_registration_get_network (NMSerialDevice *device)
{
	char terminators[] = { '\r', '\n', '\0' };

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
	switch (reply_index) {
	case 0:
		do_register (device);
		break;
	case -1:
		nm_warning ("Did not receive response for entered PIN");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		break;
	default:
		nm_warning ("Invalid PIN");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		break;
	}
}

static void
enter_pin (NMSerialDevice *device)
{
	NMSettingUmts *setting;
	char *command;
	char *responses[] = { "OK", "ERROR", "ERR", NULL };

	setting = NM_SETTING_UMTS (umts_device_get_setting (NM_UMTS_DEVICE (device), NM_TYPE_SETTING_UMTS));

	if (!setting->pin) {
		/* FIXME: Ask PIN */
		nm_warning ("PIN required but not provided");
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		return;
	}

	command = g_strdup_printf ("AT+CPIN=\"%s\"", setting->pin);
	nm_serial_device_send_command_string (device, command);
	g_free (command);

	nm_serial_device_wait_for_reply (device, 3, responses, enter_pin_done, NULL);
}

static void
enter_puk (NMSerialDevice *device)
{
	/* FIXME */
	nm_warning ("PUK entering not implemented at the moment");
	nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
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
		enter_pin (device);
		break;
	case 2:
		enter_puk (device);
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

	if (!nm_serial_device_open (NM_SERIAL_DEVICE (device)))
		return NM_ACT_STAGE_RETURN_FAILURE;

	nm_serial_device_send_command_string (serial_device, "ATZ");
	nm_serial_device_wait_for_reply (serial_device, 3, responses, init_done, NULL);

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

/*****************************************************************************/

static void
nm_umts_device_init (NMUmtsDevice *self)
{
	nm_device_set_device_type (NM_DEVICE (self), DEVICE_TYPE_UMTS);
}

static void
nm_umts_device_class_init (NMUmtsDeviceClass *klass)
{
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->check_connection = real_check_connection;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
}
