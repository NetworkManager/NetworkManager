/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#include <stdio.h>
#include <string.h>
#include "nm-cdma-device.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "nm-setting-cdma.h"
#include "nm-utils.h"
#include "nm-properties-changed-signal.h"
#include "nm-cdma-device-glue.h"
#include "nm-setting-connection.h"

G_DEFINE_TYPE (NMCdmaDevice, nm_cdma_device, NM_TYPE_SERIAL_DEVICE)

#define NM_CDMA_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_CDMA_DEVICE, NMCdmaDevicePrivate))

typedef struct {
	char *monitor_iface;
	NMSerialDevice *monitor_device;

	guint pending_id;
	guint state_to_disconnected_id;
} NMCdmaDevicePrivate;

enum {
	PROP_0,
	PROP_MONITOR_IFACE,

	LAST_PROP
};

enum {
	PROPERTIES_CHANGED,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };


NMCdmaDevice *
nm_cdma_device_new (const char *udi,
                    const char *data_iface,
                    const char *monitor_iface,
                    const char *driver,
                    gboolean managed)
{
	g_return_val_if_fail (udi != NULL, NULL);
	g_return_val_if_fail (data_iface != NULL, NULL);
	g_return_val_if_fail (driver != NULL, NULL);

	return (NMCdmaDevice *) g_object_new (NM_TYPE_CDMA_DEVICE,
	                                      NM_DEVICE_INTERFACE_UDI, udi,
	                                      NM_DEVICE_INTERFACE_IFACE, data_iface,
	                                      NM_DEVICE_INTERFACE_DRIVER, driver,
	                                      NM_CDMA_DEVICE_MONITOR_IFACE, monitor_iface,
										  NM_DEVICE_INTERFACE_MANAGED, managed,
	                                      NULL);
}

static inline void
cdma_device_set_pending (NMCdmaDevice *device, guint pending_id)
{
	NM_CDMA_DEVICE_GET_PRIVATE (device)->pending_id = pending_id;
}

static NMSetting *
cdma_device_get_setting (NMCdmaDevice *device, GType setting_type)
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

	cdma_device_set_pending (NM_CDMA_DEVICE (device), 0);

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
	NMSettingCdma *setting;
	char *command;
	guint id;
	char *responses[] = { "CONNECT", "BUSY", "NO DIAL TONE", "NO CARRIER", NULL };
	gboolean success;

	setting = NM_SETTING_CDMA (cdma_device_get_setting (NM_CDMA_DEVICE (device), NM_TYPE_SETTING_CDMA));

	command = g_strconcat ("ATDT", setting->number, NULL);
	success = nm_serial_device_send_command_string (device, command);
	g_free (command);

	if (success) {
		id = nm_serial_device_wait_for_reply (device, 60, responses, responses, dial_done, NULL);
		if (id)
			cdma_device_set_pending (NM_CDMA_DEVICE (device), id);
		else
			nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
	} else {
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
	}
}

static void
init_done (NMSerialDevice *device,
		 int reply_index,
		 gpointer user_data)
{
	cdma_device_set_pending (NM_CDMA_DEVICE (device), 0);

	switch (reply_index) {
	case 0:
		do_dial (device);
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

static void
init_modem (NMSerialDevice *device, gpointer user_data)
{
	guint id;
	char *responses[] = { "OK", "ERROR", "ERR", NULL };

	if (!nm_serial_device_send_command_string (device, "ATZ E0")) {
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
		return;
	}

	id = nm_serial_device_wait_for_reply (device, 10, responses, responses, init_done, NULL);

	if (id)
		cdma_device_set_pending (NM_CDMA_DEVICE (device), id);
	else
		nm_device_state_changed (NM_DEVICE (device), NM_DEVICE_STATE_FAILED);
}

static NMActStageReturn
real_act_stage1_prepare (NMDevice *device)
{
	NMCdmaDevicePrivate *priv = NM_CDMA_DEVICE_GET_PRIVATE (device);
	NMSerialDevice *serial_device = NM_SERIAL_DEVICE (device);
	NMSettingSerial *setting;

	setting = NM_SETTING_SERIAL (cdma_device_get_setting (NM_CDMA_DEVICE (device), NM_TYPE_SETTING_SERIAL));

	if (!nm_serial_device_open (serial_device, setting))
		return NM_ACT_STAGE_RETURN_FAILURE;

	priv->pending_id = nm_serial_device_flash (serial_device, 100, init_modem, NULL);

	return priv->pending_id ? NM_ACT_STAGE_RETURN_POSTPONE : NM_ACT_STAGE_RETURN_FAILURE;
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

		if (!s_con->autoconnect)
			continue;

		if (strcmp (s_con->type, NM_SETTING_CDMA_SETTING_NAME))
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

static void
real_connection_secrets_updated (NMDevice *dev,
                                 NMConnection *connection,
                                 GSList *updated_settings)
{
	NMActRequest *req;
	gboolean found = FALSE;
	GSList *iter;

	if (nm_device_get_state (dev) != NM_DEVICE_STATE_NEED_AUTH)
		return;

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

static void
real_deactivate_quickly (NMDevice *device)
{
	NMCdmaDevicePrivate *priv = NM_CDMA_DEVICE_GET_PRIVATE (device);

	if (priv->pending_id) {
		g_source_remove (priv->pending_id);
		priv->pending_id = 0;
	}

	NM_DEVICE_CLASS (nm_cdma_device_parent_class)->deactivate_quickly (device);
}

/*****************************************************************************/
/* Monitor device handling */

static gboolean
monitor_device_got_data (GIOChannel *source,
					GIOCondition condition,
					gpointer data)
{
	gsize bytes_read;
	char buf[4096];
	GIOStatus status;

	if (condition & G_IO_IN) {
		do {
			status = g_io_channel_read_chars (source, buf, 4096, &bytes_read, NULL);

			if (bytes_read) {
				buf[bytes_read] = '\0';
				/* Do nothing with the data for now */
				nm_debug ("Monitor got unhandled data: '%s'", buf);
			}
		} while (bytes_read == 4096 || status == G_IO_STATUS_AGAIN);
	}

	if (condition & G_IO_HUP || condition & G_IO_ERR) {
		return FALSE;
	}

	return TRUE;
}

static gboolean
setup_monitor_device (NMCdmaDevice *device)
{
	NMCdmaDevicePrivate *priv = NM_CDMA_DEVICE_GET_PRIVATE (device);
	GIOChannel *channel;
	NMSettingSerial *setting;

	if (!priv->monitor_iface) {
		nm_debug ("No monitoring udi provided");
		return FALSE;
	}

	priv->monitor_device = g_object_new (NM_TYPE_SERIAL_DEVICE,
	                                     NM_DEVICE_INTERFACE_UDI, nm_device_get_udi (NM_DEVICE (device)),
	                                     NM_DEVICE_INTERFACE_IFACE, priv->monitor_iface,
	                                     NULL);

	if (!priv->monitor_device) {
		nm_warning ("Creation of the monitoring device failed");
		return FALSE;
	}

	setting = NM_SETTING_SERIAL (nm_setting_serial_new ());
	if (!nm_serial_device_open (priv->monitor_device, setting)) {
		nm_warning ("Monitoring device open failed");
		g_object_unref (setting);
		g_object_unref (priv->monitor_device);
		return FALSE;
	}

	g_object_unref (setting);

	channel = nm_serial_device_get_io_channel (priv->monitor_device);
	g_io_add_watch (channel, G_IO_IN | G_IO_ERR | G_IO_HUP,
				 monitor_device_got_data, device);

	g_io_channel_unref (channel);

	return TRUE;
}

/*****************************************************************************/

static void
nm_cdma_device_init (NMCdmaDevice *self)
{
	nm_device_set_device_type (NM_DEVICE (self), DEVICE_TYPE_CDMA);
}

static gboolean
unavailable_to_disconnected (gpointer user_data)
{
	nm_device_state_changed (NM_DEVICE (user_data), NM_DEVICE_STATE_DISCONNECTED);
	return FALSE;
}

static void
device_state_changed (NMDeviceInterface *device, NMDeviceState state, gpointer user_data)
{
	NMCdmaDevice *self = NM_CDMA_DEVICE (user_data);
	NMCdmaDevicePrivate *priv = NM_CDMA_DEVICE_GET_PRIVATE (self);

	/* Remove any previous delayed transition to disconnected */
	if (priv->state_to_disconnected_id) {
		g_source_remove (priv->state_to_disconnected_id);
		priv->state_to_disconnected_id = 0;
	}

	/* If transitioning to UNAVAILBLE and we have a carrier, transition to
	 * DISCONNECTED because the device is ready to use.  Otherwise the carrier-on
	 * handler will handle the transition to DISCONNECTED when the carrier is detected.
	 */
	if (state == NM_DEVICE_STATE_UNAVAILABLE)
		priv->state_to_disconnected_id = g_idle_add (unavailable_to_disconnected, self);
}

static GObject*
constructor (GType type,
             guint n_construct_params,
             GObjectConstructParam *construct_params)
{
	GObject *object;

	object = G_OBJECT_CLASS (nm_cdma_device_parent_class)->constructor (type,
														  n_construct_params,
														  construct_params);
	if (!object)
		return NULL;

	/* FIXME: Make the monitor device not required for now */
	setup_monitor_device (NM_CDMA_DEVICE (object));
#if 0
	if (!setup_monitor_device (NM_CDMA_DEVICE (object))) {
		g_object_unref (object);
		object = NULL;
	}
#endif

	g_signal_connect (NM_DEVICE (object), "state-changed",
	                  G_CALLBACK (device_state_changed), NM_CDMA_DEVICE (object));

	return object;
}

static void
set_property (GObject *object, guint prop_id,
		    const GValue *value, GParamSpec *pspec)
{
	NMCdmaDevicePrivate *priv = NM_CDMA_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MONITOR_IFACE:
		/* Construct only */
		priv->monitor_iface = g_value_dup_string (value);
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
	NMCdmaDevicePrivate *priv = NM_CDMA_DEVICE_GET_PRIVATE (object);

	switch (prop_id) {
	case PROP_MONITOR_IFACE:
		g_value_set_string (value, priv->monitor_iface);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
finalize (GObject *object)
{
	NMCdmaDevicePrivate *priv = NM_CDMA_DEVICE_GET_PRIVATE (object);

	if (priv->monitor_device)
		g_object_unref (priv->monitor_device);

	g_free (priv->monitor_iface);

	if (priv->state_to_disconnected_id) {
		g_source_remove (priv->state_to_disconnected_id);
		priv->state_to_disconnected_id = 0;
	}

	G_OBJECT_CLASS (nm_cdma_device_parent_class)->finalize (object);
}

static void
nm_cdma_device_class_init (NMCdmaDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *device_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMCdmaDevicePrivate));

	object_class->constructor = constructor;
	object_class->get_property = get_property;
	object_class->set_property = set_property;
	object_class->finalize = finalize;

	device_class->get_best_auto_connection = real_get_best_auto_connection;
	device_class->get_generic_capabilities = real_get_generic_capabilities;
	device_class->act_stage1_prepare = real_act_stage1_prepare;
	device_class->connection_secrets_updated = real_connection_secrets_updated;
	device_class->deactivate_quickly = real_deactivate_quickly;

	/* Properties */
	g_object_class_install_property
		(object_class, PROP_MONITOR_IFACE,
		 g_param_spec_string (NM_CDMA_DEVICE_MONITOR_IFACE,
						  "Monitoring interface",
						  "Monitoring interface",
						  NULL,
						  G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* Signals */
	signals[PROPERTIES_CHANGED] = 
		nm_properties_changed_signal_new (object_class,
								    G_STRUCT_OFFSET (NMCdmaDeviceClass, properties_changed));

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
									 &dbus_glib_nm_cdma_device_object_info);
}
