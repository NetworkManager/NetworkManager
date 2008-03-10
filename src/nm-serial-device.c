/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#define _GNU_SOURCE  /* for strcasestr() */

#include <termio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <string.h>
#include <glib.h>

#include "nm-serial-device.h"
#include "nm-device-interface.h"
#include "nm-device-private.h"
#include "ppp-manager/nm-ppp-manager.h"
#include "nm-setting-ppp.h"
#include "nm-utils.h"

/* #define NM_DEBUG_SERIAL 1 */

G_DEFINE_TYPE (NMSerialDevice, nm_serial_device, NM_TYPE_DEVICE)

#define NM_SERIAL_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SERIAL_DEVICE, NMSerialDevicePrivate))

typedef struct {
	int fd;
	GIOChannel *channel;
	NMPPPManager *ppp_manager;
	NMIP4Config  *pending_ip4_config;
	struct termios old_t;
} NMSerialDevicePrivate;

static int
parse_baudrate (guint i)
{
	int speed;

	switch (i) {
	case 0:
		speed = B0;
		break;
	case 50:
		speed = B50;
		break;
	case 75:
		speed = B75;
		break;
	case 110:
		speed = B110;
		break;
	case 150:
		speed = B150;
		break;
	case 300:
		speed = B300;
		break;
	case 600:
		speed = B600;
		break;
	case 1200:
		speed = B1200;
		break;
	case 2400:
		speed = B2400;
		break;
	case 4800:
		speed = B4800;
		break;
	case 9600:
		speed = B9600;
		break;
	case 19200:
		speed = B19200;
		break;
	case 38400:
		speed = B38400;
		break;
	case 57600:
		speed = B57600;
		break;
	case 115200:
		speed = B115200;
		break;
	case 460800:
		speed = B460800;
		break;
	default:
		g_warning ("Invalid baudrate '%d'", i);
		speed = B9600;
	}

	return speed;
}

static int
parse_bits (guint i)
{
	int bits;

	switch (i) {
	case 5:
		bits = CS5;
		break;
	case 6:
		bits = CS6;
		break;
	case 7:
		bits = CS7;
		break;
	case 8:
		bits = CS8;
		break;
	default:
		g_warning ("Invalid bits (%d). Valid values are 5, 6, 7, 8.", i);
		bits = CS8;
	}

	return bits;
}

static int
parse_parity (char c)
{
	int parity;

	switch (c) {
	case 'n':
	case 'N':
		parity = 0;
		break;
	case 'e':
	case 'E':
		parity = PARENB;
		break;
	case 'o':
	case 'O':
		parity = PARENB | PARODD;
		break;
	default:
		g_warning ("Invalid parity (%c). Valid values are n, e, o", c);
		parity = 0;
	}

	return parity;
}

static int
parse_stopbits (guint i)
{
	int stopbits;

	switch (i) {
	case 1:
		stopbits = 0;
		break;
	case 2:
		stopbits = CSTOPB;
		break;
	default:
		g_warning ("Invalid stop bits (%d). Valid values are 1 and 2)", i);
		stopbits = 0;
	}

	return stopbits;
}

#ifdef NM_DEBUG_SERIAL
static inline void
serial_debug (const char *prefix, const char *data, int len)
{
	GString *str;
	int i;

	str = g_string_sized_new (len);
	for (i = 0; i < len; i++) {
		if (data[i] == '\0')
			g_string_append_c (str, ' ');
		else if (data[i] == '\r')
			g_string_append_c (str, '\n');
		else
			g_string_append_c (str, data[i]);
	}

	nm_debug ("%s '%s'", prefix, str->str);
	g_string_free (str, TRUE);
}
#else
static inline void
serial_debug (const char *prefix, const char *data, int len)
{
}
#endif /* NM_DEBUG_SERIAL */

static NMSetting *
serial_device_get_setting (NMSerialDevice *device, GType setting_type)
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

static gboolean
config_fd (NMSerialDevice *device, NMSettingSerial *setting)
{
	NMSerialDevicePrivate *priv = NM_SERIAL_DEVICE_GET_PRIVATE (device);
	struct termio stbuf;
	int speed;
	int bits;
	int parity;
	int stopbits;

	speed = parse_baudrate (setting->baud);
	bits = parse_bits (setting->bits);
	parity = parse_parity (setting->parity);
	stopbits = parse_stopbits (setting->stopbits);

	ioctl (priv->fd, TCGETA, &stbuf);

	stbuf.c_iflag &= ~(IGNCR | ICRNL | IUCLC | INPCK | IXON | IXANY | IGNPAR );
	stbuf.c_oflag &= ~(OPOST | OLCUC | OCRNL | ONLCR | ONLRET);
	stbuf.c_lflag &= ~(ICANON | XCASE | ECHO | ECHOE | ECHONL);
	stbuf.c_lflag &= ~(ECHO | ECHOE);
	stbuf.c_cc[VMIN] = 1;
	stbuf.c_cc[VTIME] = 0;
	stbuf.c_cc[VEOF] = 1;

	stbuf.c_cflag &= ~(CBAUD | CSIZE | CSTOPB | CLOCAL | PARENB);
	stbuf.c_cflag |= (speed | bits | CREAD | 0 | parity | stopbits);

	if (ioctl (priv->fd, TCSETA, &stbuf) < 0) {
		nm_warning ("(%s) cannot control device (errno %d)",
		            nm_device_get_iface (NM_DEVICE (device)), errno);
		return FALSE;
	}

	return TRUE;
}

gboolean
nm_serial_device_open (NMSerialDevice *device,
				   NMSettingSerial *setting)
{
	NMSerialDevicePrivate *priv;
	const char *iface;
	char *path;

	g_return_val_if_fail (NM_IS_SERIAL_DEVICE (device), FALSE);
	g_return_val_if_fail (NM_IS_SETTING_SERIAL (setting), FALSE);

	priv = NM_SERIAL_DEVICE_GET_PRIVATE (device);
	iface = nm_device_get_iface (NM_DEVICE (device));

	nm_debug ("(%s) opening device...", iface);

	path = g_build_filename ("/dev", iface, NULL);
	priv->fd = open (path, O_RDWR | O_EXCL | O_NONBLOCK | O_NOCTTY);
	g_free (path);

	if (priv->fd < 0) {
		nm_warning ("(%s) cannot open device (errno %d)", iface, errno);
		return FALSE;
	}

	if (ioctl (priv->fd, TCGETA, &priv->old_t) < 0) {
		nm_warning ("(%s) cannot control device (errno %d)", iface, errno);
		close (priv->fd);
		return FALSE;
	}

	if (!config_fd (device, setting)) {
		close (priv->fd);
		return FALSE;
	}

	priv->channel = g_io_channel_unix_new (priv->fd);

	return TRUE;
}

void
nm_serial_device_close (NMSerialDevice *device)
{
	NMSerialDevicePrivate *priv;

	g_return_if_fail (NM_IS_SERIAL_DEVICE (device));

	priv = NM_SERIAL_DEVICE_GET_PRIVATE (device);

	if (priv->fd) {
		nm_debug ("Closing device '%s'", nm_device_get_iface (NM_DEVICE (device)));

		g_io_channel_unref (priv->channel);
		ioctl (priv->fd, TCSETA, &priv->old_t);
		close (priv->fd);

		priv->fd = 0;
	}
}

gboolean
nm_serial_device_send_command (NMSerialDevice *device, GByteArray *command)
{
	int fd;
	NMSettingSerial *setting;
	int i;
	ssize_t status;

	g_return_val_if_fail (NM_IS_SERIAL_DEVICE (device), FALSE);
	g_return_val_if_fail (command != NULL, FALSE);

	fd = NM_SERIAL_DEVICE_GET_PRIVATE (device)->fd;
	setting = NM_SETTING_SERIAL (serial_device_get_setting (device, NM_TYPE_SETTING_SERIAL));

	serial_debug ("Sending:", (char *) command->data, command->len);

	for (i = 0; i < command->len; i++) {
	again:
		status = write (fd, command->data + i, 1);

		if (status < 0) {
			if (errno == EAGAIN)
				goto again;

			g_warning ("Error in writing");
			return FALSE;
		}

		if (setting->send_delay)
			usleep (setting->send_delay);
	}

	return TRUE;
}

gboolean
nm_serial_device_send_command_string (NMSerialDevice *device, const char *str)
{
	GByteArray *command;
	gboolean ret;

	g_return_val_if_fail (NM_IS_SERIAL_DEVICE (device), FALSE);
	g_return_val_if_fail (str != NULL, FALSE);

	command = g_byte_array_new ();
	g_byte_array_append (command, (guint8 *) str, strlen (str));
	g_byte_array_append (command, (guint8 *) "\r", 1);

	ret = nm_serial_device_send_command (device, command);
	g_byte_array_free (command, TRUE);

	return ret;
}

typedef struct {
	NMSerialDevice *device;
	char *terminators;
	GString *result;
	NMSerialGetReplyFn callback;
	gpointer user_data;
	guint timeout_id;
	guint got_data_id;
} GetReplyInfo;

static void
get_reply_info_destroy (gpointer data)
{
	GetReplyInfo *info = (GetReplyInfo *) data;

	if (info->got_data_id)
		g_source_remove (info->got_data_id);

	g_free (info->terminators);

	if (info->result)
		g_string_free (info->result, TRUE);

	g_free (info);
}

static gboolean
get_reply_timeout (gpointer data)
{
	GetReplyInfo *info = (GetReplyInfo *) data;

	info->callback (info->device, NULL, info->user_data);

	return FALSE;
}

static gboolean
get_reply_got_data (GIOChannel *source,
				GIOCondition condition,
				gpointer data)
{
	GetReplyInfo *info = (GetReplyInfo *) data;
	gsize bytes_read;
	char buf[4096];
	GIOStatus status;
	gboolean done = FALSE;
	int i;

	if (condition & G_IO_IN) {
		do {
			GError *err = NULL;

			status = g_io_channel_read_chars (source, buf, 4096, &bytes_read, &err);

			if (status == G_IO_STATUS_ERROR) {
				g_warning ("%s", err->message);
				g_error_free (err);
				err = NULL;
			}

			if (bytes_read > 0) {
				char *p;

				serial_debug ("Got:", buf, bytes_read);

				p = &buf[0];
				for (i = 0; i < bytes_read && !done; i++, p++) {
					int j;
					gboolean is_terminator = FALSE;

					for (j = 0; j < strlen (info->terminators); j++) {
						if (*p == info->terminators[j]) {
							is_terminator = TRUE;
							break;
						}
					}

					if (is_terminator) {
						/* Ignore terminators in the beginning of the output */
						if (info->result->len > 0)
							done = TRUE;
					} else
						g_string_append_c (info->result, *p);
				}
			}
		} while (!done || bytes_read == 4096 || status == G_IO_STATUS_AGAIN);
	}

	if (condition & G_IO_HUP || condition & G_IO_ERR) {
		g_string_free (info->result, TRUE);
		info->result = NULL;
		done = TRUE;
	}

	if (done) {
		char *result = info->result ? g_string_free (info->result, FALSE) : NULL;
		info->result = NULL;
		info->callback (info->device, result, info->user_data);
		g_free (result);

		/* Clear the id - returning FALSE already removes it */
		info->got_data_id = 0;
		g_source_remove (info->timeout_id);
	}

	return !done;
}

guint
nm_serial_device_get_reply (NMSerialDevice *device,
					   guint timeout,
					   const char *terminators,
					   NMSerialGetReplyFn callback,
					   gpointer user_data)
{
	GetReplyInfo *info;

	g_return_val_if_fail (NM_IS_SERIAL_DEVICE (device), 0);
	g_return_val_if_fail (terminators != NULL, 0);
	g_return_val_if_fail (callback != NULL, 0);

	info = g_new (GetReplyInfo, 1);
	info->device = device;
	info->terminators = g_strdup (terminators);
	info->result = g_string_new (NULL);
	info->callback = callback;
	info->user_data = user_data;

	info->got_data_id = g_io_add_watch (NM_SERIAL_DEVICE_GET_PRIVATE (device)->channel,
								 G_IO_IN | G_IO_ERR | G_IO_HUP,
								 get_reply_got_data,
								 info);

	info->timeout_id = g_timeout_add_full (G_PRIORITY_DEFAULT,
								    timeout * 1000,
								    get_reply_timeout,
								    info,
								    get_reply_info_destroy);

	return info->timeout_id;
}

typedef struct {
	NMSerialDevice *device;
	char **str_needles;
	NMSerialWaitForReplyFn callback;
	gpointer user_data;
	guint timeout_id;
	guint got_data_id;
} WaitForReplyInfo;

static void
wait_for_reply_info_destroy (gpointer data)
{
	WaitForReplyInfo *info = (WaitForReplyInfo *) data;

	if (info->got_data_id)
		g_source_remove (info->got_data_id);

	g_strfreev (info->str_needles);
	g_free (info);
}

static gboolean
wait_for_reply_timeout (gpointer data)
{
	WaitForReplyInfo *info = (WaitForReplyInfo *) data;

	info->callback (info->device, -1, info->user_data);

	return FALSE;
}

static gboolean
wait_for_reply_got_data (GIOChannel *source,
					GIOCondition condition,
					gpointer data)
{
	WaitForReplyInfo *info = (WaitForReplyInfo *) data;
	gsize bytes_read;
	char buf[4096];
	GIOStatus status;
	gboolean done = FALSE;
	int idx = -1;
	int i;

	if (condition & G_IO_IN) {
		do {
			GError *err = NULL;

			status = g_io_channel_read_chars (source, buf, 4096, &bytes_read, &err);

			if (status == G_IO_STATUS_ERROR) {
				g_warning ("%s", err->message);
				g_error_free (err);
				err = NULL;
			}

			if (bytes_read > 0) {
				serial_debug ("Got:", buf, bytes_read);

				for (i = 0; info->str_needles[i]; i++) {
					if (strcasestr (buf, info->str_needles[i])) {
						idx = i;
						done = TRUE;
					}
				}
			}
		} while (bytes_read == 4096 || status == G_IO_STATUS_AGAIN);
	}

	if (condition & G_IO_HUP || condition & G_IO_ERR)
		done = TRUE;

	if (done) {
		info->callback (info->device, idx, info->user_data);

		/* Clear the id - returning FALSE already removes it */
		info->got_data_id = 0;
		g_source_remove (info->timeout_id);
	}

	return !done;
}

guint
nm_serial_device_wait_for_reply (NMSerialDevice *device,
						   guint timeout,
						   char **responses,
						   NMSerialWaitForReplyFn callback,
						   gpointer user_data)
{
	WaitForReplyInfo *info;
	char **str_array;
	int i;

	g_return_val_if_fail (NM_IS_SERIAL_DEVICE (device), 0);
	g_return_val_if_fail (responses != NULL, 0);
	g_return_val_if_fail (callback != NULL, 0);

	/* Copy the array */
	str_array = g_new (char*, g_strv_length (responses) + 1);
	i = 0;
	while (responses[i]) {
		str_array[i] = g_strdup (responses[i]);
		i++;
	}
	str_array[i] = NULL;

	info = g_new (WaitForReplyInfo, 1);
	info->device = device;
	info->str_needles = str_array;
	info->callback = callback;
	info->user_data = user_data;

	info->got_data_id = g_io_add_watch (NM_SERIAL_DEVICE_GET_PRIVATE (device)->channel,
								 G_IO_IN | G_IO_ERR | G_IO_HUP,
								 wait_for_reply_got_data,
								 info);

	info->timeout_id = g_timeout_add_full (G_PRIORITY_DEFAULT,
								    timeout * 1000,
								    wait_for_reply_timeout,
								    info,
								    wait_for_reply_info_destroy);

	return info->timeout_id;
}

#if 0
typedef struct {
	NMSerialDevice *device;
	gboolean timed_out;
	NMSerialWaitQuietFn callback;
	gpointer user_data;
} WaitQuietInfo;

static gboolean
wait_quiet_done (gpointer data)
{
	WaitQuietInfo *info = (WaitQuietInfo *) data;

	info->callback (info->device, info->timed_out, info->user_data);

	return FALSE;
}

static gboolean
wait_quiet_quiettime (gpointer data)
{
	WaitQuietInfo *info = (WaitQuietInfo *) data;

	info->timed_out = FALSE;
	wait_quiet_done (data);

	return FALSE;
}

static gboolean
wait_quiet_got_data (GIOChannel *source,
				 GIOCondition condition,
				 gpointer data)
{
	WaitQuietInfo *info = (WaitQuietInfo *) data;
	gsize bytes_read;
	char buf[4096];
	GIOStatus status;

	if (condition & G_IO_IN) {
		do {
			status = g_io_channel_read_chars (source, buf, 4096, &bytes_read, NULL);

			if (bytes_read) {
				/* Reset the quiet time timeout */
				g_source_remove (info->quiet_id);
				info->quiet_id = g_timeout_add (info->quiet_time, wait_quiet_quiettime, info);
			}
		} while (bytes_read == 4096 || status == G_IO_STATUS_AGAIN);
	}

	if (condition & G_IO_HUP || condition & G_IO_ERR) {
		wait_quiet_done (data);
		return FALSE
	}

	return TRUE;
}

void
nm_serial_device_wait_quiet (NMSerialDevice *device,
					    guint timeout, 
					    guint quiet_time,
					    NMSerialWaitQuietFn callback,
					    gpointer user_data)
{
	WaitQuietInfo *info;

	g_return_if_fail (NM_IS_SERIAL_DEVICE (device));
	g_return_if_fail (callback != NULL);

	info = g_new (WaitQuietInfo, 1);

	info->device = device;
	info->timed_out = TRUE;
	info->callback = callback;
	info->user_data = user_data;
	
	info->got_data_id = g_io_add_watch (NM_SERIAL_DEVICE_GET_PRIVATE (device)->channel,
								 G_IO_IN | G_IO_ERR | G_IO_HUP,
								 wait_quiet_got_data,
								 info);

	info->quiet_id = g_timeout_add (quiet_time,
							  wait_quiet_timeout,
							  info);

	info->timeout_id = g_timeout_add_full (G_PRIORITY_DEFAULT,
								    timeout,
								    wait_quiet_timeout,
								    info,
								    wait_quiet_info_destroy);
}

#endif

typedef struct {
	NMSerialDevice *device;
	speed_t current_speed;
	NMSerialFlashFn callback;
	gpointer user_data;
} FlashInfo;

static speed_t
get_speed (NMSerialDevice *device)
{
	struct termios options;

	tcgetattr (NM_SERIAL_DEVICE_GET_PRIVATE (device)->fd, &options);

	return cfgetospeed (&options);
}

static void
set_speed (NMSerialDevice *device, speed_t speed)
{
	struct termios options;
	int fd;

	fd = NM_SERIAL_DEVICE_GET_PRIVATE (device)->fd;
	tcgetattr (fd, &options);

	cfsetispeed (&options, speed);
	cfsetospeed (&options, speed);

	options.c_cflag |= (CLOCAL | CREAD);
	tcsetattr (fd, TCSANOW, &options);
}

static gboolean
flash_done (gpointer data)
{
	FlashInfo *info = (FlashInfo *) data;

	set_speed (info->device, info->current_speed);
	info->callback (info->device, info->user_data);

	return FALSE;
}

guint
nm_serial_device_flash (NMSerialDevice *device,
				    guint32 flash_time,
				    NMSerialFlashFn callback,
				    gpointer user_data)
{
	FlashInfo *info;

	g_return_val_if_fail (NM_IS_SERIAL_DEVICE (device), 0);
	g_return_val_if_fail (callback != NULL, 0);

	info = g_new (FlashInfo, 1);
	info->device = device;
	info->current_speed = get_speed (device);
	info->callback = callback;
	info->user_data = user_data;

	set_speed (device, B0);

	return g_timeout_add_full (G_PRIORITY_DEFAULT,
						  flash_time,
						  flash_done,
						  info,
						  g_free);
}

GIOChannel *
nm_serial_device_get_io_channel (NMSerialDevice *device)
{
	NMSerialDevicePrivate *priv;

	g_return_val_if_fail (NM_IS_SERIAL_DEVICE (device), 0);

	priv = NM_SERIAL_DEVICE_GET_PRIVATE (device);
	if (priv->channel)
		return g_io_channel_ref (priv->channel);

	return NULL;
}

static void
ppp_state_changed (NMPPPManager *ppp_manager, NMPPPStatus status, gpointer user_data)
{
	NMDevice *device = NM_DEVICE (user_data);

	switch (status) {
	case NM_PPP_STATUS_NETWORK:
		nm_device_state_changed (device, NM_DEVICE_STATE_IP_CONFIG);
		break;
	case NM_PPP_STATUS_DISCONNECT:
		nm_device_state_changed (device, NM_DEVICE_STATE_FAILED);
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
	NM_SERIAL_DEVICE_GET_PRIVATE (device)->pending_ip4_config = g_object_ref (config);
	nm_device_activate_schedule_stage4_ip_config_get (device);
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device)
{
	NMSerialDevicePrivate *priv = NM_SERIAL_DEVICE_GET_PRIVATE (device);
	NMActRequest *req;
	NMConnection *connection;
	GError *err = NULL;
	NMActStageReturn ret;

	req = nm_device_get_act_request (device);
	g_assert (req);
	connection = nm_act_request_get_connection (req);
	g_assert (connection);

	priv->ppp_manager = nm_ppp_manager_new ();

	if (nm_ppp_manager_start (priv->ppp_manager,
						 nm_device_get_iface (device),
						 connection,
						 &err)) {
		g_signal_connect (priv->ppp_manager, "state-changed",
					   G_CALLBACK (ppp_state_changed),
					   device);
		g_signal_connect (priv->ppp_manager, "ip4-config",
					   G_CALLBACK (ppp_ip4_config),
					   device);
		ret = NM_ACT_STAGE_RETURN_POSTPONE;
	} else {
		nm_warning ("%s", err->message);
		g_error_free (err);

		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;

		ret = NM_ACT_STAGE_RETURN_FAILURE;
	}

	return ret;
}

static NMActStageReturn
real_act_stage4_get_ip4_config (NMDevice *device, NMIP4Config **config)
{
	NMSerialDevicePrivate *priv = NM_SERIAL_DEVICE_GET_PRIVATE (device);

	*config = priv->pending_ip4_config;
	priv->pending_ip4_config = NULL;

	return NM_ACT_STAGE_RETURN_SUCCESS;
}

static void
real_deactivate_quickly (NMDevice *device)
{
	NMSerialDevice *self = NM_SERIAL_DEVICE (device);
	NMSerialDevicePrivate *priv = NM_SERIAL_DEVICE_GET_PRIVATE (device);

	nm_device_set_ip_iface (device, NULL);

	if (priv->pending_ip4_config) {
		g_object_unref (priv->pending_ip4_config);
		priv->pending_ip4_config = NULL;
	}

	if (priv->ppp_manager) {
		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;
	}

	nm_serial_device_close (self);
}

static gboolean
real_is_up (NMDevice *device)
{
	/* Serial devices are always "up" */
	return TRUE;
}

static guint32
real_get_generic_capabilities (NMDevice *dev)
{
	return NM_DEVICE_CAP_NM_SUPPORTED;
}

/*****************************************************************************/

static void
nm_serial_device_init (NMSerialDevice *self)
{
}

static void
finalize (GObject *object)
{
	NMSerialDevice *self = NM_SERIAL_DEVICE (object);

	nm_serial_device_close (self);

	G_OBJECT_CLASS (nm_serial_device_parent_class)->finalize (object);
}

static void
nm_serial_device_class_init (NMSerialDeviceClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);
	NMDeviceClass *parent_class = NM_DEVICE_CLASS (klass);

	g_type_class_add_private (object_class, sizeof (NMSerialDevicePrivate));

	/* Virtual methods */
	object_class->finalize = finalize;

	parent_class->get_generic_capabilities = real_get_generic_capabilities;
	parent_class->is_up = real_is_up;
	parent_class->act_stage2_config = real_act_stage2_config;
	parent_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	parent_class->deactivate_quickly = real_deactivate_quickly;
}
