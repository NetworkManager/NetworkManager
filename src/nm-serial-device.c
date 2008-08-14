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
#include "nm-marshal.h"
#include "nm-utils.h"
#include "nm-serial-device-glue.h"

/* #define NM_DEBUG_SERIAL 1 */

#define SERIAL_BUF_SIZE 2048

G_DEFINE_TYPE (NMSerialDevice, nm_serial_device, NM_TYPE_DEVICE)

#define NM_SERIAL_DEVICE_GET_PRIVATE(o) (G_TYPE_INSTANCE_GET_PRIVATE ((o), NM_TYPE_SERIAL_DEVICE, NMSerialDevicePrivate))

typedef struct {
	int fd;
	GIOChannel *channel;
	NMPPPManager *ppp_manager;
	NMIP4Config  *pending_ip4_config;
	struct termios old_t;

	guint pending_id;
	guint timeout_id;

	/* PPP stats */
	guint32 in_bytes;
	guint32 out_bytes;
} NMSerialDevicePrivate;

enum {
	PPP_STATS,

	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

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

/* Timeout handling */

static void
nm_serial_device_timeout_removed (gpointer data)
{
	NMSerialDevicePrivate *priv = NM_SERIAL_DEVICE_GET_PRIVATE (data);

	priv->timeout_id = 0;
}

static gboolean
nm_serial_device_timed_out (gpointer data)
{
	NMSerialDevicePrivate *priv = NM_SERIAL_DEVICE_GET_PRIVATE (data);

	/* Cancel data reading */
	if (priv->pending_id)
		g_source_remove (priv->pending_id);
	else
		nm_warning ("Timeout reached, but there's nothing to time out");

	return FALSE;
}

static void
nm_serial_device_add_timeout (NMSerialDevice *self, guint timeout)
{
	NMSerialDevicePrivate *priv = NM_SERIAL_DEVICE_GET_PRIVATE (self);

	if (priv->pending_id == 0)
		nm_warning ("Adding a time out while not waiting for any data");

	if (priv->timeout_id) {
		nm_warning ("Trying to add a new time out while the old one still exists");
		g_source_remove (priv->timeout_id);
	}

	priv->timeout_id = g_timeout_add_full (G_PRIORITY_DEFAULT,
								    timeout * 1000,
								    nm_serial_device_timed_out,
								    self,
								    nm_serial_device_timeout_removed);
	if (G_UNLIKELY (priv->timeout_id == 0))
		nm_warning ("Registering serial device time out failed.");
}

static void
nm_serial_device_remove_timeout (NMSerialDevice *self)
{
	NMSerialDevicePrivate *priv = NM_SERIAL_DEVICE_GET_PRIVATE (self);

	if (priv->timeout_id)
		g_source_remove (priv->timeout_id);
}

/* Pending data reading */

static guint
nm_serial_device_set_pending (NMSerialDevice *device,
						guint timeout,
						GIOFunc callback,
						gpointer user_data,
						GDestroyNotify notify)
{
	NMSerialDevicePrivate *priv = NM_SERIAL_DEVICE_GET_PRIVATE (device);

	if (G_UNLIKELY (priv->pending_id)) {
		/* FIXME: Probably should queue up pending calls instead? */
		/* Multiple pending calls on the same GIOChannel doesn't work, so let's cancel the previous one. */
		nm_warning ("Adding new pending call while previous one isn't finished.");
		nm_warning ("Cancelling the previous pending call.");
		g_source_remove (priv->pending_id);
	}

	priv->pending_id = g_io_add_watch_full (priv->channel,
									G_PRIORITY_DEFAULT,
									G_IO_IN | G_IO_ERR | G_IO_HUP,
									callback, user_data, notify);

	nm_serial_device_add_timeout (device, timeout);

	return priv->pending_id;
}

static void
nm_serial_device_pending_done (NMSerialDevice *self)
{
	NM_SERIAL_DEVICE_GET_PRIVATE (self)->pending_id = 0;
	nm_serial_device_remove_timeout (self);
}

/****/

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

	if (priv->pending_id)
		g_source_remove (priv->pending_id);

	if (priv->fd) {
		nm_debug ("Closing device '%s'", nm_device_get_iface (NM_DEVICE (device)));

		if (priv->channel) {
			g_io_channel_unref (priv->channel);
			priv->channel = NULL;
		}

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

			g_warning ("Error in writing (errno %d)", errno);
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
} GetReplyInfo;

static void
get_reply_done (gpointer data)
{
	GetReplyInfo *info = (GetReplyInfo *) data;

	nm_serial_device_pending_done (info->device);

	/* Call the callback */
	info->callback (info->device, info->result->str, info->user_data);

	/* Free info */
	g_free (info->terminators);
	g_string_free (info->result, TRUE);

	g_slice_free (GetReplyInfo, info);
}

static gboolean
get_reply_got_data (GIOChannel *source,
				GIOCondition condition,
				gpointer data)
{
	GetReplyInfo *info = (GetReplyInfo *) data;
	gsize bytes_read;
	char buf[SERIAL_BUF_SIZE + 1];
	GIOStatus status;
	gboolean done = FALSE;
	int i;

	if (condition & G_IO_HUP || condition & G_IO_ERR) {
		g_string_truncate (info->result, 0);
		return FALSE;
	}

	do {
		GError *err = NULL;

		status = g_io_channel_read_chars (source, buf, SERIAL_BUF_SIZE, &bytes_read, &err);
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

		/* Limit the size of the buffer */
		if (info->result->len > SERIAL_BUF_SIZE) {
			g_warning ("%s (%s): response buffer filled before repsonse received",
			           __func__, nm_device_get_iface (NM_DEVICE (info->device)));
			g_string_truncate (info->result, 0);
			done = TRUE;
		}
	} while (!done || bytes_read == SERIAL_BUF_SIZE || status == G_IO_STATUS_AGAIN);

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

	info = g_slice_new0 (GetReplyInfo);
	info->device = device;
	info->terminators = g_strdup (terminators);
	info->result = g_string_new (NULL);
	info->callback = callback;
	info->user_data = user_data;

	return nm_serial_device_set_pending (device, timeout, get_reply_got_data, info, get_reply_done);
}

typedef struct {
	NMSerialDevice *device;
	char **str_needles;
	char **terminators;
	GString *result;
	NMSerialWaitForReplyFn callback;
	gpointer user_data;
	int reply_index;
	guint timeout;
	time_t start;
} WaitForReplyInfo;

static void
wait_for_reply_done (gpointer data)
{
	WaitForReplyInfo *info = (WaitForReplyInfo *) data;

	nm_serial_device_pending_done (info->device);

	/* Call the callback */
	info->callback (info->device, info->reply_index, info->user_data);

	/* Free info */
	if (info->result)
		g_string_free (info->result, TRUE);

	g_strfreev (info->str_needles);
	g_strfreev (info->terminators);
	g_slice_free (WaitForReplyInfo, info);
}

static gboolean
find_terminator (const char *line, char **terminators)
{
	int i;

	for (i = 0; terminators[i]; i++) {
		if (!strncasecmp (line, terminators[i], strlen (terminators[i])))
			return TRUE;
	}
	return FALSE;
}

static gboolean
find_response (const char *line, char **responses, gint *idx)
{
	int i;

	/* Don't look for a result again if we got one previously */
	for (i = 0; responses[i]; i++) {
		if (strcasestr (line, responses[i])) {
			*idx = i;
			return TRUE;
		}
	}
	return FALSE;
}

#define RESPONSE_LINE_MAX 128

static gboolean
wait_for_reply_got_data (GIOChannel *source,
					GIOCondition condition,
					gpointer data)
{
	WaitForReplyInfo *info = (WaitForReplyInfo *) data;
	gchar buf[SERIAL_BUF_SIZE + 1];
	gsize bytes_read;
	GIOStatus status;
	gboolean got_response = FALSE;
	gboolean done = FALSE;

	if (condition & G_IO_HUP || condition & G_IO_ERR)
		return FALSE;

	do {
		GError *err = NULL;

		status = g_io_channel_read_chars (source, buf, SERIAL_BUF_SIZE, &bytes_read, &err);
		if (status == G_IO_STATUS_ERROR) {
			g_warning ("%s", err->message);
			g_error_free (err);
			err = NULL;
		}

		if (bytes_read > 0) {
			buf[bytes_read] = 0;
			g_string_append (info->result, buf);

			serial_debug ("Got:", info->result->str, info->result->len);
		}

		/* Look for needles and terminators */
		if ((bytes_read > 0) && info->result->str) {
			char *p = info->result->str;

			/* Break the response up into lines and process each one */
			while (   (p < info->result->str + strlen (info->result->str))
			       && !(done && got_response)) {
				char line[RESPONSE_LINE_MAX] = { '\0', };
				char *tmp;
				int i;
				gboolean got_something = FALSE;

				for (i = 0; *p && (i < RESPONSE_LINE_MAX - 1); p++) {
					/* Ignore front CR/LF */
					if ((*p == '\n') || (*p == '\r')) {
						if (got_something)
							break;
					} else {
						line[i++] = *p;
						got_something = TRUE;
					}
				}
				line[i] = '\0';

				tmp = g_strstrip (line);
				if (tmp && strlen (tmp)) {
					done = find_terminator (tmp, info->terminators);
					if (info->reply_index == -1)
						got_response = find_response (tmp, info->str_needles, &(info->reply_index));
				}
			}

			if (done && got_response)
				break;
		}

		/* Limit the size of the buffer */
		if (info->result->len > SERIAL_BUF_SIZE) {
			g_warning ("%s (%s): response buffer filled before repsonse received",
			           __func__, nm_device_get_iface (NM_DEVICE (info->device)));
			done = TRUE;
			break;
		}

		/* Make sure we don't go over the timeout, in addition to the timeout
		 * handler that's been scheduled.  If for some reason this loop doesn't
		 * terminate (terminator not found, whatever) then this should make
		 * sure that NM doesn't spin the CPU forever.
		 */
		if (time (NULL) - info->start > info->timeout + 1) {
			done = TRUE;
			break;
		} else
			g_usleep (50);
	} while (!done || bytes_read == SERIAL_BUF_SIZE || status == G_IO_STATUS_AGAIN);

	return !done;
}

guint
nm_serial_device_wait_for_reply (NMSerialDevice *device,
						   guint timeout,
						   char **responses,
						   char **terminators,
						   NMSerialWaitForReplyFn callback,
						   gpointer user_data)
{
	WaitForReplyInfo *info;

	g_return_val_if_fail (NM_IS_SERIAL_DEVICE (device), 0);
	g_return_val_if_fail (responses != NULL, 0);
	g_return_val_if_fail (callback != NULL, 0);

	info = g_slice_new0 (WaitForReplyInfo);
	info->device = device;
	info->str_needles = g_strdupv (responses);
	info->terminators = g_strdupv (terminators);
	info->result = g_string_new (NULL);
	info->callback = callback;
	info->user_data = user_data;
	info->reply_index = -1;
	info->timeout = timeout;
	info->start = time (NULL);

	return nm_serial_device_set_pending (device, timeout, wait_for_reply_got_data, info, wait_for_reply_done);
}

#if 0
typedef struct {
	NMSerialDevice *device;
	gboolean timed_out;
	NMSerialWaitQuietFn callback;
	gpointer user_data;
} WaitQuietInfo;

static void
wait_quiet_done (gpointer data)
{
	WaitQuietInfo *info = (WaitQuietInfo *) data;

	nm_serial_device_pending_done (info->device);

	/* Call the callback */
	info->callback (info->device, info->timed_out, info->user_data);

	/* Free info */
	g_slice_free (WaitQuietInfo, info);
}

static gboolean
wait_quiet_quiettime (gpointer data)
{
	WaitQuietInfo *info = (WaitQuietInfo *) data;

	info->timed_out = FALSE;
	g_source_remove (NM_SERIAL_DEVICE_GET_PRIVATE (info->device)->pending);

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

	if (condition & G_IO_HUP || condition & G_IO_ERR)
		return FALSE;

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

	info = g_slice_new0 (WaitQuietInfo);
	info->device = device;
	info->timed_out = TRUE;
	info->callback = callback;
	info->user_data = user_data;
	info->quiet_id = g_timeout_add (quiet_time,
							  wait_quiet_timeout,
							  info);

	return nm_serial_device_set_pending (device, timeout, wait_quiet_got_data, info, wait_quiet_done);
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

static void
flash_done (gpointer data)
{
	FlashInfo *info = (FlashInfo *) data;

	NM_SERIAL_DEVICE_GET_PRIVATE (info->device)->pending_id = 0;

	info->callback (info->device, info->user_data);

	g_slice_free (FlashInfo, info);
}

static gboolean
flash_do (gpointer data)
{
	FlashInfo *info = (FlashInfo *) data;

	set_speed (info->device, info->current_speed);

	return FALSE;
}

guint
nm_serial_device_flash (NMSerialDevice *device,
				    guint32 flash_time,
				    NMSerialFlashFn callback,
				    gpointer user_data)
{
	FlashInfo *info;
	guint id;

	g_return_val_if_fail (NM_IS_SERIAL_DEVICE (device), 0);
	g_return_val_if_fail (callback != NULL, 0);

	info = g_slice_new0 (FlashInfo);
	info->device = device;
	info->current_speed = get_speed (device);
	info->callback = callback;
	info->user_data = user_data;

	set_speed (device, B0);

	id = g_timeout_add_full (G_PRIORITY_DEFAULT,
						flash_time,
						flash_do,
						info,
						flash_done);

	NM_SERIAL_DEVICE_GET_PRIVATE (device)->pending_id = id;

	return id;
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

NMPPPManager *
nm_serial_device_get_ppp_manager (NMSerialDevice *device)
{
	g_return_val_if_fail (NM_IS_SERIAL_DEVICE (device), NULL);

	return NM_SERIAL_DEVICE_GET_PRIVATE (device)->ppp_manager;
}

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
	NM_SERIAL_DEVICE_GET_PRIVATE (device)->pending_ip4_config = g_object_ref (config);
	nm_device_activate_schedule_stage4_ip_config_get (device);
}

static void
ppp_stats (NMPPPManager *ppp_manager,
		 guint32 in_bytes,
		 guint32 out_bytes,
		 gpointer user_data)
{
	NMSerialDevice *device = NM_SERIAL_DEVICE (user_data);
	NMSerialDevicePrivate *priv = NM_SERIAL_DEVICE_GET_PRIVATE (device);

	if (priv->in_bytes != in_bytes || priv->out_bytes != out_bytes) {
		priv->in_bytes = in_bytes;
		priv->out_bytes = out_bytes;

		g_signal_emit (device, signals[PPP_STATS], 0, in_bytes, out_bytes);
	}
}

static NMActStageReturn
real_act_stage2_config (NMDevice *device, NMDeviceStateReason *reason)
{
	NMSerialDevicePrivate *priv = NM_SERIAL_DEVICE_GET_PRIVATE (device);
	NMActRequest *req;
	GError *err = NULL;
	NMActStageReturn ret;

	req = nm_device_get_act_request (device);
	g_assert (req);

	priv->ppp_manager = nm_ppp_manager_new (nm_device_get_iface (device));
	if (nm_ppp_manager_start (priv->ppp_manager, req, &err)) {
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
real_act_stage4_get_ip4_config (NMDevice *device,
                                NMIP4Config **config,
                                NMDeviceStateReason *reason)
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

	priv->in_bytes = priv->out_bytes = 0;

	if (priv->ppp_manager) {
		g_object_unref (priv->ppp_manager);
		priv->ppp_manager = NULL;
	}

	nm_serial_device_close (self);
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
	parent_class->act_stage2_config = real_act_stage2_config;
	parent_class->act_stage4_get_ip4_config = real_act_stage4_get_ip4_config;
	parent_class->deactivate_quickly = real_deactivate_quickly;

	/* Signals */
	signals[PPP_STATS] =
		g_signal_new ("ppp-stats",
				    G_OBJECT_CLASS_TYPE (object_class),
				    G_SIGNAL_RUN_FIRST,
				    G_STRUCT_OFFSET (NMSerialDeviceClass, ppp_stats),
				    NULL, NULL,
				    nm_marshal_VOID__UINT_UINT,
				    G_TYPE_NONE, 2,
				    G_TYPE_UINT, G_TYPE_UINT);

	dbus_g_object_type_install_info (G_TYPE_FROM_CLASS (klass),
							   &dbus_glib_nm_serial_device_object_info);
}
