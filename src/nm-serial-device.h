/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SERIAL_DEVICE_H
#define NM_SERIAL_DEVICE_H

#include <nm-device.h>
#include <nm-setting-serial.h>

G_BEGIN_DECLS

#define NM_TYPE_SERIAL_DEVICE			(nm_serial_device_get_type ())
#define NM_SERIAL_DEVICE(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SERIAL_DEVICE, NMSerialDevice))
#define NM_SERIAL_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_SERIAL_DEVICE, NMSerialDeviceClass))
#define NM_IS_SERIAL_DEVICE(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SERIAL_DEVICE))
#define NM_IS_SERIAL_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_SERIAL_DEVICE))
#define NM_SERIAL_DEVICE_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_SERIAL_DEVICE, NMSerialDeviceClass))

typedef struct {
	NMDevice parent;
} NMSerialDevice;

typedef struct {
	NMDeviceClass parent;
} NMSerialDeviceClass;

GType nm_serial_device_get_type (void);

typedef void (*NMSerialGetReplyFn)     (NMSerialDevice *device,
								const char *reply,
								gpointer user_data);

typedef void (*NMSerialWaitForReplyFn) (NMSerialDevice *device,
								int reply_index,
								gpointer user_data);

typedef void (*NMSerialWaitQuietFn)    (NMSerialDevice *device,
								gboolean timed_out,
								gpointer user_data);

typedef void (*NMSerialFlashFn)        (NMSerialDevice *device,
								gpointer user_data);



gboolean nm_serial_device_open                (NMSerialDevice *device, 
									  NMSettingSerial *setting);

void     nm_serial_device_close               (NMSerialDevice *device);
gboolean nm_serial_device_send_command        (NMSerialDevice *device,
									  GByteArray *command);

gboolean nm_serial_device_send_command_string (NMSerialDevice *device,
									  const char *str);

guint    nm_serial_device_get_reply           (NMSerialDevice *device,
									  guint timeout,
									  const char *terminators,
									  NMSerialGetReplyFn callback,
									  gpointer user_data);

guint    nm_serial_device_wait_for_reply      (NMSerialDevice *device,
									  guint timeout,
									  char **responses,
									  NMSerialWaitForReplyFn callback,
									  gpointer user_data);

void     nm_serial_device_wait_quiet          (NMSerialDevice *device,
									  guint timeout, 
									  guint quiet_time,
									  NMSerialWaitQuietFn callback,
									  gpointer user_data);

guint    nm_serial_device_flash               (NMSerialDevice *device,
									  guint32 flash_time,
									  NMSerialFlashFn callback,
									  gpointer user_data);

GIOChannel *nm_serial_device_get_io_channel   (NMSerialDevice *device);

G_END_DECLS

#endif /* NM_SERIAL_DEVICE_H */
