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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2008 Red Hat, Inc.
 */

#ifndef NM_SERIAL_DEVICE_H
#define NM_SERIAL_DEVICE_H

#include <nm-device.h>
#include <nm-setting-serial.h>
#include "ppp-manager/nm-ppp-manager.h"

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

	const char * (*get_ppp_name) (NMSerialDevice *device, NMActRequest *req);

	/* Signals */
	void (*ppp_stats) (NMSerialDevice *device, guint32 in_bytes, guint32 out_bytes);
} NMSerialDeviceClass;

GType nm_serial_device_get_type (void);

typedef void (*NMSerialGetReplyFn)     (NMSerialDevice *device,
								const char *reply,
								gpointer user_data);

typedef void (*NMSerialWaitForReplyFn) (NMSerialDevice *device,
                                        int reply_index,
                                        const char *reply,
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

int nm_serial_device_wait_reply_blocking (NMSerialDevice *device,
                                          guint32 timeout_secs,
                                          const char **needles,
                                          const char **terminators);

guint    nm_serial_device_wait_for_reply      (NMSerialDevice *device,
									  guint timeout,
									  const char **responses,
									  const char **terminators,
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

NMPPPManager *nm_serial_device_get_ppp_manager (NMSerialDevice *device);

G_END_DECLS

#endif /* NM_SERIAL_DEVICE_H */
