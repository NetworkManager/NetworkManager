/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_SERIAL_DEVICE_H
#define NM_SERIAL_DEVICE_H

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_SERIAL_DEVICE            (nm_serial_device_get_type ())
#define NM_SERIAL_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SERIAL_DEVICE, NMSerialDevice))
#define NM_SERIAL_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SERIAL_DEVICE, NMSerialDeviceClass))
#define NM_IS_SERIAL_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SERIAL_DEVICE))
#define NM_IS_SERIAL_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((obj), NM_TYPE_SERIAL_DEVICE))
#define NM_SERIAL_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SERIAL_DEVICE, NMSerialDeviceClass))

typedef struct {
	NMDevice parent;
} NMSerialDevice;

typedef struct {
	NMDeviceClass parent;

	/* Signals */
	void (*ppp_stats) (NMSerialDevice *self, guint32 in_bytes, guint32 out_bytes);
} NMSerialDeviceClass;

GType nm_serial_device_get_type (void);

guint32 nm_serial_device_get_bytes_received (NMSerialDevice *self);
guint32 nm_serial_device_get_bytes_sent     (NMSerialDevice *self);

G_END_DECLS

#endif /* NM_SERIAL_DEVICE_H */
