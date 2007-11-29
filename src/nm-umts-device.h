/* -*- Mode: C; tab-width: 5; indent-tabs-mode: t; c-basic-offset: 5 -*- */

#ifndef NM_UMTS_DEVICE_H
#define NM_UMTS_DEVICE_H

#include <nm-serial-device.h>

G_BEGIN_DECLS

#define NM_TYPE_UMTS_DEVICE			(nm_umts_device_get_type ())
#define NM_UMTS_DEVICE(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_UMTS_DEVICE, NMUmtsDevice))
#define NM_UMTS_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_UMTS_DEVICE, NMUmtsDeviceClass))
#define NM_IS_UMTS_DEVICE(obj)		(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_UMTS_DEVICE))
#define NM_IS_UMTS_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_UMTS_DEVICE))
#define NM_UMTS_DEVICE_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_UMTS_DEVICE, NMUmtsDeviceClass))

typedef struct {
	NMSerialDevice parent;
} NMUmtsDevice;

typedef struct {
	NMSerialDeviceClass parent;
} NMUmtsDeviceClass;

GType nm_umts_device_get_type (void);

NMUmtsDevice *nm_umts_device_new (const char *udi,
						    const char *iface,
						    const char *driver);

G_END_DECLS

#endif /* NM_UMTS_DEVICE_H */
