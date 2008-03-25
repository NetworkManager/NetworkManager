/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#ifndef NM_CDMA_DEVICE_H
#define NM_CDMA_DEVICE_H

#include <nm-serial-device.h>

G_BEGIN_DECLS

#define NM_TYPE_CDMA_DEVICE			(nm_cdma_device_get_type ())
#define NM_CDMA_DEVICE(obj)			(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_CDMA_DEVICE, NMCdmaDevice))
#define NM_CDMA_DEVICE_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_CDMA_DEVICE, NMCdmaDeviceClass))
#define NM_IS_CDMA_DEVICE(obj)			(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_CDMA_DEVICE))
#define NM_IS_CDMA_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_CDMA_DEVICE))
#define NM_CDMA_DEVICE_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_CDMA_DEVICE, NMCdmaDeviceClass))

#define NM_CDMA_DEVICE_MONITOR_IFACE "monitor-iface"

typedef struct {
	NMSerialDevice parent;
} NMCdmaDevice;

typedef struct {
	NMSerialDeviceClass parent;

	/* Signals */
	void (*properties_changed) (NMCdmaDevice *device, GHashTable *properties);
} NMCdmaDeviceClass;

GType nm_cdma_device_get_type (void);

NMCdmaDevice *nm_cdma_device_new (const char *udi,
                                  const char *data_iface,
                                  const char *monitor_iface,
                                  const char *driver);

G_END_DECLS

#endif /* NM_CDMA_DEVICE_H */
