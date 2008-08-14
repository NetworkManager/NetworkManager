/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */

#ifndef NM_HSO_GSM_DEVICE_H
#define NM_HSO_GSM_DEVICE_H

#include <nm-gsm-device.h>

G_BEGIN_DECLS

#define NM_TYPE_HSO_GSM_DEVICE				(nm_hso_gsm_device_get_type ())
#define NM_HSO_GSM_DEVICE(obj)				(G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_HSO_GSM_DEVICE, NMHsoGsmDevice))
#define NM_HSO_GSM_DEVICE_CLASS(klass)		(G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_HSO_GSM_DEVICE, NMHsoGsmDeviceClass))
#define NM_IS_HSO_GSM_DEVICE(obj)			(G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_HSO_GSM_DEVICE))
#define NM_IS_HSO_GSM_DEVICE_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_HSO_GSM_DEVICE))
#define NM_HSO_GSM_DEVICE_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_HSO_GSM_DEVICE, NMHsoGsmDeviceClass))

#define NM_HSO_GSM_DEVICE_NETDEV_IFACE "netdev-iface"

typedef struct {
	NMGsmDevice parent;
} NMHsoGsmDevice;

typedef struct {
	NMGsmDeviceClass parent;
} NMHsoGsmDeviceClass;

GType nm_hso_gsm_device_get_type (void);

NMHsoGsmDevice *nm_hso_gsm_device_new (const char *udi,
                                       const char *data_iface,
                                       const char *monitor_iface,
                                       const char *netdev_iface,
                                       const char *driver,
                                       gboolean managed);

G_END_DECLS

#endif /* NM_HSO_GSM_DEVICE_H */
