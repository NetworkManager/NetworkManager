// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Author: Pantelis Koukousoulas <pktoss@gmail.com>
 * Copyright (C) 2009 - 2011 Red Hat Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_ADSL_H__
#define __NETWORKMANAGER_DEVICE_ADSL_H__

#include "devices/nm-device.h"

#define NM_TYPE_DEVICE_ADSL            (nm_device_adsl_get_type ())
#define NM_DEVICE_ADSL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_ADSL, NMDeviceAdsl))
#define NM_DEVICE_ADSL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_ADSL, NMDeviceAdslClass))
#define NM_IS_DEVICE_ADSL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_ADSL))
#define NM_IS_DEVICE_ADSL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_ADSL))
#define NM_DEVICE_ADSL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_ADSL, NMDeviceAdslClass))

#define NM_DEVICE_ADSL_ATM_INDEX "atm-index"

typedef struct _NMDeviceAdsl NMDeviceAdsl;
typedef struct _NMDeviceAdslClass NMDeviceAdslClass;

GType nm_device_adsl_get_type (void);

NMDevice *nm_device_adsl_new (const char *udi,
                              const char *iface,
                              const char *driver,
                              int atm_index);

#endif /* NM_DEVICE_ADSL_H */
