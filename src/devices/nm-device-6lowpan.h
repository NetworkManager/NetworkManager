// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright 2018 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_6LOWPAN_H__
#define __NETWORKMANAGER_DEVICE_6LOWPAN_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_6LOWPAN            (nm_device_6lowpan_get_type ())
#define NM_DEVICE_6LOWPAN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_6LOWPAN, NMDevice6Lowpan))
#define NM_DEVICE_6LOWPAN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_6LOWPAN, NMDevice6LowpanClass))
#define NM_IS_DEVICE_6LOWPAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_6LOWPAN))
#define NM_IS_DEVICE_6LOWPAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_6LOWPAN))
#define NM_DEVICE_6LOWPAN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_6LOWPAN, NMDevice6LowpanClass))

typedef struct _NMDevice6Lowpan NMDevice6Lowpan;
typedef struct _NMDevice6LowpanClass NMDevice6LowpanClass;

GType nm_device_6lowpan_get_type (void);

#endif /* __NETWORKMANAGER_DEVICE_6LOWPAN_H__ */
