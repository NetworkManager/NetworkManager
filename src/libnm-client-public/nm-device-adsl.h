/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 Pantelis Koukousoulas <pktoss@gmail.com>
 */

#ifndef __NM_DEVICE_ADSL_H__
#define __NM_DEVICE_ADSL_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_ADSL (nm_device_adsl_get_type())
#define NM_DEVICE_ADSL(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_ADSL, NMDeviceAdsl))
#define NM_DEVICE_ADSL_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_ADSL, NMDeviceAdslClass))
#define NM_IS_DEVICE_ADSL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_ADSL))
#define NM_IS_DEVICE_ADSL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_ADSL))
#define NM_DEVICE_ADSL_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_ADSL, NMDeviceAdslClass))

#define NM_DEVICE_ADSL_CARRIER "carrier"

/**
 * NMDeviceAdsl:
 */
typedef struct _NMDeviceAdslClass NMDeviceAdslClass;

GType nm_device_adsl_get_type(void);

gboolean nm_device_adsl_get_carrier(NMDeviceAdsl *device);

G_END_DECLS

#endif /* __NM_DEVICE_ADSL_H__ */
