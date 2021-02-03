/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef __NETWORKMANAGER_DEVICE_VRF_H__
#define __NETWORKMANAGER_DEVICE_VRF_H__

#include "nm-device-generic.h"

#define NM_TYPE_DEVICE_VRF (nm_device_vrf_get_type())
#define NM_DEVICE_VRF(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_VRF, NMDeviceVrf))
#define NM_DEVICE_VRF_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_VRF, NMDeviceVrfClass))
#define NM_IS_DEVICE_VRF(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_VRF))
#define NM_IS_DEVICE_VRF_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_VRF))
#define NM_DEVICE_VRF_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_VRF, NMDeviceVrfClass))

#define NM_DEVICE_VRF_TABLE "table"

typedef struct _NMDeviceVrf      NMDeviceVrf;
typedef struct _NMDeviceVrfClass NMDeviceVrfClass;

GType nm_device_vrf_get_type(void);

#endif /* __NETWORKMANAGER_DEVICE_VRF_H__ */
