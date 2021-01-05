/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2018 Lubomir Rintel <lkundrak@v3.sk>
 */

#ifndef __NETWORKMANAGER_DEVICE_WPAN_H__
#define __NETWORKMANAGER_DEVICE_WPAN_H__

#define NM_TYPE_DEVICE_WPAN (nm_device_wpan_get_type())
#define NM_DEVICE_WPAN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_WPAN, NMDeviceWpan))
#define NM_DEVICE_WPAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_WPAN, NMDeviceWpanClass))
#define NM_IS_DEVICE_WPAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_WPAN))
#define NM_IS_DEVICE_WPAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_WPAN))
#define NM_DEVICE_WPAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_WPAN, NMDeviceWpanClass))

typedef struct _NMDeviceWpan      NMDeviceWpan;
typedef struct _NMDeviceWpanClass NMDeviceWpanClass;

GType nm_device_wpan_get_type(void);

#endif /* __NETWORKMANAGER_DEVICE_WPAN_H__ */
