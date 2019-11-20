// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_PPP_H__
#define __NETWORKMANAGER_DEVICE_PPP_H__

#define NM_TYPE_DEVICE_PPP              (nm_device_ppp_get_type ())
#define NM_DEVICE_PPP(obj)              (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_PPP, NMDevicePpp))
#define NM_DEVICE_PPP_CLASS(klass)      (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_PPP, NMDevicePppClass))
#define NM_IS_DEVICE_PPP(obj)           (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_PPP))
#define NM_IS_DEVICE_PPP_CLASS(klass)   (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_PPP))
#define NM_DEVICE_PPP_GET_CLASS(obj)    (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_PPP, NMDevicePppClass))

typedef struct _NMDevicePpp NMDevicePpp;
typedef struct _NMDevicePppClass NMDevicePppClass;

GType nm_device_ppp_get_type (void);

#endif /* __NETWORKMANAGER_DEVICE_PPP_H__ */
