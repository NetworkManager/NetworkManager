/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_PPP_H__
#define __NM_DEVICE_PPP_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_PPP (nm_device_ppp_get_type())
#define NM_DEVICE_PPP(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_PPP, NMDevicePpp))
#define NM_DEVICE_PPP_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_PPP, NMDevicePppClass))
#define NM_IS_DEVICE_PPP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_PPP))
#define NM_IS_DEVICE_PPP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_PPP))
#define NM_DEVICE_PPP_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_PPP, NMDevicePppClass))

/**
 * NMDevicePpp:
 *
 * Since: 1.10
 */
typedef struct _NMDevicePpp      NMDevicePpp;
typedef struct _NMDevicePppClass NMDevicePppClass;

NM_AVAILABLE_IN_1_10
GType nm_device_ppp_get_type(void);

G_END_DECLS

#endif /* __NM_DEVICE_PPP_H__ */
