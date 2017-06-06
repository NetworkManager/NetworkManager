/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
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
