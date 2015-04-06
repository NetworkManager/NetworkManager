/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* NetworkManager -- Network link manager
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_GRE_H__
#define __NETWORKMANAGER_DEVICE_GRE_H__

#include "nm-device-generic.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_GRE            (nm_device_gre_get_type ())
#define NM_DEVICE_GRE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_GRE, NMDeviceGre))
#define NM_DEVICE_GRE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_GRE, NMDeviceGreClass))
#define NM_IS_DEVICE_GRE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_GRE))
#define NM_IS_DEVICE_GRE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_GRE))
#define NM_DEVICE_GRE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_GRE, NMDeviceGreClass))

#define NM_DEVICE_GRE_PARENT             "parent"
#define NM_DEVICE_GRE_INPUT_FLAGS        "input-flags"
#define NM_DEVICE_GRE_OUTPUT_FLAGS       "output-flags"
#define NM_DEVICE_GRE_INPUT_KEY          "input-key"
#define NM_DEVICE_GRE_OUTPUT_KEY         "output-key"
#define NM_DEVICE_GRE_LOCAL              "local"
#define NM_DEVICE_GRE_REMOTE             "remote"
#define NM_DEVICE_GRE_TTL                "ttl"
#define NM_DEVICE_GRE_TOS                "tos"
#define NM_DEVICE_GRE_PATH_MTU_DISCOVERY "path-mtu-discovery"

typedef NMDeviceGeneric NMDeviceGre;
typedef NMDeviceGenericClass NMDeviceGreClass;

GType nm_device_gre_get_type (void);

G_END_DECLS

#endif	/* NM_DEVICE_GRE_H */
