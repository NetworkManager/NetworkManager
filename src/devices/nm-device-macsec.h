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
 * Copyright 2017 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_MACSEC_H__
#define __NM_DEVICE_MACSEC_H__

#include "nm-device.h"

#define NM_TYPE_DEVICE_MACSEC            (nm_device_macsec_get_type ())
#define NM_DEVICE_MACSEC(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DEVICE_MACSEC, NMDeviceMacsec))
#define NM_DEVICE_MACSEC_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DEVICE_MACSEC, NMDeviceMacsecClass))
#define NM_IS_DEVICE_MACSEC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DEVICE_MACSEC))
#define NM_IS_DEVICE_MACSEC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DEVICE_MACSEC))
#define NM_DEVICE_MACSEC_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DEVICE_MACSEC, NMDeviceMacsecClass))

#define NM_DEVICE_MACSEC_SCI             "sci"
#define NM_DEVICE_MACSEC_CIPHER_SUITE    "cipher-suite"
#define NM_DEVICE_MACSEC_ICV_LENGTH      "icv-length"
#define NM_DEVICE_MACSEC_WINDOW          "window"
#define NM_DEVICE_MACSEC_ENCODING_SA     "encoding-sa"
#define NM_DEVICE_MACSEC_VALIDATION      "validation"
#define NM_DEVICE_MACSEC_ENCRYPT         "encrypt"
#define NM_DEVICE_MACSEC_PROTECT         "protect"
#define NM_DEVICE_MACSEC_INCLUDE_SCI     "include-sci"
#define NM_DEVICE_MACSEC_ES              "es"
#define NM_DEVICE_MACSEC_SCB             "scb"
#define NM_DEVICE_MACSEC_REPLAY_PROTECT  "replay-protect"

typedef struct _NMDeviceMacsec NMDeviceMacsec;
typedef struct _NMDeviceMacsecClass NMDeviceMacsecClass;

GType nm_device_macsec_get_type (void);

#endif /* __NM_DEVICE_MACSEC_H__ */
