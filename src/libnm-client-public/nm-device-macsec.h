/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NM_DEVICE_MACSEC_H__
#define __NM_DEVICE_MACSEC_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_MACSEC (nm_device_macsec_get_type())
#define NM_DEVICE_MACSEC(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_MACSEC, NMDeviceMacsec))
#define NM_DEVICE_MACSEC_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_MACSEC, NMDeviceMacsecClass))
#define NM_IS_DEVICE_MACSEC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_MACSEC))
#define NM_IS_DEVICE_MACSEC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_MACSEC))
#define NM_DEVICE_MACSEC_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_MACSEC, NMDeviceMacsecClass))

#define NM_DEVICE_MACSEC_PARENT         "parent"
#define NM_DEVICE_MACSEC_HW_ADDRESS     "hw-address"
#define NM_DEVICE_MACSEC_SCI            "sci"
#define NM_DEVICE_MACSEC_ICV_LENGTH     "icv-length"
#define NM_DEVICE_MACSEC_CIPHER_SUITE   "cipher-suite"
#define NM_DEVICE_MACSEC_WINDOW         "window"
#define NM_DEVICE_MACSEC_ENCODING_SA    "encoding-sa"
#define NM_DEVICE_MACSEC_VALIDATION     "validation"
#define NM_DEVICE_MACSEC_ENCRYPT        "encrypt"
#define NM_DEVICE_MACSEC_PROTECT        "protect"
#define NM_DEVICE_MACSEC_INCLUDE_SCI    "include-sci"
#define NM_DEVICE_MACSEC_ES             "es"
#define NM_DEVICE_MACSEC_SCB            "scb"
#define NM_DEVICE_MACSEC_REPLAY_PROTECT "replay-protect"

/**
 * NMDeviceMacsec:
 */
typedef struct _NMDeviceMacsecClass NMDeviceMacsecClass;

NM_AVAILABLE_IN_1_6
GType nm_device_macsec_get_type(void);

NM_AVAILABLE_IN_1_6
NMDevice *nm_device_macsec_get_parent(NMDeviceMacsec *device);

NM_AVAILABLE_IN_1_6
NM_DEPRECATED_IN_1_24_FOR(nm_device_get_hw_address)
const char *nm_device_macsec_get_hw_address(NMDeviceMacsec *device);

NM_AVAILABLE_IN_1_6
guint64 nm_device_macsec_get_sci(NMDeviceMacsec *device);
NM_AVAILABLE_IN_1_6
guint8 nm_device_macsec_get_icv_length(NMDeviceMacsec *device);
NM_AVAILABLE_IN_1_6
guint64 nm_device_macsec_get_cipher_suite(NMDeviceMacsec *device);
NM_AVAILABLE_IN_1_6
guint nm_device_macsec_get_window(NMDeviceMacsec *device);
NM_AVAILABLE_IN_1_6
guint8 nm_device_macsec_get_encoding_sa(NMDeviceMacsec *device);
NM_AVAILABLE_IN_1_6
const char *nm_device_macsec_get_validation(NMDeviceMacsec *device);
NM_AVAILABLE_IN_1_6
gboolean nm_device_macsec_get_encrypt(NMDeviceMacsec *device);
NM_AVAILABLE_IN_1_6
gboolean nm_device_macsec_get_protect(NMDeviceMacsec *device);
NM_AVAILABLE_IN_1_6
gboolean nm_device_macsec_get_include_sci(NMDeviceMacsec *device);
NM_AVAILABLE_IN_1_6
gboolean nm_device_macsec_get_es(NMDeviceMacsec *device);
NM_AVAILABLE_IN_1_6
gboolean nm_device_macsec_get_scb(NMDeviceMacsec *device);
NM_AVAILABLE_IN_1_6
gboolean nm_device_macsec_get_replay_protect(NMDeviceMacsec *device);
G_END_DECLS

#endif /* __NM_DEVICE_MACSEC_H__ */
