/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2011 - 2012 Red Hat, Inc.
 * Copyright (C) 2008 Novell, Inc.
 */

#ifndef __NM_DEVICE_MODEM_H__
#define __NM_DEVICE_MODEM_H__

#if !defined(__NETWORKMANAGER_H_INSIDE__) && !defined(NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-device.h"

G_BEGIN_DECLS

#define NM_TYPE_DEVICE_MODEM (nm_device_modem_get_type())
#define NM_DEVICE_MODEM(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModem))
#define NM_DEVICE_MODEM_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))
#define NM_IS_DEVICE_MODEM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_MODEM))
#define NM_IS_DEVICE_MODEM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_MODEM))
#define NM_DEVICE_MODEM_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))

#define NM_DEVICE_MODEM_MODEM_CAPABILITIES   "modem-capabilities"
#define NM_DEVICE_MODEM_CURRENT_CAPABILITIES "current-capabilities"
#define NM_DEVICE_MODEM_DEVICE_ID            "device-id"
#define NM_DEVICE_MODEM_OPERATOR_CODE        "operator-code"
#define NM_DEVICE_MODEM_APN                  "apn"

/**
 * NMDeviceModem:
 */
typedef struct _NMDeviceModemClass NMDeviceModemClass;

GType nm_device_modem_get_type(void);

NMDeviceModemCapabilities nm_device_modem_get_modem_capabilities(NMDeviceModem *self);
NMDeviceModemCapabilities nm_device_modem_get_current_capabilities(NMDeviceModem *self);

NM_AVAILABLE_IN_1_20
const char *nm_device_modem_get_device_id(NMDeviceModem *self);

NM_AVAILABLE_IN_1_20
const char *nm_device_modem_get_operator_code(NMDeviceModem *self);

NM_AVAILABLE_IN_1_20
const char *nm_device_modem_get_apn(NMDeviceModem *self);

G_END_DECLS

#endif /* __NM_DEVICE_MODEM_H__ */
