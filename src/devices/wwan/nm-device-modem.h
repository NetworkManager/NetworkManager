/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2011 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_MODEM_H__
#define __NETWORKMANAGER_DEVICE_MODEM_H__

#include "devices/nm-device.h"
#include "nm-modem.h"

#define NM_TYPE_DEVICE_MODEM (nm_device_modem_get_type())
#define NM_DEVICE_MODEM(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModem))
#define NM_DEVICE_MODEM_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))
#define NM_IS_DEVICE_MODEM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_DEVICE_MODEM))
#define NM_IS_DEVICE_MODEM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_DEVICE_MODEM))
#define NM_DEVICE_MODEM_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_DEVICE_MODEM, NMDeviceModemClass))

#define NM_DEVICE_MODEM_MODEM                "modem"
#define NM_DEVICE_MODEM_CAPABILITIES         "modem-capabilities"
#define NM_DEVICE_MODEM_CURRENT_CAPABILITIES "current-capabilities"
#define NM_DEVICE_MODEM_DEVICE_ID            "device-id"
#define NM_DEVICE_MODEM_OPERATOR_CODE        "operator-code"
#define NM_DEVICE_MODEM_APN                  "apn"

typedef struct _NMDeviceModem      NMDeviceModem;
typedef struct _NMDeviceModemClass NMDeviceModemClass;

GType nm_device_modem_get_type(void);

NMDevice *nm_device_modem_new(NMModem *modem);

#endif /* __NETWORKMANAGER_DEVICE_MODEM_H__ */
