/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#include "libnm/nm-default-libnm.h"

#include "nm-device-ppp.h"

#include "nm-device.h"

/*****************************************************************************/

struct _NMDevicePpp {
    NMDevice parent;
};

struct _NMDevicePppClass {
    NMDeviceClass parent;
};

G_DEFINE_TYPE(NMDevicePpp, nm_device_ppp, NM_TYPE_DEVICE)

/*****************************************************************************/

static void
nm_device_ppp_init(NMDevicePpp *device)
{}

const NMLDBusMetaIface _nml_dbus_meta_iface_nm_device_ppp =
    NML_DBUS_META_IFACE_INIT(NM_DBUS_INTERFACE_DEVICE_PPP,
                             nm_device_ppp_get_type,
                             NML_DBUS_META_INTERFACE_PRIO_INSTANTIATE_30, );

static void
nm_device_ppp_class_init(NMDevicePppClass *klass)
{}
