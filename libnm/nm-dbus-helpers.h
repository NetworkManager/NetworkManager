// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef __NM_DBUS_HELPERS_PRIVATE_H__
#define __NM_DBUS_HELPERS_PRIVATE_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_PRIVATE)
#error Cannot use this header.
#endif

#include "nm-std-aux/nm-dbus-compat.h"

GBusType _nm_dbus_bus_type (void);

void             _nm_dbus_proxy_replace_match   (GDBusProxy *proxy);

void _nm_dbus_bind_properties (gpointer object,
                               gpointer skeleton);

void _nm_dbus_bind_methods (gpointer object,
                            gpointer skeleton,
                            ...) G_GNUC_NULL_TERMINATED;

#endif /* __NM_DBUS_HELPERS_PRIVATE_H__ */
