/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_LOGGING_H__
#define __NETWORKMANAGER_DEVICE_LOGGING_H__

#include "nm-device.h"

#if !_NM_CC_SUPPORT_GENERIC
    #define _NM_DEVICE_CAST(self) ((NMDevice *) (self))
#elif !defined(_NMLOG_DEVICE_TYPE)
    #define _NM_DEVICE_CAST(self)                         \
        _Generic((self), NMDevice *                       \
                 : ((NMDevice *) (self)), NMDevice *const \
                 : ((NMDevice *) (self)))
#else
    #define _NM_DEVICE_CAST(self) \
        _Generic((self), \
                 _NMLOG_DEVICE_TYPE *      : ((NMDevice *) (self)), \
                 _NMLOG_DEVICE_TYPE * const: ((NMDevice *) (self)), \
                 NMDevice *                : ((NMDevice *) (self)), \
                 NMDevice *           const: ((NMDevice *) (self)))
#endif

#undef _NMLOG_ENABLED
#define _NMLOG_ENABLED(level, domain) (nm_logging_enabled((level), (domain)))
#define _NMLOG(level, domain, ...)                                                       \
    G_STMT_START                                                                         \
    {                                                                                    \
        const NMLogLevel  _level  = (level);                                             \
        const NMLogDomain _domain = (domain);                                            \
                                                                                         \
        if (nm_logging_enabled(_level, _domain)) {                                       \
            typeof(*self) *const _self   = (self);                                       \
            const char *const    _ifname = _nm_device_get_iface(_NM_DEVICE_CAST(_self)); \
                                                                                         \
            nm_log_obj(_level,                                                           \
                       _domain,                                                          \
                       _ifname,                                                          \
                       NULL,                                                             \
                       _self,                                                            \
                       "device",                                                         \
                       "%s%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__),                    \
                       NM_PRINT_FMT_QUOTED(_ifname, "(", _ifname, ")", "[null]")         \
                           _NM_UTILS_MACRO_REST(__VA_ARGS__));                           \
        }                                                                                \
    }                                                                                    \
    G_STMT_END

#endif /* __NETWORKMANAGER_DEVICE_LOGGING_H__ */
