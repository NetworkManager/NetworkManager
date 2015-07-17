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
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_DEVICE_LOGGING_H__
#define __NETWORKMANAGER_DEVICE_LOGGING_H__

#include "nm-default.h"
#include "nm-device.h"

#define _LOG_DECLARE_SELF(t) \
inline static NMDevice * \
_nm_device_log_self_to_device (t *self) \
{ \
    return (NMDevice *) self; \
}

#define _LOG(level, domain, ...) \
    nm_log_obj ((level), (domain), (self), \
                "(%s): " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
                (self) ? str_if_set (nm_device_get_iface (_nm_device_log_self_to_device (self)), "(null)") : "(none)" \
                _NM_UTILS_MACRO_REST(__VA_ARGS__))

#define _LOGT(domain, ...)      _LOG (LOGL_TRACE, domain, __VA_ARGS__)
#define _LOGD(domain, ...)      _LOG (LOGL_DEBUG, domain, __VA_ARGS__)
#define _LOGI(domain, ...)      _LOG (LOGL_INFO,  domain, __VA_ARGS__)
#define _LOGW(domain, ...)      _LOG (LOGL_WARN,  domain, __VA_ARGS__)
#define _LOGE(domain, ...)      _LOG (LOGL_ERR,   domain, __VA_ARGS__)

#endif /* __NETWORKMANAGER_DEVICE_LOGGING_H__ */
