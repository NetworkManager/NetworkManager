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

#include "nm-device.h"

#define _LOG_DECLARE_SELF(t) \
_nm_unused \
static inline NMDevice * \
_nm_device_log_self_to_device (t *self) \
{ \
    return (NMDevice *) self; \
}

#undef  _NMLOG_ENABLED
#define _NMLOG_ENABLED(level, domain) ( nm_logging_enabled ((level), (domain)) )
#define _NMLOG(level, domain, ...) \
	G_STMT_START { \
		const NMLogLevel _level = (level); \
		const NMLogDomain _domain = (domain); \
		\
		if (nm_logging_enabled (_level, _domain)) { \
			typeof (*self) *const _self = (self); \
			const char *const _ifname = _nm_device_get_iface (_nm_device_log_self_to_device (_self)); \
			\
			nm_log_obj (_level, _domain, \
			            _ifname, NULL, \
			            _self, "device", \
			            "%s%s%s: " _NM_UTILS_MACRO_FIRST(__VA_ARGS__), \
			            NM_PRINT_FMT_QUOTED (_ifname, "(", _ifname, ")", "[null]") \
			            _NM_UTILS_MACRO_REST(__VA_ARGS__)); \
		} \
	} G_STMT_END

#endif /* __NETWORKMANAGER_DEVICE_LOGGING_H__ */
