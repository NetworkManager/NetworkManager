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
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_SUPPLICANT_SETTINGS_VERIFY_H__
#define __NETWORKMANAGER_SUPPLICANT_SETTINGS_VERIFY_H__

typedef enum {
	TYPE_INVALID = 0,
	TYPE_INT,
	TYPE_BYTES,
	TYPE_UTF8,
	TYPE_KEYWORD,
	TYPE_STRING
} OptType;

OptType nm_supplicant_settings_verify_setting (const char * key,
                                               const char * value,
                                               const guint32 len);

#endif /* __NETWORKMANAGER_SUPPLICANT_SETTINGS_VERIFY_H__ */
