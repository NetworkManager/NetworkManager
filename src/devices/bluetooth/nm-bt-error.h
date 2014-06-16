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

#ifndef _NM_BLUEZ5_ERROR_H_
#define _NM_BLUEZ5_ERROR_H_

typedef enum {
	NM_BT_ERROR_CONNECTION_NOT_BT = 0,   /*< nick=ConnectionNotBt >*/
	NM_BT_ERROR_CONNECTION_INVALID,      /*< nick=ConnectionInvalid >*/
	NM_BT_ERROR_CONNECTION_INCOMPATIBLE, /*< nick=ConnectionIncompatible >*/
	NM_BT_ERROR_DUN_CONNECT_FAILED,      /*< nick=DunConnectFailed >*/
} NMBtError;

#define NM_BT_ERROR (nm_bt_error_quark ())
GQuark nm_bt_error_quark (void);

#endif  /* _NM_BT_ERROR_H_ */

