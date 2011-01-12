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
 * Copyright (C) 2009 Novell, Inc.
 */

#ifndef NM_WIMAX_UTIL_H
#define NM_WIMAX_UTIL_H

#include <glib.h>

#include <WiMaxType.h>
#include <WiMaxError.h>
#include "nm-wimax-types.h"

void nm_wimax_util_sdk_ref (void);

gboolean nm_wimax_util_sdk_is_initialized (void);

void nm_wimax_util_sdk_unref (void);

NMWimaxNspNetworkType nm_wimax_util_convert_network_type (WIMAX_API_NETWORK_TYPE wimax_network_type);

#endif	/* NM_WIMAX_UTIL_H */
