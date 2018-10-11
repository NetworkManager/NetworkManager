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

#ifndef _NM_BLUEZ5_UTILS_H_
#define _NM_BLUEZ5_UTILS_H_

typedef struct _NMBluez5DunContext NMBluez5DunContext;

typedef void (*NMBluez5DunFunc) (NMBluez5DunContext *context,
                                 const char *rfcomm_dev,
                                 GError *error,
                                 gpointer user_data);

NMBluez5DunContext *nm_bluez5_dun_new (const char *adapter,
                                       const char *remote);

void nm_bluez5_dun_connect (NMBluez5DunContext *context,
                            NMBluez5DunFunc callback,
                            gpointer user_data);

/* Clean up connection resources */
void nm_bluez5_dun_cleanup (NMBluez5DunContext *context);

/* Clean up and dispose all resources */
void nm_bluez5_dun_free (NMBluez5DunContext *context);

#endif  /* _NM_BLUEZ5_UTILS_H_ */
