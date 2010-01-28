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

#include "nm-hostname-provider.h"

const char *
nm_hostname_provider_get_hostname (NMHostnameProvider *self)
{
	g_return_val_if_fail (NM_IS_HOSTNAME_PROVIDER (self), NULL);

	return NM_HOSTNAME_PROVIDER_GET_INTERFACE (self)->get_hostname (self);
}

GType
nm_hostname_provider_get_type (void)
{
    static GType type = 0;

    if (!G_UNLIKELY (type)) {
        const GTypeInfo type_info = {
            sizeof (NMHostnameProvider), /* class_size */
            NULL,   /* base_init */
            NULL,       /* base_finalize */
            NULL,
            NULL,       /* class_finalize */
            NULL,       /* class_data */
            0,
            0,              /* n_preallocs */
            NULL
        };

        type = g_type_register_static (G_TYPE_INTERFACE, "NMHostnameProvider", &type_info, 0);
        g_type_interface_add_prerequisite (type, G_TYPE_OBJECT);
    }

    return type;
}
