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
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2008 Red Hat, Inc.
 */

#ifndef _NM_PROPERTIES_CHANGED_SIGNAL_H_
#define _NM_PROPERTIES_CHANGED_SIGNAL_H_

#include <glib-object.h>

#define NM_PROPERTY_PARAM_NO_EXPORT    (1 << (0 + G_PARAM_USER_SHIFT))

guint nm_properties_changed_signal_new (GObjectClass *object_class,
								guint class_offset);

#endif /* _NM_PROPERTIES_CHANGED_SIGNAL_H_ */
