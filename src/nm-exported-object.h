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
 * Copyright 2014 Red Hat, Inc.
 */

#ifndef NM_EXPORTED_OBJECT_H
#define NM_EXPORTED_OBJECT_H

#include <dbus/dbus-glib.h>

#include "nm-default.h"

G_BEGIN_DECLS

#define NM_TYPE_EXPORTED_OBJECT            (nm_exported_object_get_type ())
#define NM_EXPORTED_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_EXPORTED_OBJECT, NMExportedObject))
#define NM_EXPORTED_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_EXPORTED_OBJECT, NMExportedObjectClass))
#define NM_IS_EXPORTED_OBJECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_EXPORTED_OBJECT))
#define NM_IS_EXPORTED_OBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_EXPORTED_OBJECT))
#define NM_EXPORTED_OBJECT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_EXPORTED_OBJECT, NMExportedObjectClass))

typedef struct {
	GObject parent;
} NMExportedObject;

typedef struct {
	GObjectClass parent;

	const char *export_path;
} NMExportedObjectClass;

GType nm_exported_object_get_type (void);

void nm_exported_object_class_add_interface (NMExportedObjectClass *object_class,
                                             const DBusGObjectInfo *info);

const char *nm_exported_object_export      (NMExportedObject *self);
const char *nm_exported_object_get_path    (NMExportedObject *self);
gboolean    nm_exported_object_is_exported (NMExportedObject *self);
void        nm_exported_object_unexport    (NMExportedObject *self);

G_END_DECLS

#endif	/* NM_EXPORTED_OBJECT_H */
