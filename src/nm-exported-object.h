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

#include "nm-default.h"

G_BEGIN_DECLS

/*****************************************************************************/

char *nm_exported_object_skeletonify_method_name (const char *dbus_method_name);

typedef struct {
	GType dbus_skeleton_type;
	char *method_name;
	GCallback impl;
} NMExportedObjectDBusMethodImpl;

GDBusInterfaceSkeleton *nm_exported_object_skeleton_create (GType dbus_skeleton_type,
                                                            GObjectClass *object_class,
                                                            const NMExportedObjectDBusMethodImpl *methods,
                                                            guint methods_len,
                                                            GObject *target);
void nm_exported_object_skeleton_release (GDBusInterfaceSkeleton *interface);

/*****************************************************************************/

#define NM_TYPE_EXPORTED_OBJECT            (nm_exported_object_get_type ())
#define NM_EXPORTED_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_EXPORTED_OBJECT, NMExportedObject))
#define NM_EXPORTED_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_EXPORTED_OBJECT, NMExportedObjectClass))
#define NM_IS_EXPORTED_OBJECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_EXPORTED_OBJECT))
#define NM_IS_EXPORTED_OBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_EXPORTED_OBJECT))
#define NM_EXPORTED_OBJECT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_EXPORTED_OBJECT, NMExportedObjectClass))

struct _NMExportedObject {
	GDBusObjectSkeleton parent;
};

typedef struct {
	GDBusObjectSkeletonClass parent;

	const char *export_path;
	char export_on_construction;
} NMExportedObjectClass;

GType nm_exported_object_get_type (void);

void nm_exported_object_class_set_quitting  (void);

void nm_exported_object_class_add_interface (NMExportedObjectClass *object_class,
                                             GType                  dbus_skeleton_type,
                                             ...) G_GNUC_NULL_TERMINATED;

const char *nm_exported_object_export      (NMExportedObject *self);
const char *nm_exported_object_get_path    (NMExportedObject *self);
gboolean    nm_exported_object_is_exported (NMExportedObject *self);
void        nm_exported_object_unexport    (NMExportedObject *self);
GDBusInterfaceSkeleton *nm_exported_object_get_interface_by_type (NMExportedObject *self, GType interface_type);

void        _nm_exported_object_clear_and_unexport (NMExportedObject **location);
#define nm_exported_object_clear_and_unexport(location) _nm_exported_object_clear_and_unexport ((NMExportedObject **) (location))

G_END_DECLS

#endif	/* NM_EXPORTED_OBJECT_H */
