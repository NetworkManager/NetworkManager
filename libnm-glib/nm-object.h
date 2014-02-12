/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * libnm_glib -- Access network status & information from glib applications
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2012 Red Hat, Inc.
 */

#ifndef NM_OBJECT_H
#define NM_OBJECT_H

#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>

#include <nm-version.h>

G_BEGIN_DECLS

#define NM_TYPE_OBJECT            (nm_object_get_type ())
#define NM_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OBJECT, NMObject))
#define NM_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OBJECT, NMObjectClass))
#define NM_IS_OBJECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OBJECT))
#define NM_IS_OBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_OBJECT))
#define NM_OBJECT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OBJECT, NMObjectClass))

/**
 * NMObjectError:
 * @NM_OBJECT_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_OBJECT_ERROR_OBJECT_CREATION_FAILURE: an error ocured while creating an #NMObject
 *
 * Describes errors that may result from operations involving a #NMObject.
 *
 **/
typedef enum {
	NM_OBJECT_ERROR_UNKNOWN = 0,
	NM_OBJECT_ERROR_OBJECT_CREATION_FAILURE,
} NMObjectError;

#define NM_OBJECT_ERROR nm_object_error_quark ()
GQuark nm_object_error_quark (void);

#define NM_OBJECT_DBUS_CONNECTION "dbus-connection"
#define NM_OBJECT_DBUS_PATH "dbus-path"

typedef struct {
	GObject parent;
} NMObject;

typedef struct {
	GObjectClass parent;

	/* Signals */
	/* The "object-creation-failed" signal is PRIVATE for libnm-glib and
	 * is not meant for any external usage.  It indicates that an error
	 * occured during creation of an object.
	 */
	void (*object_creation_failed) (NMObject *master_object,
	                                GError *error,
	                                char *failed_path);

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
	void (*_reserved5) (void);
	void (*_reserved6) (void);
} NMObjectClass;

GType nm_object_get_type (void);

DBusGConnection *nm_object_get_connection (NMObject *object);
const char      *nm_object_get_path       (NMObject *object);

G_END_DECLS

#endif /* NM_OBJECT_H */
