/*
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
 * Copyright 2008 - 2011 Red Hat, Inc.
 */

#ifndef __NM_OBJECT_PRIVATE_H__
#define __NM_OBJECT_PRIVATE_H__

#if !((NETWORKMANAGER_COMPILATION) & NM_NETWORKMANAGER_COMPILATION_WITH_LIBNM_PRIVATE)
#error Cannot use this header.
#endif

#include "nm-object.h"

typedef gboolean (*PropertyMarshalFunc) (NMObject *, GParamSpec *, GVariant *, gpointer);

typedef GObject * (*NMObjectCreatorFunc) (GDBusConnection *, const char *);

typedef struct {
	const char *name;
	gpointer field;
	PropertyMarshalFunc func;
	GType object_type;
	const char *signal_prefix;
} NMPropertiesInfo;

void _nm_object_register_properties (NMObject *object,
                                     const char *interface,
                                     const NMPropertiesInfo *info);

void _nm_object_queue_notify (NMObject *object, const char *property);

GDBusObjectManager *_nm_object_get_dbus_object_manager (NMObject *object);

GQuark _nm_object_obj_nm_quark (void);

/* DBus property accessors */

void _nm_object_set_property (NMObject *object,
                              const char *interface,
                              const char *prop_name,
                              const char *format_string,
                              ...);

GDBusProxy *_nm_object_get_proxy (NMObject   *object,
                                  const char *interface);

struct udev;
void _nm_device_set_udev (NMDevice *device, struct udev *udev);

#endif /* __NM_OBJECT_PRIVATE_H__ */
