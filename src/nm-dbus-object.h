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
 * Copyright 2018 Red Hat, Inc.
 */

#ifndef __NM_DBUS_OBJECT_H__
#define __NM_DBUS_OBJECT_H__

/*****************************************************************************/

#include "nm-utils/c-list.h"
#include "nm-dbus-utils.h"

/*****************************************************************************/

void nm_dbus_object_set_quitting (void);

/*****************************************************************************/

/* "org.freedesktop.NetworkManager.Device.Statistics" is a special interface,
 * because although it has a legacy PropertiesChanged signal, it only notifies
 * about properties that actually exist on that interface. That is, because it
 * was added with 1.4.0 release, and thus didn't have the broken behavior like
 * other legacy interfaces. Those notify about *all* properties, even if they
 * are not part of that D-Bus interface. See also "include_in_legacy_property_changed"
 * and "legacy_property_changed". */
extern const NMDBusInterfaceInfoExtended nm_interface_info_device_statistics;

/*****************************************************************************/

#define NM_TYPE_DBUS_OBJECT            (nm_dbus_object_get_type ())
#define NM_DBUS_OBJECT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_DBUS_OBJECT, NMDBusObject))
#define NM_DBUS_OBJECT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass),  NM_TYPE_DBUS_OBJECT, NMDBusObjectClass))
#define NM_IS_DBUS_OBJECT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_DBUS_OBJECT))
#define NM_IS_DBUS_OBJECT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass),  NM_TYPE_DBUS_OBJECT))
#define NM_DBUS_OBJECT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj),  NM_TYPE_DBUS_OBJECT, NMDBusObjectClass))

#define NM_DBUS_OBJECT_PATH "path"

/* NMDBusObject and NMDBusManager cooperate strongly. Hence, there is an
 * internal data structure attached to the NMDBusObject accessible to both of them. */
struct _NMDBusObjectInternal {
	char *path;
	NMDBusManager *bus_manager;
	CList objects_lst;
	CList registration_lst_head;

	/* we perform asynchronous operation on exported objects. For example, we receive
	 * a Set property call, and asynchronously validate the operation. We must make
	 * sure that when the authentication is complete, that we are still looking at
	 * the same (exported) object. In the meantime, the object could have been
	 * unexported, or even re-exported afterwards. If that happens, we want
	 * to fail the request. For that, we keep track of a version id.  */
	guint64 export_version_id;
};

struct _NMDBusObject {
	GObject parent;
	struct _NMDBusObjectInternal internal;
};

#define NM_DEFINE_DBUS_INTERFACE_INFO(...) \
	((NMDBusInterfaceInfo *) (&((const NMDBusInterfaceInfo) { \
		__VA_ARGS__ \
	})))

typedef struct {
	GObjectClass parent;

	const char *export_path;

	const NMDBusInterfaceInfoExtended *const*interface_infos;

	bool export_on_construction;
} NMDBusObjectClass;

GType nm_dbus_object_get_type (void);

static inline NMDBusManager *
nm_dbus_object_get_manager (NMDBusObject *obj)
{
	nm_assert (NM_IS_DBUS_OBJECT (obj));

	return obj->internal.bus_manager;
}

static inline guint64
nm_dbus_object_get_export_version_id (NMDBusObject *obj)
{
	nm_assert (NM_IS_DBUS_OBJECT (obj));

	return obj->internal.export_version_id;
}

/**
 * nm_dbus_object_get_path:
 * @self: an #NMDBusObject
 *
 * Gets @self's D-Bus path.
 *
 * Returns: @self's D-Bus path, or %NULL if @self is not exported.
 */
static inline const char *
nm_dbus_object_get_path (NMDBusObject *self)
{
	g_return_val_if_fail (NM_IS_DBUS_OBJECT (self), NULL);

	return self->internal.path;
}

/**
 * nm_dbus_object_is_exported:
 * @self: an #NMDBusObject
 *
 * Checks if @self is exported
 *
 * Returns: %TRUE if @self is exported
 */
static inline gboolean
nm_dbus_object_is_exported (NMDBusObject *self)
{
	return !!nm_dbus_object_get_path (self);
}

const char *nm_dbus_object_export      (NMDBusObject *self);
void        nm_dbus_object_unexport    (NMDBusObject *self);

void        _nm_dbus_object_clear_and_unexport (NMDBusObject **location);
#define nm_dbus_object_clear_and_unexport(location) _nm_dbus_object_clear_and_unexport ((NMDBusObject **) (location))

void        nm_dbus_object_emit_signal_variant (NMDBusObject *self,
                                                const NMDBusInterfaceInfoExtended *interface_info,
                                                const GDBusSignalInfo *signal_info,
                                                GVariant *args);

void        nm_dbus_object_emit_signal (NMDBusObject *self,
                                        const NMDBusInterfaceInfoExtended *interface_info,
                                        const GDBusSignalInfo *signal_info,
                                        const char *format,
                                        ...);

#endif /* __NM_DBUS_OBJECT_H__ */
