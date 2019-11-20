// SPDX-License-Identifier: LGPL-2.1+
/*
 * Copyright (C) 2008 - 2011 Red Hat, Inc.
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

GDBusConnection *_nm_object_get_dbus_connection (gpointer self);

const char *_nm_object_get_dbus_name_owner (gpointer self);

GDBusConnection *_nm_client_get_dbus_connection (NMClient *client);

const char *_nm_client_get_dbus_name_owner (NMClient *client);

void _nm_object_dbus_call (gpointer self,
                           gpointer source_tag,
                           GCancellable *cancellable,
                           GAsyncReadyCallback user_callback,
                           gpointer user_callback_data,
                           const char *object_path,
                           const char *interface_name,
                           const char *method_name,
                           GVariant *parameters,
                           const GVariantType *reply_type,
                           GDBusCallFlags flags,
                           int timeout_msec,
                           GAsyncReadyCallback internal_callback);

GVariant *_nm_object_dbus_call_sync (gpointer self,
                                     GCancellable *cancellable,
                                     const char *object_path,
                                     const char *interface_name,
                                     const char *method_name,
                                     GVariant *parameters,
                                     const GVariantType *reply_type,
                                     GDBusCallFlags flags,
                                     int timeout_msec,
                                     gboolean strip_dbus_error,
                                     GError **error);

gboolean _nm_object_dbus_call_sync_void (gpointer self,
                                         GCancellable *cancellable,
                                         const char *object_path,
                                         const char *interface_name,
                                         const char *method_name,
                                         GVariant *parameters,
                                         GDBusCallFlags flags,
                                         int timeout_msec,
                                         gboolean strip_dbus_error,
                                         GError **error);

void _nm_object_set_property (NMObject *object,
                              const char *interface,
                              const char *prop_name,
                              const char *format_string,
                              ...);

GDBusProxy *_nm_object_get_proxy (NMObject   *object,
                                  const char *interface);

GError *_nm_object_new_error_nm_not_running (void);
void _nm_object_set_error_nm_not_running (GError **error);

struct udev;
void _nm_device_set_udev (NMDevice *device, struct udev *udev);

#endif /* __NM_OBJECT_PRIVATE_H__ */
