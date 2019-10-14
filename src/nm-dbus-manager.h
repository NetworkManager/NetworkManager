// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 * Copyright (C) 2006 - 2008 Novell, Inc.
 */

#ifndef __NM_DBUS_MANAGER_H__
#define __NM_DBUS_MANAGER_H__

#include "nm-dbus-utils.h"

#define NM_TYPE_DBUS_MANAGER (nm_dbus_manager_get_type ())
#define NM_DBUS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), NM_TYPE_DBUS_MANAGER, NMDBusManager))
#define NM_DBUS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_CAST((k), NM_TYPE_DBUS_MANAGER, NMDBusManagerClass))
#define NM_IS_DBUS_MANAGER(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), NM_TYPE_DBUS_MANAGER))
#define NM_IS_DBUS_MANAGER_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), NM_TYPE_DBUS_MANAGER))
#define NM_DBUS_MANAGER_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), NM_TYPE_DBUS_MANAGER, NMDBusManagerClass))

#define NM_DBUS_MANAGER_PRIVATE_CONNECTION_NEW           "private-connection-new"
#define NM_DBUS_MANAGER_PRIVATE_CONNECTION_DISCONNECTED  "private-connection-disconnected"

typedef struct _NMDBusManagerClass NMDBusManagerClass;

GType nm_dbus_manager_get_type (void);

NMDBusManager *nm_dbus_manager_get (void);

typedef void (*NMDBusManagerSetPropertyHandler) (NMDBusObject *obj,
                                                 const NMDBusInterfaceInfoExtended *interface_info,
                                                 const NMDBusPropertyInfoExtended *property_info,
                                                 GDBusConnection *connection,
                                                 const char *sender,
                                                 GDBusMethodInvocation *invocation,
                                                 GVariant *value,
                                                 gpointer user_data);

gboolean nm_dbus_manager_acquire_bus (NMDBusManager *self,
                                      gboolean request_name);

GDBusConnection *nm_dbus_manager_get_dbus_connection (NMDBusManager *self);

#define NM_MAIN_DBUS_CONNECTION_GET (nm_dbus_manager_get_dbus_connection (nm_dbus_manager_get ()))

void nm_dbus_manager_start (NMDBusManager *self,
                            NMDBusManagerSetPropertyHandler set_property_handler,
                            gpointer set_property_handler_data);

void nm_dbus_manager_stop (NMDBusManager *self);

gboolean nm_dbus_manager_is_stopping (NMDBusManager *self);

gpointer nm_dbus_manager_lookup_object (NMDBusManager *self, const char *path);

void _nm_dbus_manager_obj_export (NMDBusObject *obj);
void _nm_dbus_manager_obj_unexport (NMDBusObject *obj);
void _nm_dbus_manager_obj_notify (NMDBusObject *obj,
                                  guint n_pspecs,
                                  const GParamSpec *const*pspecs);
void _nm_dbus_manager_obj_emit_signal (NMDBusObject *obj,
                                       const NMDBusInterfaceInfoExtended *interface_info,
                                       const GDBusSignalInfo *signal_info,
                                       GVariant *args);

gboolean nm_dbus_manager_get_caller_info (NMDBusManager *self,
                                          GDBusMethodInvocation *context,
                                          const char **out_sender,
                                          gulong *out_uid,
                                          gulong *out_pid);

gboolean nm_dbus_manager_ensure_uid (NMDBusManager          *self,
                                     GDBusMethodInvocation *context,
                                     gulong uid,
                                     GQuark error_domain,
                                     int error_code);

gboolean nm_dbus_manager_get_unix_user (NMDBusManager *self,
                                        const char *sender,
                                        gulong *out_uid);

gboolean nm_dbus_manager_get_caller_info_from_message (NMDBusManager *self,
                                                       GDBusConnection *connection,
                                                       GDBusMessage *message,
                                                       const char **out_sender,
                                                       gulong *out_uid,
                                                       gulong *out_pid);

void nm_dbus_manager_private_server_register (NMDBusManager *self,
                                              const char *path,
                                              const char *tag);

#endif /* __NM_DBUS_MANAGER_H__ */
