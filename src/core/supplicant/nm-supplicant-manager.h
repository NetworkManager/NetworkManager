/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2006 - 2008 Red Hat, Inc.
 * Copyright (C) 2007 - 2008 Novell, Inc.
 */

#ifndef __NETWORKMANAGER_SUPPLICANT_MANAGER_H__
#define __NETWORKMANAGER_SUPPLICANT_MANAGER_H__

#include "nm-supplicant-types.h"
#include "devices/nm-device.h"

#define NM_TYPE_SUPPLICANT_MANAGER (nm_supplicant_manager_get_type())
#define NM_SUPPLICANT_MANAGER(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_SUPPLICANT_MANAGER, NMSupplicantManager))
#define NM_SUPPLICANT_MANAGER_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_SUPPLICANT_MANAGER, NMSupplicantManagerClass))
#define NM_IS_SUPPLICANT_MANAGER(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_SUPPLICANT_MANAGER))
#define NM_IS_SUPPLICANT_MANAGER_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_SUPPLICANT_MANAGER))
#define NM_SUPPLICANT_MANAGER_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_SUPPLICANT_MANAGER, NMSupplicantManagerClass))

#define NM_SUPPLICANT_MANAGER_AVAILABLE_CHANGED "available-changed"

typedef struct _NMSupplicantManagerClass NMSupplicantManagerClass;

GType nm_supplicant_manager_get_type(void);

NMSupplicantManager *nm_supplicant_manager_get(void);

NMTernary nm_supplicant_manager_is_available(NMSupplicantManager *self);

GDBusConnection *nm_supplicant_manager_get_dbus_connection(NMSupplicantManager *self);
NMRefString *    nm_supplicant_manager_get_dbus_name_owner(NMSupplicantManager *self);
NMSupplCapMask   nm_supplicant_manager_get_global_capabilities(NMSupplicantManager *self);

void nm_supplicant_manager_set_wfd_ies(NMSupplicantManager *self, GBytes *wfd_ies);

typedef struct _NMSupplMgrCreateIfaceHandle NMSupplMgrCreateIfaceHandle;

typedef void (*NMSupplicantManagerCreateInterfaceCb)(NMSupplicantManager *        self,
                                                     NMSupplMgrCreateIfaceHandle *handle,
                                                     NMSupplicantInterface *      iface,
                                                     GError *                     error,
                                                     gpointer                     user_data);

NMSupplMgrCreateIfaceHandle *
nm_supplicant_manager_create_interface(NMSupplicantManager *                self,
                                       int                                  ifindex,
                                       NMSupplicantDriver                   driver,
                                       NMSupplicantManagerCreateInterfaceCb callback,
                                       gpointer                             user_data);

void nm_supplicant_manager_create_interface_cancel(NMSupplMgrCreateIfaceHandle *handle);

NMSupplicantInterface *nm_supplicant_manager_create_interface_from_path(NMSupplicantManager *self,
                                                                        const char *object_path);

/*****************************************************************************/

void _nm_supplicant_manager_unregister_interface(NMSupplicantManager *  self,
                                                 NMSupplicantInterface *supp_iface);

void _nm_supplicant_manager_dbus_call_remove_interface(NMSupplicantManager *self,
                                                       const char *         name_owner,
                                                       const char *         iface_path);

#endif /* __NETWORKMANAGER_SUPPLICANT_MANAGER_H__ */
