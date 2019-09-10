// SPDX-License-Identifier: GPL-2.0+
/* NetworkManager -- Network link manager
 *
 * Copyright (C) 2007 - 2008 Novell, Inc.
 * Copyright (C) 2007 - 2013 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_BLUEZ5_MANAGER_H__
#define __NETWORKMANAGER_BLUEZ5_MANAGER_H__

#define NM_TYPE_BLUEZ5_MANAGER            (nm_bluez5_manager_get_type ())
#define NM_BLUEZ5_MANAGER(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_BLUEZ5_MANAGER, NMBluez5Manager))
#define NM_BLUEZ5_MANAGER_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_BLUEZ5_MANAGER, NMBluez5ManagerClass))
#define NM_IS_BLUEZ5_MANAGER(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_BLUEZ5_MANAGER))
#define NM_IS_BLUEZ5_MANAGER_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_BLUEZ5_MANAGER))
#define NM_BLUEZ5_MANAGER_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_BLUEZ5_MANAGER, NMBluez5ManagerClass))

typedef struct _NMBluez5Manager NMBluez5Manager;
typedef struct _NMBluez5ManagerClass NMBluez5ManagerClass;

GType nm_bluez5_manager_get_type (void);

NMBluez5Manager *nm_bluez5_manager_new (NMSettings *settings);

void nm_bluez5_manager_query_devices (NMBluez5Manager *manager);

#endif /* __NETWORKMANAGER_BLUEZ5_MANAGER_H__ */
