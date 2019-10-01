// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_OVSDB_H__
#define __NETWORKMANAGER_OVSDB_H__

#define NM_TYPE_OVSDB            (nm_ovsdb_get_type ())
#define NM_OVSDB(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_OVSDB, NMOvsdb))
#define NM_OVSDB_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_OVSDB, NMOvsdbClass))
#define NM_IS_OVSDB(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_OVSDB))
#define NM_IS_OVSDB_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_OVSDB))
#define NM_OVSDB_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_OVSDB, NMOvsdbClass))

#define NM_OVSDB_DEVICE_ADDED      "device-added"
#define NM_OVSDB_DEVICE_REMOVED    "device-removed"
#define NM_OVSDB_INTERFACE_FAILED  "interface-failed"

typedef struct _NMOvsdb NMOvsdb;
typedef struct _NMOvsdbClass NMOvsdbClass;

typedef void (*NMOvsdbCallback) (GError *error, gpointer user_data);

NMOvsdb *nm_ovsdb_get (void);

GType nm_ovsdb_get_type (void);

void nm_ovsdb_add_interface (NMOvsdb *self,
                             NMConnection *bridge, NMConnection *port, NMConnection *interface,
                             NMOvsdbCallback callback, gpointer user_data);

void nm_ovsdb_del_interface (NMOvsdb *self, const char *ifname,
                             NMOvsdbCallback callback, gpointer user_data);

#endif /* __NETWORKMANAGER_OVSDB_H__ */
