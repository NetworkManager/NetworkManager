/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2017 Red Hat, Inc.
 */

#ifndef __NETWORKMANAGER_OVSDB_H__
#define __NETWORKMANAGER_OVSDB_H__

#define NM_TYPE_OVSDB            (nm_ovsdb_get_type())
#define NM_OVSDB(obj)            (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NM_TYPE_OVSDB, NMOvsdb))
#define NM_OVSDB_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST((klass), NM_TYPE_OVSDB, NMOvsdbClass))
#define NM_IS_OVSDB(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NM_TYPE_OVSDB))
#define NM_IS_OVSDB_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NM_TYPE_OVSDB))
#define NM_OVSDB_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS((obj), NM_TYPE_OVSDB, NMOvsdbClass))

#define NM_OVSDB_DEVICE_ADDED     "device-added"
#define NM_OVSDB_DEVICE_REMOVED   "device-removed"
#define NM_OVSDB_INTERFACE_FAILED "interface-failed"
#define NM_OVSDB_READY            "ready"

typedef struct _NMOvsdb      NMOvsdb;
typedef struct _NMOvsdbClass NMOvsdbClass;

typedef void (*NMOvsdbCallback)(GError *error, gpointer user_data);

NMOvsdb *nm_ovsdb_get(void);

GType nm_ovsdb_get_type(void);

void nm_ovsdb_add_interface(NMOvsdb        *self,
                            NMConnection   *bridge,
                            NMConnection   *port,
                            NMConnection   *interface,
                            NMDevice       *bridge_device,
                            NMDevice       *interface_device,
                            NMOvsdbCallback callback,
                            gpointer        user_data);

void nm_ovsdb_del_interface(NMOvsdb        *self,
                            const char     *ifname,
                            NMOvsdbCallback callback,
                            gpointer        user_data);

void nm_ovsdb_set_interface_mtu(NMOvsdb        *self,
                                const char     *ifname,
                                guint32         mtu,
                                NMOvsdbCallback callback,
                                gpointer        user_data);

void nm_ovsdb_set_reapply(NMOvsdb                 *self,
                          NMDeviceType             device_type,
                          const char              *ifname,
                          const char              *connection_uuid,
                          NMSettingOvsExternalIDs *s_external_ids_old,
                          NMSettingOvsExternalIDs *s_external_ids_new,
                          NMSettingOvsOtherConfig *s_other_config_old,
                          NMSettingOvsOtherConfig *s_other_config_new);

gboolean nm_ovsdb_is_ready(NMOvsdb *self);

#endif /* __NETWORKMANAGER_OVSDB_H__ */
