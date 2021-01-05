/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_VLAN_H
#define NMT_PAGE_VLAN_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_VLAN (nmt_page_vlan_get_type())
#define NMT_PAGE_VLAN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_VLAN, NmtPageVlan))
#define NMT_PAGE_VLAN_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_VLAN, NmtPageVlanClass))
#define NMT_IS_PAGE_VLAN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_VLAN))
#define NMT_IS_PAGE_VLAN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_VLAN))
#define NMT_PAGE_VLAN_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_VLAN, NmtPageVlanClass))

typedef struct {
    NmtEditorPageDevice parent;

} NmtPageVlan;

typedef struct {
    NmtEditorPageDeviceClass parent;

} NmtPageVlanClass;

GType nmt_page_vlan_get_type(void);

NmtEditorPage *nmt_page_vlan_new(NMConnection *conn, NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_VLAN_H */
