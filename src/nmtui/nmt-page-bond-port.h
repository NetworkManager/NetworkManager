/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2021 Red Hat, Inc.
 */

#ifndef NMT_PAGE_BOND_PORT_H
#define NMT_PAGE_BOND_PORT_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_BOND_PORT (nmt_page_bond_port_get_type())
#define NMT_PAGE_BOND_PORT(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_BOND_PORT, NmtPageBondPort))
#define NMT_PAGE_BOND_PORT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_BOND_PORT, NmtPageBondPortClass))
#define NMT_IS_PAGE_BOND_PORT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_BOND_PORT))
#define NMT_IS_PAGE_BOND_PORT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_BOND_PORT))
#define NMT_PAGE_BOND_PORT_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_BOND_PORT, NmtPageBondPortClass))

typedef struct {
    NmtEditorPage parent;

} NmtPageBondPort;

typedef struct {
    NmtEditorPageClass parent;

} NmtPageBondPortClass;

GType nmt_page_bond_port_get_type(void);

NmtEditorPage *nmt_page_bond_port_new(NMConnection *conn);

#endif /* NMT_PAGE_BOND_PORT_H */
