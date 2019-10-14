// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_BOND_H
#define NMT_PAGE_BOND_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_BOND            (nmt_page_bond_get_type ())
#define NMT_PAGE_BOND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_PAGE_BOND, NmtPageBond))
#define NMT_PAGE_BOND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_PAGE_BOND, NmtPageBondClass))
#define NMT_IS_PAGE_BOND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_PAGE_BOND))
#define NMT_IS_PAGE_BOND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_PAGE_BOND))
#define NMT_PAGE_BOND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_PAGE_BOND, NmtPageBondClass))

typedef struct {
	NmtEditorPageDevice parent;

} NmtPageBond;

typedef struct {
	NmtEditorPageDeviceClass parent;

} NmtPageBondClass;

GType nmt_page_bond_get_type (void);

NmtEditorPage *nmt_page_bond_new (NMConnection   *conn,
                                  NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_BOND_H */
