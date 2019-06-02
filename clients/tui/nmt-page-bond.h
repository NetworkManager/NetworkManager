/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
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
