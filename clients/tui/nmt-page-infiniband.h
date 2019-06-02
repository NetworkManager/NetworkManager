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

#ifndef NMT_PAGE_INFINIBAND_H
#define NMT_PAGE_INFINIBAND_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_INFINIBAND            (nmt_page_infiniband_get_type ())
#define NMT_PAGE_INFINIBAND(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_PAGE_INFINIBAND, NmtPageInfiniband))
#define NMT_PAGE_INFINIBAND_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_PAGE_INFINIBAND, NmtPageInfinibandClass))
#define NMT_IS_PAGE_INFINIBAND(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_PAGE_INFINIBAND))
#define NMT_IS_PAGE_INFINIBAND_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_PAGE_INFINIBAND))
#define NMT_PAGE_INFINIBAND_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_PAGE_INFINIBAND, NmtPageInfinibandClass))

typedef struct {
	NmtEditorPageDevice parent;

} NmtPageInfiniband;

typedef struct {
	NmtEditorPageDeviceClass parent;

} NmtPageInfinibandClass;

GType nmt_page_infiniband_get_type (void);

NmtEditorPage *nmt_page_infiniband_new (NMConnection   *conn,
                                        NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_INFINIBAND_H */
