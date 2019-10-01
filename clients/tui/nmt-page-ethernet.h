// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_ETHERNET_H
#define NMT_PAGE_ETHERNET_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_ETHERNET            (nmt_page_ethernet_get_type ())
#define NMT_PAGE_ETHERNET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_PAGE_ETHERNET, NmtPageEthernet))
#define NMT_PAGE_ETHERNET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_PAGE_ETHERNET, NmtPageEthernetClass))
#define NMT_IS_PAGE_ETHERNET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_PAGE_ETHERNET))
#define NMT_IS_PAGE_ETHERNET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_PAGE_ETHERNET))
#define NMT_PAGE_ETHERNET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_PAGE_ETHERNET, NmtPageEthernetClass))

typedef struct {
	NmtEditorPageDevice parent;

} NmtPageEthernet;

typedef struct {
	NmtEditorPageDeviceClass parent;

} NmtPageEthernetClass;

GType nmt_page_ethernet_get_type (void);

NmtEditorPage *nmt_page_ethernet_new (NMConnection   *conn,
                                      NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_ETHERNET_H */
