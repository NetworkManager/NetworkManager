// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_WIFI_H
#define NMT_PAGE_WIFI_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_WIFI            (nmt_page_wifi_get_type ())
#define NMT_PAGE_WIFI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_PAGE_WIFI, NmtPageWifi))
#define NMT_PAGE_WIFI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_PAGE_WIFI, NmtPageWifiClass))
#define NMT_IS_PAGE_WIFI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_PAGE_WIFI))
#define NMT_IS_PAGE_WIFI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_PAGE_WIFI))
#define NMT_PAGE_WIFI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_PAGE_WIFI, NmtPageWifiClass))

typedef struct {
	NmtEditorPageDevice parent;

} NmtPageWifi;

typedef struct {
	NmtEditorPageDeviceClass parent;

} NmtPageWifiClass;

GType nmt_page_wifi_get_type (void);

NmtEditorPage *nmt_page_wifi_new (NMConnection   *conn,
                                  NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_WIFI_H */
