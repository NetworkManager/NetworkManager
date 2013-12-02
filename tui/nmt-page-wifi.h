/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
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

#ifndef NMT_PAGE_WIFI_H
#define NMT_PAGE_WIFI_H

#include "nmt-page-device.h"

G_BEGIN_DECLS

#define NMT_TYPE_PAGE_WIFI            (nmt_page_wifi_get_type ())
#define NMT_PAGE_WIFI(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_PAGE_WIFI, NmtPageWifi))
#define NMT_PAGE_WIFI_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_PAGE_WIFI, NmtPageWifiClass))
#define NMT_IS_PAGE_WIFI(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_PAGE_WIFI))
#define NMT_IS_PAGE_WIFI_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_PAGE_WIFI))
#define NMT_PAGE_WIFI_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_PAGE_WIFI, NmtPageWifiClass))

typedef struct {
	NmtPageDevice parent;

} NmtPageWifi;

typedef struct {
	NmtPageDeviceClass parent;

} NmtPageWifiClass;

GType nmt_page_wifi_get_type (void);

NmtNewtWidget *nmt_page_wifi_new (NMConnection   *conn,
                                  NmtDeviceEntry *deventry);

G_END_DECLS

#endif /* NMT_PAGE_WIFI_H */
