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

#ifndef NMT_DEVICE_ENTRY_H
#define NMT_DEVICE_ENTRY_H

#include "nmt-editor-grid.h"

#include <NetworkManager.h>

G_BEGIN_DECLS

#define NMT_TYPE_DEVICE_ENTRY            (nmt_device_entry_get_type ())
#define NMT_DEVICE_ENTRY(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_DEVICE_ENTRY, NmtDeviceEntry))
#define NMT_DEVICE_ENTRY_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_DEVICE_ENTRY, NmtDeviceEntryClass))
#define NMT_IS_DEVICE_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_DEVICE_ENTRY))
#define NMT_IS_DEVICE_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_DEVICE_ENTRY))
#define NMT_DEVICE_ENTRY_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_DEVICE_ENTRY, NmtDeviceEntryClass))

typedef struct {
	NmtEditorGrid parent;

} NmtDeviceEntry;

typedef struct {
	NmtEditorGridClass parent;

} NmtDeviceEntryClass;

GType nmt_device_entry_get_type (void);

NmtNewtWidget *nmt_device_entry_new (const char *label,
                                     int         width,
                                     GType       hardware_type);

typedef gboolean (*NmtDeviceEntryDeviceFilter) (NmtDeviceEntry *deventry,
                                                NMDevice       *device,
                                                gpointer        user_data);
void nmt_device_entry_set_device_filter (NmtDeviceEntry             *deventry,
                                         NmtDeviceEntryDeviceFilter  filter,
                                         gpointer                    user_data);

G_END_DECLS

#endif /* NMT_DEVICE_ENTRY_H */
