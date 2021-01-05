/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_DEVICE_ENTRY_H
#define NMT_DEVICE_ENTRY_H

#include "nmt-editor-grid.h"

#define NMT_TYPE_DEVICE_ENTRY (nmt_device_entry_get_type())
#define NMT_DEVICE_ENTRY(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_DEVICE_ENTRY, NmtDeviceEntry))
#define NMT_DEVICE_ENTRY_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_DEVICE_ENTRY, NmtDeviceEntryClass))
#define NMT_IS_DEVICE_ENTRY(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_DEVICE_ENTRY))
#define NMT_IS_DEVICE_ENTRY_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_DEVICE_ENTRY))
#define NMT_DEVICE_ENTRY_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_DEVICE_ENTRY, NmtDeviceEntryClass))

typedef struct {
    NmtEditorGrid parent;

} NmtDeviceEntry;

typedef struct {
    NmtEditorGridClass parent;

} NmtDeviceEntryClass;

GType nmt_device_entry_get_type(void);

NmtNewtWidget *nmt_device_entry_new(const char *label, int width, GType hardware_type);

typedef gboolean (*NmtDeviceEntryDeviceFilter)(NmtDeviceEntry *deventry,
                                               NMDevice *      device,
                                               gpointer        user_data);
void nmt_device_entry_set_device_filter(NmtDeviceEntry *           deventry,
                                        NmtDeviceEntryDeviceFilter filter,
                                        gpointer                   user_data);

#endif /* NMT_DEVICE_ENTRY_H */
