// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_EDITOR_PAGE_DEVICE_H
#define NMT_EDITOR_PAGE_DEVICE_H

#include "nmt-editor-page.h"
#include "nmt-device-entry.h"

#define NMT_TYPE_EDITOR_PAGE_DEVICE            (nmt_editor_page_device_get_type ())
#define NMT_EDITOR_PAGE_DEVICE(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_EDITOR_PAGE_DEVICE, NmtEditorPageDevice))
#define NMT_EDITOR_PAGE_DEVICE_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_EDITOR_PAGE_DEVICE, NmtEditorPageDeviceClass))
#define NMT_IS_EDITOR_PAGE_DEVICE(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_EDITOR_PAGE_DEVICE))
#define NMT_IS_EDITOR_PAGE_DEVICE_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_EDITOR_PAGE_DEVICE))
#define NMT_EDITOR_PAGE_DEVICE_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_EDITOR_PAGE_DEVICE, NmtEditorPageDeviceClass))

typedef struct {
	NmtEditorPage parent;

} NmtEditorPageDevice;

typedef struct {
	NmtEditorPageClass parent;

} NmtEditorPageDeviceClass;

GType nmt_editor_page_device_get_type (void);

NmtDeviceEntry *nmt_editor_page_device_get_device_entry (NmtEditorPageDevice *page);

#endif /* NMT_EDITOR_PAGE_DEVICE_H */
