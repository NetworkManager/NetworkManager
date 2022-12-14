/* SPDX-License-Identifier: LGPL-2.1-or-later */
/*
 * Copyright (C) 2022 Red Hat, Inc.
 */

#ifndef NMT_PAGE_MACSEC_H
#define NMT_PAGE_MACSEC_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_MACSEC (nmt_page_macsec_get_type())
#define NMT_PAGE_MACSEC(obj) \
    (_NM_G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_MACSEC, NmtPageMacsec))
#define NMT_PAGE_MACSEC_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_MACSEC, NmtPageMacsecClass))
#define NMT_IS_PAGE_MACSEC(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_MACSEC))
#define NMT_IS_PAGE_MACSEC_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_MACSEC))
#define NMT_PAGE_MACSEC_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_MACSEC, NmtPageMacsecClass))

typedef struct _NmtPageMacsec      NmtPageMacsec;
typedef struct _NmtPageMacsecClass NmtPageMacsecClass;

GType nmt_page_macsec_get_type(void);

NmtEditorPage *nmt_page_macsec_new(NMConnection *conn, NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_MACSEC_H */
