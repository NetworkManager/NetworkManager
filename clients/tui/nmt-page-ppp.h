/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef NMT_PAGE_PPP_H
#define NMT_PAGE_PPP_H

#include "nmt-editor-page.h"

#define NMT_TYPE_PAGE_PPP (nmt_page_ppp_get_type())
#define NMT_PAGE_PPP(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_PPP, NmtPagePpp))
#define NMT_PAGE_PPP_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_PPP, NmtPagePppClass))
#define NMT_IS_PAGE_PPP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_PPP))
#define NMT_IS_PAGE_PPP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_PPP))
#define NMT_PAGE_PPP_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_PPP, NmtPagePppClass))

typedef struct {
    NmtEditorPage parent;

} NmtPagePpp;

typedef struct {
    NmtEditorPageClass parent;

} NmtPagePppClass;

GType nmt_page_ppp_get_type(void);

NmtEditorPage *nmt_page_ppp_new(NMConnection *conn);

#endif /* NMT_PAGE_PPP_H */
