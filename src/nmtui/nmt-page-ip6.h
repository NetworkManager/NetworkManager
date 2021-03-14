/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_IP6_H
#define NMT_PAGE_IP6_H

#include "nmt-editor-page.h"

#define NMT_TYPE_PAGE_IP6 (nmt_page_ip6_get_type())
#define NMT_PAGE_IP6(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_IP6, NmtPageIP6))
#define NMT_PAGE_IP6_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_IP6, NmtPageIP6Class))
#define NMT_IS_PAGE_IP6(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_IP6))
#define NMT_IS_PAGE_IP6_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_IP6))
#define NMT_PAGE_IP6_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_IP6, NmtPageIP6Class))

typedef struct {
    NmtEditorPage parent;

} NmtPageIP6;

typedef struct {
    NmtEditorPageClass parent;

} NmtPageIP6Class;

GType nmt_page_ip6_get_type(void);

NmtEditorPage *nmt_page_ip6_new(NMConnection *conn);

#endif /* NMT_PAGE_IP6_H */
