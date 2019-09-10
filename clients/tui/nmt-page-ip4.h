// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_IP4_H
#define NMT_PAGE_IP4_H

#include "nmt-editor-page.h"

#define NMT_TYPE_PAGE_IP4            (nmt_page_ip4_get_type ())
#define NMT_PAGE_IP4(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_PAGE_IP4, NmtPageIP4))
#define NMT_PAGE_IP4_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_PAGE_IP4, NmtPageIP4Class))
#define NMT_IS_PAGE_IP4(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_PAGE_IP4))
#define NMT_IS_PAGE_IP4_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_PAGE_IP4))
#define NMT_PAGE_IP4_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_PAGE_IP4, NmtPageIP4Class))

typedef struct {
	NmtEditorPage parent;

} NmtPageIP4;

typedef struct {
	NmtEditorPageClass parent;

} NmtPageIP4Class;

GType nmt_page_ip4_get_type (void);

NmtEditorPage *nmt_page_ip4_new          (NMConnection *conn);

#endif /* NMT_PAGE_IP4_H */
