// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_LABEL_H
#define NMT_NEWT_LABEL_H

#include "nmt-newt-component.h"

#define NMT_TYPE_NEWT_LABEL            (nmt_newt_label_get_type ())
#define NMT_NEWT_LABEL(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_LABEL, NmtNewtLabel))
#define NMT_NEWT_LABEL_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_LABEL, NmtNewtLabelClass))
#define NMT_IS_NEWT_LABEL(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_LABEL))
#define NMT_IS_NEWT_LABEL_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_LABEL))
#define NMT_NEWT_LABEL_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_LABEL, NmtNewtLabelClass))

struct _NmtNewtLabel {
	NmtNewtComponent parent;

};

typedef struct {
	NmtNewtComponentClass parent;

} NmtNewtLabelClass;

GType nmt_newt_label_get_type (void);

typedef enum {
	NMT_NEWT_LABEL_NORMAL,
	NMT_NEWT_LABEL_PLAIN
} NmtNewtLabelStyle;

NmtNewtWidget     *nmt_newt_label_new           (const char        *text);

void               nmt_newt_label_set_text      (NmtNewtLabel      *label,
                                                 const char        *text);
const char        *nmt_newt_label_get_text      (NmtNewtLabel      *label);

void               nmt_newt_label_set_style     (NmtNewtLabel      *label,
                                                 NmtNewtLabelStyle  style);
NmtNewtLabelStyle  nmt_newt_label_get_style     (NmtNewtLabel      *label);

void               nmt_newt_label_set_highlight (NmtNewtLabel      *label,
                                                 gboolean           highlight);
gboolean           nmt_newt_label_get_highlight (NmtNewtLabel      *label);

#endif /* NMT_NEWT_LABEL_H */
