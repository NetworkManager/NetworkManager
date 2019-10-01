// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_SEPARATOR_H
#define NMT_NEWT_SEPARATOR_H

#include "nmt-newt-component.h"

#define NMT_TYPE_NEWT_SEPARATOR            (nmt_newt_separator_get_type ())
#define NMT_NEWT_SEPARATOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_SEPARATOR, NmtNewtSeparator))
#define NMT_NEWT_SEPARATOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_SEPARATOR, NmtNewtSeparatorClass))
#define NMT_IS_NEWT_SEPARATOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_SEPARATOR))
#define NMT_IS_NEWT_SEPARATOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_SEPARATOR))
#define NMT_NEWT_SEPARATOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_SEPARATOR, NmtNewtSeparatorClass))

struct _NmtNewtSeparator {
  NmtNewtComponent parent;

};

typedef struct {
  NmtNewtComponentClass parent;

} NmtNewtSeparatorClass;

GType nmt_newt_separator_get_type (void);

NmtNewtWidget *nmt_newt_separator_new (void);

#endif /* NMT_NEWT_SEPARATOR_H */
