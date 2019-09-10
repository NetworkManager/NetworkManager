// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_SECTION_H
#define NMT_NEWT_SECTION_H

#include "nmt-newt-container.h"

#define NMT_TYPE_NEWT_SECTION            (nmt_newt_section_get_type ())
#define NMT_NEWT_SECTION(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_SECTION, NmtNewtSection))
#define NMT_NEWT_SECTION_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_SECTION, NmtNewtSectionClass))
#define NMT_IS_NEWT_SECTION(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_SECTION))
#define NMT_IS_NEWT_SECTION_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_SECTION))
#define NMT_NEWT_SECTION_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_SECTION, NmtNewtSectionClass))

struct _NmtNewtSection {
	NmtNewtContainer parent;

};

typedef struct {
	NmtNewtContainerClass parent;

} NmtNewtSectionClass;

GType nmt_newt_section_get_type (void);

NmtNewtWidget *nmt_newt_section_new        (gboolean        show_border);

void           nmt_newt_section_set_header (NmtNewtSection *section,
                                            NmtNewtWidget  *header);
NmtNewtWidget *nmt_newt_section_get_header (NmtNewtSection *section);

void           nmt_newt_section_set_body   (NmtNewtSection *section,
                                            NmtNewtWidget  *body);
NmtNewtWidget *nmt_newt_section_get_body   (NmtNewtSection *section);

#endif /* NMT_NEWT_SECTION_H */
