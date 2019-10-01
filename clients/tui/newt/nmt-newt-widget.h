// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_WIDGET_H
#define NMT_NEWT_WIDGET_H

#include "nmt-newt-types.h"

#define NMT_TYPE_NEWT_WIDGET            (nmt_newt_widget_get_type ())
#define NMT_NEWT_WIDGET(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_NEWT_WIDGET, NmtNewtWidget))
#define NMT_NEWT_WIDGET_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_NEWT_WIDGET, NmtNewtWidgetClass))
#define NMT_IS_NEWT_WIDGET(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_NEWT_WIDGET))
#define NMT_IS_NEWT_WIDGET_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_NEWT_WIDGET))
#define NMT_NEWT_WIDGET_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_NEWT_WIDGET, NmtNewtWidgetClass))

struct _NmtNewtWidget {
	GInitiallyUnowned parent;

};

typedef struct {
	GInitiallyUnownedClass parent;

	/* signals */
	void            (*needs_rebuild)       (NmtNewtWidget *widget);
	void            (*activated)           (NmtNewtWidget *widget);

	/* methods */
	void            (*realize)             (NmtNewtWidget *widget);
	void            (*unrealize)           (NmtNewtWidget *widget);

	newtComponent * (*get_components)      (NmtNewtWidget *widget);
	NmtNewtWidget * (*find_component)      (NmtNewtWidget *widget,
	                                        newtComponent  co);

	void            (*size_request)        (NmtNewtWidget *widget,
	                                        int           *width,
	                                        int           *height);
	void            (*size_allocate)       (NmtNewtWidget *widget,
	                                        int            x,
	                                        int            y,
	                                        int            width,
	                                        int            height);

	newtComponent   (*get_focus_component) (NmtNewtWidget *widget);

} NmtNewtWidgetClass;

GType nmt_newt_widget_get_type (void);

void           nmt_newt_widget_realize        (NmtNewtWidget *widget);
void           nmt_newt_widget_unrealize      (NmtNewtWidget *widget);
gboolean       nmt_newt_widget_get_realized   (NmtNewtWidget *widget);

newtComponent *nmt_newt_widget_get_components (NmtNewtWidget *widget);

void           nmt_newt_widget_set_padding    (NmtNewtWidget *widget,
                                               int            pad_left,
                                               int            pad_top,
                                               int            pad_right,
                                               int            pad_bottom);

void           nmt_newt_widget_size_request   (NmtNewtWidget *widget,
                                               int           *width,
                                               int           *height);
void           nmt_newt_widget_size_allocate  (NmtNewtWidget *widget,
                                               int            x,
                                               int            y,
                                               int            width,
                                               int            height);

void           nmt_newt_widget_set_parent     (NmtNewtWidget *widget,
                                               NmtNewtWidget *parent);
NmtNewtWidget *nmt_newt_widget_get_parent     (NmtNewtWidget *widget);

NmtNewtForm   *nmt_newt_widget_get_form       (NmtNewtWidget *widget);

gboolean       nmt_newt_widget_get_visible    (NmtNewtWidget *widget);
void           nmt_newt_widget_set_visible    (NmtNewtWidget *widget,
                                               gboolean       visible);

newtComponent  nmt_newt_widget_get_focus_component  (NmtNewtWidget *widget);

void           nmt_newt_widget_activated            (NmtNewtWidget *widget);
gboolean       nmt_newt_widget_get_exit_on_activate (NmtNewtWidget *widget);
void           nmt_newt_widget_set_exit_on_activate (NmtNewtWidget *widget,
                                                     gboolean       exit_on_activate);

gboolean       nmt_newt_widget_get_valid      (NmtNewtWidget *widget);

NmtNewtWidget *nmt_newt_widget_find_component (NmtNewtWidget *widget,
                                               newtComponent  co);

/* protected */
void           nmt_newt_widget_needs_rebuild  (NmtNewtWidget *widget);
void           nmt_newt_widget_set_valid      (NmtNewtWidget *widget,
                                               gboolean       valid);

#endif /* NMT_NEWT_WIDGET_H */
