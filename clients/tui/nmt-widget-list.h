/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2013 Red Hat, Inc.
 */

#ifndef NMT_WIDGET_LIST_H
#define NMT_WIDGET_LIST_H

#include "nmt-newt-grid.h"

#define NMT_TYPE_WIDGET_LIST            (nmt_widget_list_get_type ())
#define NMT_WIDGET_LIST(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_WIDGET_LIST, NmtWidgetList))
#define NMT_WIDGET_LIST_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_WIDGET_LIST, NmtWidgetListClass))
#define NMT_IS_WIDGET_LIST(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_WIDGET_LIST))
#define NMT_IS_WIDGET_LIST_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_WIDGET_LIST))
#define NMT_WIDGET_LIST_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_WIDGET_LIST, NmtWidgetListClass))

typedef struct {
	NmtNewtGrid parent;

} NmtWidgetList;

typedef struct {
	NmtNewtGridClass parent;

	/* signals */
	void            (*add_clicked)    (NmtWidgetList *list);
	void            (*remove_clicked) (NmtWidgetList *list,
	                                   int            n);

	/* methods */
	NmtNewtWidget * (*create_widget)  (NmtWidgetList *list,
	                                   int            n);

} NmtWidgetListClass;

GType nmt_widget_list_get_type (void);

typedef NmtNewtWidget * (*NmtWidgetListCallback) (NmtWidgetList *list,
                                                  int            n,
                                                  gpointer       user_data);

NmtNewtWidget *nmt_widget_list_new        (NmtWidgetListCallback  create_callback,
                                           gpointer               user_data,
                                           GDestroyNotify         destroy_notify,
                                           NmtNewtWidget         *empty_widget);

int            nmt_widget_list_get_length (NmtWidgetList         *list);
void           nmt_widget_list_set_length (NmtWidgetList         *list,
                                           int                    length);

#endif /* NMT_WIDGET_LIST_H */
