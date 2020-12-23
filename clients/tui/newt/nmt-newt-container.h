/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_CONTAINER_H
#define NMT_NEWT_CONTAINER_H

#include "nmt-newt-widget.h"

#define NMT_TYPE_NEWT_CONTAINER (nmt_newt_container_get_type())
#define NMT_NEWT_CONTAINER(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_NEWT_CONTAINER, NmtNewtContainer))
#define NMT_NEWT_CONTAINER_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_NEWT_CONTAINER, NmtNewtContainerClass))
#define NMT_IS_NEWT_CONTAINER(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_NEWT_CONTAINER))
#define NMT_IS_NEWT_CONTAINER_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_NEWT_CONTAINER))
#define NMT_NEWT_CONTAINER_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_NEWT_CONTAINER, NmtNewtContainerClass))

struct _NmtNewtContainer {
    NmtNewtWidget parent;
};

typedef struct {
    NmtNewtWidgetClass parent;

    /* methods */
    void (*add)(NmtNewtContainer *container, NmtNewtWidget *child);
    void (*remove)(NmtNewtContainer *container, NmtNewtWidget *child);

    void (*child_validity_changed)(NmtNewtContainer *container, NmtNewtWidget *child);

} NmtNewtContainerClass;

GType nmt_newt_container_get_type(void);

void nmt_newt_container_remove(NmtNewtContainer *container, NmtNewtWidget *widget);

GSList *nmt_newt_container_get_children(NmtNewtContainer *container);

#endif /* NMT_NEWT_CONTAINER_H */
