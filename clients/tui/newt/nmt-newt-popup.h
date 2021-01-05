/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_NEWT_POPUP_H
#define NMT_NEWT_POPUP_H

#include "nmt-newt-button.h"

#define NMT_TYPE_NEWT_POPUP (nmt_newt_popup_get_type())
#define NMT_NEWT_POPUP(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_NEWT_POPUP, NmtNewtPopup))
#define NMT_NEWT_POPUP_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_NEWT_POPUP, NmtNewtPopupClass))
#define NMT_IS_NEWT_POPUP(obj)         (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_NEWT_POPUP))
#define NMT_IS_NEWT_POPUP_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_NEWT_POPUP))
#define NMT_NEWT_POPUP_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_NEWT_POPUP, NmtNewtPopupClass))

struct _NmtNewtPopup {
    NmtNewtButton parent;
};

typedef struct {
    NmtNewtButtonClass parent;

} NmtNewtPopupClass;

GType nmt_newt_popup_get_type(void);

typedef struct {
    char *label;
    char *id;
} NmtNewtPopupEntry;

NmtNewtWidget *nmt_newt_popup_new(NmtNewtPopupEntry *entries);

int  nmt_newt_popup_get_active(NmtNewtPopup *popup);
void nmt_newt_popup_set_active(NmtNewtPopup *popup, int active);

const char *nmt_newt_popup_get_active_id(NmtNewtPopup *popup);
void        nmt_newt_popup_set_active_id(NmtNewtPopup *popup, const char *active_id);

#endif /* NMT_NEWT_POPUP_H */
