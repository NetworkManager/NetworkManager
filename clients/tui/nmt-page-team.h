// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_TEAM_H
#define NMT_PAGE_TEAM_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_TEAM            (nmt_page_team_get_type ())
#define NMT_PAGE_TEAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NMT_TYPE_PAGE_TEAM, NmtPageTeam))
#define NMT_PAGE_TEAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NMT_TYPE_PAGE_TEAM, NmtPageTeamClass))
#define NMT_IS_PAGE_TEAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NMT_TYPE_PAGE_TEAM))
#define NMT_IS_PAGE_TEAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NMT_TYPE_PAGE_TEAM))
#define NMT_PAGE_TEAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NMT_TYPE_PAGE_TEAM, NmtPageTeamClass))

typedef struct {
	NmtEditorPageDevice parent;

} NmtPageTeam;

typedef struct {
	NmtEditorPageDeviceClass parent;

} NmtPageTeamClass;

GType nmt_page_team_get_type (void);

NmtEditorPage *nmt_page_team_new (NMConnection   *conn,
                                  NmtDeviceEntry *deventry);

#endif /* NMT_PAGE_TEAM_H */
