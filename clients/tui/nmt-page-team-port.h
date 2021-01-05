/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (C) 2013 Red Hat, Inc.
 */

#ifndef NMT_PAGE_TEAM_PORT_H
#define NMT_PAGE_TEAM_PORT_H

#include "nmt-editor-page-device.h"

#define NMT_TYPE_PAGE_TEAM_PORT (nmt_page_team_port_get_type())
#define NMT_PAGE_TEAM_PORT(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), NMT_TYPE_PAGE_TEAM_PORT, NmtPageTeamPort))
#define NMT_PAGE_TEAM_PORT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), NMT_TYPE_PAGE_TEAM_PORT, NmtPageTeamPortClass))
#define NMT_IS_PAGE_TEAM_PORT(obj) (G_TYPE_CHECK_INSTANCE_TYPE((obj), NMT_TYPE_PAGE_TEAM_PORT))
#define NMT_IS_PAGE_TEAM_PORT_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), NMT_TYPE_PAGE_TEAM_PORT))
#define NMT_PAGE_TEAM_PORT_GET_CLASS(obj) \
    (G_TYPE_INSTANCE_GET_CLASS((obj), NMT_TYPE_PAGE_TEAM_PORT, NmtPageTeamPortClass))

typedef struct {
    NmtEditorPage parent;

} NmtPageTeamPort;

typedef struct {
    NmtEditorPageClass parent;

} NmtPageTeamPortClass;

GType nmt_page_team_port_get_type(void);

NmtEditorPage *nmt_page_team_port_new(NMConnection *conn);

#endif /* NMT_PAGE_TEAM_PORT_H */
