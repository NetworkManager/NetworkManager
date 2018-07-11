/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2013 Jiri Pirko <jiri@resnulli.us>
 */

#ifndef __NM_SETTING_TEAM_PORT_H__
#define __NM_SETTING_TEAM_PORT_H__

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"
#include "nm-setting-team.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_TEAM_PORT            (nm_setting_team_port_get_type ())
#define NM_SETTING_TEAM_PORT(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_TEAM_PORT, NMSettingTeamPort))
#define NM_SETTING_TEAM_PORT_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_TEAM_PORT, NMSettingTeamPortClass))
#define NM_IS_SETTING_TEAM_PORT(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_TEAM_PORT))
#define NM_IS_SETTING_TEAM_PORT_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_TEAM_PORT))
#define NM_SETTING_TEAM_PORT_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_TEAM_PORT, NMSettingTeamPortClass))

#define NM_SETTING_TEAM_PORT_SETTING_NAME "team-port"

#define NM_SETTING_TEAM_PORT_CONFIG        "config"
#define NM_SETTING_TEAM_PORT_QUEUE_ID      "queue-id"
#define NM_SETTING_TEAM_PORT_PRIO          "prio"
#define NM_SETTING_TEAM_PORT_STICKY        "sticky"
#define NM_SETTING_TEAM_PORT_LACP_PRIO     "lacp-prio"
#define NM_SETTING_TEAM_PORT_LACP_KEY      "lacp-key"
#define NM_SETTING_TEAM_PORT_LINK_WATCHERS "link-watchers"

#define NM_SETTING_TEAM_PORT_QUEUE_ID_DEFAULT   -1
#define NM_SETTING_TEAM_PORT_LACP_PRIO_DEFAULT 255

/**
 * NMSettingTeamPort:
 *
 * Team Port Settings
 */
struct _NMSettingTeamPort {
	NMSetting parent;
};

typedef struct {
	NMSettingClass parent;

	/*< private >*/
	gpointer padding[4];
} NMSettingTeamPortClass;

GType nm_setting_team_port_get_type (void);

NMSetting *  nm_setting_team_port_new (void);

const char * nm_setting_team_port_get_config (NMSettingTeamPort *setting);
NM_AVAILABLE_IN_1_12
int nm_setting_team_port_get_queue_id (NMSettingTeamPort *setting);
NM_AVAILABLE_IN_1_12
int nm_setting_team_port_get_prio (NMSettingTeamPort *setting);
NM_AVAILABLE_IN_1_12
gboolean nm_setting_team_port_get_sticky (NMSettingTeamPort *setting);
NM_AVAILABLE_IN_1_12
int nm_setting_team_port_get_lacp_prio (NMSettingTeamPort *setting);
NM_AVAILABLE_IN_1_12
int nm_setting_team_port_get_lacp_key (NMSettingTeamPort *setting);
NM_AVAILABLE_IN_1_12
guint nm_setting_team_port_get_num_link_watchers (NMSettingTeamPort *setting);
NM_AVAILABLE_IN_1_12
NMTeamLinkWatcher *
nm_setting_team_port_get_link_watcher (NMSettingTeamPort *setting, guint idx);
NM_AVAILABLE_IN_1_12
gboolean
nm_setting_team_port_add_link_watcher (NMSettingTeamPort *setting,
                                       NMTeamLinkWatcher *link_watcher);
NM_AVAILABLE_IN_1_12
void
nm_setting_team_port_remove_link_watcher (NMSettingTeamPort *setting, guint idx);
NM_AVAILABLE_IN_1_12
gboolean
nm_setting_team_port_remove_link_watcher_by_value (NMSettingTeamPort *setting,
                                                   NMTeamLinkWatcher *link_watcher);
NM_AVAILABLE_IN_1_12
void nm_setting_team_port_clear_link_watchers (NMSettingTeamPort *setting);
G_END_DECLS

#endif /* __NM_SETTING_TEAM_PORT_H__ */
