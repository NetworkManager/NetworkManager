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

#ifndef NM_SETTING_TEAM_H
#define NM_SETTING_TEAM_H

#include <nm-setting.h>

G_BEGIN_DECLS

#define NM_TYPE_SETTING_TEAM            (nm_setting_team_get_type ())
#define NM_SETTING_TEAM(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_TEAM, NMSettingTeam))
#define NM_SETTING_TEAM_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_TEAM, NMSettingTeamClass))
#define NM_IS_SETTING_TEAM(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_TEAM))
#define NM_IS_SETTING_TEAM_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_TEAM))
#define NM_SETTING_TEAM_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_TEAM, NMSettingTeamClass))

#define NM_SETTING_TEAM_SETTING_NAME "team"

/**
 * NMSettingTeamError:
 * @NM_SETTING_TEAM_ERROR_UNKNOWN: unknown or unclassified error
 * @NM_SETTING_TEAM_ERROR_INVALID_PROPERTY: the property was invalid
 * @NM_SETTING_TEAM_ERROR_MISSING_PROPERTY: the property was missing and is
 * required
 */
typedef enum {
	NM_SETTING_TEAM_ERROR_UNKNOWN = 0,      /*< nick=UnknownError >*/
	NM_SETTING_TEAM_ERROR_INVALID_PROPERTY, /*< nick=InvalidProperty >*/
	NM_SETTING_TEAM_ERROR_MISSING_PROPERTY, /*< nick=MissingProperty >*/
} NMSettingTeamError;

#define NM_SETTING_TEAM_ERROR nm_setting_team_error_quark ()
GQuark nm_setting_team_error_quark (void);

#define NM_SETTING_TEAM_INTERFACE_NAME "interface-name"
#define NM_SETTING_TEAM_CONFIG "config"

typedef struct {
	NMSetting parent;
} NMSettingTeam;

typedef struct {
	NMSettingClass parent;

	/* Padding for future expansion */
	void (*_reserved1) (void);
	void (*_reserved2) (void);
	void (*_reserved3) (void);
	void (*_reserved4) (void);
} NMSettingTeamClass;

NM_AVAILABLE_IN_0_9_10
GType nm_setting_team_get_type (void);

NM_AVAILABLE_IN_0_9_10
NMSetting *  nm_setting_team_new                (void);

const char * nm_setting_team_get_interface_name (NMSettingTeam *setting);
const char * nm_setting_team_get_config (NMSettingTeam *setting);

G_END_DECLS

#endif /* NM_SETTING_TEAM_H */
