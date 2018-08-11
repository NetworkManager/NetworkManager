/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see
 * <http://www.gnu.org/licenses/>.
 *
 * Copyright 2018 Red Hat, Inc.
 */

#ifndef NM_SETTING_MATCH_H
#define NM_SETTING_MATCH_H

#if !defined (__NETWORKMANAGER_H_INSIDE__) && !defined (NETWORKMANAGER_COMPILATION)
#error "Only <NetworkManager.h> can be included directly."
#endif

#include "nm-setting.h"

G_BEGIN_DECLS

#define NM_TYPE_SETTING_MATCH            (nm_setting_match_get_type ())
#define NM_SETTING_MATCH(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_SETTING_MATCH, NMSettingMatch))
#define NM_SETTING_MATCH_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_SETTING_MATCH, NMSettingMatchClass))
#define NM_IS_SETTING_MATCH(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_SETTING_MATCH))
#define NM_IS_SETTING_MATCH_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_SETTING_MATCH))
#define NM_SETTING_MATCH_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_SETTING_MATCH, NMSettingMatchClass))

#define NM_SETTING_MATCH_SETTING_NAME      "match"

#define NM_SETTING_MATCH_INTERFACE_NAME    "interface-name"

typedef struct _NMSettingMatchClass NMSettingMatchClass;


NM_AVAILABLE_IN_1_14
GType nm_setting_match_get_type (void);
NM_AVAILABLE_IN_1_14
NMSetting *nm_setting_match_new (void);

NM_AVAILABLE_IN_1_14
guint nm_setting_match_get_num_interface_names (NMSettingMatch *setting);
NM_AVAILABLE_IN_1_14
const char *nm_setting_match_get_interface_name (NMSettingMatch *setting, int idx);
NM_AVAILABLE_IN_1_14
void nm_setting_match_remove_interface_name (NMSettingMatch *setting, int idx);
NM_AVAILABLE_IN_1_14
gboolean nm_setting_match_remove_interface_name_by_value (NMSettingMatch *setting,
                                                          const char *interface_name);
NM_AVAILABLE_IN_1_14
void nm_setting_match_add_interface_name (NMSettingMatch *setting,
                                          const char *interface_name);
NM_AVAILABLE_IN_1_14
void nm_setting_match_clear_interface_names (NMSettingMatch *setting);
NM_AVAILABLE_IN_1_14
const char *const *nm_setting_match_get_interface_names (NMSettingMatch *setting, guint *length);
G_END_DECLS

#endif /* NM_SETTING_MATCH_H */
